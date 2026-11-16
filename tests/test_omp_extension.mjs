import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import test from "node:test";
import extension from "../omp/groupib-asm-approval.ts";

const requestId = token => createHash("sha256").update(token).digest("hex").slice(0, 16);

async function socketFixture(token, name) {
  const directory = await mkdtemp(join(tmpdir(), "groupib-asm-approval-"));
  const socket = join(directory, "approval.sock");
  let receive;
  const response = new Promise(resolve => { receive = resolve; });
  const server = createServer(connection => {
    let data = "";
    connection.on("data", chunk => { data += chunk; });
    connection.on("end", () => receive(JSON.parse(data)));
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(socket, resolve);
  });
  return {
    event: {
      server: "groupib-asm",
      method: "notifications/message",
      params: {
        logger: "groupib-asm.approval", level: "notice",
        data: {
          version: 1, socket, token, base_url: "https://asm.example/",
          path: "/api/v1/issues/comments/add", body: { companyId: name, body: `comment ${name}` },
        },
      },
    },
    response,
    async close() {
      await new Promise(resolve => server.close(resolve));
      await rm(directory, { recursive: true, force: true });
    },
  };
}

// Emulates a modal UI that activates its next queued dialog before resolving
// the promise for the previous one, as OMP's terminal UI can do.
function queuedUI() {
  let current;
  const pending = [];
  const opened = [];
  function advance() {
    if (!current && pending.length) {
      current = pending.shift();
      opened.push(current);
    }
  }
  function request(kind, payload, signal) {
    return new Promise(resolve => {
      const entry = { kind, payload, resolve };
      pending.push(entry);
      if (signal) signal.addEventListener("abort", () => {
        if (current === entry) current = undefined;
        else {
          const index = pending.indexOf(entry);
          if (index >= 0) pending.splice(index, 1);
        }
        advance();
        resolve(undefined);
      }, { once: true });
      advance();
    });
  }
  return {
    opened,
    get current() { return current; },
    editor: (title, prefill, { signal }) => request("editor", { title, prefill }, signal),
    select: (title, options, { signal }) => request("select", { title, options }, signal),
    respond(value) {
      assert.ok(current, "a dialog must be open");
      const done = current;
      current = undefined;
      advance();
      done.resolve(value);
    },
  };
}

async function waitFor(predicate, message) {
  for (let i = 0; i < 200; i++) {
    if (predicate()) return;
    await delay(5);
  }
  assert.fail(message);
}

test("notification handler returns while review remains open", async () => {
  const request = await socketFixture("e".repeat(64), "slow-review");
  const handlers = {};
  extension({ on(name, handler) { handlers[name] = handler; } });
  const ui = queuedUI();
  const ctx = { hasUI: true, agent: { kind: "main" }, ui };
  try {
    const handler = handlers.mcp_notification(request.event, ctx);
    const returned = await Promise.race([Promise.resolve(handler).then(() => true), delay(200, false)]);
    assert.equal(returned, true, "notification handler waited for human review");
    await waitFor(() => ui.current?.kind === "editor", "preview was not displayed");
    ui.respond(ui.current.payload.prefill);
    await waitFor(() => ui.current?.kind === "select", "decision was not displayed");
    ui.respond("Approve once");
    assert.deepEqual(await request.response, { token: request.event.params.data.token, approved: true });
  } finally {
    handlers.session_shutdown();
    await request.close();
  }
});

test("concurrent approvals keep each preview, decision and callback together", async () => {
  const one = await socketFixture("a".repeat(64), "company-A");
  const two = await socketFixture("b".repeat(64), "company-B");
  const handlers = {};
  extension({ on(name, handler) { handlers[name] = handler; } });
  const ui = queuedUI();
  const ctx = { hasUI: true, agent: { kind: "main" }, ui };
  try {
    const first = handlers.mcp_notification(one.event, ctx);
    await waitFor(() => ui.current?.kind === "editor", "first preview was not displayed");
    assert.match(ui.current.payload.prefill, /company-A/);
    const firstPreview = ui.current.payload.prefill;
    const second = handlers.mcp_notification(two.event, ctx);
    // Allow the second notification to reach the UI queue if it is not serialized.
    await delay(100);
    ui.respond(ui.current.payload.prefill);
    await waitFor(() => ui.current, "first decision was not displayed");
    assert.equal(ui.current.kind, "select", "another preview appeared before the first decision");
    assert.match(firstPreview, new RegExp(requestId(one.event.params.data.token)));
    assert.match(ui.current.payload.title, new RegExp(requestId(one.event.params.data.token)));
    ui.respond("Approve once");
    assert.deepEqual(await one.response, { token: one.event.params.data.token, approved: true });
    await waitFor(() => ui.current?.kind === "editor", "second preview was not displayed");
    assert.match(ui.current.payload.prefill, /company-B/);
    assert.match(ui.current.payload.prefill, new RegExp(requestId(two.event.params.data.token)));
    ui.respond(ui.current.payload.prefill);
    await waitFor(() => ui.current?.kind === "select", "second decision was not displayed");
    assert.match(ui.current.payload.title, new RegExp(requestId(two.event.params.data.token)));
    ui.respond("Deny");
    assert.deepEqual(await two.response, { token: two.event.params.data.token, approved: false });
    await Promise.all([first, second]);
    assert.deepEqual(ui.opened.map(entry => entry.kind), ["editor", "select", "editor", "select"]);
  } finally {
    handlers.session_shutdown();
    await Promise.all([one.close(), two.close()]);
  }
});

test("a cancelled review releases the next request without sending a callback", async () => {
  const one = await socketFixture("c".repeat(64), "cancelled-company");
  const two = await socketFixture("d".repeat(64), "next-company");
  const handlers = {};
  extension({ on(name, handler) { handlers[name] = handler; } });
  const ui = queuedUI();
  const ctx = { hasUI: true, agent: { kind: "main" }, ui };
  try {
    const first = handlers.mcp_notification(one.event, ctx);
    await waitFor(() => ui.current?.kind === "editor", "first preview was not displayed");
    const second = handlers.mcp_notification(two.event, ctx);
    await delay(100);
    ui.respond(undefined);
    await first;
    await waitFor(() => ui.current?.kind === "editor", "next preview was not displayed");
    assert.match(ui.current.payload.prefill, /next-company/);
    ui.respond(ui.current.payload.prefill);
    await waitFor(() => ui.current?.kind === "select", "next decision was not displayed");
    ui.respond("Deny");
    assert.deepEqual(await two.response, { token: two.event.params.data.token, approved: false });
    await second;
    assert.equal(await Promise.race([one.response.then(() => true), delay(50, false)]), false);
    assert.deepEqual(ui.opened.map(entry => entry.kind), ["editor", "editor", "select"]);
  } finally {
    handlers.session_shutdown();
    await Promise.all([one.close(), two.close()]);
  }
});
