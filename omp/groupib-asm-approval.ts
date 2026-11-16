import { createHash } from "node:crypto";
import { lstat, realpath } from "node:fs/promises";
import { createConnection } from "node:net";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, normalize } from "node:path";

// Factories are rebound in child sessions, but their module state is shared.
// Keep claims briefly after completion to suppress repeated notification delivery.
const claimed = new Set<string>();
// The OMP UI can activate a queued dialog before the previous promise resolves.
// Hold one process-wide slot across preview, decision, and socket callback.
let approvalTurn: Promise<void> = Promise.resolve();
const CLAIM_LIFETIME_MS = 65_000;
const REQUEST_DEADLINE_MS = 55_000;
const CONNECT_DEADLINE_MS = 2_000;
const MAX_BODY_CHARS = 16_000;
const MAX_NOTIFICATION_CHARS = 18_000;

interface NotificationEvent {
  server: string;
  method: string;
  params: unknown;
}

interface AskResult {
  kind: string;
  results?: Array<{
    id: string;
    selectedOptions: string[];
    customInput?: string;
    timedOut?: boolean;
  }>;
}

interface DialogContext {
  hasUI: boolean;
  agent: { kind: string };
  ui: {
    editor(title: string, prefill?: string, options?: { signal?: AbortSignal }): Promise<string | undefined>;
    select(title: string, options: string[], dialogOptions?: { signal?: AbortSignal }): Promise<string | undefined>;
    askDialog?: (
      questions: Array<{
        id: string;
        question: string;
        options: Array<{ label: string }>;
      }>,
      options?: { signal?: AbortSignal },
    ) => Promise<AskResult | undefined>;
  };
}

interface ExtensionAPI {
  on(event: "mcp_notification", handler: (event: NotificationEvent, ctx: DialogContext) => Promise<void>): void;
  on(event: "session_shutdown", handler: () => void): void;
}

type Approval = { socket: string; token: string; requestId: string; preview: string };

function object(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

// Escape every non-ASCII code unit as well as JSON controls, so terminal escape
// sequences, bidi controls and embedded newlines cannot alter the review UI.
function asciiJson(value: unknown): string {
  const json = JSON.stringify(value);
  if (json === undefined) throw new Error("Not JSON");
  return json.replace(/[\u007f-\uffff]/g, char => `\\u${char.charCodeAt(0).toString(16).padStart(4, "0")}`);
}

function parseNotification(event: NotificationEvent): Approval | undefined {
  if (event.server !== "groupib-asm" || event.method !== "notifications/message") return;
  if (!object(event.params) || event.params.logger !== "groupib-asm.approval" || event.params.level !== "notice") return;
  const data = event.params.data;
  if (!object(data) || data.version !== 1 || !object(data.body)) return;
  const { socket, token, path, base_url: baseUrl } = data;
  if (typeof socket !== "string" || !isAbsolute(socket) || normalize(socket) !== socket || socket.includes("\0")) return;
  if (basename(socket) !== "approval.sock" || !/^groupib-asm-approval-[A-Za-z0-9_-]+$/.test(basename(dirname(socket)))) return;
  if (typeof token !== "string" || !/^[0-9a-f]{64}$/.test(token)) return;
  if (typeof path !== "string" || !/^\/api\/v1\/(?:[A-Za-z0-9_-]+\/)*[A-Za-z0-9_-]+$/.test(path)) return;
  if (typeof baseUrl !== "string" || !/^[\x21-\x7e]+$/.test(baseUrl) || baseUrl.includes("\\")) return;
  let url: URL;
  try {
    url = new URL(baseUrl);
  } catch {
    return;
  }
  if ((url.protocol !== "http:" && url.protocol !== "https:") || !url.hostname || url.username || url.password || url.search || url.hash) return;
  const body = asciiJson(data.body);
  if (body.length > MAX_BODY_CHARS || asciiJson(data).length > MAX_NOTIFICATION_CHARS) return;
  const requestId = createHash("sha256").update(token).digest("hex").slice(0, 16);
  // JSON string literals preserve exact values without letting content format the UI.
  const preview = `Request ID: ${requestId}\n` +
    `Review the ENTIRE request. Scroll through all content before continuing.\n` +
    `Submit unchanged to proceed to the separate approval question; cancel to refuse.\n\n` +
    `Method: POST\nBase URL (JSON string): ${asciiJson(baseUrl)}\n` +
    `API path (JSON string): ${asciiJson(path)}\nJSON body:\n${body}`;
  return { socket, token, requestId, preview };
}

async function validSocket(socket: string): Promise<boolean> {
  try {
    if (typeof process.getuid !== "function") return false;
    const root = normalize(tmpdir());
    const directory = dirname(socket);
    if (!isAbsolute(root) || dirname(directory) !== root) return false;
    const [rootReal, directoryReal, dirStat, socketStat] = await Promise.all([
      realpath(root), realpath(directory), lstat(directory), lstat(socket),
    ]);
    const uid = process.getuid();
    return directoryReal === join(rootReal, basename(directory)) &&
      dirStat.isDirectory() && dirStat.uid === uid && (dirStat.mode & 0o7777) === 0o700 &&
      socketStat.isSocket() && socketStat.uid === uid;
  } catch {
    return false;
  }
}

function untilAborted<T>(work: Promise<T>, signal: AbortSignal): Promise<T> {
  const { promise, resolve, reject } = Promise.withResolvers<T>();
  if (signal.aborted) {
    reject(new Error("Approval expired"));
    return promise;
  }
  const abort = () => reject(new Error("Approval expired"));
  signal.addEventListener("abort", abort, { once: true });
  void work.then(
    value => { signal.removeEventListener("abort", abort); resolve(value); },
    error => { signal.removeEventListener("abort", abort); reject(error); },
  );
  return promise;
}

async function choose(ctx: DialogContext, requestId: string, signal: AbortSignal): Promise<boolean | undefined> {
  const question = `Approve Group-IB ASM request ${requestId}?`;
  if (typeof ctx.ui.askDialog === "function") {
    const answer = await untilAborted(ctx.ui.askDialog([{
      id: "groupib-asm-approval",
      question,
      options: [{ label: "Deny" }, { label: "Approve once" }],
    }], { signal }), signal);
    if (answer?.kind !== "submit" || !Array.isArray(answer.results) || answer.results.length !== 1) return;
    const result = answer.results[0];
    if (result.id !== "groupib-asm-approval" || result.timedOut || result.customInput ||
        !Array.isArray(result.selectedOptions) || result.selectedOptions.length !== 1) return;
    if (result.selectedOptions[0] === "Approve once") return true;
    if (result.selectedOptions[0] === "Deny") return false;
    return;
  }
  const answer = await untilAborted(ctx.ui.select(question, ["Deny", "Approve once"], { signal }), signal);
  if (answer === "Approve once") return true;
  if (answer === "Deny") return false;
}

async function sendAnswer(approval: Approval, approved: boolean, signal: AbortSignal): Promise<void> {
  if (signal.aborted || !(await validSocket(approval.socket)) || signal.aborted) return;
  const { promise, resolve } = Promise.withResolvers<void>();
  const socket = createConnection({ path: approval.socket });
  const timer = setTimeout(() => socket.destroy(), CONNECT_DEADLINE_MS);
  const abort = () => socket.destroy();
  const finish = () => {
    clearTimeout(timer);
    signal.removeEventListener("abort", abort);
    resolve();
  };
  signal.addEventListener("abort", abort, { once: true });
  socket.once("error", () => socket.destroy());
  socket.once("close", finish);
  socket.once("connect", () => {
    if (signal.aborted) return socket.destroy();
    // end() flushes exactly one line and half-closes; the server waits for EOF.
    socket.end(`${JSON.stringify({ token: approval.token, approved })}\n`);
  });
  if (signal.aborted) socket.destroy();
  await promise;
}

export default function groupibAsmApproval(pi: ExtensionAPI): void {
  const active = new Set<AbortController>();
  pi.on("session_shutdown", () => {
    for (const controller of active) controller.abort();
  });
  pi.on("mcp_notification", async (event, ctx) => {
    // Borrowed MCP connections fan notifications out to main and child sessions.
    if (!ctx.hasUI || ctx.agent?.kind !== "main") return;
    let approval: Approval | undefined;
    try {
      approval = parseNotification(event);
    } catch {
      return;
    }
    if (!approval || claimed.has(approval.token) || claimed.size >= 512) return;
    claimed.add(approval.token);
    const claimTimer = setTimeout(() => claimed.delete(approval!.token), CLAIM_LIFETIME_MS);
    claimTimer.unref?.();
    const controller = new AbortController();
    active.add(controller);
    const timer = setTimeout(() => controller.abort(), REQUEST_DEADLINE_MS);
    const { promise: turn, resolve: releaseTurn } = Promise.withResolvers<void>();
    const previousTurn = approvalTurn;
    approvalTurn = previousTurn.then(() => turn);
    // Reserving the turn happens before awaiting; even cancelled waiters release
    // their slot only after their predecessors finish.
    // Release on every exit, including shutdown and dialog failures.
    try {
      await previousTurn;
      if (!(await validSocket(approval.socket)) || controller.signal.aborted) return;
      if (typeof ctx.ui.editor !== "function" || typeof ctx.ui.select !== "function") return;
      const reviewed = await untilAborted(ctx.ui.editor(
        "Group-IB ASM request: review all, then submit unchanged",
        approval.preview,
        { signal: controller.signal },
      ), controller.signal);
      if (reviewed !== approval.preview || controller.signal.aborted) return;
      const answer = await choose(ctx, approval.requestId, controller.signal);
      if (typeof answer !== "boolean" || controller.signal.aborted) return;
      await sendAnswer(approval, answer, controller.signal);
    } catch {
      // Missing UI, cancellation, invalid requests and socket failures all fail closed.
    } finally {
      releaseTurn();
      clearTimeout(timer);
      active.delete(controller);
    }
  });
}
