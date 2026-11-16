import asyncio
import json
import stat
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from mcp.server.mcpserver.exceptions import ToolError

from groupib_asm_mcp import server
from groupib_asm_mcp.client import AsmClient


class Session:
    def __init__(self, capabilities=None):
        self.client_capabilities = capabilities
        self.notification = asyncio.get_running_loop().create_future()

    async def send_log_message(self, **kwargs):
        self.notification.set_result(kwargs)


def context(session):
    return SimpleNamespace(
        request_context=SimpleNamespace(session=session),
        elicit=AsyncMock(),
    )


def make_client(requests):
    def handler(request):
        requests.append(request)
        return httpx.Response(200, json={"ok": True})

    return AsmClient(
        "login",
        "secret",
        base_url="https://asm.example/prefix",
        transport=httpx.MockTransport(handler),
    )


async def send_callback(data, callback):
    _, writer = await asyncio.open_unix_connection(data["socket"])
    writer.write(callback)
    await writer.drain()
    writer.close()
    await writer.wait_closed()


async def start_approval(client, ctx, path="/api/v1/write", body=None):
    task = asyncio.create_task(server._mutate_with_approval(client, ctx, path, body or {}))
    notification = await asyncio.wait_for(ctx.request_context.session.notification, 1)
    return task, notification


async def test_approval_notification_and_exact_request():
    requests = []
    client = make_client(requests)
    session = Session()
    ctx = context(session)
    body = {"message": "full unicode: こんにちは", "nested": {"optional": None}, "skip": None}
    task, notification = await start_approval(client, ctx, body=body)
    data = notification["data"]
    assert notification["level"] == "notice"
    assert notification["logger"] == "groupib-asm.approval"
    assert set(data) == {"version", "socket", "token", "path", "body", "base_url"}
    assert data["version"] == 1
    assert data["path"] == "/api/v1/write"
    assert data["body"] == {"message": body["message"], "nested": {"optional": None}}
    assert data["base_url"] == "https://asm.example/prefix/"
    assert len(data["token"]) == 64 and all(c in "0123456789abcdef" for c in data["token"])
    sock = Path(data["socket"])
    assert sock.is_absolute() and sock.name == "approval.sock"
    assert sock.parent.name.startswith("groupib-asm-approval-")
    assert stat.S_IMODE(sock.parent.stat().st_mode) == 0o700
    await send_callback(
        data, json.dumps({"token": data["token"], "approved": True}).encode() + b"\n"
    )
    assert json.loads(await task) == {"ok": True}
    assert len(requests) == 1
    assert str(requests[0].url) == "https://asm.example/prefix/api/v1/write"
    assert json.loads(requests[0].content) == data["body"]
    assert not sock.parent.exists()
    with pytest.raises(OSError):
        await asyncio.open_unix_connection(str(sock))
    ctx.elicit.assert_not_awaited()
    await client.aclose()


@pytest.mark.parametrize(
    "callback",
    [
        lambda token: json.dumps({"token": token, "approved": False}).encode() + b"\n",
        lambda token: json.dumps({"token": "0" * 64, "approved": True}).encode() + b"\n",
        lambda token: b"not json\n",
        lambda token: b"{}\n",
        lambda token: json.dumps({"token": token, "approved": 1}).encode() + b"\n",
        lambda token: json.dumps({"token": token, "approved": True, "extra": 1}).encode() + b"\n",
        lambda token: (f'{{"token":"{token}","approved":false,"approved":true}}\n').encode(),
        lambda token: json.dumps({"token": token, "approved": True}).encode(),
        lambda token: json.dumps({"token": token, "approved": True}).encode() + b"\n{}\n",
        lambda token: b"x" * 4096,
        lambda token: b"\xff\n",
        lambda token: json.dumps({"token": "é", "approved": True}).encode() + b"\n",
    ],
)
async def test_rejected_responses_fail_closed_and_cleanup(callback):
    requests = []
    client = make_client(requests)
    session = Session()
    task, notification = await start_approval(client, context(session), body={"x": 1})
    data = notification["data"]
    await send_callback(data, callback(data["token"]))
    with pytest.raises(ToolError, match="not approved"):
        await task
    assert not requests
    assert not Path(data["socket"]).parent.exists()
    await client.aclose()


async def test_timeout_cleans_up_without_mutation(monkeypatch):
    monkeypatch.setattr(server, "_APPROVAL_TIMEOUT", 0.05)
    requests = []
    client = make_client(requests)
    session = Session()
    task, notification = await start_approval(client, context(session))
    with pytest.raises(ToolError, match="timed out"):
        await task
    assert not requests
    assert not Path(notification["data"]["socket"]).parent.exists()
    await client.aclose()


async def test_partial_callback_expires_and_closes_connection(monkeypatch):
    monkeypatch.setattr(server, "_APPROVAL_TIMEOUT", 0.05)
    requests = []
    client = make_client(requests)
    session = Session()
    task, notification = await start_approval(client, context(session))
    reader, writer = await asyncio.open_unix_connection(notification["data"]["socket"])
    writer.write(b"{")
    await writer.drain()
    with pytest.raises(ToolError, match="timed out"):
        await task
    assert await asyncio.wait_for(reader.read(), 1) == b""
    writer.close()
    await writer.wait_closed()
    assert not requests
    assert not Path(notification["data"]["socket"]).parent.exists()
    await client.aclose()


async def test_cancellation_propagates_and_cleans_up():
    requests = []
    client = make_client(requests)
    session = Session()
    task, notification = await start_approval(client, context(session))
    _, writer = await asyncio.open_unix_connection(notification["data"]["socket"])
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    writer.close()
    await writer.wait_closed()
    assert not requests
    assert not Path(notification["data"]["socket"]).parent.exists()
    await client.aclose()


async def test_notification_failure_cleans_up_and_does_not_mutate():
    requests = []
    client = make_client(requests)
    sockets = []

    async def fail(**kwargs):
        sockets.append(kwargs["data"]["socket"])
        raise RuntimeError("transport closed")

    session = SimpleNamespace(client_capabilities=None, send_log_message=fail)
    with pytest.raises(ToolError, match="approval is unavailable"):
        await server._mutate_with_approval(client, context(session), "/api/v1/write", {})
    assert not requests
    assert not Path(sockets[0]).parent.exists()
    await client.aclose()


async def test_notification_send_disconnect_fails_closed():
    requests = []
    client = make_client(requests)
    sockets = []

    async def disconnect(**kwargs):
        sockets.append(kwargs["data"]["socket"])
        raise OSError("connection closed")

    session = SimpleNamespace(client_capabilities=None, send_log_message=disconnect)
    with pytest.raises(ToolError, match="approval is unavailable"):
        await server._mutate_with_approval(client, context(session), "/api/v1/write", {})
    assert not requests
    assert not Path(sockets[0]).parent.exists()
    await client.aclose()


async def test_missing_session_fails_closed():
    requests = []
    client = make_client(requests)
    with pytest.raises(ToolError, match="approval is unavailable"):
        await server._mutate_with_approval(client, SimpleNamespace(), "/api/v1/write", {})
    assert not requests
    await client.aclose()


@pytest.mark.parametrize("form,url", [(object(), None), (None, None)])
async def test_form_and_legacy_capabilities_use_elicitation(form, url):
    requests = []
    client = make_client(requests)
    capabilities = SimpleNamespace(elicitation=SimpleNamespace(form=form, url=url))
    session = Session(capabilities)
    ctx = context(session)
    ctx.elicit.return_value = SimpleNamespace(action="accept", data=server.Approval(approve=True))
    await server._mutate_with_approval(client, ctx, "/api/v1/write", {"x": 1})
    assert len(requests) == 1
    assert "Base URL: https://asm.example/prefix/" in ctx.elicit.await_args.args[0]
    assert not session.notification.done()
    await client.aclose()


async def test_url_only_capability_uses_bridge():
    requests = []
    client = make_client(requests)
    capabilities = SimpleNamespace(elicitation=SimpleNamespace(form=None, url=object()))
    session = Session(capabilities)
    ctx = context(session)
    task, notification = await start_approval(client, ctx)
    data = notification["data"]
    await send_callback(
        data, json.dumps({"token": data["token"], "approved": False}).encode() + b"\n"
    )
    with pytest.raises(ToolError, match="not approved"):
        await task
    ctx.elicit.assert_not_awaited()
    assert not requests
    await client.aclose()


async def test_explicit_elicitation_decline_does_not_fallback():
    requests = []
    client = make_client(requests)
    session = Session(SimpleNamespace(elicitation=SimpleNamespace(form=object(), url=None)))
    ctx = context(session)
    ctx.elicit.return_value = SimpleNamespace(action="decline")
    with pytest.raises(ToolError, match="not approved"):
        await server._mutate_with_approval(client, ctx, "/api/v1/write", {})
    assert not requests
    assert not session.notification.done()
    await client.aclose()


async def test_two_simultaneous_requests_are_independent():
    requests = []
    client = make_client(requests)
    first, second = Session(), Session()
    task1, notice1 = await start_approval(client, context(first), body={"request": 1})
    task2, notice2 = await start_approval(client, context(second), body={"request": 2})
    data1, data2 = notice1["data"], notice2["data"]
    assert data1["socket"] != data2["socket"] and data1["token"] != data2["token"]
    await send_callback(
        data1, json.dumps({"token": data2["token"], "approved": True}).encode() + b"\n"
    )
    await send_callback(
        data2, json.dumps({"token": data2["token"], "approved": True}).encode() + b"\n"
    )
    with pytest.raises(ToolError):
        await task1
    await task2
    assert len(requests) == 1 and json.loads(requests[0].content) == {"request": 2}
    assert not await asyncio.to_thread(Path(data1["socket"]).exists)
    assert not await asyncio.to_thread(Path(data2["socket"]).exists)
    await client.aclose()


@pytest.mark.parametrize(
    "base_url",
    [
        "https://username:password@asm.example",
        "https://asm.example?secret=value",
        "https://asm.example#secret",
    ],
)
async def test_unsafe_base_url_fails_before_notification(base_url):
    requests = []
    client = AsmClient(
        "login",
        "secret",
        base_url=base_url,
        transport=httpx.MockTransport(lambda request: requests.append(request)),
    )
    session = Session()
    with pytest.raises(ToolError, match="credentials"):
        await server._mutate_with_approval(client, context(session), "/api/v1/write", {})
    assert not session.notification.done()
    assert not requests
    await client.aclose()
