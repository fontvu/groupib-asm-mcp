import asyncio
import json
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime

import httpx
import pytest

from groupib_asm_mcp.client import AsmClient, AsmError


async def _query(client: AsmClient, method: str) -> str:
    if method == "get":
        return await client.get("/query", {"count": 2})
    if method == "post":
        return await client.post("/query", {"count": 2})
    return await client.post_paged("/query", {"count": 2})


@pytest.mark.parametrize("method", ["get", "post", "post_paged"])
async def test_rate_limit_retries_then_succeeds(monkeypatch, method):
    calls = []
    delays = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if len(calls) < 3:
            return httpx.Response(429, json={"message": "rate limited"})
        return httpx.Response(200, json={"items": [{"id": 1}], "seqUpdate": 5})

    async def sleep(delay):
        delays.append(delay)

    monkeypatch.setattr("groupib_asm_mcp.client.asyncio.sleep", sleep)
    client = AsmClient("u", "k", transport=httpx.MockTransport(handler))
    try:
        result = json.loads(await _query(client, method))
    finally:
        await client.aclose()

    assert result == {"items": [{"id": 1}], "seqUpdate": 5}
    assert len(calls) == 3
    assert delays == [0.5, 1.0]


async def test_retry_after_delta_seconds_is_honored(monkeypatch):
    delays = []
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(429, headers={"Retry-After": "7"}, text="slow down")
        return httpx.Response(200, json={"ok": True})

    async def sleep(delay):
        delays.append(delay)

    monkeypatch.setattr("groupib_asm_mcp.client.asyncio.sleep", sleep)
    client = AsmClient("u", "k", transport=httpx.MockTransport(handler))
    try:
        assert json.loads(await client.get("/query")) == {"ok": True}
    finally:
        await client.aclose()
    assert calls == 2
    assert delays == [7.0]


async def test_retry_after_http_date_is_honored(monkeypatch):
    delays = []
    calls = 0
    now = datetime(2026, 1, 1, tzinfo=UTC)
    retry_at = format_datetime(now + timedelta(seconds=10), usegmt=True)

    class FixedDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return now

    monkeypatch.setattr("groupib_asm_mcp.client.datetime", FixedDateTime)

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(429, headers={"Retry-After": retry_at})
        return httpx.Response(200, json={"ok": True})

    async def sleep(delay):
        delays.append(delay)

    monkeypatch.setattr("groupib_asm_mcp.client.asyncio.sleep", sleep)
    client = AsmClient("u", "k", transport=httpx.MockTransport(handler))
    try:
        await client.get("/query")
    finally:
        await client.aclose()
    assert calls == 2
    assert delays == [10.0]


@pytest.mark.parametrize("value", ["not-a-date", "-1", "1.5", "9" * 129])
async def test_invalid_retry_after_fails_without_retrying(value):
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(429, headers={"Retry-After": value}, text="slow down")

    client = AsmClient("u", "k", transport=httpx.MockTransport(handler))
    try:
        with pytest.raises(AsmError, match=r"HTTP 429.*Invalid Retry-After"):
            await client.get("/query")
    finally:
        await client.aclose()
    assert calls == 1


@pytest.mark.parametrize("value", ["31", "9" * 100])
async def test_long_retry_after_is_not_shortened(value):
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(429, headers={"Retry-After": value}, text="slow down")

    client = AsmClient("u", "k", transport=httpx.MockTransport(handler))
    try:
        with pytest.raises(AsmError, match=r"HTTP 429.*exceeds the maximum retry delay"):
            await client.get("/query")
    finally:
        await client.aclose()
    assert calls == 1


async def test_retry_after_beyond_remaining_deadline_is_not_shortened():
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(429, headers={"Retry-After": "10"}, text="slow down")

    client = AsmClient("u", "k", timeout=5, transport=httpx.MockTransport(handler))
    try:
        with pytest.raises(AsmError, match=r"HTTP 429.*remaining operation deadline"):
            await client.get("/query")
    finally:
        await client.aclose()
    assert calls == 1


async def test_exhausted_429_retries_keep_response_details(monkeypatch):
    calls = 0
    delays = []

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(429, json={"message": "quota exceeded"})

    async def sleep(delay):
        delays.append(delay)

    monkeypatch.setattr("groupib_asm_mcp.client.asyncio.sleep", sleep)
    client = AsmClient("u", "k", transport=httpx.MockTransport(handler))
    try:
        with pytest.raises(AsmError, match=r"HTTP 429: quota exceeded.*retries exhausted"):
            await client.post("/query", {})
    finally:
        await client.aclose()
    assert calls == 4
    assert delays == [0.5, 1.0, 2.0]


async def test_retry_delay_shares_the_operation_deadline(monkeypatch):
    loop = asyncio.get_running_loop()
    real_time = loop.time
    elapsed = 0.0
    calls = 0
    delays = []

    def clock():
        return real_time() + elapsed

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(429, text="slow down")

    async def sleep(delay):
        nonlocal elapsed
        delays.append(delay)
        elapsed += delay

    monkeypatch.setattr(loop, "time", clock)
    monkeypatch.setattr("groupib_asm_mcp.client.asyncio.sleep", sleep)
    client = AsmClient("u", "k", timeout=1.25, transport=httpx.MockTransport(handler))
    try:
        with pytest.raises(AsmError, match=r"HTTP 429.*remaining operation deadline"):
            await client.get("/query")
    finally:
        await client.aclose()
    assert calls == 2
    assert delays == [0.5]


async def test_page_refetch_retries_without_changing_its_cursor(monkeypatch):
    calls = []
    delays = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        calls.append(body)
        if len(calls) == 2:
            return httpx.Response(429, text="slow down")
        items = [{"id": i, "pad": "x" * 1000} for i in range(body["count"])]
        return httpx.Response(200, json={"items": items, "seqUpdate": len(items)})

    async def sleep(delay):
        delays.append(delay)

    monkeypatch.setattr("groupib_asm_mcp.client.asyncio.sleep", sleep)
    client = AsmClient("u", "k", max_chars=10_000, transport=httpx.MockTransport(handler))
    try:
        result = json.loads(await client.post_paged("/query", {"count": 20, "seqUpdate": 3}))
    finally:
        await client.aclose()
    assert len(calls) == 3
    assert calls[1] == calls[2]
    assert calls[1]["seqUpdate"] == 3
    assert 0 < calls[1]["count"] < calls[0]["count"]
    assert len(result["items"]) == result["seqUpdate"] == calls[1]["count"]
    assert delays == [0.5]


@pytest.mark.parametrize("status", [400, 401, 403, 500, 503])
async def test_other_statuses_are_not_retried(status):
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(status, text="failure")

    client = AsmClient("u", "k", transport=httpx.MockTransport(handler))
    try:
        with pytest.raises(AsmError, match=f"HTTP {status}"):
            await client.get("/query")
    finally:
        await client.aclose()
    assert calls == 1


async def test_transport_error_is_not_retried():
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        raise httpx.ConnectError("connection failed", request=request)

    client = AsmClient("u", "k", transport=httpx.MockTransport(handler))
    try:
        with pytest.raises(AsmError, match=r"GET /query failed: ConnectError"):
            await client.get("/query")
    finally:
        await client.aclose()
    assert calls == 1


@pytest.mark.parametrize("method", ["get", "post", "post_paged"])
async def test_operation_deadline_cancels_stalled_http_request(method):
    entered = asyncio.Event()
    cancelled = asyncio.Event()

    async def handler(request: httpx.Request) -> httpx.Response:
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()
        return httpx.Response(200, json={})

    client = AsmClient("u", "k", timeout=0.01, transport=httpx.MockTransport(handler))
    try:
        with pytest.raises(AsmError, match=r"exceeded the 0.01s operation deadline"):
            await _query(client, method)
    finally:
        await client.aclose()
    assert entered.is_set()
    assert cancelled.is_set()


async def test_page_refetch_shares_the_original_deadline(monkeypatch):
    loop = asyncio.get_running_loop()
    real_time = loop.time
    elapsed = 0.0
    calls = []

    def clock():
        return real_time() + elapsed

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal elapsed
        body = json.loads(request.content)
        calls.append(body)
        elapsed += 0.6
        items = [{"id": i, "pad": "x" * 1000} for i in range(body["count"])]
        return httpx.Response(200, json={"items": items, "seqUpdate": len(items)})

    monkeypatch.setattr(loop, "time", clock)
    client = AsmClient(
        "u", "k", timeout=1, max_chars=10_000, transport=httpx.MockTransport(handler)
    )
    try:
        with pytest.raises(AsmError, match=r"exceeded the 1s operation deadline"):
            await client.post_paged("/query", {"count": 20, "seqUpdate": 3})
    finally:
        await client.aclose()
    assert len(calls) == 2
    assert 0 < calls[1]["count"] < calls[0]["count"]
    assert calls[1]["seqUpdate"] == 3


async def test_external_cancellation_propagates():
    entered = asyncio.Event()

    async def handler(request: httpx.Request) -> httpx.Response:
        entered.set()
        await asyncio.Event().wait()
        return httpx.Response(200, json={})

    client = AsmClient("u", "k", transport=httpx.MockTransport(handler))
    try:
        task = asyncio.create_task(client.get("/query"))
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    finally:
        await client.aclose()
