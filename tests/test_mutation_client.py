import asyncio
import json

import httpx
import pytest

from groupib_asm_mcp.client import AsmClient, AsmError


def make_client(handler, **kwargs):
    return AsmClient(
        "analyst@example.com", "secret-key", transport=httpx.MockTransport(handler), **kwargs
    )


async def test_mutation_posts_once_and_drops_only_top_level_none():
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json={"updated": True})

    client = make_client(handler)
    result = await client.mutate("/api/v1/write", {"omit": None, "nested": {"value": None}})
    assert json.loads(result) == {"updated": True}
    assert len(requests) == 1
    assert requests[0].method == "POST"
    assert json.loads(requests[0].content) == {"nested": {"value": None}}


@pytest.mark.parametrize("status", [200, 201, 204])
async def test_empty_success_response(status):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(status)

    assert json.loads(await make_client(handler).mutate("/api/v1/write", {})) is None
    assert len(calls) == 1


async def test_mutation_result_is_capped():
    client = make_client(
        lambda request: httpx.Response(200, json={"data": "x" * 50000}), max_chars=20000
    )
    result = await client.mutate("/api/v1/write", {})
    assert len(result) <= 20000
    json.loads(result)


@pytest.mark.parametrize("status", [429, 500, 503])
async def test_status_errors_are_not_retried_and_do_not_disclose_response(status):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(status, text="secret-key analyst@example.com")

    with pytest.raises(AsmError) as error:
        await make_client(handler).mutate("/api/v1/write", {})
    assert len(calls) == 1
    assert f"HTTP {status}" in str(error.value)
    assert "may have been applied" in str(error.value)
    assert "secret-key" not in str(error.value)
    assert "analyst@example.com" not in str(error.value)


@pytest.mark.parametrize("exception", [httpx.ReadError, httpx.ReadTimeout])
async def test_transport_failures_are_uncertain_and_never_retried(exception):
    calls = []

    def handler(request):
        calls.append(request)
        raise exception("secret-key analyst@example.com", request=request)

    with pytest.raises(AsmError) as error:
        await make_client(handler).mutate("/api/v1/write", {})
    assert len(calls) == 1
    assert "may have been applied" in str(error.value)
    assert "secret-key" not in str(error.value)
    assert "analyst@example.com" not in str(error.value)


async def test_operation_deadline_reports_uncertain_outcome():
    calls = []

    async def handler(request):
        calls.append(request)
        await asyncio.sleep(10)
        return httpx.Response(200, json={})

    with pytest.raises(AsmError, match=r"timed out.*may have been applied"):
        await make_client(handler, timeout=0.01).mutate("/api/v1/write", {})
    assert len(calls) == 1


async def test_non_json_success_has_uncertain_outcome():
    with pytest.raises(AsmError, match=r"non-JSON.*may have been applied"):
        await make_client(lambda request: httpx.Response(200, text="not json")).mutate(
            "/api/v1/write", {}
        )


@pytest.mark.parametrize("method", ["post", "post_paged"])
async def test_read_posts_still_retry_rate_limits(method, monkeypatch):
    calls = []

    async def no_sleep(delay):
        pass

    def handler(request):
        calls.append(request)
        if len(calls) == 1:
            return httpx.Response(429)
        return httpx.Response(200, json={"items": []})

    monkeypatch.setattr("groupib_asm_mcp.client.asyncio.sleep", no_sleep)
    result = await getattr(make_client(handler), method)("/api/v1/read", {})
    assert json.loads(result) == {"items": []}
    assert len(calls) == 2
