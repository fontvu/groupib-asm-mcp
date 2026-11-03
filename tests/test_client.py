import base64
import json

import httpx
import pytest

from groupib_asm_mcp.client import AsmClient, AsmError, path_segment
from groupib_asm_mcp.server import client_from_env


def make_client(handler) -> AsmClient:
    return AsmClient("analyst@example.com", "s3cret", transport=httpx.MockTransport(handler))


async def test_sends_basic_auth_and_drops_unset_fields():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers["authorization"]
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"count": 0, "items": []})

    client = make_client(handler)
    await client.post("/api/v1/issues/updated", {"companyId": "c1", "dateFrom": None, "count": 5})

    expected = base64.b64encode(b"analyst@example.com:s3cret").decode()
    assert seen["auth"] == f"Basic {expected}"
    assert seen["body"] == {"companyId": "c1", "count": 5}


async def test_error_status_reaches_the_model_with_detail_and_hint():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "Unauthorized"})

    with pytest.raises(AsmError, match=r"HTTP 401: Unauthorized\. Check that GIB_ASM_LOGIN"):
        await make_client(handler).get("/api/v1/clients")


async def test_error_message_never_contains_credentials():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="boom")

    with pytest.raises(AsmError) as info:
        await make_client(handler).get("/api/v1/clients")
    assert "s3cret" not in str(info.value)


def test_path_segment_cannot_escape_its_segment():
    assert path_segment("../etc/passwd") == "..%2Fetc%2Fpasswd"


@pytest.mark.parametrize("placeholder", ["", "GIB_ASM_API_KEY", "${GIB_ASM_API_KEY}"])
def test_unresolved_credentials_are_rejected(monkeypatch, placeholder):
    monkeypatch.setenv("GIB_ASM_LOGIN", "analyst@example.com")
    monkeypatch.setenv("GIB_ASM_API_KEY", placeholder)
    with pytest.raises(AsmError, match="must both be set"):
        client_from_env()


async def test_oversized_page_is_refetched_smaller_so_the_cursor_stays_valid():
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        calls.append(body)
        n = body.get("count", 10)
        items = [{"id": i, "pad": "x" * 1000} for i in range(n)]
        return httpx.Response(200, json={"count": f"{n} of 999", "items": items, "seqUpdate": 42})

    client = AsmClient("u", "k", transport=httpx.MockTransport(handler), max_chars=20_000)

    text = await client.post_paged(
        "/api/v1/issues/updated", {"companyId": "c1", "count": 100, "seqUpdate": 5}
    )

    result = json.loads(text)
    assert len(text) <= 20_000
    assert "truncated" not in result  # nothing was dropped from the page
    assert result["seqUpdate"] == 42  # so the API's cursor still continues exactly after it
    assert len(calls) == 2
    assert calls[1]["count"] < 100
    assert calls[1]["companyId"] == "c1"
    assert calls[1]["seqUpdate"] == 5  # same starting point as the first request
    assert len(result["items"]) == calls[1]["count"]


async def test_page_that_already_fits_is_fetched_once():
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, json={"count": "2 of 2", "items": [{"id": 1}, {"id": 2}]})

    client = AsmClient("u", "k", transport=httpx.MockTransport(handler))
    await client.post_paged("/api/v1/issues/updated", {"companyId": "c1"})
    assert len(calls) == 1


@pytest.mark.parametrize("bad", ["abc", "500", "-1"])
def test_invalid_size_limit_is_rejected(monkeypatch, bad):
    monkeypatch.setenv("GIB_ASM_LOGIN", "analyst@example.com")
    monkeypatch.setenv("GIB_ASM_API_KEY", "s3cret")
    monkeypatch.setenv("GIB_ASM_MAX_RESULT_CHARS", bad)
    with pytest.raises(AsmError, match="GIB_ASM_MAX_RESULT_CHARS"):
        client_from_env()


async def test_page_size_follows_actual_item_sizes_not_the_average():
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        calls.append(body)
        # First 50 items are tiny, the rest large (but under the per-record cap): the average
        # size is a poor guide to how many fit.
        items = [{"id": i, "pad": "x" * (100 if i < 50 else 3_500)} for i in range(body["count"])]
        return httpx.Response(200, json={"count": f"{len(items)} of 999", "items": items})

    client = AsmClient("u", "k", transport=httpx.MockTransport(handler), max_chars=20_000)

    text = await client.post_paged("/api/v1/issues/updated", {"companyId": "c1", "count": 100})

    result = json.loads(text)
    assert len(text) <= 20_000
    assert "truncated" not in result
    assert len(calls) == 2
    # An average-based estimate would ask for ~7 items; the real prefix that fits is 50 + a few.
    assert calls[1]["count"] >= 50
    assert len(result["items"]) == calls[1]["count"]


async def test_page_starting_with_a_huge_record_keeps_every_record_and_a_valid_cursor():
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        calls.append(body)
        items = []
        for i in range(body["count"]):
            leaks = [{"u": "x" * 100}] * (300 if i == 0 else 1)  # record 0 alone is ~30k chars
            items.append({"id": f"i{i}", "pad": "p" * 900, "body": {"type": "t", "leaks": leaks}})
        return httpx.Response(
            200, json={"count": f"{len(items)} of 99", "items": items, "seqUpdate": 42}
        )

    client = AsmClient("u", "k", transport=httpx.MockTransport(handler), max_chars=20_000)

    text = await client.post_paged("/api/v1/issues/updated", {"companyId": "c1", "count": 60})

    result = json.loads(text)
    assert len(text) <= 20_000
    assert all(isinstance(item, dict) for item in result["items"])  # no record became a string
    assert result["items"][0]["body"]["leaks"].startswith("<omitted: ")
    assert result["items"][0]["body"]["type"] == "t"
    assert [o["path"] for o in result["truncated"]["omitted"]] == ["items[0].body.leaks"]
    assert "lists" not in result["truncated"]  # the page was fitted, not trimmed
    assert result["seqUpdate"] == 42  # so the cursor continues exactly after this page
    assert len(result["items"]) == calls[-1]["count"] > 1
