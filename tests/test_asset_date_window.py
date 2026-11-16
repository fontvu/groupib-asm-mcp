"""Verify the repo fix: list_assets must default dateFrom so the API's implicit
recent-window clip does not silently truncate the inventory.

Mirrors tests/test_issue_date_window.py but for list_assets, and asserts the
request body actually carries the default.
"""

import json

import httpx

from groupib_asm_mcp.client import AsmClient
from groupib_asm_mcp.server import create_server


async def test_asset_listing_includes_older_assets_unless_window_is_narrowed():
    seen_bodies = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        seen_bodies.append(body)
        assets = [{"asset": "recent.rgsgame.com", "type": "domain"}]
        if body.get("dateFrom", "2026-01-01") <= "2025-11-27":
            assets.append({"asset": "older.rgsgame.com", "type": "domain"})
        return httpx.Response(200, json={"items": assets})

    client = AsmClient("user", "key", transport=httpx.MockTransport(handler))
    try:
        server = create_server(client)
        default = await server.call_tool("list_assets", {"company_id": "company"})
        narrowed = await server.call_tool(
            "list_assets", {"company_id": "company", "date_from": "2026-01-01"}
        )
        assert [item["asset"] for item in json.loads(default.content[0].text)["items"]] == [
            "recent.rgsgame.com",
            "older.rgsgame.com",
        ]
        assert [item["asset"] for item in json.loads(narrowed.content[0].text)["items"]] == [
            "recent.rgsgame.com"
        ]
        # the default must be explicit in the request body, not left to the API
        assert seen_bodies[0].get("dateFrom") == "1970-01-01"
        assert seen_bodies[1].get("dateFrom") == "2026-01-01"
    finally:
        await client.aclose()


async def test_leak_listing_includes_older_leaks_unless_window_is_narrowed():
    seen_bodies = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        seen_bodies.append(body)
        leaks = [{"id": "recent"}]
        if body.get("dateFrom", "2026-01-01") <= "2025-11-27":
            leaks.append({"id": "older"})
        return httpx.Response(200, json={"items": leaks})

    client = AsmClient("user", "key", transport=httpx.MockTransport(handler))
    try:
        server = create_server(client)
        default = await server.call_tool("list_leaks", {"company_id": "company"})
        narrowed = await server.call_tool(
            "list_leaks", {"company_id": "company", "date_from": "2026-01-01"}
        )
        assert [item["id"] for item in json.loads(default.content[0].text)["items"]] == [
            "recent",
            "older",
        ]
        assert [item["id"] for item in json.loads(narrowed.content[0].text)["items"]] == ["recent"]
        assert seen_bodies[0].get("dateFrom") == "1970-01-01"
        assert seen_bodies[1].get("dateFrom") == "2026-01-01"
    finally:
        await client.aclose()
