import json

import httpx

from groupib_asm_mcp.client import AsmClient
from groupib_asm_mcp.server import create_server


async def test_issue_listing_includes_older_findings_unless_window_is_narrowed():
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        findings = [{"id": "recent", "lastSeen": "2026-11-16"}]
        if body.get("dateFrom", "2026-01-01") <= "2025-11-27":
            findings.append({"id": "older", "lastSeen": "2025-11-27"})
        return httpx.Response(200, json={"items": findings})

    client = AsmClient("user", "key", transport=httpx.MockTransport(handler))
    try:
        server = create_server(client)
        default = await server.call_tool("list_issues", {"company_id": "company"})
        narrowed = await server.call_tool(
            "list_issues", {"company_id": "company", "date_from": "2026-01-01"}
        )
        assert [item["id"] for item in json.loads(default.content[0].text)["items"]] == [
            "recent", "older"
        ]
        assert [item["id"] for item in json.loads(narrowed.content[0].text)["items"]] == [
            "recent"
        ]
    finally:
        await client.aclose()
