import json

import httpx

from groupib_asm_mcp.client import AsmClient
from groupib_asm_mcp.server import create_server


async def test_typosquatting_filter_returns_matching_assets():
    def handler(request: httpx.Request) -> httpx.Response:
        if json.loads(request.content).get("type") == ["typosq"]:
            return httpx.Response(200, json={"items": [{"type": "typosq", "asset": "example.net"}]})
        return httpx.Response(200, json={"items": [{"type": "domain", "asset": "example.com"}]})

    client = AsmClient("user", "key", transport=httpx.MockTransport(handler))
    try:
        result = await create_server(client).call_tool(
            "list_assets", {"company_id": "company", "type": ["typosq"]}
        )
        data = json.loads(result.content[0].text)
        assert data["items"] == [{"type": "typosq", "asset": "example.net"}]
    finally:
        await client.aclose()
