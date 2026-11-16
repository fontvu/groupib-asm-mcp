"""Filter parameters must survive clients that re-wrap a single-element array.

Some MCP clients emit a single-element array as ``{"item": "domain"}`` or as a bare
string instead of a one-element array. The server normalizes those forms; the
published JSON schema must stay unchanged so clients still see an array parameter.
"""

import json

import httpx
import pytest
from mcp.server.mcpserver.exceptions import ToolError

from groupib_asm_mcp.client import AsmClient
from groupib_asm_mcp.server import create_server


def _server(bodies):
    def handler(request: httpx.Request) -> httpx.Response:
        bodies.append(json.loads(request.content))
        return httpx.Response(200, json={"items": [], "count": "0 of 0"})

    return AsmClient("user", "key", transport=httpx.MockTransport(handler))


@pytest.mark.parametrize(
    ("label", "supplied", "expected"),
    [
        ("array", ["domain"], ["domain"]),
        ("bare string", "domain", ["domain"]),
        ("single-key object", {"item": "domain"}, ["domain"]),
        ("single-key object with list", {"item": ["domain"]}, ["domain"]),
        ("multiple values", ["domain", "ssl"], ["domain", "ssl"]),
    ],
)
async def test_list_assets_type_accepts_rewrapped_forms(label, supplied, expected):
    bodies: list[dict] = []
    client = _server(bodies)
    try:
        await create_server(client).call_tool(
            "list_assets", {"company_id": "company", "type": supplied}
        )
        assert bodies[-1]["type"] == expected
    finally:
        await client.aclose()


async def test_list_assets_rejects_an_unrecognised_filter_shape():
    bodies: list[dict] = []
    client = _server(bodies)
    try:
        with pytest.raises(ToolError):
            await create_server(client).call_tool(
                "list_assets", {"company_id": "company", "type": {"x": 1}}
            )
        assert not bodies
    finally:
        await client.aclose()


async def test_published_schema_still_declares_array_parameters():
    bodies: list[dict] = []
    client = _server(bodies)
    try:
        server = create_server(client)
        tools = {tool.name: tool for tool in await server.list_tools()}
        properties = tools["list_assets"].input_schema["properties"]
        for name in ("type", "status", "discover", "has_issues"):
            schema = properties[name]
            array_branch = next(
                branch for branch in schema["anyOf"] if branch.get("type") == "array"
            )
            assert array_branch["items"]["enum"], name
    finally:
        await client.aclose()


async def test_status_filter_accepts_a_rewrapped_form():
    bodies: list[dict] = []
    client = _server(bodies)
    try:
        await create_server(client).call_tool(
            "list_assets", {"company_id": "company", "status": {"item": "new"}}
        )
        assert bodies[-1]["status"] == ["new"]
    finally:
        await client.aclose()
