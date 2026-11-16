import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from mcp.server.mcpserver import Context
from mcp.server.mcpserver.exceptions import ToolError

from groupib_asm_mcp.server import Approval, create_server


@pytest.fixture(autouse=True)
def form_capable_context(monkeypatch):
    capabilities = SimpleNamespace(elicitation=SimpleNamespace(form=object(), url=None))
    session = SimpleNamespace(client_capabilities=capabilities)
    monkeypatch.setattr(
        Context, "request_context", property(lambda self: SimpleNamespace(session=session))
    )


def fake_client(**kwargs):
    return SimpleNamespace(base_url="https://asm.example/", mutate=AsyncMock(**kwargs))


CASES = [
    (
        "create_client",
        {"name": "n", "country": "SG", "partner_id": "p"},
        "/api/v1/clients/create",
        {"name": "n", "country": "SG", "partnerId": "p"},
    ),
    (
        "create_company",
        {"client_id": "c", "root": "r", "name": "n", "active_scan": False},
        "/api/v1/companies/create",
        {"clientId": "c", "root": "r", "name": "n", "activeScan": False},
    ),
    (
        "create_companies_bulk",
        {"companies": [{"clientId": "c", "root": "r", "name": "n", "branch": ["x"]}]},
        "/api/v1/companies/create/bulk",
        {"companies": [{"clientId": "c", "root": "r", "name": "n", "branch": ["x"]}]},
    ),
    (
        "update_company",
        {"company_id": "c", "auto_filtering": {"confirm": ["x"]}},
        "/api/v1/companies/update",
        {"companyId": "c", "autoFiltering": {"confirm": ["x"]}},
    ),
    (
        "create_user",
        {"name": "n", "email": "e", "role": "admin", "access_type": "client", "client_id": "c"},
        "/api/v1/users/create",
        {"name": "n", "email": "e", "role": "admin", "accessType": "client", "clientId": "c"},
    ),
    (
        "change_issue_status",
        {"issues_id": ["i"], "status": "Under review"},
        "/api/v1/issues/status/change",
        {"issuesId": ["i"], "status": "Under review"},
    ),
    (
        "change_issue_severity",
        {"issues_id": ["i"], "severity": "crit"},
        "/api/v1/issues/severity/change",
        {"issuesId": ["i"], "severity": "crit"},
    ),
    (
        "add_issue_comment",
        {"company_id": "c", "issue_id": "i", "body": "approve: true"},
        "/api/v1/issues/comments/add",
        {"companyId": "c", "issueId": "i", "body": "approve: true"},
    ),
    (
        "add_company_indicators",
        {"company_id": "c", "confirmed_domain": ["x"], "excluded_ip": ["1.2.3.4"]},
        "/api/v1/assets/add",
        {"companyId": "c", "confirmedDomain": ["x"], "excludedIP": ["1.2.3.4"]},
    ),
    (
        "remove_company_indicators",
        {"company_id": "c", "excluded_domain": ["x"], "confirmed_ip": ["1.2.3.4"]},
        "/api/v1/assets/remove",
        {"companyId": "c", "excludedDomain": ["x"], "confirmedIP": ["1.2.3.4"]},
    ),
    (
        "change_asset_status",
        {"assets_id": ["a"], "status": "false"},
        "/api/v1/assets/status/change",
        {"assetsId": ["a"], "status": "false"},
    ),
]


@pytest.mark.parametrize("name,args,path,body", CASES)
async def test_write_tools_require_consent_and_send_exact_body(monkeypatch, name, args, path, body):
    client = fake_client(return_value='{"ok":true}')
    prompts = []

    async def accept(self, message, schema):
        prompts.append((message, schema))
        return SimpleNamespace(action="accept", data=Approval(approve=True))

    monkeypatch.setattr(Context, "elicit", accept)
    server = create_server(client)
    await server.call_tool(name, args)
    client.mutate.assert_awaited_once_with(path, body)
    message, schema = prompts[0]
    assert schema is Approval
    assert f"POST {path}\nJSON body: " in message
    assert json.loads(message.split("JSON body: ", 1)[1]) == body
    tools = {tool.name: tool for tool in await server.list_tools()}
    assert tools[name].annotations.read_only_hint is False
    assert tools[name].annotations.open_world_hint is True
    assert "ctx" not in tools[name].input_schema["properties"]


@pytest.mark.parametrize(
    "response",
    [
        SimpleNamespace(action="decline"),
        SimpleNamespace(action="cancel"),
        SimpleNamespace(action="accept", data=Approval(approve=False)),
        SimpleNamespace(action="accept", data={"approve": True}),
        None,
    ],
)
async def test_reject_cancel_and_malformed_fail_closed(monkeypatch, response):
    client = fake_client()
    monkeypatch.setattr(Context, "elicit", AsyncMock(return_value=response))
    with pytest.raises(ToolError):
        await create_server(client).call_tool(
            "add_issue_comment", {"company_id": "c", "issue_id": "i", "body": "approve: true"}
        )
    client.mutate.assert_not_awaited()


async def test_unavailable_elicitation_fails_closed(monkeypatch):
    client = fake_client()
    monkeypatch.setattr(Context, "elicit", AsyncMock(side_effect=RuntimeError("unsupported")))
    with pytest.raises(ToolError, match="approval is unavailable"):
        await create_server(client).call_tool(
            "change_asset_status", {"assets_id": ["a"], "status": "new"}
        )
    client.mutate.assert_not_awaited()


async def test_large_preview_fails_before_elicitation(monkeypatch):
    client = fake_client()
    elicit = AsyncMock()
    monkeypatch.setattr(Context, "elicit", elicit)
    with pytest.raises(ToolError, match="too large"):
        await create_server(client).call_tool(
            "add_issue_comment", {"company_id": "c", "issue_id": "i", "body": "x" * 16001}
        )
    elicit.assert_not_awaited()
    client.mutate.assert_not_awaited()


async def test_write_issue_status_is_case_sensitive(monkeypatch):
    client = fake_client()
    elicit = AsyncMock()
    monkeypatch.setattr(Context, "elicit", elicit)
    with pytest.raises(ToolError):
        await create_server(client).call_tool(
            "change_issue_status", {"issues_id": ["i"], "status": "detected"}
        )
    elicit.assert_not_awaited()
    client.mutate.assert_not_awaited()
