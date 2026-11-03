"""MCP server exposing the read-only part of the Group-IB ASM REST API.

Only endpoints that read data are wrapped. The write endpoints in the API (creating clients,
companies and users, changing issue/asset status or severity, comments, adding or removing
assets) are deliberately not exposed.
"""

from __future__ import annotations

import os
from typing import Annotated, Any, Literal

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations
from pydantic import Field

from groupib_asm_mcp.capping import MAX_RESULT_CHARS, MIN_RESULT_CHARS
from groupib_asm_mcp.client import DEFAULT_BASE_URL, AsmClient, AsmError, path_segment

READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, open_world_hint=True)

IssueStatus = Literal["detected", "under review", "solved", "ignored", "false positive"]
Severity = Literal["crit", "high", "medium", "low"]
AssetDiscoveredBy = Literal["auto", "enrich", "manual", "cloud", "integration"]
AssetStatus = Literal["new", "false", "confirmed"]
AssetType = Literal["domain", "ssl", "ip", "ip_range", "software", "login_form", "typosq"]
AssetDiscover = Literal["auto", "enrich", "manual", "cloud"]
HasIssues = Literal["crit", "high", "medium", "low", "clean"]
DateField = Literal["last_seen", "first_seen"]
Order = Literal["asc", "desc"]

CompanyId = Annotated[str, Field(description="ASM company id (see list_companies)")]
DateFrom = Annotated[str | None, Field(description="Start of the date window, as a date string")]
DateTo = Annotated[str | None, Field(description="End of the date window, as a date string")]
Cursor = Annotated[
    int | str | None,
    Field(
        description=(
            "seqUpdate cursor: pass the seqUpdate value from a previous response of the same "
            "query to continue after it"
        )
    ),
]
Count = Annotated[int | None, Field(ge=1, description="Page size (API default is 10)")]

INSTRUCTIONS = (
    "Read-only access to Group-IB Attack Surface Management. Start with list_companies to find "
    "a company id, then query its issues, assets, scores and reports. In issue results the "
    "top-level `status` is the lifecycle state (Detected, Under review, Solved, Manually solved, "
    "Ignored, False positive) while `body.status` is "
    "the severity label (e.g. 'Critical severity')."
)


def _env(name: str) -> str:
    """Read an env var. Empty values and unresolved omp placeholders count as unset."""
    value = os.environ.get(name, "").strip()
    return "" if value == name or value.startswith("${") else value


def client_from_env() -> AsmClient:
    """Build a client from GIB_ASM_LOGIN / GIB_ASM_API_KEY (and optional GIB_ASM_BASE_URL)."""
    login = _env("GIB_ASM_LOGIN")
    api_key = _env("GIB_ASM_API_KEY")
    if not login or not api_key:
        msg = (
            "GIB_ASM_LOGIN and GIB_ASM_API_KEY must both be set: the ASM API uses HTTP Basic "
            "auth with your ASM login and the API key from Help -> API."
        )
        raise AsmError(msg)
    base_url = _env("GIB_ASM_BASE_URL") or DEFAULT_BASE_URL
    max_chars = _max_chars_from_env()
    return AsmClient(login, api_key, base_url=base_url, max_chars=max_chars)


def _max_chars_from_env() -> int:
    raw = _env("GIB_ASM_MAX_RESULT_CHARS")
    if not raw:
        return MAX_RESULT_CHARS
    if not raw.isdigit() or int(raw) < MIN_RESULT_CHARS:
        msg = f"GIB_ASM_MAX_RESULT_CHARS must be an integer >= {MIN_RESULT_CHARS}, got {raw!r}."
        raise AsmError(msg)
    return int(raw)


def create_server(client: AsmClient) -> MCPServer:
    """Create the MCP server; every tool talks to the ASM API through ``client``."""
    mcp = MCPServer("groupib-asm", instructions=INSTRUCTIONS)

    # ---- tenants -------------------------------------------------------------------------

    @mcp.tool(annotations=READ_ONLY)
    async def list_partners() -> Any:
        """List Group-IB ASM partners visible to this account."""
        return await client.get("/api/v1/partners")

    @mcp.tool(annotations=READ_ONLY)
    async def list_clients() -> Any:
        """List clients (the top-level tenants that own companies)."""
        return await client.get("/api/v1/clients")

    @mcp.tool(annotations=READ_ONLY)
    async def get_client(
        client_id: Annotated[str, Field(description="ASM client id (see list_clients)")],
    ) -> Any:
        """Get one client's details."""
        return await client.get(f"/api/v1/clients/{path_segment(client_id)}")

    @mcp.tool(annotations=READ_ONLY)
    async def list_companies(
        status: Annotated[
            str | None, Field(description="Company status filter; one value or comma-separated")
        ] = None,
        client_id: Annotated[str | None, Field(description="Only companies of this client")] = None,
    ) -> Any:
        """List companies (monitored organizations) with score and footprint."""
        return await client.get("/api/v1/companies", {"status": status, "clientId": client_id})

    @mcp.tool(annotations=READ_ONLY)
    async def get_company(company_id: CompanyId) -> Any:
        """Get a company's settings: license, active scan, asset quota, auto-filtering rules."""
        return await client.get(f"/api/v1/companies/{path_segment(company_id)}")

    # ---- issues --------------------------------------------------------------------------

    @mcp.tool(annotations=READ_ONLY)
    async def list_issues(
        company_id: CompanyId,
        date_from: DateFrom = None,
        date_to: DateTo = None,
        category: Annotated[
            list[str] | None,
            Field(
                description=(
                    "Issue categories, e.g. 'DNS & Domains', 'Vulnerabilities', "
                    "'Network Security', 'Leaked Credentials', 'Malware Security', "
                    "'SSL/TLS Security', 'Email Security', 'Darkweb mentions'"
                )
            ),
        ] = None,
        test_name: Annotated[list[str] | None, Field(description="Issue type names")] = None,
        status: Annotated[list[IssueStatus] | None, Field(description="Lifecycle states")] = None,
        severity: list[Severity] | None = None,
        filter_string: Annotated[str | None, Field(description="Free-text search string")] = None,
        manual_review: bool | None = None,
        exceeded_asset: bool | None = None,
        active_scan: bool | None = None,
        manual_severity: bool | None = None,
        cloud_issue: bool | None = None,
        asset_discovered: list[AssetDiscoveredBy] | None = None,
        asset_status: list[AssetStatus] | None = None,
        count: Count = None,
        seq_update: Cursor = None,
        date_field: Annotated[
            DateField | None, Field(description="Which timestamp the date window applies to")
        ] = None,
        order: Order | None = None,
    ) -> Any:
        """List a company's issues (findings), filtered and paged.

        Unset filters mean "all". Each item's top-level `status` is the lifecycle state;
        `body.status` is the severity label. The `status` filter only accepts its own lowercase
        values; `solved` also matches items displayed as "Manually solved", and display values
        such as "Manually solved" are rejected by the filter.
        """
        return await client.post_paged(
            "/api/v1/issues/updated",
            {
                "companyId": company_id,
                "dateFrom": date_from,
                "dateTo": date_to,
                "category": category,
                "testName": test_name,
                "status": status,
                "severity": severity,
                "filterString": filter_string,
                "manualReview": manual_review,
                "exceededAsset": exceeded_asset,
                "activeScan": active_scan,
                "manualSeverity": manual_severity,
                "cloudIssue": cloud_issue,
                "assetDiscovered": asset_discovered,
                "assetStatus": asset_status,
                "count": count,
                "seqUpdate": seq_update,
                "dateField": date_field,
                "order": order,
            },
        )

    @mcp.tool(annotations=READ_ONLY)
    async def get_issue_evidence(
        issue_id: Annotated[str, Field(description="Issue id from list_issues")],
    ) -> Any:
        """Get the evidence for one issue (affected asset details, requests, signatures)."""
        return await client.get(f"/api/v1/issues/evidence/{path_segment(issue_id)}")

    @mcp.tool(annotations=READ_ONLY)
    async def get_issues_evidence_bulk(
        issue_ids: Annotated[list[str], Field(description="Issue ids from list_issues")],
    ) -> Any:
        """Get evidence for several issues in one call.

        Issue types without batch support come back with `supported: false`; use
        get_issue_evidence for those.
        """
        return await client.post("/api/v1/issues/evidence/bulk", {"issueId": issue_ids})

    # ---- assets --------------------------------------------------------------------------

    @mcp.tool(annotations=READ_ONLY)
    async def list_assets(
        company_id: CompanyId,
        date_from: DateFrom = None,
        date_to: DateTo = None,
        type: list[AssetType] | None = None,  # noqa: A002 - mirrors the API field name
        status: list[AssetStatus] | None = None,
        discover: Annotated[
            list[AssetDiscover] | None, Field(description="How the asset was discovered")
        ] = None,
        has_issues: Annotated[
            list[HasIssues] | None,
            Field(description="Highest issue severity on the asset, or 'clean' for none"),
        ] = None,
        filter_string: Annotated[str | None, Field(description="Free-text search string")] = None,
        count: Count = None,
        seq_update: Cursor = None,
        date_field: DateField | None = None,
        order: Order | None = None,
    ) -> Any:
        """List a company's discovered assets (domains, IPs, SSL certs, software, ...)."""
        return await client.post_paged(
            "/api/v1/assets/updated",
            {
                "companyId": company_id,
                "dateFrom": date_from,
                "dateTo": date_to,
                "type": type,
                "status": status,
                "discover": discover,
                "hasIssues": has_issues,
                "filterString": filter_string,
                "count": count,
                "seqUpdate": seq_update,
                "dateField": date_field,
                "order": order,
            },
        )

    @mcp.tool(annotations=READ_ONLY)
    async def get_company_indicators(company_id: CompanyId) -> Any:
        """Get a company's confirmed and excluded root domains and IPs."""
        return await client.get(f"/api/v1/assets/{path_segment(company_id)}")

    # ---- scores, leaks, reports ----------------------------------------------------------

    @mcp.tool(annotations=READ_ONLY)
    async def get_dashboard_scores(
        company_id: CompanyId, date_from: DateFrom = None, date_to: DateTo = None
    ) -> Any:
        """Get a company's overall score, industry comparison and per-category scores."""
        return await client.post(
            "/api/v1/dashboard/scores",
            {"companyId": company_id, "dateFrom": date_from, "dateTo": date_to},
        )

    @mcp.tool(annotations=READ_ONLY)
    async def list_leaks(
        company_id: CompanyId,
        date_from: DateFrom = None,
        date_to: DateTo = None,
        status: list[IssueStatus] | None = None,
        count: Count = None,
        seq_update: Cursor = None,
        order: Order | None = None,
    ) -> Any:
        """List a company's leak alerts (leaked credentials and data)."""
        return await client.post_paged(
            "/api/v1/leaks/updated",
            {
                "companyId": company_id,
                "dateFrom": date_from,
                "dateTo": date_to,
                "status": status,
                "count": count,
                "seqUpdate": seq_update,
                "order": order,
            },
        )

    @mcp.tool(annotations=READ_ONLY)
    async def list_reports(company_id: CompanyId) -> Any:
        """List all scan reports ever made for a company, in short form."""
        return await client.get(f"/api/v1/reports/{path_segment(company_id)}")

    @mcp.tool(annotations=READ_ONLY)
    async def get_last_report(company_id: CompanyId) -> Any:
        """Get a company's latest full scan report."""
        return await client.get(f"/api/v1/reports/{path_segment(company_id)}/last")

    @mcp.tool(annotations=READ_ONLY)
    async def get_report(
        report_id: Annotated[str, Field(description="Report id from list_reports")],
    ) -> Any:
        """Get one full scan report by id."""
        return await client.get(f"/api/v1/reports/{path_segment(report_id)}/report")

    # ---- audit logs ----------------------------------------------------------------------

    @mcp.tool(annotations=READ_ONLY)
    async def get_company_logs(
        company_id: CompanyId,
        date_from: Annotated[str, Field(description="Start of the date window")],
        date_to: Annotated[str, Field(description="End of the date window")],
    ) -> Any:
        """Get the log of actions performed on a company within a date window."""
        return await client.post(
            "/api/v1/companies/logs",
            {"companyId": company_id, "dateFrom": date_from, "dateTo": date_to},
        )

    @mcp.tool(annotations=READ_ONLY)
    async def get_user_logs(date_from: DateFrom = None, date_to: DateTo = None) -> Any:
        """Get the log of user actions within an optional date window."""
        return await client.post("/api/v1/users/logs", {"dateFrom": date_from, "dateTo": date_to})

    return mcp
