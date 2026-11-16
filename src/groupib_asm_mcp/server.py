"""MCP server exposing the Group-IB ASM REST API."""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import socket
import tempfile
from pathlib import Path
from typing import Annotated, Any, Literal

from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import BaseModel, ConfigDict, Field, StrictBool

from groupib_asm_mcp.capping import MAX_RESULT_CHARS, MIN_RESULT_CHARS
from groupib_asm_mcp.client import DEFAULT_BASE_URL, AsmClient, AsmError, path_segment

READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, open_world_hint=True)
WRITE = ToolAnnotations(
    read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=True
)
DESTRUCTIVE_WRITE = ToolAnnotations(
    read_only_hint=False, destructive_hint=True, idempotent_hint=False, open_world_hint=True
)

LicenseType = Literal[
    "asm",
    "cspm",
    "asm_cspm",
    "3rd_party",
    "attack surface management",
    "third party risk management",
]
WriteIssueStatus = Literal["Detected", "Under review", "Solved", "False positive", "Ignored"]


class Approval(BaseModel):
    approve: StrictBool = Field(description="Approve this exact API request")


class CreateCompany(BaseModel):
    model_config = ConfigDict(extra="forbid")

    clientId: str
    root: str
    name: str
    licenseType: LicenseType | None = None
    activeScan: bool | None = None
    branch: list[str] | None = None
    subAsRoot: bool | None = None


class AutoFiltering(BaseModel):
    model_config = ConfigDict(extra="forbid")

    confirm: list[str] | None = None
    ignore: list[str] | None = None


_APPROVAL_TIMEOUT = 60.0
_MAX_APPROVAL_RESPONSE_BYTES = 4096


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


async def _omp_approval(session: Any, path: str, body: dict[str, Any], base_url: str) -> bool:
    """Request a single-use approval over a private, deadline-bound local socket."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + _APPROVAL_TIMEOUT
    token = secrets.token_hex(32)
    try:
        async with asyncio.timeout_at(deadline):
            with tempfile.TemporaryDirectory(prefix="groupib-asm-approval-") as directory:
                socket_path = str(Path(directory) / "approval.sock")
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                    os.chmod(directory, 0o700)
                    listener.setblocking(False)
                    listener.bind(socket_path)
                    listener.listen(1)
                    await session.send_log_message(
                        level="notice",
                        logger="groupib-asm.approval",
                        data={
                            "version": 1,
                            "socket": socket_path,
                            "token": token,
                            "path": path,
                            "body": body,
                            "base_url": base_url,
                        },
                    )
                    connection, _ = await loop.sock_accept(listener)
                    # No second connection can obtain or reuse this approval.
                    listener.close()
                    with connection:
                        connection.setblocking(False)
                        response = bytearray()
                        while len(response) <= _MAX_APPROVAL_RESPONSE_BYTES:
                            chunk = await loop.sock_recv(
                                connection, _MAX_APPROVAL_RESPONSE_BYTES + 1 - len(response)
                            )
                            if not chunk:
                                break
                            response.extend(chunk)
                        if (
                            len(response) > _MAX_APPROVAL_RESPONSE_BYTES
                            or not response.endswith(b"\n")
                            or response.count(b"\n") != 1
                        ):
                            return False
                        try:
                            payload = json.loads(
                                response.decode("utf-8"), object_pairs_hook=_unique_object
                            )
                        except (ValueError, TypeError, RecursionError):
                            return False
                        if (
                            not isinstance(payload, dict)
                            or set(payload) != {"token", "approved"}
                            or not isinstance(payload["token"], str)
                            or not payload["token"].isascii()
                            or type(payload["approved"]) is not bool
                        ):
                            return False
                        approved = (
                            secrets.compare_digest(payload["token"], token)
                            and payload["approved"] is True
                        )
                        if loop.time() >= deadline:
                            raise TimeoutError
                        return approved
    except TimeoutError:
        raise ToolError("Interactive approval timed out; no request was sent.") from None
    except Exception:
        raise ToolError("Interactive approval is unavailable; no request was sent.") from None


async def _mutate_with_approval(
    client: AsmClient, ctx: Context, path: str, body: dict[str, Any]
) -> Any:
    """Show the complete request and fail closed unless explicitly approved."""
    # Freeze the actual JSON body for both display and the request, matching mutate's
    # removal of top-level nulls even if a caller passes them directly.
    preview = json.dumps(
        {key: value for key, value in body.items() if value is not None},
        ensure_ascii=True,
        separators=(",", ":"),
    )
    if len(preview) > 16000:
        raise ToolError("Write request is too large to display in full for approval.")
    body = json.loads(preview)
    base_url = client.base_url
    try:
        session = ctx.request_context.session
        capabilities = session.client_capabilities
        elicitation = capabilities.elicitation if capabilities is not None else None
        supports_form = elicitation is not None and (
            elicitation.form is not None or elicitation.url is None
        )
    except (AttributeError, ValueError) as exc:
        raise ToolError("Interactive approval is unavailable; no request was sent.") from exc
    if supports_form:
        try:
            result = await ctx.elicit(
                f"Approve this Group-IB ASM write request?\nBase URL: {base_url}\n"
                f"POST {path}\nJSON body: {preview}",
                Approval,
            )
        except Exception as exc:
            raise ToolError("Interactive approval is unavailable; no request was sent.") from exc
        approved = (
            getattr(result, "action", None) == "accept"
            and isinstance(getattr(result, "data", None), Approval)
            and result.data.approve is True
        )
    else:
        approved = await _omp_approval(session, path, json.loads(preview), base_url)
    if not approved:
        raise ToolError("Write request was not approved; no request was sent.")
    return await client.mutate(path, body)


def _optional(**values: Any) -> dict[str, Any]:
    return {key: value for key, value in values.items() if value is not None}


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
    "Access to Group-IB Attack Surface Management. Write tools require interactive approval "
    "of the exact request and fail closed when interactive approval is unavailable. Start with "
    "list_companies to find a company id, then query its issues, assets, scores and reports. "
    "In issue results the "
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

    # ---- writes: each request requires interactive approval -----------------------------

    @mcp.tool(annotations=WRITE)
    async def create_client(
        name: str,
        country: str,
        ctx: Context,
        partner_id: str | None = None,
        industry: str | None = None,
        manager_id: str | None = None,
    ) -> Any:
        """Create a client; optional values are omitted unless supplied."""
        body = {
            "name": name,
            "country": country,
            **_optional(partnerId=partner_id, industry=industry, managerId=manager_id),
        }
        return await _mutate_with_approval(client, ctx, "/api/v1/clients/create", body)

    @mcp.tool(annotations=WRITE)
    async def create_company(
        client_id: str,
        root: str,
        name: str,
        ctx: Context,
        license_type: LicenseType | None = None,
        active_scan: bool | None = None,
        branch: list[str] | None = None,
        sub_as_root: bool | None = None,
    ) -> Any:
        """Create one company for a client."""
        body = {
            "clientId": client_id,
            "root": root,
            "name": name,
            **_optional(
                licenseType=license_type,
                activeScan=active_scan,
                branch=branch,
                subAsRoot=sub_as_root,
            ),
        }
        return await _mutate_with_approval(client, ctx, "/api/v1/companies/create", body)

    @mcp.tool(annotations=WRITE)
    async def create_companies_bulk(companies: list[CreateCompany], ctx: Context) -> Any:
        """Create companies in bulk using the API's company field names."""
        body = {"companies": [company.model_dump(exclude_none=True) for company in companies]}
        return await _mutate_with_approval(client, ctx, "/api/v1/companies/create/bulk", body)

    @mcp.tool(annotations=DESTRUCTIVE_WRITE)
    async def update_company(
        company_id: CompanyId,
        ctx: Context,
        branches: str | None = None,
        name: str | None = None,
        website: str | None = None,
        root_indicator: str | None = None,
        use_only_confirmed_assets: bool | None = None,
        use_auto_resolving_cloud_assets: bool | None = None,
        auto_filtering: AutoFiltering | None = None,
    ) -> Any:
        """Update company settings, including optional auto-filtering rules."""
        body = {
            "companyId": company_id,
            **_optional(
                branches=branches,
                name=name,
                website=website,
                rootIndicator=root_indicator,
                useOnlyConfirmedAssets=use_only_confirmed_assets,
                useAutoResolvingCloudAssets=use_auto_resolving_cloud_assets,
                autoFiltering=auto_filtering.model_dump(exclude_none=True)
                if auto_filtering is not None
                else None,
            ),
        }
        return await _mutate_with_approval(client, ctx, "/api/v1/companies/update", body)

    @mcp.tool(annotations=WRITE)
    async def create_user(
        name: str,
        email: str,
        role: Literal["user", "admin", "read only"],
        access_type: Literal["client", "partner"],
        ctx: Context,
        client_id: str | None = None,
        partner_id: str | None = None,
    ) -> Any:
        """Create an ASM user with the specified role and access type."""
        body = {
            "name": name,
            "email": email,
            "role": role,
            "accessType": access_type,
            **_optional(clientId=client_id, partnerId=partner_id),
        }
        return await _mutate_with_approval(client, ctx, "/api/v1/users/create", body)

    @mcp.tool(annotations=DESTRUCTIVE_WRITE)
    async def change_issue_status(
        issues_id: list[str], status: WriteIssueStatus, ctx: Context
    ) -> Any:
        """Change issue lifecycle status; status values are case-sensitive."""
        return await _mutate_with_approval(
            client, ctx, "/api/v1/issues/status/change", {"issuesId": issues_id, "status": status}
        )

    @mcp.tool(annotations=DESTRUCTIVE_WRITE)
    async def change_issue_severity(issues_id: list[str], severity: Severity, ctx: Context) -> Any:
        """Manually set issue severity, overriding automatic rescoring."""
        return await _mutate_with_approval(
            client,
            ctx,
            "/api/v1/issues/severity/change",
            {"issuesId": issues_id, "severity": severity},
        )

    @mcp.tool(annotations=WRITE)
    async def add_issue_comment(
        company_id: CompanyId, issue_id: str, body: str, ctx: Context
    ) -> Any:
        """Add a comment to an issue."""
        return await _mutate_with_approval(
            client,
            ctx,
            "/api/v1/issues/comments/add",
            {"companyId": company_id, "issueId": issue_id, "body": body},
        )

    @mcp.tool(annotations=WRITE)
    async def add_company_indicators(
        company_id: CompanyId,
        ctx: Context,
        confirmed_domain: list[str] | None = None,
        excluded_domain: list[str] | None = None,
        confirmed_ip: list[str] | None = None,
        excluded_ip: list[str] | None = None,
    ) -> Any:
        """Add confirmed or excluded domain and IP indicators to a company."""
        body = {
            "companyId": company_id,
            **_optional(
                confirmedDomain=confirmed_domain,
                excludedDomain=excluded_domain,
                confirmedIP=confirmed_ip,
                excludedIP=excluded_ip,
            ),
        }
        return await _mutate_with_approval(client, ctx, "/api/v1/assets/add", body)

    @mcp.tool(annotations=DESTRUCTIVE_WRITE)
    async def remove_company_indicators(
        company_id: CompanyId,
        ctx: Context,
        confirmed_domain: list[str] | None = None,
        excluded_domain: list[str] | None = None,
        confirmed_ip: list[str] | None = None,
        excluded_ip: list[str] | None = None,
    ) -> Any:
        """Remove confirmed or excluded domain and IP indicators from a company."""
        body = {
            "companyId": company_id,
            **_optional(
                confirmedDomain=confirmed_domain,
                excludedDomain=excluded_domain,
                confirmedIP=confirmed_ip,
                excludedIP=excluded_ip,
            ),
        }
        return await _mutate_with_approval(client, ctx, "/api/v1/assets/remove", body)

    @mcp.tool(annotations=DESTRUCTIVE_WRITE)
    async def change_asset_status(assets_id: list[str], status: AssetStatus, ctx: Context) -> Any:
        """Change the status of assets by ID."""
        return await _mutate_with_approval(
            client, ctx, "/api/v1/assets/status/change", {"assetsId": assets_id, "status": status}
        )

    return mcp
