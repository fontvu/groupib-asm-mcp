# groupib-asm-mcp

Read-only [MCP](https://modelcontextprotocol.io) server for the Group-IB **Attack Surface
Management** REST API (`https://asm.group-ib.com`, API version 2.9.3).

Only endpoints that read data are exposed. Creating clients/companies/users, changing issue or
asset status/severity, comments, and adding/removing assets are **not** wrapped. The full API
spec is available at `/api/doc/swagger.json` after signing in to ASM.

## Credentials

The API uses HTTP Basic auth: your **ASM login** (usually an email) as the username and the
**API key** as the password. Both are required, and only ASM *Admin* users can use the API.
Generate a key in ASM under **Help -> REST API & Integrations -> Generate API Key** (asks for
your SSO password and shows the key once).

```sh
export GIB_ASM_LOGIN='you@example.com'
export GIB_ASM_API_KEY='...'          # never commit this
# optional: GIB_ASM_BASE_URL (default https://asm.group-ib.com)
# optional: GIB_ASM_MAX_RESULT_CHARS (default 30000)
```

The server refuses to start if either variable is missing.

## Run / register

```sh
uv sync
uv run groupib-asm-mcp          # speaks MCP over stdio
```

omp (`~/.omp/agent/mcp.json`) resolves the `env` entries below from its own environment, so
the key never lands in the config file. Replace `/absolute/path/to/groupib-asm` with the path to
your checkout:

```json
"groupib-asm": {
  "type": "stdio",
  "command": "uv",
  "args": ["run", "--quiet", "--project", "/absolute/path/to/groupib-asm", "groupib-asm-mcp"],
  "env": { "GIB_ASM_LOGIN": "GIB_ASM_LOGIN", "GIB_ASM_API_KEY": "GIB_ASM_API_KEY" },
  "timeout": 90000
}
```

Restart omp after exporting the variables.

## Tools

| Tool | API |
| --- | --- |
| `list_partners` | `GET /api/v1/partners` |
| `list_clients`, `get_client` | `GET /api/v1/clients[/{id}]` |
| `list_companies`, `get_company` | `GET /api/v1/companies[/{id}]` |
| `list_issues` | `POST /api/v1/issues/updated` |
| `get_issue_evidence`, `get_issues_evidence_bulk` | `GET /api/v1/issues/evidence/{id}`, `POST .../bulk` |
| `list_assets`, `get_company_indicators` | `POST /api/v1/assets/updated`, `GET /api/v1/assets/{companyId}` |
| `get_dashboard_scores` | `POST /api/v1/dashboard/scores` |
| `list_leaks` | `POST /api/v1/leaks/updated` |
| `list_reports`, `get_last_report`, `get_report` | `GET /api/v1/reports/...` |
| `get_company_logs`, `get_user_logs` | `POST /api/v1/companies/logs`, `POST /api/v1/users/logs` |

In issue results the top-level `status` is the lifecycle state (`Detected`, `Under review`,
`Solved`, `Manually solved`, `Ignored`, `False positive`) and `body.status` is the severity label
(`Critical severity`, ...). `Manually solved` appears in live data but not in the Swagger enum.

`list_assets` also supports `type=["typosq"]` for lookalike domains. The API's
`filter_string` is a free-text search, not an exact asset-name filter; results can match
discovery paths or other fields. Check each returned asset and its attribution.

## Result size and paging

Every tool result is kept under 30,000 ASCII bytes (`GIB_ASM_MAX_RESULT_CHARS`, minimum 10000)
as valid compact JSON. Unicode round-trips through JSON escapes. The default avoids truncation
by hosts with smaller output limits; raising it may cause a host to truncate the result.

- **Paged queries** (`list_issues`, `list_assets`, `list_leaks`): if a page is too big, the same
  request is repeated with a smaller `count`, so nothing is dropped and the returned `seqUpdate`
  still continues exactly where the page ends. Page through everything by passing each response's
  `seqUpdate` as `seq_update` until `items` comes back empty.
- **Unpaged lists** (`get_company_indicators`, `list_reports`): the longest prefix that fits is
  returned, with `truncated.lists = {field: {returned, available}}` saying what was cut.
- **Huge single records** (e.g. `get_issues_evidence_bulk`, where one issue's DNS history is
  megabytes, or a leaked-credentials issue whose `body.leaks` is ~70k chars): the heaviest fields
  of that record are replaced by `"<omitted: N chars>"`, and `truncated.omitted` lists their paths
  and sizes. The remaining fields are returned intact, and records are never dropped or replaced
  as a whole. Fetch an omitted record on its own (e.g. `get_issue_evidence`) or raise
  `GIB_ASM_MAX_RESULT_CHARS` to see the full field.

Read-only requests that receive HTTP 429 are retried up to three times with backoff. A valid
`Retry-After` is respected; if it exceeds the maximum 30-second retry delay or the remaining
operation deadline, the call returns an explicit error rather than retrying early. Each tool
call has a 60-second overall deadline including retries and page refetches.

## Development

```sh
uv run pytest
uv run ruff check . && uv run ruff format --check .
```
