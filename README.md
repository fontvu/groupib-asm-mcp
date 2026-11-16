# groupib-asm-mcp

[MCP](https://modelcontextprotocol.io) server for the Group-IB **Attack Surface Management**
REST API (`https://asm.group-ib.com`, API version 2.9.3). It wraps all 28 operations in the
bundled API specification, including writes. The current API specification is available at
`/api/doc/swagger.json` after signing in to ASM.

Write tools require interactive approval of the exact destination, endpoint and complete JSON
body. MCP clients that support form elicitation receive a standard approval request; OMP uses
the extension below. A rejected, unavailable, cancelled or expired approval sends no request.
Requests whose JSON body exceeds 16,000 characters are rejected instead of showing an
incomplete approval preview. Client implementations decide how to handle MCP elicitation, so
use one that presents it to a human.

OMP's approval extension serializes each review, decision, and callback. It opens a scrollable
review followed by an **Approve once / Deny** question; both display the same request ID. Review
the whole request and submit it unchanged before answering. OMP must run interactively with an
extension-capable UI; headless sessions fail closed. Approval expires after 60 seconds, including
time spent waiting behind another request.
The notification handler returns while the review runs, so OMP's handler timeout does not cut
short the approval dialog. The review and response still expire under the deadline above.

## Getting started

### Prerequisites and installation

You need Git, [uv](https://docs.astral.sh/uv/getting-started/installation/), Python 3.12 or
newer, and a Group-IB ASM account with Admin API access.

```sh
git clone https://github.com/fontvu/groupib-asm-mcp.git
cd groupib-asm-mcp
uv sync
```

Generate an API key in ASM under **Help -> REST API & Integrations -> Generate API Key**.
The server uses HTTP Basic authentication with your ASM login (usually an email) and API key.
Export both in the shell that starts your agent; do not commit them or put them in shared config:

```sh
export GIB_ASM_LOGIN='you@example.com'
export GIB_ASM_API_KEY='...'          # replace with your API key
# optional: GIB_ASM_BASE_URL (default https://asm.group-ib.com)
# optional: GIB_ASM_MAX_RESULT_CHARS (default 30000)
```

The server refuses to start if either credential is missing. To run it directly for an MCP
client, use `uv run groupib-asm-mcp` from the checkout; it speaks MCP over stdio, not HTTP.

### Connect OMP

In `~/.omp/agent/mcp.json`, add this entry to the existing `mcpServers` object. Replace
`/absolute/path/to/groupib-asm` with the actual checkout path. OMP resolves the `env` entries
from its own environment, so export the variables before starting it:

```json
"groupib-asm": {
  "type": "stdio",
  "command": "uv",
  "args": ["run", "--quiet", "--project", "/absolute/path/to/groupib-asm", "groupib-asm-mcp"],
  "env": { "GIB_ASM_LOGIN": "GIB_ASM_LOGIN", "GIB_ASM_API_KEY": "GIB_ASM_API_KEY" },
  "timeout": 90000
}
```

Install the OMP confirmation extension for the default profile by creating a symlink to the
checked-out extension:

```sh
mkdir -p ~/.omp/agent/extensions
ln -s /absolute/path/to/groupib-asm/omp/groupib-asm-approval.ts \
  ~/.omp/agent/extensions/groupib-asm-approval.ts
```

The extension and MCP server must run as the same local user and share a temporary directory;
do not use the bridge for a remote MCP server. It communicates the answer over a private,
single-use local socket; it never sends credentials to OMP. If the extension or UI is absent,
the write is refused after the approval deadline.

Start or restart `omp`, then ask it to list the Group-IB companies. For example: “Use Group-IB
ASM to list my companies.” If it cannot connect, check the exported credentials, checkout path,
and OMP's MCP status. Writes additionally require the interactive approval extension above.

### Connect Pi

The following configuration is for Pi with its [built-in MCP support](https://docs.pi.dev/latest/mcp).
In `~/.pi/agent/mcp.json`, add the entry below to the `mcpServers` object, replacing the checkout
path. If the file does not exist, use the complete JSON shown. Pi expands `${...}` from its
environment; do not substitute actual secrets into this file.

```json
{
  "mcpServers": {
    "groupib-asm": {
      "command": "uv",
      "args": ["run", "--quiet", "--project", "/absolute/path/to/groupib-asm", "groupib-asm-mcp"],
      "env": {
        "GIB_ASM_LOGIN": "${GIB_ASM_LOGIN}",
        "GIB_ASM_API_KEY": "${GIB_ASM_API_KEY}"
      },
      "timeout": 90
    }
  }
}
```

Run `pi mcp list` from the shell with the credentials exported, then start `pi` and ask it to
list the Group-IB companies. In a running session, use `/reload` after changing the config and
`/mcp` to inspect the connection. If a separate MCP adapter replaces Pi's built-in support,
follow that adapter's configuration instructions instead.

Read-only tools do not need the OMP extension. The OMP extension is **not** a Pi integration:
write tools require a Pi MCP client that presents the server's form elicitation to a human.
Pi write approval has not been verified here; if elicitation is unsupported or unavailable,
writes fail closed. Never bypass the approval requirement.

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
| `create_client` | `POST /api/v1/clients/create` |
| `create_company`, `create_companies_bulk`, `update_company` | `POST /api/v1/companies/create`, `POST .../create/bulk`, `POST .../update` |
| `create_user` | `POST /api/v1/users/create` |
| `change_issue_status`, `change_issue_severity`, `add_issue_comment` | `POST /api/v1/issues/status/change`, `POST .../severity/change`, `POST .../comments/add` |
| `add_company_indicators`, `remove_company_indicators`, `change_asset_status` | `POST /api/v1/assets/add`, `POST .../remove`, `POST .../status/change` |

For issue status changes, the API accepts case-sensitive values (`Detected`, `Under review`,
`Solved`, `False positive`, `Ignored`), unlike the lowercase values used when filtering issues.

In issue results the top-level `status` is the lifecycle state (`Detected`, `Under review`,
`Solved`, `Manually solved`, `Ignored`, `False positive`) and `body.status` is the severity label
(`Critical severity`, ...). `Manually solved` appears in live data but not in the Swagger enum.

`list_issues` defaults `date_from` to `1970-01-01` to avoid the API's implicit recent
date window, which can hide older findings even when their status is under review. Set
`date_from` explicitly to narrow the window; API date limits and retention still apply.
Other paged tools retain their API date defaults.

`list_assets` also supports `type=["typosq"]` for lookalike domains. The API's
`filter_string` is a free-text search, not an exact asset-name filter; results can match
discovery paths or other fields. Check each returned asset and its attribution.

An automatically discovered asset or a shared WHOIS address or IP is a lead, not proof of
ownership or responsibility. Review the full discovery path against authoritative inventory before
confirming an asset or classifying a finding. Leaked-credential evidence can contain duplicate or
misparsed fields; validate and deduplicate actual accounts before relying on record counts. A
false attribution to one company does not by itself invalidate the underlying security finding.

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

Write requests are sent **once**, never automatically retried. A timeout, transport error,
non-JSON response, or unsuccessful HTTP response may leave the outcome uncertain: check ASM's
state before attempting the change again. Writes can create users, change scan settings, or
alter issue and asset classifications; verify the requested values before approving.

## Development

```sh
uv run pytest
node --test tests/test_omp_extension.mjs  # Node.js 22.6+ with native TypeScript stripping
uv run ruff check . && uv run ruff format --check .
```
