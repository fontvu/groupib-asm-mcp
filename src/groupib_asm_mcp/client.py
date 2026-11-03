"""Thin async client for the Group-IB Attack Surface Management REST API."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import quote

import httpx
from mcp.server.mcpserver.exceptions import ToolError

from groupib_asm_mcp.capping import (
    MAX_RESULT_CHARS,
    cap_result,
    dump,
    fit_budget,
    longest_fitting_prefix,
    without_oversized_records,
)

_MAX_PAGE_SHRINKS = 2

DEFAULT_BASE_URL = "https://asm.group-ib.com"

_STATUS_HINTS = {
    401: (
        "Check that GIB_ASM_LOGIN is your ASM login and GIB_ASM_API_KEY the key from Help -> API "
        "(HTTP Basic auth). Only ASM Admin users can use the API."
    ),
    403: (
        "No access to this client or company, or the id does not exist: the API answers 403 "
        "for both, so re-check the id (see list_companies) before assuming a permissions problem."
    ),
    404: "Not found. Check the id (company, client, issue or report).",
}


class AsmError(ToolError):
    """The ASM API rejected or failed a request; the message is shown to the model."""


def path_segment(value: str) -> str:
    """Percent-encode an id for use as one URL path segment."""
    return quote(value, safe="")


def _error_detail(response: httpx.Response) -> str:
    try:
        body = response.json()
    except ValueError:
        return response.text[:300]
    if isinstance(body, dict):
        for key in ("error", "message", "detail"):
            if key in body:
                return str(body[key])[:300]
    return json.dumps(body)[:300]


class AsmClient:
    """Authenticated client. Credentials are only ever sent in the Basic auth header."""

    def __init__(
        self,
        login: str,
        api_key: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 60.0,
        max_chars: int = MAX_RESULT_CHARS,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._max_chars = max_chars
        self._http = httpx.AsyncClient(
            base_url=base_url,
            auth=httpx.BasicAuth(login, api_key),
            headers={"Accept": "application/json"},
            timeout=timeout,
            transport=transport,
        )

    async def get(self, path: str, params: dict[str, Any] | None = None) -> str:
        data = await self._fetch("GET", path, params=_drop_none(params or {}))
        return cap_result(data, self._max_chars)

    async def post(self, path: str, body: dict[str, Any]) -> str:
        data = await self._fetch("POST", path, json=_drop_none(body))
        return cap_result(data, self._max_chars)

    async def post_paged(self, path: str, body: dict[str, Any]) -> str:
        """POST a ``seqUpdate``-paged list query without ever dropping items from a page.

        If the page is too large for one tool result, the same request (same cursor) is repeated
        with ``count`` set to the number of leading items that actually fit, so the returned
        ``seqUpdate`` still continues exactly where the page ends. Trimming the page instead
        would make that cursor skip the dropped items.
        """
        body = _drop_none(body)
        data = await self._fetch("POST", path, json=body)
        for _ in range(_MAX_PAGE_SHRINKS):
            items = data.get("items") if isinstance(data, dict) else None
            if not isinstance(items, list) or len(dump(data)) <= self._max_chars:
                break
            # Fit what cap_result will really return: records with heavy fields already omitted.
            prepared = without_oversized_records(data, self._max_chars)
            fitted = longest_fitting_prefix(prepared, "items", fit_budget(self._max_chars))
            if not 1 <= fitted < len(items):
                break  # everything fits once heavy fields are omitted, or nothing fits
            data = await self._fetch("POST", path, json={**body, "count": fitted})
        return cap_result(data, self._max_chars)

    async def aclose(self) -> None:
        await self._http.aclose()

    async def _fetch(self, method: str, path: str, **kwargs: Any) -> Any:
        try:
            response = await self._http.request(method, path, **kwargs)
        except httpx.HTTPError as exc:
            msg = f"{method} {path} failed: {type(exc).__name__}"
            raise AsmError(msg) from exc
        if response.is_success:
            try:
                return response.json()
            except ValueError as exc:
                msg = f"{method} {path} returned a non-JSON body"
                raise AsmError(msg) from exc
        hint = _STATUS_HINTS.get(response.status_code, "")
        msg = f"{method} {path} -> HTTP {response.status_code}: {_error_detail(response)}. {hint}"
        raise AsmError(msg.strip())


def _drop_none(values: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in values.items() if value is not None}
