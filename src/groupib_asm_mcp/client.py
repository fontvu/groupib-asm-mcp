"""Thin async client for the Group-IB Attack Surface Management REST API."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
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
_MAX_RATE_LIMIT_RETRIES = 3
_INITIAL_RETRY_DELAY = 0.5
_MAX_RETRY_DELAY = 30.0
_MAX_RETRY_AFTER_LENGTH = 128

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


def _retry_after_seconds(value: str) -> float:
    """Parse Retry-After without accepting an ambiguous or unbounded server delay."""
    if len(value) > _MAX_RETRY_AFTER_LENGTH:
        raise ValueError("overlong Retry-After")
    value = value.strip()
    if not value:
        raise ValueError("empty Retry-After")
    if value.isascii() and value.isdigit():
        # Avoid converting arbitrarily long integers, and reject rather than shorten the delay.
        if len(value.lstrip("0")) > 10:
            return float("inf")
        return float(int(value))
    try:
        retry_at = parsedate_to_datetime(value)
        if retry_at.tzinfo is None:
            raise ValueError("date has no timezone")
        return max(0.0, (retry_at - datetime.now(UTC)).total_seconds())
    except (TypeError, ValueError, OverflowError, IndexError) as exc:
        raise ValueError("invalid Retry-After") from exc


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
        self._timeout = timeout
        self._http = httpx.AsyncClient(
            base_url=base_url,
            auth=httpx.BasicAuth(login, api_key),
            headers={"Accept": "application/json"},
            timeout=timeout,
            transport=transport,
        )

    async def get(self, path: str, params: dict[str, Any] | None = None) -> str:
        async with self._operation("GET", path) as deadline:
            data = await self._fetch("GET", path, deadline, params=_drop_none(params or {}))
            return cap_result(data, self._max_chars)

    async def post(self, path: str, body: dict[str, Any]) -> str:
        async with self._operation("POST", path) as deadline:
            data = await self._fetch("POST", path, deadline, json=_drop_none(body))
            return cap_result(data, self._max_chars)

    async def post_paged(self, path: str, body: dict[str, Any]) -> str:
        """POST a ``seqUpdate``-paged list query without ever dropping items from a page.

        If the page is too large for one tool result, the same request (same cursor) is repeated
        with ``count`` set to the number of leading items that actually fit, so the returned
        ``seqUpdate`` still continues exactly where the page ends. Trimming the page instead
        would make that cursor skip the dropped items.
        """
        async with self._operation("POST", path) as deadline:
            body = _drop_none(body)
            data = await self._fetch("POST", path, deadline, json=body)
            for _ in range(_MAX_PAGE_SHRINKS):
                items = data.get("items") if isinstance(data, dict) else None
                if not isinstance(items, list) or len(dump(data)) <= self._max_chars:
                    break
                # Fit what cap_result will really return: records with heavy fields already omitted.
                prepared = without_oversized_records(data, self._max_chars)
                fitted = longest_fitting_prefix(prepared, "items", fit_budget(self._max_chars))
                if not 1 <= fitted < len(items):
                    break  # everything fits once heavy fields are omitted, or nothing fits
                data = await self._fetch("POST", path, deadline, json={**body, "count": fitted})
            return cap_result(data, self._max_chars)

    async def aclose(self) -> None:
        await self._http.aclose()

    @asynccontextmanager
    async def _operation(self, method: str, path: str) -> AsyncIterator[float]:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self._timeout
        timeout = asyncio.timeout_at(deadline)
        try:
            async with timeout:
                yield deadline
                # Synchronous result fitting cannot be interrupted by an asyncio timer.
                if loop.time() >= deadline:
                    raise TimeoutError
        except TimeoutError as exc:
            if timeout.expired() or loop.time() >= deadline:
                msg = f"{method} {path} exceeded the {self._timeout:g}s operation deadline"
                raise AsmError(msg) from exc
            raise

    async def _fetch(self, method: str, path: str, deadline: float, **kwargs: Any) -> Any:
        for attempt in range(_MAX_RATE_LIMIT_RETRIES + 1):
            if asyncio.get_running_loop().time() >= deadline:
                msg = f"{method} {path} exceeded the {self._timeout:g}s operation deadline"
                raise AsmError(msg)
            try:
                response = await self._http.request(method, path, **kwargs)
            except httpx.HTTPError as exc:
                if asyncio.get_running_loop().time() >= deadline:
                    msg = f"{method} {path} exceeded the {self._timeout:g}s operation deadline"
                    raise AsmError(msg) from exc
                msg = f"{method} {path} failed: {type(exc).__name__}"
                raise AsmError(msg) from exc
            if asyncio.get_running_loop().time() >= deadline:
                msg = f"{method} {path} exceeded the {self._timeout:g}s operation deadline"
                raise AsmError(msg)
            if response.is_success:
                try:
                    return response.json()
                except ValueError as exc:
                    msg = f"{method} {path} returned a non-JSON body"
                    raise AsmError(msg) from exc

            hint = _STATUS_HINTS.get(response.status_code, "")
            msg = (
                f"{method} {path} -> HTTP {response.status_code}: {_error_detail(response)}. {hint}"
            )
            if response.status_code != 429:
                raise AsmError(msg.strip())
            if attempt == _MAX_RATE_LIMIT_RETRIES:
                raise AsmError(f"{msg.strip()} Rate-limit retries exhausted.")

            delay = _INITIAL_RETRY_DELAY * 2**attempt
            retry_after = response.headers.get("Retry-After")
            if retry_after is not None:
                try:
                    delay = max(delay, _retry_after_seconds(retry_after))
                except ValueError as exc:
                    raise AsmError(
                        f"{msg.strip()} Invalid Retry-After; refusing to retry."
                    ) from exc
            if delay > _MAX_RETRY_DELAY:
                raise AsmError(f"{msg.strip()} Retry-After exceeds the maximum retry delay.")
            if delay >= deadline - asyncio.get_running_loop().time():
                raise AsmError(
                    f"{msg.strip()} Retry delay exceeds the remaining operation deadline."
                )
            await asyncio.sleep(delay)


def _drop_none(values: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in values.items() if value is not None}
