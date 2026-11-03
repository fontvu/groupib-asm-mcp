"""Keep tool results within a size budget without silently losing data.

A result that is too large is shrunk in three steps, and every change is reported in a
``truncated`` object on the result, so the model can tell what it did not receive:

1. **Omit heavy fields of oversized records.** A single record bigger than a quarter of the
   budget (one issue with a 70k ``leaks`` array) has its heaviest fields replaced with an
   ``"<omitted: N chars>"`` placeholder. Records and collections themselves are never omitted.
2. **Trim lists** (``items`` and friends) to the longest prefix that fits. Paging cursors
   (``seqUpdate``) are removed from a trimmed result, because continuing from the API's cursor
   would skip the items that were dropped. (Paged queries avoid this: see
   ``AsmClient.post_paged``, which re-requests a smaller page instead.)
3. **Omit heavy fields anywhere.** If the payload is still too large, the largest remaining
   field is replaced with a placeholder, repeatedly, until the rest fits. If no safe target
   exists, an explicit "too large, narrow the query" result is returned instead.
"""

from __future__ import annotations

import json
from typing import Any

MAX_RESULT_CHARS = 30_000
MIN_RESULT_CHARS = 10_000  # smaller limits leave no room for the ``truncated`` object

# Room reserved for the ``truncated`` object itself, so adding it cannot push a result over.
_MARKER_BUDGET = 4_000
_MAX_OMISSIONS = 100
_LISTED_OMISSIONS = 15
_DOMINANT_SHARE = 0.5
_PROTECTED_DEPTH = 2  # root children (collections) and the records inside them
_ENTER_MIN_DIVISOR = 10  # a child is "sizable" if it holds at least 1/10 of the budget
_RECORD_SHARE_DIVISOR = 4  # one record may use at most 1/4 of the budget before its fields go
_CURSOR_KEYS = ("seqUpdate",)


def dump(data: Any) -> str:
    """Serialize as compact ASCII JSON, so character counts equal UTF-8 byte counts."""
    return json.dumps(data, separators=(",", ":"), ensure_ascii=True)


def cap_result(data: Any, limit: int = MAX_RESULT_CHARS) -> str:
    """Serialize ``data`` to compact JSON of at most ``limit`` ASCII bytes."""
    text = dump(data)
    if len(text) <= limit:
        return text

    budget = fit_budget(limit)
    lists: dict[str, dict[str, int]] = {}
    omitted: list[dict[str, Any]] = []
    current = data

    if isinstance(current, dict):
        current = _omit_oversized_records(current, budget // _RECORD_SHARE_DIVISOR, omitted)
        current = _trim_lists(current, budget, lists)
    current = _omit_heavy_fields(current, budget, omitted)

    if isinstance(current, dict):
        marker: dict[str, Any] = {}
        if lists:
            marker["lists"] = lists
            for key in _CURSOR_KEYS:
                current.pop(key, None)
            marker["note"] = (
                "Result trimmed to fit the size limit. Paging cursors were removed because "
                "continuing from them would skip the dropped items: re-run with a smaller "
                "count or a narrower date window."
            )
        if omitted:
            marker["omitted"] = omitted[:_LISTED_OMISSIONS]
            if len(omitted) > _LISTED_OMISSIONS:
                marker["omitted_more"] = len(omitted) - _LISTED_OMISSIONS
            marker["omitted_note"] = (
                "Fields shown as '<omitted: N chars>' were too large for one result. Fetch that "
                "record on its own (e.g. get_issue_evidence) or raise GIB_ASM_MAX_RESULT_CHARS."
            )
        if marker:
            current = {**current, "truncated": marker}
    result = dump(current)
    if len(result) > limit:  # pathological shape that omission could not shrink enough
        return dump(
            {
                "truncated": {
                    "note": "Result is too large to return in full; narrow the query.",
                    "chars": len(text),
                }
            }
        )
    return result


def _trim_lists(data: dict[str, Any], budget: int, lists: dict[str, dict[str, int]]) -> dict:
    """Cut top-level lists to the longest prefix that fits, largest list first.

    A list is only trimmed if at least one element survives; otherwise the elements are
    individually too large and are left for ``_omit_heavy_fields``.
    """
    current = data
    by_size = sorted(
        (key for key, value in data.items() if isinstance(value, list) and value),
        key=lambda key: len(dump(data[key])),
        reverse=True,
    )
    for key in by_size:
        if len(dump(current)) <= budget:
            break
        full = data[key]
        low = longest_fitting_prefix(current, key, budget)
        if low >= 1:
            current = {**current, key: full[:low]}
            lists[key] = {"returned": low, "available": len(full)}
    return current


def longest_fitting_prefix(data: dict[str, Any], key: str, budget: int) -> int:
    """Largest ``n`` such that ``data`` with ``data[key][:n]`` serializes within ``budget``.

    Returns 0 when not even one element fits, and the full length when everything fits.
    """
    full = data[key]
    if len(dump(data)) <= budget:
        return len(full)
    low, high = 0, len(full)  # n=high does not fit; search for the largest n that does
    while low < high - 1:
        mid = (low + high) // 2
        if len(dump({**data, key: full[:mid]})) <= budget:
            low = mid
        else:
            high = mid
    return low


def fit_budget(limit: int) -> int:
    """Size a result may reach before it needs room for its ``truncated`` object."""
    return limit - _MARKER_BUDGET


def without_oversized_records(data: dict[str, Any], limit: int) -> dict[str, Any]:
    """Return ``data`` with the heavy fields of any single oversized record omitted.

    This is the first step of ``cap_result``, exposed so a paged query can work out how many
    records fit *after* it, and re-request exactly that many.
    """
    return _omit_oversized_records(data, fit_budget(limit) // _RECORD_SHARE_DIVISOR, [])


def _omit_oversized_records(
    data: dict[str, Any], record_limit: int, omitted: list[dict[str, Any]]
) -> dict[str, Any]:
    """Omit heavy fields inside any list element larger than ``record_limit``.

    A record that is huge on its own (one issue with a 70k ``leaks`` array) would otherwise force
    either dropping whole records or omitting the entire list. Only its heavy fields go.
    """
    current = data
    for key, value in data.items():
        if not isinstance(value, list):
            continue
        records = list(value)
        for index, record in enumerate(value):
            if not isinstance(record, dict | list) or len(dump(record)) <= record_limit:
                continue
            local: list[dict[str, Any]] = []
            records[index] = _omit_heavy_fields(record, record_limit, local, protected_depth=0)
            prefix = f"{key}[{index}]"
            omitted.extend(
                {
                    "path": f"{prefix}{'' if o['path'].startswith('[') else '.'}{o['path']}",
                    "chars": o["chars"],
                }
                for o in local
            )
        if records != list(value):
            current = {**current, key: records}
    return current


def _omit_heavy_fields(
    data: Any,
    budget: int,
    omitted: list[dict[str, Any]],
    protected_depth: int = _PROTECTED_DEPTH,
) -> Any:
    """Replace the largest field with a placeholder until the payload fits the budget."""
    current = data
    for _ in range(_MAX_OMISSIONS):
        if len(dump(current)) <= budget:
            break
        target = _heaviest_node(current, budget // _ENTER_MIN_DIVISOR, protected_depth)
        if target is None:
            break
        path, chars = target
        omitted.append({"path": _format_path(path), "chars": chars})
        current = _replace(current, path, f"<omitted: {chars} chars>")
    return current


def _heaviest_node(
    root: Any, enter_min: int, protected_depth: int
) -> tuple[tuple[str | int, ...], int] | None:
    """Find the field to omit: follow the bytes down to where the bulk actually lives.

    The root, its collections (``items``) and the records inside them are never omitted whole;
    only fields within a record are. Inside a record we descend while one child holds most of the
    bytes. When the bytes are spread over many small children (a long ``leaks`` list), that whole
    container is omitted; in a record with no heavy container, its largest field is.
    """
    sizes: dict[int, int] = {}

    def size(node: Any) -> int:
        key = id(node)
        if key not in sizes:
            if isinstance(node, dict):
                sizes[key] = 2 + sum(len(dump(k)) + 2 + size(v) for k, v in node.items())
            elif isinstance(node, list):
                sizes[key] = 2 + sum(1 + size(v) for v in node)
            else:
                sizes[key] = len(dump(node))
        return sizes[key]

    def children(node: Any) -> list[tuple[str | int, Any]]:
        if isinstance(node, dict):
            return list(node.items())
        if isinstance(node, list):
            return list(enumerate(node))
        return []

    path: tuple[str | int, ...] = ()
    node = root
    while True:
        kids = [(k, v) for k, v in children(node) if not _is_placeholder(v)]
        if not kids:
            break
        key, child = max(kids, key=lambda kv: size(kv[1]))
        # The root, its collections and the records inside them are not omitted whole while they
        # contain a sizable child: go into it. Below that, follow the bytes while one child
        # holds most of them.
        sizable = size(child) >= enter_min
        if (len(path) < protected_depth and sizable) or size(child) >= _DOMINANT_SHARE * size(node):
            path, node = (*path, key), child
            if not children(child):  # the heavy field is a plain value: omit just that
                break
            continue
        if len(path) == protected_depth or not path:
            # A record with spread fields, or the root: omit the largest child, keep the rest.
            path, node = (*path, key), child
        break  # otherwise the bytes are spread over many small children: omit this container
    if not path or _is_record_or_collection(root, path, protected_depth):
        return None  # no safe target: the caller falls back to an explicit "too large" result
    return path, size(node)


def _is_record_or_collection(root: Any, path: tuple[str | int, ...], protected_depth: int) -> bool:
    """True if ``path`` points at a list of records, or at a record inside one.

    Omitting those would silently drop whole records while the caller still holds a cursor that
    claims they were returned. Only applies to payload-level searches (``protected_depth > 0``);
    a record searched on its own is expected to lose fields.
    """
    if not protected_depth:
        return False
    collection = (
        root if isinstance(root, list) else root.get(path[0]) if isinstance(root, dict) else None
    )
    depth_limit = 1 if isinstance(root, list) else 2  # the collection itself, or a record in it
    is_record_list = isinstance(collection, list) and any(
        isinstance(e, dict | list) for e in collection
    )
    return is_record_list and len(path) <= depth_limit


def _is_placeholder(node: Any) -> bool:
    return isinstance(node, str) and node.startswith("<omitted: ")


def _format_path(path: tuple[str | int, ...]) -> str:
    return "".join(f"[{part}]" if isinstance(part, int) else f".{part}" for part in path).lstrip(
        "."
    )


def _replace(root: Any, path: tuple[str | int, ...], value: Any) -> Any:
    """Return a copy of ``root`` with the node at ``path`` replaced (parents copied)."""
    if not path:
        return value
    head, rest = path[0], path[1:]
    if isinstance(root, dict):
        return {**root, head: _replace(root[head], rest, value)}
    copy = list(root)
    copy[head] = _replace(root[head], rest, value)
    return copy
