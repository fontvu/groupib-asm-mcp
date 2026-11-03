import copy
import json

from groupib_asm_mcp.capping import cap_result, dump


def test_small_payload_is_returned_unchanged():
    data = {"count": 2, "items": [1, 2], "seqUpdate": 7}
    assert json.loads(cap_result(data)) == data


def test_long_list_is_cut_to_the_largest_fitting_prefix_and_cursor_is_dropped():
    items = [{"id": i, "pad": "x" * 100} for i in range(1000)]
    data = {"count": "1000 of 1000", "items": items, "seqUpdate": 9}

    text = cap_result(data, limit=10_000)

    result = json.loads(text)
    kept = len(result["items"])
    assert len(text) <= 10_000
    assert 0 < kept < 1000
    assert result["items"] == items[:kept]
    assert result["truncated"]["lists"] == {"items": {"returned": kept, "available": 1000}}
    # Continuing from the API's cursor would skip the dropped items, so it must not be offered.
    assert "seqUpdate" not in result
    assert "smaller count" in result["truncated"]["note"]
    # Largest prefix: one more item would not have fit in the budget used for trimming.
    assert len(dump({**data, "items": items[: kept + 1]})) > 10_000 - 4_000


def test_one_huge_field_is_omitted_and_its_siblings_survive():
    record = {"id": "x1", "name": "host", "whois": {"a": 1}, "dns": "d" * 200_000}
    data = {"count": 1, "items": [{"issueId": "i1", "category": "c", "items": [record]}]}

    result = json.loads(cap_result(data, limit=8_000))

    kept = result["items"][0]["items"][0]
    assert kept["id"] == "x1"
    assert kept["name"] == "host"
    assert kept["whois"] == {"a": 1}
    assert kept["dns"] == "<omitted: 200002 chars>"
    assert result["items"][0]["issueId"] == "i1"
    assert result["truncated"]["omitted"] == [{"path": "items[0].items[0].dns", "chars": 200_002}]
    assert "lists" not in result["truncated"]  # nothing was cut by prefix


def test_bytes_spread_over_many_small_fields_omit_the_whole_container():
    data = {"keep": "me", "bulk": {f"k{i}": "v" * 50 for i in range(2000)}}

    result = json.loads(cap_result(data, limit=6_000))

    assert result["keep"] == "me"
    assert result["bulk"].startswith("<omitted: ")
    assert result["truncated"]["omitted"][0]["path"] == "bulk"


def test_result_never_exceeds_the_limit_even_for_pathological_shapes():
    data = {f"field{i}": "x" * 400 for i in range(500)}  # no field dominates, none is a list

    text = cap_result(data, limit=5_000)

    assert len(text) <= 5_000
    assert "truncated" in json.loads(text)


def test_input_is_not_modified():
    data = {"items": [{"pad": "x" * 100} for _ in range(500)], "seqUpdate": 3}
    before = copy.deepcopy(data)

    cap_result(data, limit=5_000)

    assert data == before


def test_several_heavy_records_lose_their_heavy_field_never_the_records():
    def record(i: int) -> dict:
        leaks = [{"user": "x" * 100} for _ in range(300)]  # ~31k chars, no single entry dominates
        return {"id": f"i{i}", "status": "Ignored", "body": {"type": "t", "leaks": leaks}}

    # Each record alone is over the budget and none dominates the list (4 x ~31k).
    data = {"count": "4 of 4", "items": [record(i) for i in range(4)], "seqUpdate": 9}

    text = cap_result(data, limit=20_000)

    result = json.loads(text)
    assert len(text) <= 20_000
    assert [item["id"] for item in result["items"]] == ["i0", "i1", "i2", "i3"]
    assert all(item["body"]["type"] == "t" for item in result["items"])
    assert all(item["body"]["leaks"].startswith("<omitted: ") for item in result["items"])
    assert {o["path"] for o in result["truncated"]["omitted"]} == {
        f"items[{i}].body.leaks" for i in range(4)
    }
    assert result["seqUpdate"] == 9  # no item was dropped, so the cursor remains valid
    assert "lists" not in result["truncated"]


def test_a_list_of_records_is_never_shredded_into_placeholders():
    # A bare list cannot be prefix-trimmed safely (no envelope to carry a note), and dropping
    # records one by one into "<omitted>" strings would be silent data loss: say so explicitly.
    data = [{"id": i, "pad": "x" * 500} for i in range(500)]

    text = cap_result(data, limit=10_000)

    result = json.loads(text)
    assert len(text) <= 10_000
    assert isinstance(result, dict)
    assert "narrow the query" in result["truncated"]["note"]
    assert "<omitted:" not in text
