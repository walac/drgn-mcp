"""Characterize parser, truncation, hexdump, and pagination helpers."""

from collections.abc import Callable, Iterator

import pytest

from drgn_mcp.tools._helpers import format_hexdump, paginated_lines, parse_address, truncate_output


def test_parse_address_accepts_decimal_integer() -> None:
    assert parse_address(0) == 0
    assert parse_address(4096) == 4096
    assert parse_address(0xDEADBEEF) == 0xDEADBEEF


def test_parse_address_accepts_hexadecimal_string() -> None:
    assert parse_address("0x0") == 0
    assert parse_address("0x1000") == 4096
    assert parse_address("0Xdeadbeef") == 0xDEADBEEF


def test_parse_address_rejects_invalid_literal() -> None:
    with pytest.raises(ValueError):
        parse_address("not-an-address")


def test_truncate_output_unchanged_at_exact_boundary() -> None:
    text = "x" * 80
    assert truncate_output(text, max_len=80, keep="head") == text
    assert truncate_output(text, max_len=80, keep="tail") == text


def test_truncate_output_head_above_boundary_includes_total_length() -> None:
    text = "h" * 20 + "t" * 20
    result = truncate_output(text, max_len=20, keep="head")
    assert result == ("h" * 20) + "\n... (truncated, 40 total chars)"


def test_truncate_output_tail_above_boundary_includes_total_length() -> None:
    text = "h" * 20 + "t" * 20
    result = truncate_output(text, max_len=20, keep="tail")
    assert result == "... (truncated, 40 total chars)\n" + ("t" * 20)


def test_format_hexdump_full_row_uses_padded_address_and_nonprintable_ascii() -> None:
    data = bytes(range(16))
    assert format_hexdump(data, 0) == (
        "0x0000000000000000  "
        "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f   "
        "................"
    )


def test_format_hexdump_partial_and_full_rows_with_printable_ascii() -> None:
    data = b"Hello, World!!!!Hi\x00\xff"
    assert format_hexdump(data, 0x1000) == (
        "0x0000000000001000  "
        "48 65 6c 6c 6f 2c 20 57 6f 72 6c 64 21 21 21 21   "
        "Hello, World!!!!\n"
        "0x0000000000001010  "
        "48 69 00 ff                                       "
        "Hi.."
    )


@pytest.mark.parametrize(
    ("offset", "limit"),
    [
        (0, 0),
        (-3, -2),
    ],
)
def test_paginated_lines_normalizes_zero_and_negative_offset_and_limit(
    offset: int, limit: int
) -> None:
    formatted: list[str] = []

    def format_item(item: str) -> str:
        formatted.append(item)
        return item

    lines = paginated_lines(["a", "b", "c"], format_item, offset=offset, limit=limit)

    assert formatted == ["a"]
    assert lines == [
        "a",
        "... (limited to 1 entries, use offset=1 for next page)",
    ]


def test_paginated_lines_skips_offset_items() -> None:
    formatted: list[str] = []

    def format_item(item: str) -> str:
        formatted.append(item)
        return f"item-{item}"

    lines = paginated_lines(["0", "1", "2", "3"], format_item, offset=2, limit=10)

    assert formatted == ["2", "3"]
    assert lines == ["item-2", "item-3"]


def test_paginated_lines_appends_next_page_hint() -> None:
    lines = paginated_lines(
        ["a", "b", "c", "d", "e"],
        str,
        offset=1,
        limit=2,
        label="tasks",
    )
    assert lines == [
        "b",
        "c",
        "... (limited to 2 tasks, use offset=3 for next page)",
    ]


def test_paginated_lines_formats_item_fault(drgn_error: Callable[..., BaseException]) -> None:
    fault = drgn_error("fault", "bad item", address=0x20)

    def format_item(item: str) -> str:
        if item == "bad":
            raise fault
        return item

    assert paginated_lines(["ok", "bad", "later"], format_item) == [
        "ok",
        "<fault: bad item: 0x20>",
        "later",
    ]


def test_paginated_lines_aborts_on_iterator_fault(
    drgn_error: Callable[..., BaseException],
) -> None:
    fault = drgn_error("fault", "unmapped", address=0x100)

    def items() -> Iterator[str]:
        yield "ok"
        raise fault

    assert paginated_lines(items(), str) == [
        "ok",
        "... Traversal aborted due to memory fault: unmapped: 0x100",
    ]
