"""Shared helpers for drgn-mcp tool modules."""

from typing import Literal

MAX_OUTPUT_LEN = 8000


def parse_address(address: int | str) -> int:
    """Convert an address parameter to int, accepting both int and hex str."""
    return address if isinstance(address, int) else int(address, 0)


def truncate_output(
    output: str,
    max_len: int = MAX_OUTPUT_LEN,
    *,
    keep: Literal["head", "tail"] = "head",
) -> str:
    """Truncate output string to max_len with a notice.

    Args:
        output: The string to truncate.
        max_len: Maximum allowed length.
        keep: Which end to keep — "head" keeps the beginning (default),
              "tail" keeps the end (useful for logs like dmesg).
    """
    if len(output) <= max_len:
        return output
    total = len(output)
    if keep == "tail":
        return f"... (truncated, {total} total chars)\n{output[-max_len:]}"
    return output[:max_len] + f"\n... (truncated, {total} total chars)"


def paginated_lines(
    iterator,
    format_item,
    *,
    offset: int = 0,
    limit: int = 100,
    label: str = "entries",
) -> list[str]:
    """Collect formatted lines from an iterator with offset/limit pagination.

    Returns a list of formatted strings. Appends a pagination hint when
    the limit is reached so the LLM knows how to fetch the next page.
    """
    offset = max(0, offset)
    limit = max(1, limit)
    lines: list[str] = []
    skipped = 0
    count = 0
    for item in iterator:
        if skipped < offset:
            skipped += 1
            continue
        if count >= limit:
            lines.append(
                f"... (limited to {limit} {label}, use offset={offset + limit} for next page)"
            )
            break
        lines.append(format_item(item))
        count += 1
    return lines


def format_hexdump(data: bytes, base_addr: int) -> str:
    """Format raw bytes as a hex dump with ASCII representation."""
    lines = []
    for offset in range(0, len(data), 16):
        chunk = data[offset : offset + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{base_addr + offset:#018x}  {hex_part:<48s}  {ascii_part}")
    return "\n".join(lines)
