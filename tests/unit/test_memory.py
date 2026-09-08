"""Characterize memory, address, page, slab, VMA, and process-memory tools."""

from collections.abc import Callable, Iterator
from types import SimpleNamespace

import pytest

from drgn_mcp.tools import memory
from drgn_mcp.tools._helpers import MAX_OUTPUT_LEN
from tests.conftest import FakeBytes, FakeValue, FaultyValue, Stringable, mark_loaded


class _PageSizeProgram:
    """Program stand-in that answers ``prog['PAGE_SIZE']`` via FakeValue."""

    def __init__(self, page_size: int = 4096, **attrs: object) -> None:
        self._page_size = page_size
        for name, value in attrs.items():
            setattr(self, name, value)

    def __getitem__(self, name: str) -> FakeValue:
        if name == "PAGE_SIZE":
            return FakeValue(self._page_size)
        raise KeyError(name)


def _user_task(mm: object | None = None) -> SimpleNamespace:
    if mm is None:
        mm = SimpleNamespace()
    return SimpleNamespace(mm=SimpleNamespace(read_=lambda: mm))


def _kthread() -> SimpleNamespace:
    return SimpleNamespace(mm=SimpleNamespace(read_=lambda: None))


def _vma(*, start: int, end: int, flags: int = 0x75) -> SimpleNamespace:
    return SimpleNamespace(
        vm_start=FakeValue(start),
        vm_end=FakeValue(end),
        vm_flags=FakeValue(flags),
    )


# --- read_memory ---------------------------------------------------------------


def test_read_memory_formats_hexdump(fake_program: Callable[..., SimpleNamespace]) -> None:
    payload = b"Hello, World!!!!Hi\x00\xff"

    def read(addr: int, size: int) -> bytes:
        assert addr == 0x1000
        assert size == 20
        return payload

    mark_loaded(fake_program(read=read))

    assert memory.read_memory(0x1000, size=20) == (
        "0x0000000000001000  "
        "48 65 6c 6c 6f 2c 20 57 6f 72 6c 64 21 21 21 21   "
        "Hello, World!!!!\n"
        "0x0000000000001010  "
        "48 69 00 ff                                       "
        "Hi.."
    )


def test_read_memory_parses_hex_string_and_caps_size(
    fake_program: Callable[..., SimpleNamespace],
) -> None:
    sizes: list[int] = []

    def read(addr: int, size: int) -> bytes:
        sizes.append(size)
        assert addr == 0x2000
        return b"\x00" * 16

    mark_loaded(fake_program(read=read))

    result = memory.read_memory("0x2000", size=5000)

    assert sizes == [4096]
    assert result == (
        "0x0000000000002000  "
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   "
        "................"
    )


def test_read_memory_reports_fault(
    fake_program: Callable[..., SimpleNamespace],
    drgn_error: Callable[..., BaseException],
) -> None:
    fault = drgn_error("fault", "unmapped", address=0xABC)

    def read(addr: int, size: int) -> bytes:
        raise fault

    mark_loaded(fake_program(read=read))

    assert memory.read_memory(0xABC, size=8) == f"Memory fault at 0xabc: {fault}"


# --- get_dmesg ----------------------------------------------------------------


def test_get_dmesg_formats_timestamped_records(monkeypatch: pytest.MonkeyPatch) -> None:
    records = [
        SimpleNamespace(timestamp=1_500_000_000, text="early boot"),
        SimpleNamespace(timestamp=2_250_000_000, text="oops"),
    ]
    monkeypatch.setattr(memory, "get_printk_records", lambda prog: records)
    mark_loaded()

    assert memory.get_dmesg() == "[    1.500000] early boot\n[    2.250000] oops"


def test_get_dmesg_appends_iterator_fault(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    fault = drgn_error("fault", "log walk", address=0x10)
    good = SimpleNamespace(timestamp=0, text="ok")

    def records(prog: object) -> Iterator[SimpleNamespace]:
        yield good
        raise fault

    monkeypatch.setattr(memory, "get_printk_records", records)
    mark_loaded()

    assert memory.get_dmesg() == (
        f"[    0.000000] ok\n... Log buffer read aborted due to memory fault: {fault}"
    )


def test_get_dmesg_truncates_from_the_tail(monkeypatch: pytest.MonkeyPatch) -> None:
    texts = [f"msg{i:04d}" + "A" * 40 for i in range(200)]
    records = [SimpleNamespace(timestamp=0, text=text) for text in texts]
    monkeypatch.setattr(memory, "get_printk_records", lambda prog: records)
    mark_loaded()

    raw = "\n".join(f"[{0.0:>12.6f}] {text}" for text in texts)
    assert len(raw) > MAX_OUTPUT_LEN

    assert memory.get_dmesg() == (
        f"... (truncated, {len(raw)} total chars)\n{raw[-MAX_OUTPUT_LEN:]}"
    )


# --- search_memory ------------------------------------------------------------


def test_search_memory_bytes_lists_hex_addresses(
    fake_program: Callable[..., SimpleNamespace],
) -> None:
    def search_memory(pattern: bytes, alignment: int = 1) -> Iterator[int]:
        assert pattern == b"swapper"
        assert alignment == 8
        yield 0x1000
        yield 0x2000

    mark_loaded(fake_program(search_memory=search_memory))

    assert memory.search_memory("swapper", search_type="bytes", alignment=8) == ("0x1000\n0x2000")


@pytest.mark.parametrize("search_type", ["u32", "u64", "word"])
def test_search_memory_integer_types_format_address_and_value(
    fake_program: Callable[..., SimpleNamespace],
    search_type: str,
) -> None:
    def search_fn(value: int) -> Iterator[tuple[int, int]]:
        assert value == 0xDEADBEEF
        yield (0x2000, value)

    mark_loaded(fake_program(**{f"search_memory_{search_type}": search_fn}))

    assert memory.search_memory("0xdeadbeef", search_type=search_type) == "0x2000: 0xdeadbeef"


def test_search_memory_regex_shows_matched_bytes(
    fake_program: Callable[..., SimpleNamespace],
) -> None:
    class _Match:
        def __str__(self) -> str:
            return "matched-str"

        def __repr__(self) -> str:
            return "matched-repr"

    def search_memory_regex(pattern: bytes) -> Iterator[tuple[int, object]]:
        assert pattern == b"panic.*"
        yield (0x3000, _Match())

    mark_loaded(fake_program(search_memory_regex=search_memory_regex))

    assert memory.search_memory("panic.*", search_type="regex") == "0x3000: matched-repr"


def test_search_memory_reports_unknown_type() -> None:
    mark_loaded()

    assert memory.search_memory("x", search_type="bogus") == (
        "Unknown search type 'bogus'. Use: bytes, u32, u64, word, regex."
    )


def test_search_memory_reports_no_matches(fake_program: Callable[..., SimpleNamespace]) -> None:
    mark_loaded(fake_program(search_memory=lambda pattern, alignment=1: iter(())))

    assert memory.search_memory("missing") == "No matches found"


def test_search_memory_appends_limit_notice(
    fake_program: Callable[..., SimpleNamespace],
) -> None:
    def search_memory(pattern: bytes, alignment: int = 1) -> Iterator[int]:
        yield from (0x10, 0x20, 0x30)

    mark_loaded(fake_program(search_memory=search_memory))

    assert memory.search_memory("x", limit=2) == (
        "0x10\n0x20\n... (limited to 2 results, use higher limit to see more)"
    )


def test_search_memory_reports_invalid_integer_pattern() -> None:
    mark_loaded()

    assert memory.search_memory("not-an-int", search_type="u32") == (
        "Invalid pattern: invalid literal for int() with base 0: 'not-an-int'"
    )


def test_search_memory_reports_fault(
    fake_program: Callable[..., SimpleNamespace],
    drgn_error: Callable[..., BaseException],
) -> None:
    fault = drgn_error("fault", "search walk", address=0x11)

    def search_memory(pattern: bytes, alignment: int = 1) -> Iterator[int]:
        raise fault

    mark_loaded(fake_program(search_memory=search_memory))

    assert memory.search_memory("x") == f"Memory fault during search: {fault}"


# --- get_source_location -------------------------------------------------------


def test_get_source_location_stringifies_result(
    fake_program: Callable[..., SimpleNamespace],
) -> None:
    def source_location(address: object) -> Stringable:
        assert address == "schedule+0x15"
        return Stringable("kernel/sched/core.c:10:0")

    mark_loaded(fake_program(source_location=source_location))

    assert memory.get_source_location("schedule+0x15") == "kernel/sched/core.c:10:0"


def test_get_source_location_reports_missing(
    fake_program: Callable[..., SimpleNamespace],
) -> None:
    def source_location(address: object) -> str:
        raise LookupError(address)

    mark_loaded(fake_program(source_location=source_location))

    assert memory.get_source_location(0xABCD) == "No source location found for '43981'"


def test_get_source_location_reports_fault(
    fake_program: Callable[..., SimpleNamespace],
    drgn_error: Callable[..., BaseException],
) -> None:
    fault = drgn_error("fault", "debuginfo", address=0x12)

    def source_location(address: object) -> str:
        raise fault

    mark_loaded(fake_program(source_location=source_location))

    assert memory.get_source_location("panic+0x50") == (
        f"Memory fault resolving 'panic+0x50': {fault}"
    )


# --- read_typed_memory -----------------------------------------------------------


def test_read_typed_memory_decodes_c_string_with_replacement(
    fake_program: Callable[..., SimpleNamespace],
) -> None:
    def read_c_string(addr: int, physical: bool, max_size: int = 8000) -> bytes:
        assert addr == 0x1000
        assert physical is True
        assert max_size == 8000
        return b"hello\xff"

    mark_loaded(fake_program(read_c_string=read_c_string))

    assert memory.read_typed_memory(0x1000, value_type="c_string", physical=True) == ("hello\ufffd")


def test_read_typed_memory_formats_integer_array(
    fake_program: Callable[..., SimpleNamespace],
) -> None:
    values = {0x1000: 1, 0x1008: 2}

    def read_u64(addr: int, physical: bool) -> int:
        assert physical is False
        return values[addr]

    mark_loaded(fake_program(read_u64=read_u64, address_size=lambda: 8))

    assert memory.read_typed_memory(0x1000, value_type="u64", count=2) == (
        "0x0000000000001000: 0x1\n0x0000000000001008: 0x2"
    )


@pytest.mark.parametrize("value_type, stride", [("u8", 1), ("u16", 2), ("u32", 4)])
def test_read_typed_memory_integer_types_use_fixed_stride(
    fake_program: Callable[..., SimpleNamespace],
    value_type: str,
    stride: int,
) -> None:
    addrs: list[int] = []
    physical_flags: list[bool] = []

    def read_fn(addr: int, physical: bool) -> int:
        addrs.append(addr)
        physical_flags.append(physical)
        return 0xAA

    mark_loaded(fake_program(**{f"read_{value_type}": read_fn, "address_size": lambda: 8}))

    result = memory.read_typed_memory(0x10, value_type=value_type, count=2, physical=True)

    assert addrs == [0x10, 0x10 + stride]
    assert physical_flags == [True, True]
    assert result == f"0x0000000000000010: 0xaa\n{0x10 + stride:#018x}: 0xaa"


def test_read_typed_memory_word_uses_address_size_stride(
    fake_program: Callable[..., SimpleNamespace],
) -> None:
    addrs: list[int] = []

    def read_word(addr: int, physical: bool) -> int:
        addrs.append(addr)
        return 0xAA

    mark_loaded(fake_program(read_word=read_word, address_size=lambda: 4))

    result = memory.read_typed_memory("0x10", value_type="word", count=2)

    assert addrs == [0x10, 0x14]
    assert result == "0x0000000000000010: 0xaa\n0x0000000000000014: 0xaa"


def test_read_typed_memory_caps_count_at_256(
    fake_program: Callable[..., SimpleNamespace],
) -> None:
    calls = 0

    def read_u8(addr: int, physical: bool) -> int:
        nonlocal calls
        calls += 1
        return 0

    mark_loaded(fake_program(read_u8=read_u8, address_size=lambda: 8))

    result = memory.read_typed_memory(0, value_type="u8", count=300)

    assert calls == 256
    lines = result.splitlines()
    assert len(lines) == 256
    assert lines[0] == "0x0000000000000000: 0x0"
    assert lines[-1] == "0x00000000000000ff: 0x0"


def test_read_typed_memory_reports_unknown_type() -> None:
    mark_loaded()

    assert memory.read_typed_memory(0, value_type="float") == (
        "Unknown type 'float'. Use: u8, u16, u32, u64, word, c_string."
    )


def test_read_typed_memory_reports_fault(
    fake_program: Callable[..., SimpleNamespace],
    drgn_error: Callable[..., BaseException],
) -> None:
    fault = drgn_error("fault", "typed read", address=0x20)

    def read_u32(addr: int, physical: bool) -> int:
        raise fault

    mark_loaded(fake_program(read_u32=read_u32, address_size=lambda: 8))

    assert memory.read_typed_memory(0x2000, value_type="u32") == (
        f"Memory fault at 0x2000: {fault}"
    )


# --- translate_address ---------------------------------------------------------


@pytest.mark.parametrize(
    "direction",
    ["virt_to_phys", "phys_to_virt", "virt_to_page", "pfn_to_page", "virt_to_pfn"],
)
def test_translate_address_prog_directions(
    monkeypatch: pytest.MonkeyPatch,
    direction: str,
) -> None:
    def helper(prog: object, addr: int) -> Stringable:
        assert addr == 0x1000
        return Stringable(f"{direction}:{addr:#x}")

    monkeypatch.setattr(memory, direction, helper)
    mark_loaded()

    assert memory.translate_address(0x1000, direction) == f"{direction}:0x1000"


@pytest.mark.parametrize("direction", ["page_to_virt", "page_to_pfn"])
def test_translate_address_page_object_directions(
    monkeypatch: pytest.MonkeyPatch,
    direction: str,
) -> None:
    def fake_object(prog: object, type_name: str, value: int = 0) -> SimpleNamespace:
        assert type_name == "struct page *"
        return SimpleNamespace(value=value)

    def helper(page: SimpleNamespace) -> Stringable:
        return Stringable(f"{direction}:{page.value:#x}")

    monkeypatch.setattr(memory.drgn, "Object", fake_object)
    monkeypatch.setattr(memory, direction, helper)
    mark_loaded()

    assert memory.translate_address("0x2000", direction) == f"{direction}:0x2000"


def test_translate_address_reports_unknown_direction() -> None:
    mark_loaded()

    assert memory.translate_address(0, "virt_to_bus") == (
        "Unknown direction 'virt_to_bus'. Use: virt_to_phys, "
        "phys_to_virt, virt_to_page, page_to_virt, page_to_pfn, "
        "pfn_to_page, virt_to_pfn."
    )


def test_translate_address_reports_fault(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    fault = drgn_error("fault", "not direct map", address=0x30)

    def virt_to_phys(prog: object, addr: int) -> int:
        raise fault

    monkeypatch.setattr(memory, "virt_to_phys", virt_to_phys)
    mark_loaded()

    assert memory.translate_address(0x1000) == f"Translation failed: {fault}"


# --- get_page_info ------------------------------------------------------------


def test_get_page_info_from_virtual_address(monkeypatch: pytest.MonkeyPatch) -> None:
    page = Stringable("page@ffff")
    monkeypatch.setattr(memory, "virt_to_page", lambda prog, addr: page)
    monkeypatch.setattr(memory, "decode_page_flags", lambda p: "locked|lru")
    monkeypatch.setattr(memory, "PageSlab", lambda p: False)
    monkeypatch.setattr(memory, "PageCompound", lambda p: False)
    mark_loaded()

    assert memory.get_page_info(0xFFFF888100000000) == (
        "Page: page@ffff\nFlags: locked|lru\nSlab: False\nCompound: False"
    )


def test_get_page_info_from_pfn_includes_compound_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    page = Stringable("page@pfn")
    monkeypatch.setattr(memory, "pfn_to_page", lambda prog, addr: page)
    monkeypatch.setattr(memory, "decode_page_flags", lambda p: "head")
    monkeypatch.setattr(memory, "PageSlab", lambda p: True)
    monkeypatch.setattr(memory, "PageCompound", lambda p: True)
    monkeypatch.setattr(memory, "compound_order", lambda p: FakeValue(3))
    mark_loaded()

    assert memory.get_page_info(256, source="pfn") == (
        "Page: page@pfn\nFlags: head\nSlab: True\nCompound: True\nCompound order: 3"
    )


def test_get_page_info_reports_unknown_source() -> None:
    mark_loaded()

    assert memory.get_page_info(0, source="phys") == "Unknown source 'phys'. Use: virt, pfn."


def test_get_page_info_reports_fault(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    fault = drgn_error("fault", "bad page", address=0x40)

    def virt_to_page(prog: object, addr: int) -> object:
        raise fault

    monkeypatch.setattr(memory, "virt_to_page", virt_to_page)
    mark_loaded()

    assert memory.get_page_info(0x1000) == f"Cannot access page at 0x1000: {fault}"


# --- get_slab_info --------------------------------------------------------------


def test_get_slab_info_named_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    cache = SimpleNamespace(name=FakeBytes(b"task_struct"), size=FakeValue(9088))
    usage = SimpleNamespace(num_slabs=2, num_objs=10, free_objs=3)
    monkeypatch.setattr(memory, "find_slab_cache", lambda prog, name: cache)
    monkeypatch.setattr(memory, "slab_cache_usage", lambda c: usage)
    mark_loaded()

    assert memory.get_slab_info("task_struct") == "\n".join(
        [
            "Cache: task_struct",
            "Object size: 9088",
            "Slabs: 2",
            "Objects: 10",
            "Free objects: 3",
        ]
    )


def test_get_slab_info_reports_missing_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(memory, "find_slab_cache", lambda prog, name: None)
    mark_loaded()

    assert memory.get_slab_info("nope") == "No slab cache found with name 'nope'"


def test_get_slab_info_lists_caches_and_usage_fault(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    fault = drgn_error("fault", "usage", address=0x50)
    total = SimpleNamespace(reclaimable_pages=10, unreclaimable_pages=20)
    good = SimpleNamespace(name=FakeBytes(b"kmalloc-64"))
    bad = SimpleNamespace(name=FakeBytes(b"dentry"))
    usage = SimpleNamespace(num_slabs=1, num_objs=4, free_objs=1)

    def slab_cache_usage(cache: SimpleNamespace) -> SimpleNamespace:
        if cache is bad:
            raise fault
        return usage

    monkeypatch.setattr(memory, "slab_total_usage", lambda prog: total)
    monkeypatch.setattr(memory, "for_each_slab_cache", lambda prog: [good, bad])
    monkeypatch.setattr(memory, "slab_cache_usage", slab_cache_usage)
    mark_loaded()

    assert memory.get_slab_info() == (
        "Total slab pages: reclaimable=10, unreclaimable=20\n"
        "\n"
        "kmalloc-64: 4 objs, 1 free, 1 slabs\n"
        "dentry: <error reading usage>"
    )


def test_get_slab_info_reports_total_fault(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    fault = drgn_error("fault", "totals", address=0x51)

    def slab_total_usage(prog: object) -> SimpleNamespace:
        raise fault

    monkeypatch.setattr(memory, "slab_total_usage", slab_total_usage)
    monkeypatch.setattr(memory, "for_each_slab_cache", lambda prog: [])
    mark_loaded()

    assert memory.get_slab_info() == f"Total slab pages: <error: {fault}>\n"


def test_get_slab_info_named_cache_propagates_usage_fault(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    fault = drgn_error("fault", "named usage", address=0x52)
    cache = SimpleNamespace(name=FakeBytes(b"task_struct"), size=FakeValue(9088))

    def slab_cache_usage(c: object) -> SimpleNamespace:
        raise fault

    monkeypatch.setattr(memory, "find_slab_cache", lambda prog, name: cache)
    monkeypatch.setattr(memory, "slab_cache_usage", slab_cache_usage)
    mark_loaded()

    with pytest.raises(type(fault)) as caught:
        memory.get_slab_info("task_struct")
    assert caught.value is fault


def test_get_slab_info_propagates_iterator_fault(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    fault = drgn_error("fault", "cache walk", address=0x53)
    good = SimpleNamespace(name=FakeBytes(b"kmalloc-64"))
    usage = SimpleNamespace(num_slabs=1, num_objs=4, free_objs=1)
    total = SimpleNamespace(reclaimable_pages=10, unreclaimable_pages=20)

    def caches(prog: object) -> Iterator[SimpleNamespace]:
        yield good
        raise fault

    monkeypatch.setattr(memory, "slab_total_usage", lambda prog: total)
    monkeypatch.setattr(memory, "for_each_slab_cache", caches)
    monkeypatch.setattr(memory, "slab_cache_usage", lambda c: usage)
    mark_loaded()

    with pytest.raises(type(fault)) as caught:
        memory.get_slab_info()
    assert caught.value is fault


def test_get_slab_info_propagates_invalid_cache_name(monkeypatch: pytest.MonkeyPatch) -> None:
    total = SimpleNamespace(reclaimable_pages=10, unreclaimable_pages=20)
    bad = SimpleNamespace(name=FakeBytes(b"kmalloc-64\xff"))
    usage = SimpleNamespace(num_slabs=1, num_objs=4, free_objs=1)

    monkeypatch.setattr(memory, "slab_total_usage", lambda prog: total)
    monkeypatch.setattr(memory, "for_each_slab_cache", lambda prog: [bad])
    monkeypatch.setattr(memory, "slab_cache_usage", lambda c: usage)
    mark_loaded()

    with pytest.raises(UnicodeDecodeError):
        memory.get_slab_info()


def test_get_slab_info_named_cache_propagates_invalid_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cache = SimpleNamespace(name=FakeBytes(b"task_struct\xff"), size=FakeValue(9088))
    usage = SimpleNamespace(num_slabs=2, num_objs=10, free_objs=3)
    monkeypatch.setattr(memory, "find_slab_cache", lambda prog, name: cache)
    monkeypatch.setattr(memory, "slab_cache_usage", lambda c: usage)
    mark_loaded()

    with pytest.raises(UnicodeDecodeError):
        memory.get_slab_info("task_struct")


# --- get_vma_info -------------------------------------------------------------


def test_get_vma_info_reports_missing_task(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(memory, "_find_task", lambda prog, pid: None)
    mark_loaded()

    assert memory.get_vma_info(99) == "No task found with PID 99"


def test_get_vma_info_reports_kernel_thread(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(memory, "_find_task", lambda prog, pid: _kthread())
    mark_loaded()

    assert memory.get_vma_info(2) == "Task 2 has no mm_struct (kernel thread?)"


def test_get_vma_info_lookup_formats_containing_vma(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vma = _vma(start=0x1000, end=0x2000, flags=0x75)
    monkeypatch.setattr(memory, "_find_task", lambda prog, pid: _user_task())
    monkeypatch.setattr(memory, "vma_find", lambda mm, addr: vma)
    monkeypatch.setattr(memory, "vma_name", lambda v: b"[heap]\xff")
    mark_loaded()

    assert memory.get_vma_info(1, address="0x1800") == (
        "VMA: 0x1000-0x2000\nName: [heap]\ufffd\nFlags: 0x75"
    )


def test_get_vma_info_lookup_reports_miss(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(memory, "_find_task", lambda prog, pid: _user_task())
    monkeypatch.setattr(memory, "vma_find", lambda mm, addr: None)
    mark_loaded()

    assert memory.get_vma_info(1, address=0xABCD) == ("No VMA contains address 0xabcd in task 1")


def test_get_vma_info_lookup_reports_fault(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    fault = drgn_error("fault", "vma walk", address=0x60)

    def vma_find(mm: object, addr: int) -> object:
        raise fault

    monkeypatch.setattr(memory, "_find_task", lambda prog, pid: _user_task())
    monkeypatch.setattr(memory, "vma_find", vma_find)
    mark_loaded()

    assert memory.get_vma_info(1, address=0x1000) == (
        f"Memory fault looking up VMA at 0x1000: {fault}"
    )


def test_get_vma_info_formats_item_fault(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    fault = drgn_error("fault", "bad vma", address=0x61)
    good = _vma(start=0x1000, end=0x2000)

    bad = SimpleNamespace(vm_start=FaultyValue(fault))

    monkeypatch.setattr(memory, "_find_task", lambda prog, pid: _user_task())
    monkeypatch.setattr(memory, "for_each_vma", lambda mm: [good, bad])
    monkeypatch.setattr(memory, "vma_name", lambda v: b"[stack]")
    mark_loaded()

    assert memory.get_vma_info(1) == f"0x1000-0x2000 [stack]\n<fault: {fault}>"


def test_get_vma_info_appends_limit_notice(monkeypatch: pytest.MonkeyPatch) -> None:
    vmas = [_vma(start=0x1000 * i, end=0x1000 * (i + 1)) for i in range(1, 4)]
    monkeypatch.setattr(memory, "_find_task", lambda prog, pid: _user_task())
    monkeypatch.setattr(memory, "for_each_vma", lambda mm: vmas)
    monkeypatch.setattr(memory, "vma_name", lambda v: b"[stack]")
    mark_loaded()

    assert memory.get_vma_info(1, limit=2) == (
        "0x1000-0x2000 [stack]\n0x2000-0x3000 [stack]\n... (limited to 2 VMAs)"
    )


def test_get_vma_info_aborts_on_iterator_fault(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    fault = drgn_error("fault", "mm walk", address=0x62)
    good = _vma(start=0x1000, end=0x2000)

    def vmas(mm: object) -> Iterator[SimpleNamespace]:
        yield good
        raise fault

    monkeypatch.setattr(memory, "_find_task", lambda prog, pid: _user_task())
    monkeypatch.setattr(memory, "for_each_vma", vmas)
    monkeypatch.setattr(memory, "vma_name", lambda v: b"anon")
    mark_loaded()

    assert memory.get_vma_info(1) == (
        f"0x1000-0x2000 anon\n... Traversal aborted due to memory fault: {fault}"
    )


def test_get_vma_info_reports_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(memory, "_find_task", lambda prog, pid: _user_task())
    monkeypatch.setattr(memory, "for_each_vma", lambda mm: [])
    mark_loaded()

    assert memory.get_vma_info(1) == "No VMAs found"


# --- get_memory_summary ----------------------------------------------------------


def test_get_memory_summary_converts_pages_to_mb(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(memory, "totalram_pages", lambda prog: 1024)
    monkeypatch.setattr(memory, "vm_memory_committed", lambda prog: 512)
    monkeypatch.setattr(memory, "vm_commit_limit", lambda prog: 2048)
    mark_loaded(_PageSizeProgram(4096))

    assert memory.get_memory_summary() == (
        "Total RAM: 1024 pages (4 MB)\n"
        "Committed: 512 pages (2 MB)\n"
        "Commit limit: 2048 pages (8 MB)"
    )


def test_get_memory_summary_reports_fault(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    fault = drgn_error("fault", "meminfo", address=0x70)

    def totalram_pages(prog: object) -> int:
        raise fault

    monkeypatch.setattr(memory, "totalram_pages", totalram_pages)
    mark_loaded()

    assert memory.get_memory_summary() == f"Memory fault reading memory stats: {fault}"


# --- get_task_memory -----------------------------------------------------------


def test_get_task_memory_formats_rss_pages_and_vsize_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rss = SimpleNamespace(total=1024, file=512, anon=256, shmem=128, swap=64)
    monkeypatch.setattr(memory, "_find_task", lambda prog, pid: _user_task())
    monkeypatch.setattr(memory, "task_rss", lambda prog, task: rss)
    monkeypatch.setattr(memory, "task_vsize", lambda task: 8 * 1024 * 1024)
    mark_loaded(_PageSizeProgram(4096))

    assert memory.get_task_memory(1) == (
        "PID 1 memory:\n"
        "RSS: 1024 pages (4 MB) [file=512, anon=256, shmem=128, swap=64]\n"
        "Virtual size: 8388608 bytes (8 MB)"
    )


def test_get_task_memory_reports_missing_task(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(memory, "_find_task", lambda prog, pid: None)
    mark_loaded()

    assert memory.get_task_memory(99) == "No task found with PID 99"


def test_get_task_memory_reports_kernel_thread(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(memory, "_find_task", lambda prog, pid: _kthread())
    mark_loaded()

    assert memory.get_task_memory(2) == "Task 2 is a kernel thread (no mm_struct)"


def test_get_task_memory_reports_fault(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    fault = drgn_error("fault", "rss", address=0x80)

    def task_rss(prog: object, task: object) -> object:
        raise fault

    monkeypatch.setattr(memory, "_find_task", lambda prog, pid: _user_task())
    monkeypatch.setattr(memory, "task_rss", task_rss)
    mark_loaded(_PageSizeProgram(4096))

    assert memory.get_task_memory(1) == f"Memory fault reading memory stats for PID 1: {fault}"


# --- read_process_memory ----------------------------------------------------------


def test_read_process_memory_formats_hexdump(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = bytes(range(16))

    def access_process_vm(task: object, addr: int, size: int) -> bytes:
        assert addr == 0x400000
        assert size == 16
        return payload

    monkeypatch.setattr(memory, "_find_task", lambda prog, pid: _user_task())
    monkeypatch.setattr(memory, "access_process_vm", access_process_vm)
    mark_loaded()

    assert memory.read_process_memory(1, 0x400000, size=16) == (
        "0x0000000000400000  "
        "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f   "
        "................"
    )


def test_read_process_memory_caps_size(monkeypatch: pytest.MonkeyPatch) -> None:
    sizes: list[int] = []

    def access_process_vm(task: object, addr: int, size: int) -> bytes:
        sizes.append(size)
        return b"\x00" * 16

    monkeypatch.setattr(memory, "_find_task", lambda prog, pid: _user_task())
    monkeypatch.setattr(memory, "access_process_vm", access_process_vm)
    mark_loaded()

    result = memory.read_process_memory(1, "0x400000", size=8000)

    assert sizes == [4096]
    assert result == (
        "0x0000000000400000  "
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   "
        "................"
    )


def test_read_process_memory_reports_missing_task(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(memory, "_find_task", lambda prog, pid: None)
    mark_loaded()

    assert memory.read_process_memory(9, 0x1000) == "No task found with PID 9"


def test_read_process_memory_reports_kernel_thread(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(memory, "_find_task", lambda prog, pid: _kthread())
    mark_loaded()

    assert memory.read_process_memory(2, 0x1000) == "Task 2 is a kernel thread (no address space)"


def test_read_process_memory_reports_fault(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    fault = drgn_error("fault", "no page", address=0x90)

    def access_process_vm(task: object, addr: int, size: int) -> bytes:
        raise fault

    monkeypatch.setattr(memory, "_find_task", lambda prog, pid: _user_task())
    monkeypatch.setattr(memory, "access_process_vm", access_process_vm)
    mark_loaded()

    assert memory.read_process_memory(1, 0x7F000) == (f"Memory fault at 0x7f000 in task 1: {fault}")
