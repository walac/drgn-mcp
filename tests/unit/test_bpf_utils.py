"""Characterize BPF and debugger-utility tools."""

from collections.abc import Callable, Iterator
from types import SimpleNamespace

import pytest

from drgn_mcp.tools import bpf, utils
from tests.conftest import FakeBytes, FakeValue, FaultyValue, Stringable, mark_loaded


def _bpf_prog(prog_id: int, prog_type: int, name: bytes = b"handler") -> SimpleNamespace:
    return SimpleNamespace(
        aux=SimpleNamespace(id=FakeValue(prog_id), name=FakeBytes(name)),
        type=FakeValue(prog_type),
    )


def _bpf_map(
    map_id: int,
    map_type: int,
    name: bytes = b"events",
    key_size: int = 4,
    value_size: int = 8,
    max_entries: int = 1024,
) -> SimpleNamespace:
    return SimpleNamespace(
        id=FakeValue(map_id),
        map_type=FakeValue(map_type),
        name=FakeBytes(name),
        key_size=FakeValue(key_size),
        value_size=FakeValue(value_size),
        max_entries=FakeValue(max_entries),
    )


def _faulty_bpf_map(error: BaseException) -> SimpleNamespace:
    return SimpleNamespace(id=FaultyValue(error), map_type=FakeValue(1), name=FakeBytes(b"events"))


def _faulty_bpf_link(error: BaseException) -> SimpleNamespace:
    return SimpleNamespace(id=FaultyValue(error), type=FakeValue(1))


def _faulty_btf(error: BaseException) -> SimpleNamespace:
    return SimpleNamespace(id=FaultyValue(error), name=FakeBytes(b"vmlinux"))


# --- list_bpf -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("bpf_type", "helper", "items", "expected"),
    [
        ("progs", "bpf_prog_for_each", [_bpf_prog(7, 3)], "prog id=7 type=3"),
        ("maps", "bpf_map_for_each", [_bpf_map(8, 1, b"map\xff")], "map id=8 type=1 name=map�"),
        (
            "links",
            "bpf_link_for_each",
            [SimpleNamespace(id=FakeValue(9), type=FakeValue(2))],
            "link id=9 type=2",
        ),
        (
            "btf",
            "bpf_btf_for_each",
            [SimpleNamespace(id=FakeValue(10), name=None)],
            "btf id=10 name=",
        ),
    ],
)
def test_list_bpf_selects_and_formats_requested_type(
    monkeypatch: pytest.MonkeyPatch,
    bpf_type: str,
    helper: str,
    items: list[SimpleNamespace],
    expected: str,
) -> None:
    monkeypatch.setattr(bpf, helper, lambda prog: items)
    mark_loaded()

    assert bpf.list_bpf(bpf_type) == expected


def test_list_bpf_paginates_programs(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        bpf,
        "bpf_prog_for_each",
        lambda prog: [_bpf_prog(1, 1), _bpf_prog(2, 2), _bpf_prog(3, 3)],
    )
    mark_loaded()

    assert bpf.list_bpf("progs", offset=1, limit=1) == "\n".join(
        [
            "prog id=2 type=2",
            "... (limited to 1 progs, use offset=2 for next page)",
        ]
    )


def test_list_bpf_reports_unknown_and_empty_types(monkeypatch: pytest.MonkeyPatch) -> None:
    mark_loaded()
    assert bpf.list_bpf("unknown") == "Unknown BPF type 'unknown'. Use: progs, maps, links, btf."

    monkeypatch.setattr(bpf, "bpf_map_for_each", lambda prog: [])
    assert bpf.list_bpf("maps") == "No BPF maps found"


def test_list_bpf_formats_item_and_traversal_faults(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    item_fault = drgn_error("fault", "bad program", address=0x10)
    walk_fault = drgn_error("fault", "program walk", address=0x11)

    def programs(prog: object) -> Iterator[SimpleNamespace]:
        yield SimpleNamespace(aux=SimpleNamespace(id=FaultyValue(item_fault)), type=FakeValue(1))
        raise walk_fault

    monkeypatch.setattr(bpf, "bpf_prog_for_each", programs)
    mark_loaded()

    assert bpf.list_bpf() == "\n".join(
        [f"prog <fault: {item_fault}>", f"... Traversal aborted due to memory fault: {walk_fault}"]
    )


@pytest.mark.parametrize(
    ("bpf_type", "helper", "items", "expected"),
    [
        (
            "maps",
            "bpf_map_for_each",
            [_bpf_map(1, 1), _bpf_map(2, 2), _bpf_map(3, 3)],
            "map id=2 type=2 name=events\n... (limited to 1 maps, use offset=2 for next page)",
        ),
        (
            "links",
            "bpf_link_for_each",
            [
                SimpleNamespace(id=FakeValue(1), type=FakeValue(1)),
                SimpleNamespace(id=FakeValue(2), type=FakeValue(2)),
                SimpleNamespace(id=FakeValue(3), type=FakeValue(3)),
            ],
            "link id=2 type=2\n... (limited to 1 links, use offset=2 for next page)",
        ),
        (
            "btf",
            "bpf_btf_for_each",
            [
                SimpleNamespace(id=FakeValue(1), name=FakeBytes(b"one")),
                SimpleNamespace(id=FakeValue(2), name=FakeBytes(b"two")),
                SimpleNamespace(id=FakeValue(3), name=FakeBytes(b"three")),
            ],
            "btf id=2 name=two\n... (limited to 1 btf, use offset=2 for next page)",
        ),
    ],
)
def test_list_bpf_subtypes_paginate(
    monkeypatch: pytest.MonkeyPatch,
    bpf_type: str,
    helper: str,
    items: list[SimpleNamespace],
    expected: str,
) -> None:
    monkeypatch.setattr(bpf, helper, lambda prog: items)
    mark_loaded()

    assert bpf.list_bpf(bpf_type, offset=1, limit=1) == expected


@pytest.mark.parametrize(
    ("bpf_type", "helper", "faulty_item", "label"),
    [
        ("maps", "bpf_map_for_each", _faulty_bpf_map, "map"),
        ("links", "bpf_link_for_each", _faulty_bpf_link, "link"),
        ("btf", "bpf_btf_for_each", _faulty_btf, "btf"),
    ],
)
def test_list_bpf_subtypes_format_item_and_traversal_faults(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
    bpf_type: str,
    helper: str,
    faulty_item: Callable[[BaseException], SimpleNamespace],
    label: str,
) -> None:
    item_fault = drgn_error("fault", "bad item", address=0x20)
    walk_fault = drgn_error("fault", "walk failed", address=0x21)

    def items(prog: object) -> Iterator[SimpleNamespace]:
        yield faulty_item(item_fault)
        raise walk_fault

    monkeypatch.setattr(bpf, helper, items)
    mark_loaded()

    assert bpf.list_bpf(bpf_type) == "\n".join(
        [
            f"{label} <fault: {item_fault}>",
            f"... Traversal aborted due to memory fault: {walk_fault}",
        ]
    )


# --- get_bpf_prog / get_bpf_map ------------------------------------------------


def test_get_bpf_prog_formats_details_and_replaces_invalid_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    program = object()

    def lookup(loaded_program: object, prog_id: int) -> SimpleNamespace:
        assert loaded_program is program
        assert prog_id == 42
        return _bpf_prog(prog_id, 5, b"xdp\xff")

    monkeypatch.setattr(bpf, "bpf_prog_by_id", lookup)
    mark_loaded(program)

    assert bpf.get_bpf_prog(42) == "BPF program ID=42\nType: 5\nName: xdp�"


def test_get_bpf_prog_reports_missing_lookup_and_read_faults(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    mark_loaded()
    monkeypatch.setattr(bpf, "bpf_prog_by_id", lambda prog, prog_id: None)
    assert bpf.get_bpf_prog(42) == "No BPF program found with ID 42"

    lookup_fault = drgn_error("fault", "id tree", address=0x12)
    monkeypatch.setattr(
        bpf, "bpf_prog_by_id", lambda prog, prog_id: (_ for _ in ()).throw(lookup_fault)
    )
    assert bpf.get_bpf_prog(42) == f"Error looking up BPF program 42: {lookup_fault}"

    read_fault = drgn_error("fault", "aux unavailable", address=0x13)
    broken = SimpleNamespace(
        type=FaultyValue(read_fault), aux=SimpleNamespace(name=FakeBytes(b"xdp"))
    )
    monkeypatch.setattr(bpf, "bpf_prog_by_id", lambda prog, prog_id: broken)
    assert bpf.get_bpf_prog(42) == f"Memory fault reading BPF program 42: {read_fault}"


def test_get_bpf_map_formats_all_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    program = object()

    def lookup(loaded_program: object, map_id: int) -> SimpleNamespace:
        assert loaded_program is program
        assert map_id == 12
        return _bpf_map(map_id, 2, b"stats\xff", 8, 16, 64)

    monkeypatch.setattr(bpf, "bpf_map_by_id", lookup)
    mark_loaded(program)

    assert bpf.get_bpf_map(12) == "\n".join(
        [
            "BPF map ID=12",
            "Type: 2",
            "Name: stats�",
            "Key size: 8",
            "Value size: 16",
            "Max entries: 64",
        ]
    )


def test_get_bpf_map_reports_missing_lookup_and_read_faults(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    mark_loaded()
    monkeypatch.setattr(bpf, "bpf_map_by_id", lambda prog, map_id: None)
    assert bpf.get_bpf_map(12) == "No BPF map found with ID 12"

    assert_error = LookupError("not in idr")
    monkeypatch.setattr(
        bpf, "bpf_map_by_id", lambda prog, map_id: (_ for _ in ()).throw(assert_error)
    )
    assert bpf.get_bpf_map(12) == "Error looking up BPF map 12: not in idr"

    read_fault = drgn_error("fault", "map name", address=0x14)
    broken = _bpf_map(12, 2)
    broken.name = SimpleNamespace(string_=lambda: (_ for _ in ()).throw(read_fault))
    monkeypatch.setattr(bpf, "bpf_map_by_id", lambda prog, map_id: broken)
    assert bpf.get_bpf_map(12) == f"Memory fault reading BPF map 12: {read_fault}"


# --- get_bpf_prog_maps ---------------------------------------------------------


def test_get_bpf_prog_maps_formats_and_limits_maps(monkeypatch: pytest.MonkeyPatch) -> None:
    loaded_program = object()
    bpf_program = _bpf_prog(42, 5)

    def lookup(program: object, prog_id: int) -> SimpleNamespace:
        assert program is loaded_program
        assert prog_id == 42
        return bpf_program

    def used_maps(program: object) -> list[SimpleNamespace]:
        assert program is bpf_program
        return [_bpf_map(1, 1), _bpf_map(2, 2)]

    monkeypatch.setattr(bpf, "bpf_prog_by_id", lookup)
    monkeypatch.setattr(bpf, "bpf_prog_used_maps", used_maps)
    mark_loaded(loaded_program)

    assert bpf.get_bpf_prog_maps(42, limit=1) == "\n".join(
        ["map id=1 type=1 name=events", "... (limited to 1 maps)"]
    )


def test_get_bpf_prog_maps_reports_missing_lookup_and_walk_faults(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    mark_loaded()
    monkeypatch.setattr(bpf, "bpf_prog_by_id", lambda prog, prog_id: None)
    assert bpf.get_bpf_prog_maps(42) == "No BPF program found with ID 42"

    lookup_error = LookupError("gone")
    monkeypatch.setattr(
        bpf, "bpf_prog_by_id", lambda prog, prog_id: (_ for _ in ()).throw(lookup_error)
    )
    assert bpf.get_bpf_prog_maps(42) == "Error looking up BPF program 42: gone"

    walk_fault = drgn_error("fault", "used map", address=0x15)
    monkeypatch.setattr(bpf, "bpf_prog_by_id", lambda prog, prog_id: _bpf_prog(42, 5))
    monkeypatch.setattr(
        bpf, "bpf_prog_used_maps", lambda bpf_prog: (_ for _ in ()).throw(walk_fault)
    )
    assert bpf.get_bpf_prog_maps(42) == f"... Traversal aborted due to memory fault: {walk_fault}"


# --- get_cgroup_bpf ------------------------------------------------------------


def test_get_cgroup_bpf_selects_attached_or_effective_programs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    program = object()
    cgroup = object()
    seen_paths: list[str] = []

    def lookup(loaded_program: object, path: str) -> object:
        assert loaded_program is program
        seen_paths.append(path)
        return cgroup

    def attached(found_cgroup: object, attach_type: int) -> list[SimpleNamespace]:
        assert found_cgroup is cgroup
        assert attach_type == 7
        return [_bpf_prog(1, 2)]

    def effective(found_cgroup: object, attach_type: int) -> list[SimpleNamespace]:
        assert found_cgroup is cgroup
        assert attach_type == 7
        return [_bpf_prog(3, 4)]

    monkeypatch.setattr(bpf, "cgroup_get_from_path", lookup)
    monkeypatch.setattr(bpf, "cgroup_bpf_prog_for_each", attached)
    monkeypatch.setattr(bpf, "cgroup_bpf_prog_for_each_effective", effective)
    mark_loaded(program)

    assert bpf.get_cgroup_bpf("/slice", attach_type=7) == "prog id=1 type=2"
    assert bpf.get_cgroup_bpf("/slice", attach_type=7, effective=True) == "prog id=3 type=4"
    assert seen_paths == ["/slice", "/slice"]


def test_get_cgroup_bpf_limits_and_formats_faults(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    cgroup = object()
    item_fault = drgn_error("fault", "bad attachment", address=0x16)

    def attached(cgrp: object, attach_type: int) -> Iterator[SimpleNamespace]:
        yield _bpf_prog(1, 2)
        yield SimpleNamespace(aux=SimpleNamespace(id=FaultyValue(item_fault)), type=FakeValue(3))
        yield _bpf_prog(4, 5)
        yield _bpf_prog(6, 7)

    monkeypatch.setattr(bpf, "cgroup_get_from_path", lambda prog, path: cgroup)
    monkeypatch.setattr(bpf, "cgroup_bpf_prog_for_each", attached)
    mark_loaded()

    assert bpf.get_cgroup_bpf(limit=3) == "\n".join(
        [
            "prog id=1 type=2",
            f"prog <fault: {item_fault}>",
            "prog id=4 type=5",
            "... (limited to 3 programs)",
        ]
    )


def test_get_cgroup_bpf_reports_missing_lookup_and_traversal_faults(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    mark_loaded()
    monkeypatch.setattr(bpf, "cgroup_get_from_path", lambda prog, path: None)
    assert bpf.get_cgroup_bpf("/missing") == "No cgroup found at path '/missing'"

    lookup_fault = drgn_error("fault", "cgroup root", address=0x18)
    monkeypatch.setattr(
        bpf, "cgroup_get_from_path", lambda prog, path: (_ for _ in ()).throw(lookup_fault)
    )
    assert bpf.get_cgroup_bpf("/gone") == f"Error looking up cgroup '/gone': {lookup_fault}"

    walk_fault = drgn_error("fault", "attachments", address=0x19)
    monkeypatch.setattr(bpf, "cgroup_get_from_path", lambda prog, path: object())

    def attached(cgrp: object, attach_type: int) -> Iterator[SimpleNamespace]:
        # Yielding makes this a generator so the fault occurs on first next().
        yield from ()
        raise walk_fault

    monkeypatch.setattr(bpf, "cgroup_bpf_prog_for_each", attached)
    assert bpf.get_cgroup_bpf() == f"... Traversal aborted due to memory fault: {walk_fault}"


# --- identify_address ----------------------------------------------------------


def test_identify_address_parses_hex_and_returns_helper_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[int] = []

    def identify(prog: object, address: int) -> str:
        seen.append(address)
        return "function symbol: schedule+0x15"

    monkeypatch.setattr(utils, "_identify_address", identify)
    mark_loaded()

    assert utils.identify_address("0xfeed") == "function symbol: schedule+0x15"
    assert seen == [0xFEED]


def test_identify_address_reports_invalid_fault_and_unrecognized(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    mark_loaded()
    with pytest.raises(ValueError, match="invalid literal"):
        utils.identify_address("not-an-address")

    fault = drgn_error("fault", "unmapped", address=0xFEED)
    monkeypatch.setattr(
        utils, "_identify_address", lambda prog, address: (_ for _ in ()).throw(fault)
    )
    assert (
        utils.identify_address(0xFEED) == f"Cannot identify address 0xfeed: memory fault: {fault}"
    )

    monkeypatch.setattr(utils, "_identify_address", lambda prog, address: None)
    assert utils.identify_address(0xFEED) == "Unrecognized address: 0xfeed"


# --- annotated_stack -----------------------------------------------------------


def test_annotated_stack_captures_printer_output(
    monkeypatch: pytest.MonkeyPatch,
    fake_program: Callable[..., SimpleNamespace],
) -> None:
    trace = object()

    def stack_trace(thread_id: int) -> object:
        assert thread_id == 42
        return trace

    monkeypatch.setattr(
        utils, "print_annotated_stack", lambda stack: print("0xffff: schedule+0x15")
    )
    mark_loaded(fake_program(stack_trace=stack_trace))

    assert utils.annotated_stack(42) == "0xffff: schedule+0x15\n"


def test_annotated_stack_reports_empty_trace_and_annotation_fault(
    monkeypatch: pytest.MonkeyPatch,
    fake_program: Callable[..., SimpleNamespace],
    drgn_error: Callable[..., BaseException],
) -> None:
    trace = object()
    monkeypatch.setattr(utils, "print_annotated_stack", lambda stack: None)
    mark_loaded(fake_program(stack_trace=lambda thread_id: trace))
    assert utils.annotated_stack(42) == "Empty stack"

    fault = drgn_error("fault", "stack unreadable", address=0x20)

    def print_then_fault(stack: object) -> None:
        print("0xffff: task_struct")
        raise fault

    monkeypatch.setattr(utils, "print_annotated_stack", print_then_fault)
    assert (
        utils.annotated_stack(42)
        == f"0xffff: task_struct\n\n... Annotation aborted due to memory fault: {fault}"
    )


def test_annotated_stack_reports_missing_thread(
    fake_program: Callable[..., SimpleNamespace],
) -> None:
    def stack_trace(thread_id: int) -> object:
        raise LookupError("no such thread")

    mark_loaded(fake_program(stack_trace=stack_trace))

    assert utils.annotated_stack(42) == "Cannot get stack trace for thread 42: no such thread"


# --- read_percpu ---------------------------------------------------------------


def test_read_percpu_reads_selected_cpu(monkeypatch: pytest.MonkeyPatch) -> None:
    value = object()
    seen: list[tuple[object, int]] = []

    def eval_expr(expr: str) -> object:
        assert expr == "prog['runqueues']"
        return value

    def per_cpu(var: object, cpu: int) -> Stringable:
        seen.append((var, cpu))
        return Stringable("(struct rq *)0xffff")

    monkeypatch.setattr(utils, "_eval_expr", eval_expr)
    monkeypatch.setattr(utils, "per_cpu", per_cpu)
    mark_loaded()

    assert utils.read_percpu("prog['runqueues']", cpu=3) == "(struct rq *)0xffff"
    assert seen == [(value, 3)]


def test_read_percpu_reports_expression_and_selected_cpu_faults(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    mark_loaded()
    monkeypatch.setattr(
        utils, "_eval_expr", lambda expr: (_ for _ in ()).throw(ValueError("bad expr"))
    )
    assert utils.read_percpu("bad") == "Error evaluating expression: bad expr"

    fault = drgn_error("fault", "cpu offline", address=0x21)
    monkeypatch.setattr(utils, "_eval_expr", lambda expr: object())
    monkeypatch.setattr(utils, "per_cpu", lambda var, cpu: (_ for _ in ()).throw(fault))
    assert utils.read_percpu("prog['x']", cpu=1) == f"Memory fault reading CPU 1: {fault}"


def test_read_percpu_formats_all_cpus_and_continues_after_fault(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    value = object()
    fault = drgn_error("fault", "percpu base", address=0x22)
    monkeypatch.setattr(utils, "_eval_expr", lambda expr: value)
    monkeypatch.setattr(utils, "for_each_online_cpu", lambda prog: [0, 2])
    monkeypatch.setattr(
        utils,
        "per_cpu",
        lambda var, cpu: (_ for _ in ()).throw(fault) if cpu == 0 else Stringable("worker"),
    )
    mark_loaded()

    assert utils.read_percpu("prog['current_task']") == f"cpu 0: <fault: {fault}>\ncpu 2: worker"


def test_read_percpu_reports_no_online_cpus(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(utils, "_eval_expr", lambda expr: object())
    monkeypatch.setattr(utils, "for_each_online_cpu", lambda prog: [])
    mark_loaded()

    assert utils.read_percpu("prog['runqueues']") == "No online CPUs found"
