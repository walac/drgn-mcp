"""Characterize linked-list, rbtree, xarray, and IDR traversal tools."""

from collections.abc import Callable, Iterator
from types import SimpleNamespace

import pytest

from drgn_mcp.state import state
from drgn_mcp.tools import traversal
from tests.conftest import FakeValue, Stringable, mark_loaded

INVALID_FORMAT_EXPR = "entry."
NEXT_PAGE = "... (limited to 2 entries, use offset=3 for next page)"


def _invalid_format_output() -> str:
    """Expected tool text for INVALID_FORMAT_EXPR, using this interpreter's SyntaxError."""
    try:
        compile(INVALID_FORMAT_EXPR, "<format_expr>", "eval")
    except SyntaxError as e:
        return f"Syntax error in format_expr: {e}"
    raise AssertionError(f"{INVALID_FORMAT_EXPR!r} compiled as eval")


class _FaultyValue:
    """Stand-in whose value_() raises, matching default_fmt's only access."""

    def __init__(self, error: BaseException) -> None:
        self._error = error

    def value_(self) -> int:
        raise self._error


def _head(type_name: str) -> SimpleNamespace:
    """Minimal list head: only ``type_.type_name()``, which is all dispatch reads.

    ``traverse_list`` chooses ``hlist_for_each_entry`` vs ``list_for_each_entry`` by
    substring on that name. ``"list_head"`` is contained in ``"hlist_head"``, so
    the hlist check must run first; tests pass distinct names to pin that order.
    """
    return SimpleNamespace(type_=SimpleNamespace(type_name=lambda: type_name))


def _stub_eval(monkeypatch: pytest.MonkeyPatch, obj: object) -> list[str]:
    """Replace ``traversal._eval_expr`` with a recorder that returns ``obj``.

    The tools evaluate the caller's expression via the name imported onto the
    traversal module, then walk that object. Patching that name (not
    ``_traverse``) is the real seam. The returned list is the expression
    argument: a stub that ignores it would still pass if production started
    evaluating a constant and discarding ``head_expr`` / ``root_expr`` / etc.
    ``mark_loaded()`` is required because every tool calls ``require_loaded()``.
    """
    seen: list[str] = []

    def eval_expr(expr: str) -> object:
        seen.append(expr)
        return obj

    monkeypatch.setattr(traversal, "_eval_expr", eval_expr)
    mark_loaded()
    return seen


def _stub_helper(
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    items: object | BaseException,
) -> None:
    """Replace a traversal-module walk helper with a canned iterable or error.

    Wrappers close over ``list_for_each_entry``, ``xa_for_each``, and the other
    imported names and pass them into ``_traverse``. Patching those names on
    ``traversal`` is what the tools actually call. ``items`` is either the
    walk result or a ``BaseException`` to raise on call, so empty / populated /
    helper-fault cases share one stub. Argument forwarding is left to
    happy-path tests that install their own helper and record ``seen``.
    """

    def helper(*_args: object, **_kwargs: object) -> object:
        if isinstance(items, BaseException):
            raise items
        return items

    monkeypatch.setattr(traversal, name, helper)


def _abort(fault: BaseException) -> str:
    """Walk-abort line ``_traverse`` appends after a per-entry ``FaultError``.

    Shared so list / rbtree / xarray / IDR abort tests cannot drift from each
    other. ``FaultError``'s ``str()`` includes the address, so tests interpolate
    the same exception object the stub raised rather than hard-coding text.
    """
    return f"... Traversal aborted due to memory fault: {fault}"


def _eval_error(
    monkeypatch: pytest.MonkeyPatch,
    error: BaseException,
) -> list[str]:
    """Like ``_stub_eval``, but ``_eval_expr`` raises ``error``.

    ``_traverse`` catches ``EVAL_ERRORS`` around the head/root/xa/idr expression
    and returns ``Error evaluating {label} expression: {e}``. That path never
    runs if the stub returns an object. Records the expression for the same
    reason ``_stub_eval`` does: the label in the message does not prove which
    string was evaluated.
    """
    seen: list[str] = []

    def boom(expr: str) -> object:
        seen.append(expr)
        raise error

    monkeypatch.setattr(traversal, "_eval_expr", boom)
    mark_loaded()
    return seen


# --- traverse_list ------------------------------------------------------------


def test_traverse_list_defaults_to_hex_addresses(monkeypatch: pytest.MonkeyPatch) -> None:
    head = _head("struct list_head")
    seen: list[tuple[object, object, object]] = []

    def list_for_each_entry(
        entry_type: object, head_obj: object, member: object
    ) -> list[FakeValue]:
        seen.append((entry_type, head_obj, member))
        return [FakeValue(0x1000), FakeValue(0x2000)]

    monkeypatch.setattr(traversal, "list_for_each_entry", list_for_each_entry)
    seen_expr = _stub_eval(monkeypatch, head)

    assert traversal.traverse_list("prog['tasks']", "struct task_struct", "sibling") == (
        "0x1000\n0x2000"
    )
    assert seen == [("struct task_struct", head, "sibling")]
    assert seen_expr == ["prog['tasks']"]


def test_traverse_list_uses_hlist_helper(monkeypatch: pytest.MonkeyPatch) -> None:
    head = _head("struct hlist_head")
    seen: list[tuple[object, object, object]] = []

    def hlist_for_each_entry(
        entry_type: object, head_obj: object, member: object
    ) -> list[FakeValue]:
        seen.append((entry_type, head_obj, member))
        return [FakeValue(0x3000)]

    monkeypatch.setattr(traversal, "hlist_for_each_entry", hlist_for_each_entry)
    seen_expr = _stub_eval(monkeypatch, head)

    assert traversal.traverse_list("prog['heads']", "struct hlist_node", "node") == "0x3000"
    assert seen == [("struct hlist_node", head, "node")]
    assert seen_expr == ["prog['heads']"]


def test_traverse_list_rejects_non_list_head(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_eval(monkeypatch, _head("struct rb_root"))

    assert traversal.traverse_list("root", "struct vm_area_struct", "vm_rb") == (
        "Expected struct list_head or hlist_head, got struct rb_root"
    )


def test_traverse_list_reports_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_helper(monkeypatch, "list_for_each_entry", [])
    _stub_eval(monkeypatch, _head("struct list_head"))

    assert traversal.traverse_list("head", "struct task_struct", "sibling") == "Empty list"


def test_traverse_list_formats_with_mocked_globals(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_helper(monkeypatch, "list_for_each_entry", [FakeValue(0xABC)])
    _stub_eval(monkeypatch, _head("struct list_head"))
    state._globals = {"label": Stringable("task")}

    assert (
        traversal.traverse_list("head", "struct task_struct", "sibling", format_expr="label")
        == "task"
    )
    assert (
        traversal.traverse_list(
            "head",
            "struct task_struct",
            "sibling",
            format_expr="f'{entry.value_():#x}'",
        )
        == "0xabc"
    )


def test_traverse_list_reports_invalid_format_expr(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_eval(monkeypatch, _head("struct list_head"))

    assert (
        traversal.traverse_list(
            "head",
            "struct task_struct",
            "sibling",
            format_expr=INVALID_FORMAT_EXPR,
        )
        == _invalid_format_output()
    )


def test_traverse_list_aborts_on_per_entry_fault(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    fault = drgn_error("fault", "bad entry", address=0x10)
    _stub_helper(
        monkeypatch,
        "list_for_each_entry",
        [FakeValue(0x1000), _FaultyValue(fault)],
    )
    _stub_eval(monkeypatch, _head("struct list_head"))

    assert traversal.traverse_list("head", "struct task_struct", "sibling") == (
        f"0x1000\n{_abort(fault)}"
    )


def test_traverse_list_aborts_on_format_expr_fault(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    fault = drgn_error("fault", "bad format", address=0x14)
    _stub_helper(
        monkeypatch,
        "list_for_each_entry",
        [FakeValue(0x1000), _FaultyValue(fault)],
    )
    _stub_eval(monkeypatch, _head("struct list_head"))

    assert (
        traversal.traverse_list(
            "head",
            "struct task_struct",
            "sibling",
            format_expr="f'{entry.value_():#x}'",
        )
        == f"0x1000\n{_abort(fault)}"
    )


def test_traverse_list_aborts_on_iterator_fault(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    fault = drgn_error("fault", "walk failed", address=0x11)

    def items() -> Iterator[FakeValue]:
        yield FakeValue(0x1000)
        raise fault

    _stub_helper(monkeypatch, "list_for_each_entry", items())
    _stub_eval(monkeypatch, _head("struct list_head"))

    assert traversal.traverse_list("head", "struct task_struct", "sibling") == (
        f"0x1000\n{_abort(fault)}"
    )


def test_traverse_list_reports_helper_fault(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    fault = drgn_error("fault", "unmapped head", address=0x12)
    _stub_helper(monkeypatch, "list_for_each_entry", fault)
    _stub_eval(monkeypatch, _head("struct list_head"))

    assert traversal.traverse_list("head", "struct task_struct", "sibling") == str(fault)


@pytest.mark.parametrize("kind", ["fault", "lookup"])
def test_traverse_list_reports_head_expression_error(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
    kind: str,
) -> None:
    fault = drgn_error(kind, "bad head", address=0x13)
    seen_expr = _eval_error(monkeypatch, fault)

    assert traversal.traverse_list("nope", "struct task_struct", "sibling") == (
        f"Error evaluating head expression: {fault}"
    )
    assert seen_expr == ["nope"]


def test_traverse_list_paginates_and_appends_next_page_notice(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_helper(
        monkeypatch,
        "list_for_each_entry",
        [FakeValue(addr) for addr in (0x10, 0x20, 0x30, 0x40)],
    )
    _stub_eval(monkeypatch, _head("struct list_head"))

    assert (
        traversal.traverse_list(
            "head",
            "struct task_struct",
            "sibling",
            offset=1,
            limit=2,
        )
        == f"0x20\n0x30\n{NEXT_PAGE}"
    )


def test_traverse_list_omits_next_page_notice_on_exact_page(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_helper(
        monkeypatch,
        "list_for_each_entry",
        [FakeValue(addr) for addr in (0x10, 0x20)],
    )
    _stub_eval(monkeypatch, _head("struct list_head"))

    assert (
        traversal.traverse_list(
            "head",
            "struct task_struct",
            "sibling",
            limit=2,
        )
        == "0x10\n0x20"
    )


def test_traverse_list_offset_past_end_reports_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_helper(
        monkeypatch,
        "list_for_each_entry",
        [FakeValue(addr) for addr in (0x10, 0x20)],
    )
    _stub_eval(monkeypatch, _head("struct list_head"))

    assert (
        traversal.traverse_list(
            "head",
            "struct task_struct",
            "sibling",
            offset=5,
        )
        == "Empty list"
    )


# Pins shared _traverse() clamp; rbtree/xarray/idr use the same path.
def test_traverse_list_normalizes_nonpositive_offset_and_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_helper(
        monkeypatch,
        "list_for_each_entry",
        [FakeValue(addr) for addr in (0x10, 0x20)],
    )
    _stub_eval(monkeypatch, _head("struct list_head"))

    assert (
        traversal.traverse_list(
            "head",
            "struct task_struct",
            "sibling",
            offset=-3,
            limit=0,
        )
        == "0x10\n... (limited to 1 entries, use offset=1 for next page)"
    )


# --- traverse_rbtree ----------------------------------------------------------


def test_traverse_rbtree_defaults_to_hex_addresses(monkeypatch: pytest.MonkeyPatch) -> None:
    root = SimpleNamespace()
    seen: list[tuple[object, object, object]] = []

    def rbtree_inorder_for_each_entry(
        entry_type: object, obj: object, member: object
    ) -> list[FakeValue]:
        seen.append((entry_type, obj, member))
        return [FakeValue(0x4000), FakeValue(0x5000)]

    monkeypatch.setattr(traversal, "rbtree_inorder_for_each_entry", rbtree_inorder_for_each_entry)
    seen_expr = _stub_eval(monkeypatch, root)

    assert traversal.traverse_rbtree("prog['mm'].mm_rb", "struct vm_area_struct", "vm_rb") == (
        "0x4000\n0x5000"
    )
    assert seen == [("struct vm_area_struct", root, "vm_rb")]
    assert seen_expr == ["prog['mm'].mm_rb"]


def test_traverse_rbtree_reports_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_helper(monkeypatch, "rbtree_inorder_for_each_entry", [])
    _stub_eval(monkeypatch, SimpleNamespace())

    assert traversal.traverse_rbtree("root", "struct vm_area_struct", "vm_rb") == "Empty tree"


def test_traverse_rbtree_formats_with_mocked_globals(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_helper(monkeypatch, "rbtree_inorder_for_each_entry", [FakeValue(0xABC)])
    _stub_eval(monkeypatch, SimpleNamespace())
    state._globals = {"label": Stringable("vma")}

    assert (
        traversal.traverse_rbtree("root", "struct vm_area_struct", "vm_rb", format_expr="label")
        == "vma"
    )
    assert (
        traversal.traverse_rbtree(
            "root",
            "struct vm_area_struct",
            "vm_rb",
            format_expr="f'{entry.value_():#x}'",
        )
        == "0xabc"
    )


def test_traverse_rbtree_reports_invalid_format_expr(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_eval(monkeypatch, SimpleNamespace())

    assert (
        traversal.traverse_rbtree(
            "root",
            "struct vm_area_struct",
            "vm_rb",
            format_expr=INVALID_FORMAT_EXPR,
        )
        == _invalid_format_output()
    )


def test_traverse_rbtree_aborts_on_per_entry_fault(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    fault = drgn_error("fault", "bad node", address=0x20)
    _stub_helper(
        monkeypatch,
        "rbtree_inorder_for_each_entry",
        [FakeValue(0x4000), _FaultyValue(fault)],
    )
    _stub_eval(monkeypatch, SimpleNamespace())

    assert traversal.traverse_rbtree("root", "struct vm_area_struct", "vm_rb") == (
        f"0x4000\n{_abort(fault)}"
    )


def test_traverse_rbtree_aborts_on_iterator_fault(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    fault = drgn_error("fault", "tree walk", address=0x21)

    def items() -> Iterator[FakeValue]:
        yield FakeValue(0x4000)
        raise fault

    _stub_helper(monkeypatch, "rbtree_inorder_for_each_entry", items())
    _stub_eval(monkeypatch, SimpleNamespace())

    assert traversal.traverse_rbtree("root", "struct vm_area_struct", "vm_rb") == (
        f"0x4000\n{_abort(fault)}"
    )


def test_traverse_rbtree_reports_helper_fault(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    fault = drgn_error("fault", "unmapped root", address=0x22)
    _stub_helper(monkeypatch, "rbtree_inorder_for_each_entry", fault)
    _stub_eval(monkeypatch, SimpleNamespace())

    assert traversal.traverse_rbtree("root", "struct vm_area_struct", "vm_rb") == str(fault)


def test_traverse_rbtree_reports_root_expression_error(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    fault = drgn_error("fault", "bad root", address=0x23)
    seen_expr = _eval_error(monkeypatch, fault)

    assert traversal.traverse_rbtree("nope", "struct vm_area_struct", "vm_rb") == (
        f"Error evaluating root expression: {fault}"
    )
    assert seen_expr == ["nope"]


def test_traverse_rbtree_paginates_and_appends_next_page_notice(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_helper(
        monkeypatch,
        "rbtree_inorder_for_each_entry",
        [FakeValue(addr) for addr in (0x10, 0x20, 0x30, 0x40)],
    )
    _stub_eval(monkeypatch, SimpleNamespace())

    assert (
        traversal.traverse_rbtree(
            "root",
            "struct vm_area_struct",
            "vm_rb",
            offset=1,
            limit=2,
        )
        == f"0x20\n0x30\n{NEXT_PAGE}"
    )


# --- traverse_xarray ----------------------------------------------------------


def test_traverse_xarray_defaults_to_index_and_hex_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    xa = SimpleNamespace()
    seen: list[object] = []

    def xa_for_each(obj: object) -> list[tuple[int, FakeValue]]:
        seen.append(obj)
        return [(0, FakeValue(0x6000)), (3, FakeValue(0x7000))]

    monkeypatch.setattr(traversal, "xa_for_each", xa_for_each)
    seen_expr = _stub_eval(monkeypatch, xa)

    assert traversal.traverse_xarray("prog['i_pages']") == "0: 0x6000\n3: 0x7000"
    assert seen == [xa]
    assert seen_expr == ["prog['i_pages']"]


def test_traverse_xarray_reports_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_helper(monkeypatch, "xa_for_each", [])
    _stub_eval(monkeypatch, SimpleNamespace())

    assert traversal.traverse_xarray("xa") == "Empty xarray"


def test_traverse_xarray_formats_with_mocked_globals(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_helper(monkeypatch, "xa_for_each", [(7, FakeValue(0xABC))])
    _stub_eval(monkeypatch, SimpleNamespace())
    state._globals = {"label": Stringable("page")}

    assert traversal.traverse_xarray("xa", format_expr="label") == "page"
    assert (
        traversal.traverse_xarray("xa", format_expr="f'{index} {entry.value_():#x}'") == "7 0xabc"
    )


def test_traverse_xarray_reports_invalid_format_expr(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_eval(monkeypatch, SimpleNamespace())

    assert (
        traversal.traverse_xarray("xa", format_expr=INVALID_FORMAT_EXPR) == _invalid_format_output()
    )


def test_traverse_xarray_aborts_on_per_entry_fault(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    fault = drgn_error("fault", "bad slot", address=0x30)
    _stub_helper(
        monkeypatch,
        "xa_for_each",
        [(0, FakeValue(0x6000)), (1, _FaultyValue(fault))],
    )
    _stub_eval(monkeypatch, SimpleNamespace())

    assert traversal.traverse_xarray("xa") == f"0: 0x6000\n{_abort(fault)}"


def test_traverse_xarray_aborts_on_iterator_fault(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    fault = drgn_error("fault", "xa walk", address=0x31)

    def items() -> Iterator[tuple[int, FakeValue]]:
        yield (0, FakeValue(0x6000))
        raise fault

    _stub_helper(monkeypatch, "xa_for_each", items())
    _stub_eval(monkeypatch, SimpleNamespace())

    assert traversal.traverse_xarray("xa") == f"0: 0x6000\n{_abort(fault)}"


def test_traverse_xarray_reports_helper_fault(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    fault = drgn_error("fault", "unmapped xa", address=0x32)
    _stub_helper(monkeypatch, "xa_for_each", fault)
    _stub_eval(monkeypatch, SimpleNamespace())

    assert traversal.traverse_xarray("xa") == str(fault)


def test_traverse_xarray_reports_expression_error(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    fault = drgn_error("fault", "bad xa", address=0x33)
    seen_expr = _eval_error(monkeypatch, fault)

    assert traversal.traverse_xarray("nope") == f"Error evaluating xarray expression: {fault}"
    assert seen_expr == ["nope"]


def test_traverse_xarray_paginates_and_appends_next_page_notice(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_helper(
        monkeypatch,
        "xa_for_each",
        [(i, FakeValue(addr)) for i, addr in enumerate((0x10, 0x20, 0x30, 0x40))],
    )
    _stub_eval(monkeypatch, SimpleNamespace())

    assert traversal.traverse_xarray("xa", offset=1, limit=2) == f"1: 0x20\n2: 0x30\n{NEXT_PAGE}"


# --- traverse_idr -------------------------------------------------------------


def test_traverse_idr_defaults_to_id_and_hex_address(monkeypatch: pytest.MonkeyPatch) -> None:
    idr = SimpleNamespace()
    seen: list[tuple[object, object]] = []

    def idr_for_each_entry(obj: object, entry_type: object) -> list[tuple[int, FakeValue]]:
        seen.append((obj, entry_type))
        return [(1, FakeValue(0x8000)), (4, FakeValue(0x9000))]

    monkeypatch.setattr(traversal, "idr_for_each_entry", idr_for_each_entry)
    seen_expr = _stub_eval(monkeypatch, idr)

    assert traversal.traverse_idr("prog['cgroup_hierarchy_idr']", "struct cgroup_root") == (
        "1: 0x8000\n4: 0x9000"
    )
    assert seen == [(idr, "struct cgroup_root")]
    assert seen_expr == ["prog['cgroup_hierarchy_idr']"]


def test_traverse_idr_reports_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_helper(monkeypatch, "idr_for_each_entry", [])
    _stub_eval(monkeypatch, SimpleNamespace())

    assert traversal.traverse_idr("idr", "struct cgroup_root") == "Empty IDR"


def test_traverse_idr_formats_with_mocked_globals(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_helper(monkeypatch, "idr_for_each_entry", [(9, FakeValue(0xABC))])
    _stub_eval(monkeypatch, SimpleNamespace())
    state._globals = {"label": Stringable("cgroup")}

    assert traversal.traverse_idr("idr", "struct cgroup_root", format_expr="label") == "cgroup"
    assert (
        traversal.traverse_idr(
            "idr",
            "struct cgroup_root",
            format_expr="f'{id} {entry.value_():#x}'",
        )
        == "9 0xabc"
    )


def test_traverse_idr_reports_invalid_format_expr(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_eval(monkeypatch, SimpleNamespace())

    assert (
        traversal.traverse_idr("idr", "struct cgroup_root", format_expr=INVALID_FORMAT_EXPR)
        == _invalid_format_output()
    )


def test_traverse_idr_aborts_on_per_entry_fault(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    fault = drgn_error("fault", "bad id", address=0x40)
    _stub_helper(
        monkeypatch,
        "idr_for_each_entry",
        [(1, FakeValue(0x8000)), (2, _FaultyValue(fault))],
    )
    _stub_eval(monkeypatch, SimpleNamespace())

    assert traversal.traverse_idr("idr", "struct cgroup_root") == f"1: 0x8000\n{_abort(fault)}"


def test_traverse_idr_aborts_on_iterator_fault(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    fault = drgn_error("fault", "idr walk", address=0x41)

    def items() -> Iterator[tuple[int, FakeValue]]:
        yield (1, FakeValue(0x8000))
        raise fault

    _stub_helper(monkeypatch, "idr_for_each_entry", items())
    _stub_eval(monkeypatch, SimpleNamespace())

    assert traversal.traverse_idr("idr", "struct cgroup_root") == f"1: 0x8000\n{_abort(fault)}"


def test_traverse_idr_reports_helper_fault(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    fault = drgn_error("fault", "unmapped idr", address=0x42)
    _stub_helper(monkeypatch, "idr_for_each_entry", fault)
    _stub_eval(monkeypatch, SimpleNamespace())

    assert traversal.traverse_idr("idr", "struct cgroup_root") == str(fault)


def test_traverse_idr_reports_expression_error(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    fault = drgn_error("fault", "bad idr", address=0x43)
    seen_expr = _eval_error(monkeypatch, fault)

    assert traversal.traverse_idr("nope", "struct cgroup_root") == (
        f"Error evaluating IDR expression: {fault}"
    )
    assert seen_expr == ["nope"]


def test_traverse_idr_paginates_and_appends_next_page_notice(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_helper(
        monkeypatch,
        "idr_for_each_entry",
        [(i, FakeValue(addr)) for i, addr in enumerate((0x10, 0x20, 0x30, 0x40), start=1)],
    )
    _stub_eval(monkeypatch, SimpleNamespace())

    assert (
        traversal.traverse_idr(
            "idr",
            "struct cgroup_root",
            offset=1,
            limit=2,
        )
        == f"2: 0x20\n3: 0x30\n{NEXT_PAGE}"
    )
