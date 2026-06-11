from collections.abc import Callable, Iterator
from typing import Any

import drgn
from drgn.helpers.linux.idr import idr_for_each_entry
from drgn.helpers.linux.list import hlist_for_each_entry, list_for_each_entry
from drgn.helpers.linux.rbtree import rbtree_inorder_for_each_entry
from drgn.helpers.linux.xarray import xa_for_each

from drgn_mcp._app import EVAL_ERRORS, _eval_expr, mcp
from drgn_mcp.state import state


def _traverse(
    expr: str,
    expr_label: str,
    make_iterator: Callable[[Any], Iterator],
    *,
    format_expr: str,
    offset: int,
    limit: int,
    loop_vars: Callable[[Any], dict[str, Any]],
    default_fmt: Callable[[Any], str],
    empty_msg: str,
) -> str:
    """Shared traversal logic for all traverse_* tools.

    Args:
        expr: drgn expression to evaluate for the data structure head/root.
        expr_label: Human-readable label for error messages (e.g., "head", "root").
        make_iterator: Factory that takes the evaluated object and returns an iterator.
        format_expr: User-supplied Python expression for formatting each entry.
        offset: Number of entries to skip.
        limit: Maximum entries to return.
        loop_vars: Extracts loop variable dict from each yielded item for format_expr eval.
        default_fmt: Default formatter when format_expr is empty.
        empty_msg: Message returned when the iterator yields nothing.
    """
    state.require_loaded()
    offset = max(0, offset)
    limit = max(1, limit)

    try:
        obj = _eval_expr(expr)
    except EVAL_ERRORS as e:
        return f"Error evaluating {expr_label} expression: {e}"

    fmt_code = None
    if format_expr:
        try:
            fmt_code = compile(format_expr, "<format_expr>", "eval")
        except SyntaxError as e:
            return f"Syntax error in format_expr: {e}"

    try:
        iterator = make_iterator(obj)
    except (TypeError, drgn.FaultError) as e:
        return str(e)

    lines: list[str] = []
    skipped = 0
    count = 0
    try:
        for item in iterator:
            if skipped < offset:
                skipped += 1
                continue
            if count >= limit:
                lines.append(
                    f"... (limited to {limit} entries, use offset={offset + limit} for next page)"
                )
                break
            if fmt_code:
                lines.append(
                    str(eval(fmt_code, state.globals, loop_vars(item)))  # noqa: S307
                )
            else:
                lines.append(default_fmt(item))
            count += 1
    except drgn.FaultError as e:
        lines.append(f"... Traversal aborted due to memory fault: {e}")

    return "\n".join(lines) if lines else empty_msg


@mcp.tool()
def traverse_list(
    head_expr: str,
    entry_type: str,
    member: str,
    limit: int = 100,
    format_expr: str = "",
    offset: int = 0,
) -> str:
    """Traverse a Linux kernel linked list (list_head or hlist_head).

    Use this to iterate over standard kernel doubly-linked lists or hash lists.
    It automatically detects whether the head is a struct list_head or
    struct hlist_head and uses the appropriate drgn helper.

    To prevent context window exhaustion, this tool does not dump full structs
    by default. Use format_expr to extract exactly the fields you need.

    Args:
        head_expr: A drgn Python expression evaluating to the list head
            (e.g., "prog['init_task'].children").
        entry_type: The C type name of the struct containing the list node
            (e.g., "struct task_struct").
        member: The name of the list_head/hlist_head member within the struct
            (e.g., "sibling").
        limit: Maximum number of entries to traverse.
        format_expr: Optional Python expression evaluated for each entry to format
            the output. The current entry is available as the "entry" variable
            (a drgn.Object pointer). If empty, defaults to returning the hex
            address of the entry pointer.
        offset: Number of entries to skip (for pagination).

    Returns:
        A multi-line string with one line per entry. If format_expr is provided,
        shows the result of that expression. Otherwise, shows the hex address.
        Appends a warning if traversal is aborted due to memory corruption.

    Examples:
        traverse_list("prog['init_task'].children", "struct task_struct", "sibling")
        traverse_list("prog['init_task'].children", "struct task_struct", "sibling",
            format_expr="f'PID: {entry.pid.value_()}'")
    """

    def make_iterator(head_obj):
        type_name = head_obj.type_.type_name()
        if "hlist_head" in type_name:
            return hlist_for_each_entry(entry_type, head_obj, member)
        if "list_head" in type_name:
            return list_for_each_entry(entry_type, head_obj, member)
        raise TypeError(f"Expected struct list_head or hlist_head, got {type_name}")

    return _traverse(
        head_expr,
        "head",
        make_iterator,
        format_expr=format_expr,
        offset=offset,
        limit=limit,
        loop_vars=lambda entry: {"entry": entry},
        default_fmt=lambda entry: f"{entry.value_():#x}",
        empty_msg="Empty list",
    )


@mcp.tool()
def traverse_rbtree(
    root_expr: str,
    entry_type: str,
    member: str,
    limit: int = 100,
    format_expr: str = "",
    offset: int = 0,
) -> str:
    """Traverse a Linux kernel Red-Black tree in sorted order.

    Use this to iterate over rb_root structures, such as a process's Virtual
    Memory Areas (VMAs) or the completely fair scheduler (CFS) runqueue.

    Args:
        root_expr: A drgn Python expression evaluating to the rb_root
            (e.g., "prog['init_task'].mm.mm_rb").
        entry_type: The C type name of the struct containing the rb_node
            (e.g., "struct vm_area_struct").
        member: The name of the rb_node member within the struct
            (e.g., "vm_rb").
        limit: Maximum number of entries to traverse.
        format_expr: Optional Python expression evaluated for each entry. The
            current entry is available as the "entry" variable (a drgn.Object
            pointer). If empty, defaults to returning the hex address.
        offset: Number of entries to skip (for pagination).

    Returns:
        A multi-line string with one line per entry, formatted via format_expr
        or defaulting to hex addresses. Appends a warning on memory faults.

    Examples:
        traverse_rbtree("prog['init_task'].mm.mm_rb", "struct vm_area_struct",
            "vm_rb")
        traverse_rbtree("prog['init_task'].mm.mm_rb", "struct vm_area_struct",
            "vm_rb",
            format_expr="f'{entry.vm_start.value_():#x} - {entry.vm_end.value_():#x}'")
    """
    return _traverse(
        root_expr,
        "root",
        lambda obj: rbtree_inorder_for_each_entry(entry_type, obj, member),
        format_expr=format_expr,
        offset=offset,
        limit=limit,
        loop_vars=lambda entry: {"entry": entry},
        default_fmt=lambda entry: f"{entry.value_():#x}",
        empty_msg="Empty tree",
    )


@mcp.tool()
def traverse_xarray(
    xa_expr: str,
    limit: int = 100,
    format_expr: str = "",
    offset: int = 0,
) -> str:
    """Traverse a Linux kernel XArray data structure.

    Use this to iterate over an XArray, which maps unsigned long indices to
    pointers. Common uses include the page cache (i_pages) or open file tables.

    Args:
        xa_expr: A drgn Python expression evaluating to the struct xarray
            (e.g., "prog['init_task'].mm.exe_file.f_mapping.i_pages").
        limit: Maximum number of entries to traverse.
        format_expr: Optional Python expression evaluated for each entry.
            Two variables are available in scope:
            - "index": The integer index in the XArray.
            - "entry": The drgn.Object pointer stored at that index.
            If empty, defaults to "index: hex_address".
        offset: Number of entries to skip (for pagination).

    Returns:
        A multi-line string with one line per entry. Appends a warning if
        traversal is aborted due to memory corruption.

    Examples:
        traverse_xarray("prog['init_task'].mm.exe_file.f_mapping.i_pages")
        traverse_xarray("prog['init_task'].mm.exe_file.f_mapping.i_pages",
            format_expr="f'index {index}: page {entry.value_():#x}'")
    """
    return _traverse(
        xa_expr,
        "xarray",
        xa_for_each,
        format_expr=format_expr,
        offset=offset,
        limit=limit,
        loop_vars=lambda item: {"index": item[0], "entry": item[1]},
        default_fmt=lambda item: f"{item[0]}: {item[1].value_():#x}",
        empty_msg="Empty xarray",
    )


@mcp.tool()
def traverse_idr(
    idr_expr: str,
    entry_type: str,
    limit: int = 100,
    format_expr: str = "",
    offset: int = 0,
) -> str:
    """Traverse a Linux kernel IDR (Integer ID Management) data structure.

    Use this to iterate over an IDR, which maps integer IDs to pointers.
    Common uses include PID allocation, IPC IDs, or cgroup hierarchies.

    Args:
        idr_expr: A drgn Python expression evaluating to the struct idr
            (e.g., "prog['cgroup_hierarchy_idr']").
        entry_type: The C type of the stored pointer (e.g., "struct cgroup_root").
        limit: Maximum number of entries to traverse.
        format_expr: Optional Python expression evaluated for each entry.
            Two variables are available in scope:
            - "id": The integer ID.
            - "entry": The drgn.Object pointer stored for that ID.
            If empty, defaults to "id: hex_address".
        offset: Number of entries to skip (for pagination).

    Returns:
        A multi-line string with one line per entry. Appends a warning if
        traversal is aborted due to memory corruption.

    Examples:
        traverse_idr("prog['cgroup_hierarchy_idr']", "struct cgroup_root")
        traverse_idr("prog['cgroup_hierarchy_idr']", "struct cgroup_root",
            format_expr="f'cgroup ID {id}: {entry.value_():#x}'")
    """
    return _traverse(
        idr_expr,
        "IDR",
        lambda obj: idr_for_each_entry(obj, entry_type),
        format_expr=format_expr,
        offset=offset,
        limit=limit,
        loop_vars=lambda item: {"id": item[0], "entry": item[1]},
        default_fmt=lambda item: f"{item[0]}: {item[1].value_():#x}",
        empty_msg="Empty IDR",
    )
