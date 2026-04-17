import drgn

from drgn_mcp._app import mcp, _eval_expr
from drgn_mcp.state import state


@mcp.tool()
def traverse_list(
    head_expr: str,
    entry_type: str,
    member: str,
    limit: int = 100,
    format_expr: str = "",
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

    Returns:
        A multi-line string with one line per entry. If format_expr is provided,
        shows the result of that expression. Otherwise, shows the hex address.
        Appends a warning if traversal is aborted due to memory corruption.

    Examples:
        traverse_list("prog['init_task'].children", "struct task_struct", "sibling")
        traverse_list("prog['init_task'].children", "struct task_struct", "sibling",
            format_expr="f'PID: {entry.pid.value_()}'")
    """
    state.require_loaded()
    from drgn.helpers.linux.list import (
        hlist_for_each_entry,
        list_for_each_entry,
    )

    try:
        head_obj = _eval_expr(head_expr)
    except (drgn.FaultError, LookupError, ValueError, SyntaxError, AttributeError, TypeError) as e:
        return f"Error evaluating head expression: {e}"

    type_name = head_obj.type_.type_name()
    if "hlist_head" in type_name:
        iterator = hlist_for_each_entry(entry_type, head_obj, member)
    elif "list_head" in type_name:
        iterator = list_for_each_entry(entry_type, head_obj, member)
    else:
        return f"Expected struct list_head or hlist_head, got {type_name}"

    fmt_code = None
    if format_expr:
        try:
            fmt_code = compile(format_expr, "<format_expr>", "eval")
        except SyntaxError as e:
            return f"Syntax error in format_expr: {e}"

    lines = []
    count = 0
    try:
        for entry in iterator:
            if count >= limit:
                lines.append(f"... (limited to {limit} entries)")
                break
            if fmt_code:
                lines.append(
                    str(eval(  # noqa: S307
                        fmt_code, {**state.globals, "entry": entry}
                    ))
                )
            else:
                lines.append(f"{entry.value_():#x}")
            count += 1
    except drgn.FaultError as e:
        lines.append(f"... Traversal aborted due to memory fault: {e}")

    return "\n".join(lines) if lines else "Empty list"


@mcp.tool()
def traverse_rbtree(
    root_expr: str,
    entry_type: str,
    member: str,
    limit: int = 100,
    format_expr: str = "",
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
    state.require_loaded()
    from drgn.helpers.linux.rbtree import rbtree_inorder_for_each_entry

    try:
        root_obj = _eval_expr(root_expr)
    except (drgn.FaultError, LookupError, ValueError, SyntaxError, AttributeError, TypeError) as e:
        return f"Error evaluating root expression: {e}"

    fmt_code = None
    if format_expr:
        try:
            fmt_code = compile(format_expr, "<format_expr>", "eval")
        except SyntaxError as e:
            return f"Syntax error in format_expr: {e}"

    lines = []
    count = 0
    try:
        for entry in rbtree_inorder_for_each_entry(
            entry_type, root_obj, member
        ):
            if count >= limit:
                lines.append(f"... (limited to {limit} entries)")
                break
            if fmt_code:
                lines.append(
                    str(eval(  # noqa: S307
                        fmt_code, {**state.globals, "entry": entry}
                    ))
                )
            else:
                lines.append(f"{entry.value_():#x}")
            count += 1
    except drgn.FaultError as e:
        lines.append(f"... Traversal aborted due to memory fault: {e}")

    return "\n".join(lines) if lines else "Empty tree"


@mcp.tool()
def traverse_xarray(
    xa_expr: str,
    limit: int = 100,
    format_expr: str = "",
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

    Returns:
        A multi-line string with one line per entry. Appends a warning if
        traversal is aborted due to memory corruption.

    Examples:
        traverse_xarray("prog['init_task'].mm.exe_file.f_mapping.i_pages")
        traverse_xarray("prog['init_task'].mm.exe_file.f_mapping.i_pages",
            format_expr="f'index {index}: page {entry.value_():#x}'")
    """
    state.require_loaded()
    from drgn.helpers.linux.xarray import xa_for_each

    try:
        xa_obj = _eval_expr(xa_expr)
    except (drgn.FaultError, LookupError, ValueError, SyntaxError, AttributeError, TypeError) as e:
        return f"Error evaluating xarray expression: {e}"

    fmt_code = None
    if format_expr:
        try:
            fmt_code = compile(format_expr, "<format_expr>", "eval")
        except SyntaxError as e:
            return f"Syntax error in format_expr: {e}"

    lines = []
    count = 0
    try:
        for index, entry in xa_for_each(xa_obj):
            if count >= limit:
                lines.append(f"... (limited to {limit} entries)")
                break
            if fmt_code:
                lines.append(
                    str(eval(  # noqa: S307
                        fmt_code,
                        {**state.globals, "index": index, "entry": entry},
                    ))
                )
            else:
                lines.append(f"{index}: {entry.value_():#x}")
            count += 1
    except drgn.FaultError as e:
        lines.append(f"... Traversal aborted due to memory fault: {e}")

    return "\n".join(lines) if lines else "Empty xarray"


@mcp.tool()
def traverse_idr(
    idr_expr: str,
    entry_type: str,
    limit: int = 100,
    format_expr: str = "",
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

    Returns:
        A multi-line string with one line per entry. Appends a warning if
        traversal is aborted due to memory corruption.

    Examples:
        traverse_idr("prog['cgroup_hierarchy_idr']", "struct cgroup_root")
        traverse_idr("prog['cgroup_hierarchy_idr']", "struct cgroup_root",
            format_expr="f'cgroup ID {id}: {entry.value_():#x}'")
    """
    state.require_loaded()
    from drgn.helpers.linux.idr import idr_for_each_entry

    try:
        idr_obj = _eval_expr(idr_expr)
    except (drgn.FaultError, LookupError, ValueError, SyntaxError, AttributeError, TypeError) as e:
        return f"Error evaluating IDR expression: {e}"

    fmt_code = None
    if format_expr:
        try:
            fmt_code = compile(format_expr, "<format_expr>", "eval")
        except SyntaxError as e:
            return f"Syntax error in format_expr: {e}"

    lines = []
    count = 0
    try:
        for id, entry in idr_for_each_entry(idr_obj, entry_type):
            if count >= limit:
                lines.append(f"... (limited to {limit} entries)")
                break
            if fmt_code:
                lines.append(
                    str(eval(  # noqa: S307
                        fmt_code,
                        {**state.globals, "id": id, "entry": entry},
                    ))
                )
            else:
                lines.append(f"{id}: {entry.value_():#x}")
            count += 1
    except drgn.FaultError as e:
        lines.append(f"... Traversal aborted due to memory fault: {e}")

    return "\n".join(lines) if lines else "Empty IDR"
