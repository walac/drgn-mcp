import contextlib
import io
import itertools
import traceback

import drgn
from mcp.server.fastmcp import FastMCP

from drgn_mcp.state import state

mcp = FastMCP(
    "drgn-mcp",
    instructions=(
        "You are connected to a drgn debugger session for Linux kernel crash dump analysis.\n"
        "\n"
        "drgn is a programmable debugger. Use the available tools to investigate crash dumps.\n"
        "Start by loading a core dump with load_core_dump, then use the analysis tools.\n"
        "For anything not covered by structured tools, use eval_expression with drgn Python\n"
        "expressions.\n"
        "\n"
        "Key drgn concepts:\n"
        "- Program: represents the debugged program (kernel crash dump)\n"
        "- Object: represents a value in the program (variable, struct member, etc.)\n"
        "- Type: represents a C type (struct, enum, pointer, etc.)\n"
        "- StackTrace/StackFrame: call stack information\n"
        "- Thread: a thread/task in the program\n"
        "\n"
        "Available in eval context: prog (the Program), all drgn helpers\n"
        "(for_each_task, find_task, etc.), cast, sizeof, container_of, offsetof,\n"
        "and all drgn.helpers.linux.* helpers."
    ),
)


@mcp.tool()
def load_core_dump(
    core_path: str,
    vmlinux_path: str = "",
    extra_symbols: list[str] | None = None,
) -> str:
    """Load a vmcore crash dump and optional vmlinux debug symbols.

    CRITICAL: This must be called before any other tool can be used. It initializes
    the drgn debugging session.

    Args:
        core_path: Absolute path to the vmcore crash dump file.
        vmlinux_path: Optional absolute path to the vmlinux file with DWARF debug info.
        extra_symbols: Optional list of paths to additional symbol files.

    Returns:
        A string containing basic program information on success, or an error
        message if loading fails.

    Examples:
        load_core_dump("/var/crash/vmcore", "/usr/lib/debug/boot/vmlinux-5.15.0")
    """
    return state.load(core_path, vmlinux_path or None, extra_symbols or None)


@mcp.tool()
def eval_expression(expression: str) -> str:
    """Evaluate a drgn Python expression or statement.

    Use this as a catch-all for complex queries not covered by specialized tools.
    Prefer using specialized tools (like get_thread, lookup_symbol) first.

    The expression runs in a context with these pre-loaded:
    - prog: the loaded drgn.Program
    - All drgn module attributes (cast, sizeof, container_of, etc.)
    - All drgn.helpers.common helpers
    - All drgn.helpers.linux helpers (if kernel program)

    Args:
        expression: Python code to evaluate. Tries Python's eval() builtin first,
            falls back to the exec() builtin on SyntaxError.

    Returns:
        The captured stdout output or string representation of the result.
        Truncated at 8KB. Returns an error message if evaluation fails.

    Examples:
        eval_expression("prog.crashed_thread().stack_trace()")
        eval_expression("prog['jiffies']")
        eval_expression("for task in for_each_task(prog): print(task.pid.value_(), task.comm.string_())")
        eval_expression("print_annotated_stack(prog.stack_trace(prog.crashed_thread()))")
    """
    state.require_loaded()

    stdout_capture = io.StringIO()
    result = None

    try:
        try:
            code = compile(expression, "<eval>", "eval")
            with contextlib.redirect_stdout(stdout_capture):
                result = eval(code, state.globals)
        except SyntaxError:
            code = compile(expression, "<eval>", "exec")  # noqa: S102
            with contextlib.redirect_stdout(stdout_capture):
                exec(code, state.globals)  # noqa: S102
    except Exception:
        return f"Error evaluating expression:\n{traceback.format_exc()}"

    output_parts = []
    stdout_str = stdout_capture.getvalue()
    if stdout_str:
        output_parts.append(stdout_str)
    if result is not None:
        output_parts.append(repr(result) if not isinstance(result, str) else result)

    output = "\n".join(output_parts) if output_parts else "(no output)"

    max_len = 8000
    if len(output) > max_len:
        output = output[:max_len] + f"\n... (truncated, {len(output)} total chars)"

    return output


@mcp.tool()
def get_program_info() -> str:
    """Retrieve basic information about the loaded drgn program.

    Use this to check the architecture, platform, and whether the loaded dump
    is a Linux kernel.

    Returns:
        A multi-line string detailing the program flags, platform, and kernel status.
    """
    return state.format_program_info()


@mcp.tool()
def get_crashed_thread() -> str:
    """Retrieve the thread that caused the panic along with its stack trace.

    DIFFERENCE FROM get_panic_info: get_crashed_thread returns only the crashed
    thread and its stack trace; get_panic_info additionally extracts the kernel
    panic message.

    Returns:
        A multi-line string showing the crashed thread's metadata and full
        stack trace.
    """
    prog = state.require_loaded()
    thread = prog.crashed_thread()
    trace = thread.stack_trace()
    return (
        f"Crashed thread: tid={thread.tid}, name={thread.name}\n"
        f"\nStack trace:\n{trace}"
    )


@mcp.tool()
def get_stack_trace(thread_id: int) -> str:
    """Retrieve the stack trace for a specific thread by its ID.

    DIFFERENCE FROM get_thread: get_stack_trace only returns stack frames.
    Use get_thread if you also need thread metadata (name, state).

    Args:
        thread_id: The numeric ID of the thread to inspect.

    Returns:
        A multi-line string showing the stack frames with function names,
        addresses, and source locations.

    Examples:
        get_stack_trace(1)
        get_stack_trace(4096)
    """
    prog = state.require_loaded()
    trace = prog.stack_trace(thread_id)
    return str(trace)


@mcp.tool()
def list_threads(limit: int = 100) -> str:
    """List all threads in the program.

    Use this to get a high-level overview. For detailed inspection of a single
    thread, use get_thread or get_stack_trace.

    Args:
        limit: Maximum number of threads to return.

    Returns:
        A multi-line string listing threads with TID and name.
        Appends a truncation notice if threads exceed limit.
    """
    prog = state.require_loaded()
    lines = []
    count = 0
    for thread in prog.threads():
        if count >= limit:
            lines.append(f"... (showing {limit} of more threads, use higher limit)")
            break
        lines.append(f"tid={thread.tid} name={thread.name}")
        count += 1
    if not lines:
        return "No threads found"
    return "\n".join(lines)


@mcp.tool()
def lookup_object(name: str) -> str:
    """Look up a global variable, function, or constant by name using DWARF debug info.

    DIFFERENCE FROM lookup_symbol: lookup_object queries DWARF debug info and returns
    a fully typed drgn Object. Use lookup_symbol to query the raw ELF symbol table
    when DWARF info is missing or when you need raw addresses and sizes.

    Args:
        name: The exact name of the variable, function, or constant.

    Returns:
        The string representation of the drgn Object, showing its type and value.

    Examples:
        lookup_object("jiffies")
        lookup_object("init_task")
    """
    prog = state.require_loaded()
    obj = prog[name]
    return str(obj)


@mcp.tool()
def lookup_type(type_name: str) -> str:
    """Look up a C type definition by its name.

    Use this to inspect the layout, size, and members of structs, unions,
    enums, or typedefs.

    Args:
        type_name: The name of the C type (e.g., "struct task_struct", "pid_t").

    Returns:
        A multi-line string showing the full C type definition, including
        member offsets and sizes.

    Examples:
        lookup_type("struct task_struct")
        lookup_type("enum pid_type")
    """
    prog = state.require_loaded()
    t = prog.type(type_name)
    return str(t)


@mcp.tool()
def list_tasks(limit: int = 100) -> str:
    """List all tasks (processes) in the Linux kernel.

    Use this to get a high-level overview of running processes. For detailed
    inspection of a specific task, use find_task.

    Args:
        limit: Maximum number of tasks to return.

    Returns:
        A multi-line string listing tasks with PID, comm (name), and state
        character. Appends a truncation notice if tasks exceed limit.
    """
    prog = state.require_loaded()
    from drgn.helpers.linux.sched import for_each_task, task_state_to_char

    lines = []
    count = 0
    for task in for_each_task(prog):
        if count >= limit:
            lines.append(f"... (truncated at {limit})")
            break
        pid = task.pid.value_()
        comm = task.comm.string_().decode()
        state_char = task_state_to_char(task)
        lines.append(f"pid={pid} comm={comm} state={state_char}")
        count += 1
    return "\n".join(lines)


@mcp.tool()
def find_task(pid: int) -> str:
    """Find a specific Linux kernel task by its PID and show detailed information.

    Use this to deeply inspect a specific process's struct task_struct.

    Args:
        pid: The numeric Process ID to inspect.

    Returns:
        A detailed string representation of the task's struct task_struct.
        Returns an error message if no task is found with the given PID.

    Examples:
        find_task(1)
        find_task(1234)
    """
    prog = state.require_loaded()
    from drgn.helpers.linux.pid import find_task as _find_task

    task = _find_task(prog, pid)
    if task is None:
        return f"No task found with PID {pid}"
    return str(task.format_(dereference=True))


@mcp.tool()
def list_modules() -> str:
    """List all loaded kernel modules.

    Use this to see which kernel modules (.ko) were loaded at the time
    of the crash.

    Returns:
        A multi-line string listing the names of all loaded kernel modules.
    """
    prog = state.require_loaded()
    from drgn.helpers.linux.module import for_each_module

    names = [mod.name.string_().decode() for mod in for_each_module(prog)]
    return "\n".join(names) if names else "No modules loaded"


@mcp.tool()
def read_memory(address: int | str, size: int = 64) -> str:
    """Read raw memory at the given address and return a hex dump.

    DIFFERENCE FROM read_typed_memory: read_memory returns a raw hex dump
    with ASCII representation. Prefer read_typed_memory when you know the
    underlying data type (e.g., u64, c_string).

    Args:
        address: The memory address to read from. Can be an integer or hex string.
        size: Number of bytes to read. Maximum is 4096 bytes.

    Returns:
        A multi-line hex dump showing address, hex bytes, and ASCII
        representation (16 bytes per line).

    Examples:
        read_memory("0xffffffff81000000", size=128)
        read_memory(0xffffffff81000000)
    """
    prog = state.require_loaded()
    addr = address if isinstance(address, int) else int(address, 0)
    size = min(size, 4096)
    data = prog.read(addr, size)
    lines = []
    for offset in range(0, len(data), 16):
        chunk = data[offset : offset + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{addr + offset:#018x}  {hex_part:<48s}  {ascii_part}")
    return "\n".join(lines)


@mcp.tool()
def get_dmesg() -> str:
    """Retrieve the kernel log buffer (dmesg output).

    Use this to read the kernel logs leading up to the crash.

    Returns:
        A multi-line string containing timestamped kernel log messages.
        Truncates from the front at 8KB, keeping the most recent messages.
    """
    prog = state.require_loaded()
    from drgn.helpers.linux.printk import get_printk_records

    lines = [
        f"[{r.timestamp.total_seconds():>12.6f}] {r.text}"
        for r in get_printk_records(prog)
    ]
    output = "\n".join(lines)

    max_len = 8000
    if len(output) > max_len:
        return f"... (truncated, {len(output)} total chars)\n{output[-max_len:]}"
    return output


@mcp.tool()
def get_panic_info() -> str:
    """Retrieve the kernel panic message and the crashed thread's stack trace.

    DIFFERENCE FROM get_crashed_thread: get_panic_info also extracts the specific
    panic message from the kernel. Use get_dmesg if you need the full kernel
    log context.

    Returns:
        A multi-line string containing the panic message (if found) followed
        by the crashed thread's stack trace. Returns partial results if
        extraction fails for either component.
    """
    prog = state.require_loaded()
    lines = []
    try:
        from drgn.helpers.linux.panic import panic_message

        msg = panic_message(prog)
        lines.append(f"Panic message: {msg}")
    except (drgn.FaultError, LookupError, ImportError, ValueError) as e:
        lines.append(f"Could not retrieve panic message: {e}")

    try:
        thread = prog.crashed_thread()
        trace = thread.stack_trace()
        lines.append(f"\nCrashed thread: tid={thread.tid}")
        lines.append(f"Stack trace:\n{trace}")
    except ValueError as e:
        lines.append(f"\nCould not retrieve crashed thread: {e}")

    return "\n".join(lines)


@mcp.tool()
def search_memory(
    pattern: str,
    search_type: str = "bytes",
    alignment: int = 1,
    limit: int = 10,
) -> str:
    """Search all program memory for specific strings, integers, or regular expressions.

    Use this to find addresses containing specific data when you know the value but not
    the exact memory location. The required format for pattern strictly depends on
    the search_type.

    Args:
        pattern: The value to search for. Format rules based on search_type:
            - "bytes": A plain text string that will be UTF-8 encoded (e.g., "swapper").
              Do NOT pass space-separated hex bytes.
            - "u32", "u64", "word": A valid Python integer literal string (e.g., "0xdeadbeef" or "42").
            - "regex": A regular expression string that will be evaluated as a byte regex.
        search_type: The type of data to search for. Must be "bytes", "u32", "u64", "word", or "regex".
        alignment: Memory alignment for "bytes" searches (e.g., 8 for 64-bit aligned). Ignored for other types.
        limit: Maximum number of matches to return.

    Returns:
        A multi-line string of matches (one per line). Format depends on search_type:
        - "bytes": Hex addresses only.
        - "u32", "u64", "word": "address: value" pairs.
        - "regex": "address: matched_bytes_repr".
        Returns "No matches found" if empty. Appends a truncation notice if matches exceed limit.

    Examples:
        search_memory("swapper", search_type="bytes")
        search_memory("0xdeadbeef", search_type="u32", alignment=4)
        search_memory("42", search_type="u64", alignment=8)
        search_memory("panic.*", search_type="regex")
    """
    prog = state.require_loaded()

    lines = []
    count = 0

    try:
        match search_type:
            case "bytes":
                for addr in prog.search_memory(
                    pattern.encode(), alignment=alignment
                ):
                    if count >= limit:
                        break
                    lines.append(f"{addr:#x}")
                    count += 1
            case "u32" | "u64" | "word":
                value = int(pattern, 0)
                search_fn = getattr(prog, f"search_memory_{search_type}")
                for addr, found in search_fn(value):
                    if count >= limit:
                        break
                    lines.append(f"{addr:#x}: {found:#x}")
                    count += 1
            case "regex":
                for addr, match_bytes in prog.search_memory_regex(
                    pattern.encode()
                ):
                    if count >= limit:
                        break
                    lines.append(f"{addr:#x}: {match_bytes!r}")
                    count += 1
            case _:
                return (
                    f"Unknown search type '{search_type}'. "
                    "Use: bytes, u32, u64, word, regex."
                )
    except drgn.FaultError as e:
        return f"Memory fault during search: {e}"
    except ValueError as e:
        return f"Invalid pattern: {e}"

    if not lines:
        return "No matches found"

    output = "\n".join(lines)
    if count >= limit:
        output += f"\n... (limited to {limit} results, use higher limit to see more)"
    return output


@mcp.tool()
def get_source_location(address: int | str) -> str:
    """Map a code address or symbol to its exact C source code location (file, line, column).

    Similar to 'addr2line'. Use this to find exactly where in the source code an instruction
    pointer or function address belongs. It automatically resolves and displays the full
    inline function chain if the address falls within inlined code.

    Args:
        address: A numeric address (e.g., 0xffffffff81000000), a hex address string
                 (e.g., "0xffffffff81000000"), or a "symbol+offset" string (e.g., "schedule+0x15").

    Returns:
        A string showing the exact source file, line, and column.
        For inlined code, returns a multi-line call chain from innermost to outermost
        (e.g., "#0 inner_func at file.c:10" followed by "#1 outer_func at file.c:20").
        Returns an error message if the location cannot be resolved.

    Examples:
        get_source_location(0xffffffff823ab120)
        get_source_location("panic+0x50")
    """
    prog = state.require_loaded()

    try:
        return str(prog.source_location(address))
    except LookupError:
        return f"No source location found for '{address}'"
    except drgn.FaultError as e:
        return f"Memory fault resolving '{address}': {e}"


@mcp.tool()
def read_typed_memory(
    address: int | str,
    value_type: str = "u64",
    count: int = 1,
    physical: bool = False,
) -> str:
    """Read and format specific data types from memory.

    Prefer this over read_memory when you know the underlying data type (e.g., reading an
    array of pointers or a C string). It formats the output natively rather than returning
    a raw hex dump.

    Args:
        address: Starting memory address as integer or hex string.
        value_type: The type of data to read. Must be one of: "u8", "u16", "u32", "u64",
                    "word" (pointer size), or "c_string".
        count: Number of consecutive elements to read (ignored if value_type is "c_string").
        physical: If True, treat the address as a physical memory address instead of virtual.

    Returns:
        The formatted memory contents based on value_type:
        - Integer types: Multi-line string of "address: value" pairs (addresses are
          0x-prefixed and padded to 18 characters; values are hex).
        - "c_string": The decoded text string directly.
        Returns an error message if the type is unknown or memory is inaccessible.

    Examples:
        read_typed_memory("0xffff888100000000", value_type="c_string")
        read_typed_memory(0xffffffff82000000, value_type="u64", count=4)
    """
    prog = state.require_loaded()
    addr = address if isinstance(address, int) else int(address, 0)

    try:
        match value_type:
            case "c_string":
                data = prog.read_c_string(addr, physical, max_size=8000)
                return data.decode(errors="replace")
            case "u8" | "u16" | "u32" | "u64" | "word":
                read_fn = getattr(prog, f"read_{value_type}")
                type_sizes: dict[str, int] = {
                    "u8": 1, "u16": 2, "u32": 4, "u64": 8,
                    "word": prog.address_size(),
                }
                size = type_sizes[value_type]
                count = min(count, 256)

                lines = []
                for i in range(count):
                    value = read_fn(addr + i * size, physical)
                    lines.append(f"{addr + i * size:#018x}: {value:#x}")
                return "\n".join(lines)
            case _:
                return (
                    f"Unknown type '{value_type}'. "
                    "Use: u8, u16, u32, u64, word, c_string."
                )
    except drgn.FaultError as e:
        return f"Memory fault at {addr:#x}: {e}"


@mcp.tool()
def lookup_symbol(address_or_name: int | str, limit: int = 100) -> str:
    """Search the ELF symbol table (vmlinux/kallsyms) by name or address.

    DIFFERENCE FROM lookup_object: lookup_symbol queries the raw ELF symbol table, while
    lookup_object queries DWARF debug info. Use lookup_symbol to resolve raw instruction
    pointers to "symbol+offset", or to find basic symbol boundaries when DWARF info is missing.

    Args:
        address_or_name: A numeric address or hex string (e.g., 0xffffffff81000000 or
                         "0xffffffff81000000") to find the containing symbol, or a symbol
                         name string (e.g., "kmalloc") to list all matching symbols with
                         their address, size, binding, and kind.
        limit: Maximum number of symbols to return for name searches (default 100).

    Returns:
        Symbol metadata including name, address, size, binding (e.g., GLOBAL), and kind.
        - By address: Multi-line output for the containing symbol. Appends "+offset" to
          the name if the address is not at the exact symbol start.
        - By name: One line per matching symbol containing all fields. Truncated if
          matches exceed limit.
        Returns an error message if no matching symbol is found.

    Examples:
        lookup_symbol(0xffffffff81000000)
        lookup_symbol("schedule")
    """
    prog = state.require_loaded()

    if isinstance(address_or_name, int):
        try:
            sym = prog.symbol(address_or_name)
            offset = address_or_name - sym.address
            offset_str = f"+{offset:#x}" if offset else ""
            return (
                f"name={sym.name}{offset_str}\n"
                f"address={sym.address:#x}\n"
                f"size={sym.size}\n"
                f"binding={sym.binding.name}\n"
                f"kind={sym.kind.name}"
            )
        except LookupError:
            return f"No symbol found containing address {address_or_name:#x}"

    # String: could be a hex address string or a symbol name
    try:
        return lookup_symbol(int(address_or_name, 0))
    except ValueError:
        pass

    syms = prog.symbols(address_or_name)
    if not syms:
        return f"No symbol found with name '{address_or_name}'"

    lines = [
        f"name={sym.name} address={sym.address:#x} "
        f"size={sym.size} binding={sym.binding.name} kind={sym.kind.name}"
        for sym in itertools.islice(syms, limit)
    ]
    if len(syms) > limit:
        remaining = len(syms) - limit
        lines.append(
            f"... ({remaining} more symbols, use higher limit to see all)"
        )
    return "\n".join(lines)


@mcp.tool()
def get_thread(tid: int) -> str:
    """Retrieve detailed metadata and the full stack trace for a specific thread.

    Use this when you need to deeply inspect a single thread's state and call
    stack. This provides much more detail than list_threads, which only shows
    high-level summaries of all threads.

    Args:
        tid: The numeric Thread ID (PID) to inspect.

    Returns:
        A multi-line string starting with thread metadata (TID, name) followed by the
        full stack trace. Each stack frame shows the function name, address, and source location.
        Returns an error message if the thread is not found or the stack fails to unwind.

    Examples:
        get_thread(1)
        get_thread(4096)
    """
    prog = state.require_loaded()

    try:
        thread = prog.thread(tid)
    except LookupError:
        return f"No thread found with tid={tid}"

    lines = [f"Thread: tid={thread.tid}, name={thread.name}"]

    try:
        trace = thread.stack_trace()
        lines.append(f"\nStack trace:\n{trace}")
    except ValueError as e:
        lines.append(f"\nCould not get stack trace: {e}")

    return "\n".join(lines)


def _eval_expr(expr: str) -> object:
    """Evaluate a drgn Python expression and return the resulting object.

    This is an internal helper used by traversal tools to resolve string
    expressions into drgn Objects (e.g., resolving "prog['init_task'].children"
    into a struct list_head). It uses the global drgn state context.

    Args:
        expr: A valid drgn Python expression string.

    Returns:
        The evaluated Python object (typically a drgn.Object).
    """
    return eval(  # noqa: S307
        compile(expr, "<eval>", "eval"), state.globals
    )


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


@mcp.tool()
def translate_address(
    address: int | str,
    direction: str = "virt_to_phys",
) -> str:
    """Translate a memory address between virtual, physical, page, and PFN forms.

    Use this to convert between different kernel address representations. All
    translations operate on directly mapped (linear) addresses.

    Args:
        address: The address or PFN to translate, as integer or hex string.
        direction: The translation to perform. Must be one of:
            - "virt_to_phys": virtual address to physical address
            - "phys_to_virt": physical address to virtual address
            - "virt_to_page": virtual address to struct page pointer
            - "page_to_virt": page pointer to virtual address
            - "page_to_pfn": page pointer to page frame number
            - "pfn_to_page": page frame number to struct page pointer
            - "virt_to_pfn": virtual address to page frame number

    Returns:
        The translated address in hex format, or an error message if the
        translation fails (e.g., address not in direct map).

    Examples:
        translate_address(0xffff888100000000, "virt_to_phys")
        translate_address("0x100000", direction="phys_to_virt")
        translate_address(0xffff888100000000, "virt_to_pfn")
    """
    prog = state.require_loaded()
    from drgn.helpers.linux.mm import (
        page_to_pfn,
        page_to_virt,
        pfn_to_page,
        phys_to_virt,
        virt_to_page,
        virt_to_pfn,
        virt_to_phys,
    )

    addr = address if isinstance(address, int) else int(address, 0)

    try:
        match direction:
            case "virt_to_phys":
                result = virt_to_phys(prog, addr)
            case "phys_to_virt":
                result = phys_to_virt(prog, addr)
            case "virt_to_page":
                result = virt_to_page(prog, addr)
            case "page_to_virt":
                result = page_to_virt(prog.object("struct page *", addr))
            case "page_to_pfn":
                result = page_to_pfn(prog.object("struct page *", addr))
            case "pfn_to_page":
                result = pfn_to_page(prog, addr)
            case "virt_to_pfn":
                result = virt_to_pfn(prog, addr)
            case _:
                return (
                    f"Unknown direction '{direction}'. Use: virt_to_phys, "
                    "phys_to_virt, virt_to_page, page_to_virt, page_to_pfn, "
                    "pfn_to_page, virt_to_pfn."
                )
        return str(result)
    except drgn.FaultError as e:
        return f"Translation failed: {e}"


@mcp.tool()
def get_page_info(
    address: int | str,
    source: str = "virt",
) -> str:
    """Get detailed information about a memory page.

    Use this to inspect page flags, compound page status, and slab membership
    for a given page. Useful for diagnosing memory corruption or understanding
    page state at crash time.

    Args:
        address: The address or PFN identifying the page.
        source: How to interpret the address. Must be one of:
            - "virt": address is a virtual address (default)
            - "pfn": address is a page frame number

    Returns:
        A multi-line string showing page flags (decoded), compound page info,
        slab membership, and page address. Returns an error message if the
        page cannot be resolved.

    Examples:
        get_page_info(0xffff888100000000)
        get_page_info(256, source="pfn")
    """
    prog = state.require_loaded()
    from drgn.helpers.linux.mm import (
        PageCompound,
        PageSlab,
        compound_order,
        decode_page_flags,
        pfn_to_page,
        virt_to_page,
    )

    addr = address if isinstance(address, int) else int(address, 0)

    try:
        match source:
            case "virt":
                page = virt_to_page(prog, addr)
            case "pfn":
                page = pfn_to_page(prog, addr)
            case _:
                return f"Unknown source '{source}'. Use: virt, pfn."

        lines = [f"Page: {page}"]
        lines.append(f"Flags: {decode_page_flags(page)}")
        lines.append(f"Slab: {PageSlab(page)}")
        is_compound = PageCompound(page)
        lines.append(f"Compound: {is_compound}")
        if is_compound:
            lines.append(f"Compound order: {compound_order(page).value_()}")
        return "\n".join(lines)
    except drgn.FaultError as e:
        return f"Cannot access page at {addr:#x}: {e}"


@mcp.tool()
def get_slab_info(cache_name: str = "") -> str:
    """Get information about kernel slab caches.

    Use this to inspect the slab allocator's state, either listing all caches
    with usage statistics or showing details for a specific cache by name.

    Args:
        cache_name: Optional name of a specific slab cache to inspect
            (e.g., "task_struct", "kmalloc-256"). If empty, lists all caches
            with summary usage stats.

    Returns:
        If cache_name is empty: a multi-line summary of all slab caches with
        object counts and slab counts.
        If cache_name is provided: detailed usage for that specific cache.
        Returns an error message if the named cache is not found.

    Examples:
        get_slab_info()
        get_slab_info("task_struct")
    """
    prog = state.require_loaded()
    from drgn.helpers.linux.slab import (
        find_slab_cache,
        for_each_slab_cache,
        slab_cache_usage,
        slab_total_usage,
    )

    if cache_name:
        cache = find_slab_cache(prog, cache_name)
        if cache is None:
            return f"No slab cache found with name '{cache_name}'"
        usage = slab_cache_usage(cache)
        name = cache.name.string_().decode()
        return (
            f"Cache: {name}\n"
            f"Object size: {cache.size.value_()}\n"
            f"Slabs: {usage.num_slabs}\n"
            f"Objects: {usage.num_objs}\n"
            f"Free objects: {usage.free_objs}"
        )

    lines = []
    try:
        total = slab_total_usage(prog)
        lines.append(
            f"Total slab pages: reclaimable={total.reclaimable_pages}, "
            f"unreclaimable={total.unreclaimable_pages}"
        )
    except drgn.FaultError as e:
        lines.append(f"Total slab pages: <error: {e}>")
    lines.append("")
    for cache in for_each_slab_cache(prog):
        name = cache.name.string_().decode()
        try:
            usage = slab_cache_usage(cache)
            lines.append(
                f"{name}: {usage.num_objs} objs, "
                f"{usage.free_objs} free, {usage.num_slabs} slabs"
            )
        except drgn.FaultError:
            lines.append(f"{name}: <error reading usage>")
    return "\n".join(lines)


@mcp.tool()
def get_vma_info(
    pid: int,
    address: int | str | None = None,
    limit: int = 100,
) -> str:
    """Inspect virtual memory areas (VMAs) for a kernel task.

    Use this to list all VMAs in a process's address space, or find the
    specific VMA containing a given address. Useful for diagnosing page
    faults, memory mapping issues, or understanding process memory layout.

    Args:
        pid: The PID of the task whose VMAs to inspect.
        address: Optional address to find the containing VMA. If not provided,
            lists all VMAs for the task.
        limit: Maximum number of VMAs to return when listing all (default 100).

    Returns:
        If address is not provided: a multi-line listing of all VMAs showing
        start, end, and name/path for each.
        If address is provided: details of the VMA containing that address,
        or a message if no VMA contains it.
        Returns an error if the task or its mm_struct is not found.

    Examples:
        get_vma_info(1)
        get_vma_info(1234, address=0x7f0000000000)
    """
    prog = state.require_loaded()
    from drgn.helpers.linux.mm import for_each_vma, vma_find, vma_name
    from drgn.helpers.linux.pid import find_task as _find_task

    task = _find_task(prog, pid)
    if task is None:
        return f"No task found with PID {pid}"

    mm = task.mm.read_()
    if not mm:
        return f"Task {pid} has no mm_struct (kernel thread?)"

    if address is not None:
        addr = address if isinstance(address, int) else int(address, 0)
        vma = vma_find(mm, addr)
        if not vma:
            return f"No VMA contains address {addr:#x} in task {pid}"
        name = vma_name(vma).decode(errors="replace")
        return (
            f"VMA: {vma.vm_start.value_():#x}-{vma.vm_end.value_():#x}\n"
            f"Name: {name}\n"
            f"Flags: {vma.vm_flags.value_():#x}"
        )

    lines = []
    count = 0
    for vma in for_each_vma(mm):
        if count >= limit:
            lines.append(f"... (limited to {limit} VMAs)")
            break
        start = vma.vm_start.value_()
        end = vma.vm_end.value_()
        name = vma_name(vma).decode(errors="replace")
        lines.append(f"{start:#x}-{end:#x} {name}")
        count += 1

    return "\n".join(lines) if lines else "No VMAs found"


@mcp.tool()
def list_netdevs(limit: int = 100) -> str:
    """List all network devices with their names and IP addresses.

    Use this to see network interfaces that were active at the time of the
    crash, including their IPv4 and IPv6 addresses.

    Args:
        limit: Maximum number of devices to return.

    Returns:
        A multi-line string listing each network device with its name and
        assigned IP addresses. Appends a truncation notice if devices
        exceed limit.

    Examples:
        list_netdevs()
    """
    prog = state.require_loaded()
    from drgn.helpers.linux.net import (
        for_each_netdev,
        netdev_ipv4_addrs,
        netdev_ipv6_addrs,
        netdev_name,
    )

    lines = []
    count = 0
    for dev in for_each_netdev(prog, None):
        if count >= limit:
            lines.append(f"... (limited to {limit} devices)")
            break
        name = netdev_name(dev).decode(errors="replace")
        ipv4 = [str(a) for a in netdev_ipv4_addrs(dev)]
        ipv6 = [str(a) for a in netdev_ipv6_addrs(dev)]
        addrs = ", ".join(ipv4 + ipv6) or "no addresses"
        lines.append(f"{name}: {addrs}")
        count += 1

    return "\n".join(lines) if lines else "No network devices found"


@mcp.tool()
def list_mounts(limit: int = 200) -> str:
    """List all mounted filesystems.

    Use this to see the mount table at the time of the crash, including
    source device, mount point, and filesystem type.

    Args:
        limit: Maximum number of mounts to return.

    Returns:
        A multi-line string listing each mount with source, destination,
        and filesystem type. Appends a truncation notice if mounts
        exceed limit.

    Examples:
        list_mounts()
    """
    prog = state.require_loaded()
    from drgn.helpers.linux.fs import (
        for_each_mount,
        mount_dst,
        mount_fstype,
        mount_src,
    )

    lines = []
    count = 0
    for mnt in for_each_mount(prog, None):
        if count >= limit:
            lines.append(f"... (limited to {limit} mounts)")
            break
        src = mount_src(mnt).decode(errors="replace")
        dst = mount_dst(mnt).decode(errors="replace")
        fstype = mount_fstype(mnt).decode(errors="replace")
        lines.append(f"{src} on {dst} type {fstype}")
        count += 1

    return "\n".join(lines) if lines else "No mounts found"


@mcp.tool()
def list_files(pid: int, limit: int = 100) -> str:
    """List all open files for a kernel task by PID.

    Use this to inspect a process's open file descriptors at crash time,
    showing the file descriptor number and the file path.

    Args:
        pid: The PID of the task whose files to list.
        limit: Maximum number of files to return.

    Returns:
        A multi-line string listing each open file with its fd number and
        path. Returns an error if the task is not found.

    Examples:
        list_files(1)
        list_files(1234, limit=50)
    """
    prog = state.require_loaded()
    from drgn.helpers.linux.fs import d_path, for_each_file
    from drgn.helpers.linux.pid import find_task as _find_task

    task = _find_task(prog, pid)
    if task is None:
        return f"No task found with PID {pid}"

    lines = []
    count = 0
    for fd, file in for_each_file(task):
        if count >= limit:
            lines.append(f"... (limited to {limit} files)")
            break
        try:
            path = d_path(file).decode(errors="replace")
        except drgn.FaultError:
            path = "<fault>"
        lines.append(f"fd={fd} {path}")
        count += 1

    return "\n".join(lines) if lines else "No open files"


@mcp.tool()
def get_lock_info(lock_expr: str) -> str:
    """Inspect the state of a kernel lock (mutex or read-write semaphore).

    Use this to determine who holds a lock and whether it is contended.
    Accepts a drgn expression that evaluates to a mutex or rwsem object.

    Args:
        lock_expr: A drgn Python expression evaluating to a struct mutex
            or struct rw_semaphore (e.g., "prog['my_mutex']",
            "task.mm.mmap_lock").

    Returns:
        Lock state information: owner task (if any), and for rwsem whether
        it is read-locked, write-locked, or unlocked. Returns an error
        if the expression cannot be evaluated or the type is unrecognized.

    Examples:
        get_lock_info("prog['namespace_sem']")
        get_lock_info("find_task(prog, 1).mm.mmap_lock")
    """
    state.require_loaded()
    from drgn.helpers.linux.locking import (
        mutex_owner,
        rwsem_locked,
        rwsem_owner,
    )

    try:
        lock_obj = _eval_expr(lock_expr)
    except (drgn.FaultError, LookupError, ValueError, SyntaxError, AttributeError, TypeError) as e:
        return f"Error evaluating lock expression: {e}"

    type_name = lock_obj.type_.type_name()

    # Substring matching instead of match/case because type_name may
    # include pointer qualifiers (e.g., "struct mutex *").
    try:
        if "mutex" in type_name:
            owner = mutex_owner(lock_obj)
            if not owner:
                return "Mutex: unlocked (no owner)"
            pid = owner.pid.value_()
            comm = owner.comm.string_().decode(errors="replace")
            return f"Mutex: locked by pid={pid} comm={comm}"

        if "rw_semaphore" in type_name:
            locked = rwsem_locked(lock_obj)
            owner = rwsem_owner(lock_obj)
            lines = [f"RW semaphore: {locked.name}"]
            if owner and owner.value_():
                pid = owner.pid.value_()
                comm = owner.comm.string_().decode(errors="replace")
                lines.append(f"Owner: pid={pid} comm={comm}")
            return "\n".join(lines)
    except drgn.FaultError as e:
        return f"Memory fault reading lock state: {e}"

    return f"Unrecognized lock type: {type_name}. Expected mutex or rw_semaphore."


@mcp.tool()
def list_irqs(limit: int = 256) -> str:
    """List all allocated interrupt descriptors.

    Use this to see IRQ numbers, controller chip names, and action handler
    names for all interrupts in the system.

    Args:
        limit: Maximum number of IRQs to return.

    Returns:
        A multi-line string listing each IRQ with its number, chip name,
        and registered action names.

    Examples:
        list_irqs()
    """
    prog = state.require_loaded()
    from drgn.helpers.linux.irq import (
        for_each_irq_desc,
        irq_desc_action_names,
        irq_desc_chip_name,
    )

    lines = []
    count = 0
    for irq_num, desc in for_each_irq_desc(prog):
        if count >= limit:
            lines.append(f"... (limited to {limit} IRQs)")
            break
        chip = irq_desc_chip_name(desc)
        chip_str = chip.decode(errors="replace") if chip else "none"
        actions = irq_desc_action_names(desc)
        action_str = ", ".join(
            a.decode(errors="replace") for a in actions
        ) if actions else "none"
        lines.append(f"IRQ {irq_num}: chip={chip_str} actions=[{action_str}]")
        count += 1

    return "\n".join(lines) if lines else "No IRQs found"


@mcp.tool()
def list_bpf(bpf_type: str = "progs", limit: int = 100) -> str:
    """List BPF programs, maps, or links loaded in the kernel.

    Use this to inspect the BPF subsystem state at crash time.

    Args:
        bpf_type: What to list. Must be one of:
            - "progs": BPF programs (default)
            - "maps": BPF maps
            - "links": BPF links
        limit: Maximum number of entries to return.

    Returns:
        A multi-line string listing BPF objects with their IDs and types.
        Returns an error for unknown bpf_type values.

    Examples:
        list_bpf()
        list_bpf("maps")
        list_bpf("links")
    """
    prog = state.require_loaded()
    from drgn.helpers.linux.bpf import (
        bpf_link_for_each,
        bpf_map_for_each,
        bpf_prog_for_each,
    )

    lines = []
    count = 0

    match bpf_type:
        case "progs":
            for bpf_prog in bpf_prog_for_each(prog):
                if count >= limit:
                    lines.append(f"... (limited to {limit} programs)")
                    break
                prog_id = bpf_prog.aux.id.value_()
                prog_type = bpf_prog.type.value_()
                lines.append(f"prog id={prog_id} type={prog_type}")
                count += 1
        case "maps":
            for bpf_map in bpf_map_for_each(prog):
                if count >= limit:
                    lines.append(f"... (limited to {limit} maps)")
                    break
                map_id = bpf_map.id.value_()
                map_type = bpf_map.map_type.value_()
                name = bpf_map.name.string_().decode(errors="replace")
                lines.append(f"map id={map_id} type={map_type} name={name}")
                count += 1
        case "links":
            for bpf_link in bpf_link_for_each(prog):
                if count >= limit:
                    lines.append(f"... (limited to {limit} links)")
                    break
                link_id = bpf_link.id.value_()
                link_type = bpf_link.type.value_()
                lines.append(f"link id={link_id} type={link_type}")
                count += 1
        case _:
            return (
                f"Unknown BPF type '{bpf_type}'. "
                "Use: progs, maps, links."
            )

    return "\n".join(lines) if lines else f"No BPF {bpf_type} found"


@mcp.tool()
def get_cpu_info() -> str:
    """Get CPU topology and online/offline state.

    Use this to understand the CPU configuration at crash time, including
    which CPUs were online and how many are possible.

    Returns:
        A multi-line string showing the number of online and possible CPUs
        and listing the individual online CPU IDs.

    Examples:
        get_cpu_info()
    """
    prog = state.require_loaded()
    from drgn.helpers.linux.cpumask import (
        for_each_online_cpu,
        num_online_cpus,
        num_possible_cpus,
    )

    online = num_online_cpus(prog)
    possible = num_possible_cpus(prog)
    online_cpus = list(for_each_online_cpu(prog))

    return (
        f"Online CPUs: {online}/{possible}\n"
        f"Online CPU IDs: {online_cpus}"
    )


@mcp.tool()
def get_kconfig(key: str = "") -> str:
    """Get the kernel build configuration (kconfig).

    Use this to check specific kernel configuration options or dump the
    entire config. Useful for understanding kernel capabilities and
    enabled features at build time.

    Args:
        key: Optional config option name to look up (e.g., "CONFIG_SMP").
            If empty, returns all configuration options.

    Returns:
        If key is provided: the value of that config option, or "not set".
        If key is empty: all config options as "KEY=VALUE" lines.

    Examples:
        get_kconfig("CONFIG_SMP")
        get_kconfig("CONFIG_PREEMPT")
        get_kconfig()
    """
    prog = state.require_loaded()
    from drgn.helpers.linux.kconfig import get_kconfig as _get_kconfig

    config = _get_kconfig(prog)

    if key:
        value = config.get(key)
        return f"{key}={value}" if value is not None else f"{key} is not set"

    lines = [f"{k}={v}" for k, v in sorted(config.items())]
    max_len = 8000
    output = "\n".join(lines)
    if len(output) > max_len:
        output = output[:max_len] + f"\n... (truncated, {len(output)} total chars)"
    return output


@mcp.tool()
def identify_address(address: int | str) -> str:
    """Identify what a memory address refers to.

    Use this to classify an unknown address. It can recognize function and
    object symbols, task structures, task stacks, allocated and free slab
    objects, page structures, and vmap regions. Particularly useful when
    examining raw pointer values found on the stack or in data structures.

    Args:
        address: The memory address to identify, as integer or hex string.

    Returns:
        A string describing what the address refers to (e.g.,
        "function symbol: schedule+0x15"), or "Unrecognized address" if
        the address cannot be identified.

    Examples:
        identify_address(0xffffffff81392370)
        identify_address("0xffff888100123000")
    """
    prog = state.require_loaded()
    from drgn.helpers.common.memory import identify_address as _identify_address

    addr = address if isinstance(address, int) else int(address, 0)
    try:
        result = _identify_address(prog, addr)
    except drgn.FaultError as e:
        return f"Cannot identify address {addr:#x}: memory fault: {e}"
    return result if result is not None else f"Unrecognized address: {addr:#x}"


@mcp.tool()
def annotated_stack(thread_id: int) -> str:
    """Get a stack trace with annotated memory values.

    DIFFERENCE FROM get_stack_trace: annotated_stack shows the actual contents
    of stack memory with each pointer value identified (symbols, slab objects,
    task structs, etc.). Use this for deep stack analysis when you need to
    understand what data is on the stack, not just the call chain.

    Args:
        thread_id: The thread ID (PID) whose stack to annotate.

    Returns:
        A multi-line annotated stack dump showing stack pointer, value, and
        identification for each entry. Truncated at 8KB. Returns an error
        if the thread is not found or the stack cannot be unwound.

    Examples:
        annotated_stack(1)
        annotated_stack(4096)
    """
    prog = state.require_loaded()
    from drgn.helpers.common.stack import print_annotated_stack

    try:
        trace = prog.stack_trace(thread_id)
    except (LookupError, ValueError) as e:
        return f"Cannot get stack trace for thread {thread_id}: {e}"

    stdout_capture = io.StringIO()
    try:
        with contextlib.redirect_stdout(stdout_capture):
            print_annotated_stack(trace)
    except drgn.FaultError as e:
        stdout_capture.write(
            f"\n... Annotation aborted due to memory fault: {e}"
        )

    output = stdout_capture.getvalue()
    max_len = 8000
    if len(output) > max_len:
        output = output[:max_len] + f"\n... (truncated, {len(output)} total chars)"
    return output if output else "Empty stack"


@mcp.tool()
def read_percpu(var_expr: str, cpu: int = -1) -> str:
    """Read a per-CPU variable for a specific CPU or all online CPUs.

    Use this to inspect per-CPU data structures like runqueues, counters,
    or per-CPU caches. Per-CPU variables have a separate instance for each
    CPU, and this tool resolves them to their actual values.

    Args:
        var_expr: A drgn Python expression evaluating to a per-CPU variable
            (e.g., "prog['runqueues']", "prog['cpu_info']").
        cpu: CPU number to read from. If -1 (default), reads from all
            online CPUs.

    Returns:
        If cpu is specified: the string representation of the per-CPU
        variable on that CPU.
        If cpu is -1: one line per online CPU showing "cpu N: value".
        Returns an error if the expression cannot be evaluated.

    Examples:
        read_percpu("prog['runqueues']", cpu=0)
        read_percpu("prog['runqueues']")
    """
    prog = state.require_loaded()
    from drgn.helpers.linux.cpumask import for_each_online_cpu
    from drgn.helpers.linux.percpu import per_cpu

    try:
        var = _eval_expr(var_expr)
    except (drgn.FaultError, LookupError, ValueError, SyntaxError, AttributeError, TypeError) as e:
        return f"Error evaluating expression: {e}"

    if cpu >= 0:
        try:
            result = per_cpu(var, cpu)
            return str(result)
        except drgn.FaultError as e:
            return f"Memory fault reading CPU {cpu}: {e}"

    lines = []
    for cpu_id in for_each_online_cpu(prog):
        try:
            result = per_cpu(var, cpu_id)
            lines.append(f"cpu {cpu_id}: {result}")
        except drgn.FaultError as e:
            lines.append(f"cpu {cpu_id}: <fault: {e}>")

    max_len = 8000
    output = "\n".join(lines) if lines else "No online CPUs found"
    if len(output) > max_len:
        output = output[:max_len] + f"\n... (truncated, {len(output)} total chars)"
    return output


def main():
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
