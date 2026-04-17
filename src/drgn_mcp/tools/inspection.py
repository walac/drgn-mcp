import itertools

import drgn

from drgn_mcp._app import mcp
from drgn_mcp.state import state


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
    return f"Crashed thread: tid={thread.tid}, name={thread.name}\n\nStack trace:\n{trace}"


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
        lines.append(f"... ({remaining} more symbols, use higher limit to see all)")
    return "\n".join(lines)


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
    from drgn.helpers.linux.pid import for_each_task
    from drgn.helpers.linux.sched import task_state_to_char

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
