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
    """Load a kernel crash dump for analysis.

    Args:
        core_path: Path to the core dump file (vmcore)
        vmlinux_path: Optional path to vmlinux with debug symbols
        extra_symbols: Optional list of additional symbol file paths
    """
    return state.load(core_path, vmlinux_path or None, extra_symbols or None)


@mcp.tool()
def eval_expression(expression: str) -> str:
    """Evaluate a drgn Python expression or statement.

    The expression runs in a context with these pre-loaded:
    - prog: the loaded drgn.Program
    - All drgn module attributes (cast, sizeof, container_of, etc.)
    - All drgn.helpers.common helpers
    - All drgn.helpers.linux helpers (if kernel program)

    Examples:
        "prog.crashed_thread().stack_trace()"
        "prog['jiffies']"
        "for task in for_each_task(prog): print(task.pid.value_(), task.comm.string_())"
        "print_annotated_stack(prog.stack_trace(prog.crashed_thread()))"
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
    """Get information about the loaded program (flags, platform, type)."""
    return state.format_program_info()


@mcp.tool()
def get_crashed_thread() -> str:
    """Get the thread that caused the crash/panic, including its full stack trace."""
    prog = state.require_loaded()
    thread = prog.crashed_thread()
    trace = thread.stack_trace()
    lines = [f"Crashed thread: tid={thread.tid}, name={thread.name}"]
    lines.append("\nStack trace:")
    lines.append(str(trace))
    return "\n".join(lines)


@mcp.tool()
def get_stack_trace(thread_id: int) -> str:
    """Get the stack trace for a specific thread by its thread ID."""
    prog = state.require_loaded()
    trace = prog.stack_trace(thread_id)
    return str(trace)


@mcp.tool()
def list_threads(limit: int = 100) -> str:
    """List all threads in the program. Returns tid and name for each."""
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
    """Look up a global variable, function, or constant by name."""
    prog = state.require_loaded()
    obj = prog[name]
    return str(obj)


@mcp.tool()
def lookup_type(type_name: str) -> str:
    """Look up a type definition (struct, union, enum, typedef, etc.)."""
    prog = state.require_loaded()
    t = prog.type(type_name)
    return str(t)


@mcp.tool()
def list_tasks(limit: int = 100) -> str:
    """List all tasks (processes) in the kernel. Shows PID, comm (name), and state."""
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
    """Find a task by PID and show detailed information."""
    prog = state.require_loaded()
    from drgn.helpers.linux.pid import find_task as _find_task

    task = _find_task(prog, pid)
    if task is None:
        return f"No task found with PID {pid}"
    return str(task.format_(dereference=True))


@mcp.tool()
def list_modules() -> str:
    """List all loaded kernel modules."""
    prog = state.require_loaded()
    from drgn.helpers.linux.module import for_each_module

    lines = []
    for mod in for_each_module(prog):
        name = mod.name.string_().decode()
        lines.append(name)
    return "\n".join(lines) if lines else "No modules loaded"


@mcp.tool()
def read_memory(address: int | str, size: int = 64) -> str:
    """Read raw memory at the given address.
    Address should be a hex string (e.g., '0xffffffff81000000') or integer.
    Returns a hex dump. Max 4096 bytes."""
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
    """Get the kernel log buffer (dmesg output)."""
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
    """Get information about the kernel panic/crash, including the panic message
    and the crashed thread's stack trace."""
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


def main():
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
