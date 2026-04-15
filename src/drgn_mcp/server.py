import contextlib
import io
import traceback

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
def read_memory(address: str, size: int = 64) -> str:
    """Read raw memory at the given address.
    Address should be a hex string (e.g., '0xffffffff81000000').
    Returns a hex dump. Max 4096 bytes."""
    prog = state.require_loaded()
    addr = int(address, 0)
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
    except Exception:
        lines.append("Could not retrieve panic message")

    try:
        thread = prog.crashed_thread()
        trace = thread.stack_trace()
        lines.append(f"\nCrashed thread: tid={thread.tid}")
        lines.append(f"Stack trace:\n{trace}")
    except ValueError as e:
        lines.append(f"\nCould not retrieve crashed thread: {e}")

    return "\n".join(lines)


def main():
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
