import contextlib
import io
import traceback

from drgn_mcp._app import mcp
from drgn_mcp.state import state


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
