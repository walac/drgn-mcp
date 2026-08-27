import asyncio
import contextlib
import ctypes
import importlib
import inspect
import io
import pkgutil
import threading

import drgn.helpers.linux

from drgn_mcp._app import mcp
from drgn_mcp.state import state
from drgn_mcp.tools._helpers import truncate_output


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


_STDOUT_LIMIT = 16384


class _BoundedStringIO(io.StringIO):
    def write(self, s: str) -> int:
        if self.tell() >= _STDOUT_LIMIT:
            return len(s)
        return super().write(s[: _STDOUT_LIMIT - self.tell()])


class _EvalTimeout(BaseException):
    """Raised when eval_expression exceeds its time limit.

    Inherits from BaseException (not Exception) so that user
    expressions containing ``except Exception`` cannot swallow it.
    """


# Only one eval_expression call may have a worker thread in flight at a time,
# since they share the mutable state.globals eval context. Tracking the active
# thread (rather than blocking on a lock) lets us fail fast with a clear error
# when a previous call is still stuck, instead of a new call silently timing
# out while waiting to acquire a lock that will never be released.
_eval_state_lock = threading.Lock()
_active_eval_thread: threading.Thread | None = None

_set_async_exc = ctypes.pythonapi.PyThreadState_SetAsyncExc
_set_async_exc.argtypes = [ctypes.c_ulong, ctypes.py_object]
_set_async_exc.restype = ctypes.c_int


def _raise_in_thread(thread: threading.Thread, exc_type: type[BaseException]) -> None:
    """Inject *exc_type* into *thread* (CPython). Signal handlers only run on the main thread.

    Only interrupts at Python bytecode boundaries — a thread blocked in
    native code (e.g. a slow drgn/libkdumpfile call) will not be interrupted
    until it returns to the interpreter. There is a narrow TOCTOU window
    between the liveness check and the injection where CPython could reuse
    *thread*'s ident for an unrelated thread; this is only ever called
    immediately after the eval timeout fires, so the eval thread is
    overwhelmingly likely to still be alive, and _active_eval_thread ensures
    at most one eval worker thread exists at a time.
    """
    ident = thread.ident
    if ident is None or not thread.is_alive():
        return
    affected = _set_async_exc(ctypes.c_ulong(ident), ctypes.py_object(exc_type))
    if affected > 1:
        _set_async_exc(ctypes.c_ulong(ident), None)


def _eval_in_thread(expression: str, stdout_capture: _BoundedStringIO) -> object:
    with contextlib.redirect_stdout(stdout_capture):
        try:
            code = compile(expression, "<eval>", "eval")
            return eval(code, state.globals)
        except SyntaxError:
            code = compile(expression, "<eval>", "exec")
            exec(code, state.globals)
            return None


async def _join_thread(thread: threading.Thread, timeout: float | None) -> None:
    await asyncio.to_thread(thread.join, timeout)


def _format_eval_error(exc: BaseException, expression: str, partial_output: str) -> str:
    import drgn

    error_type = type(exc).__name__
    error_msg = str(exc)

    match exc:
        case _EvalTimeout():
            error_type = "TimeoutError"
            error_msg = "Expression exceeded the execution time limit."
            hint = (
                "The expression likely hit an infinite loop or is traversing a very large "
                "data structure. Try adding a limit to your iteration (e.g., "
                "itertools.islice) or increase the timeout parameter."
            )
        case drgn.FaultError():
            hint = (
                "A memory fault occurred, meaning the address is unmapped or the data "
                "structure is corrupted. Try accessing a different field or check if the "
                "pointer is valid with identify_address first."
            )
        case drgn.ObjectAbsentError():
            hint = (
                "The object exists in the type system but has no value "
                "(e.g., optimized out by the compiler)."
            )
        case LookupError():
            hint = (
                "The symbol, type, or variable was not found. Check the name "
                "spelling or use lookup_symbol to search."
            )
        case TypeError():
            hint = "Type mismatch. Use list_helpers to check function signatures before calling."
        case SyntaxError():
            hint = "Check the expression for syntax errors (unmatched parentheses, missing colons, etc.)."
        case NameError():
            hint = (
                "The name was not found in the eval context. Use list_helpers "
                "to see available functions, or check variable spelling."
            )
        case _:
            import traceback

            hint = ""
            error_msg = "".join(traceback.format_exception(exc))

    parts = [f"Error ({error_type}): {error_msg}", f"Expression: {expression}"]
    if hint:
        parts.append(f"Hint: {hint}")
    if partial_output:
        max_partial = 2000
        if len(partial_output) > max_partial:
            partial_output = partial_output[:max_partial] + "\n... (partial output truncated)"
        parts.append(f"Partial output before error:\n{partial_output}")

    return "\n\n".join(parts)


# async so the event loop stays free; eval runs in a worker and is interrupted
# with PyThreadState_SetAsyncExc (SIGALRM only fires on the main thread).
@mcp.tool()
async def eval_expression(expression: str, timeout: int = 30) -> str:
    """Evaluate a drgn Python expression or statement.

    Use this as a catch-all for complex queries not covered by specialized tools.
    Prefer using specialized tools (like get_thread, lookup_symbol) first.
    Use list_helpers to discover available functions in the eval context.

    The expression runs in a context with these pre-loaded:
    - prog: the loaded drgn.Program
    - All drgn module attributes (cast, sizeof, container_of, etc.)
    - All drgn.helpers.common helpers (print_annotated_stack, identify_address, etc.)
    - All drgn.helpers.linux helpers (for_each_task, list_for_each_entry, etc.)

    Commonly useful helpers available in the eval context:
    - Memory: access_process_vm, cmdline, follow_page, virt_to_phys
    - Networking: for_each_netdev, sk_fullsock, skb_shinfo, netdev_priv
    - Filesystem: d_path, fget, inode_path, path_lookup
    - Scheduler: cpu_curr, idle_task, loadavg, task_rq
    - Signals: decode_sigset, sigpending_for_each
    - Data structures: list_for_each_entry, rbtree_inorder_for_each_entry,
      xa_for_each, idr_for_each_entry, hlist_for_each_entry
    - Types: cast, sizeof, container_of, offsetof, alignof

    Args:
        expression: Python code to evaluate. Tries Python's eval() builtin first,
            falls back to the exec() builtin on SyntaxError.
        timeout: Maximum execution time in seconds. Protects against infinite
            loops from corrupted data structures. Set to 0 to disable.

    Returns:
        The captured stdout output or string representation of the result.
        Truncated at 8KB. Returns a structured error message if evaluation
        fails, including the exception type and a hint for common drgn errors.

    Examples:
        eval_expression("prog.crashed_thread().stack_trace()")
        eval_expression("prog['jiffies']")
        eval_expression("for task in for_each_task(prog): print(task.pid.value_(), task.comm.string_())")
        eval_expression("print_annotated_stack(prog.stack_trace(prog.crashed_thread()))")
    """
    state.require_loaded()

    global _active_eval_thread

    stdout_capture = _BoundedStringIO()
    result: object = None
    worker_exc: BaseException | None = None

    def worker() -> None:
        nonlocal result, worker_exc
        try:
            result = _eval_in_thread(expression, stdout_capture)
        except (Exception, _EvalTimeout) as exc:
            worker_exc = exc

    with _eval_state_lock:
        if _active_eval_thread is not None and _active_eval_thread.is_alive():
            return (
                "Error: a previous eval_expression call is still running, likely "
                "stuck in native code that could not be interrupted. The server "
                "must be restarted before eval_expression can be used again."
            )
        thread = threading.Thread(target=worker, name="drgn-eval", daemon=True)
        _active_eval_thread = thread

    thread.start()
    await _join_thread(thread, timeout if timeout > 0 else None)
    timed_out = thread.is_alive()
    if timed_out:
        _raise_in_thread(thread, _EvalTimeout)
        await _join_thread(thread, 1.0)

    if worker_exc is not None:
        return _format_eval_error(worker_exc, expression, stdout_capture.getvalue())
    if timed_out:
        return _format_eval_error(_EvalTimeout(), expression, stdout_capture.getvalue())

    output_parts = []
    stdout_str = stdout_capture.getvalue()
    if stdout_str:
        output_parts.append(stdout_str)
    if result is not None:
        output_parts.append(repr(result) if not isinstance(result, str) else result)

    output = "\n".join(output_parts) if output_parts else "(no output)"

    return truncate_output(output)


@mcp.tool()
def list_helpers(module: str = "") -> str:
    """List all drgn helper functions available in the eval_expression context.

    Use this to discover what functions are available before writing
    eval_expression calls. Shows functions grouped by module with their
    names, signatures, and brief descriptions.

    Args:
        module: Optional module filter. If provided, only show helpers from
            that module (e.g., "mm", "net", "sched", "list"). If empty,
            lists all available modules and their function counts.

    Returns:
        If module is empty: a summary of all helper modules with function
        counts.
        If module is provided: each function with its signature and
        one-line description, ready for use in eval_expression calls.

    Examples:
        list_helpers()
        list_helpers("mm")
        list_helpers("sched")
    """
    state.require_loaded()

    module_objs: dict[str, object] = {}
    modules: dict[str, list[str]] = {}
    for mod_info in pkgutil.iter_modules(
        drgn.helpers.linux.__path__,
        prefix="drgn.helpers.linux.",
    ):
        mod = importlib.import_module(mod_info.name)
        all_names = getattr(mod, "__all__", [])
        short_name = mod_info.name.rsplit(".", 1)[-1]
        modules[short_name] = sorted(all_names)
        module_objs[short_name] = mod

    if module:
        if module not in modules:
            available = ", ".join(sorted(modules.keys()))
            return f"Unknown module '{module}'. Available: {available}"
        mod = module_objs[module]
        names = modules[module]
        lines = [f"{module} ({len(names)} functions):"]
        for name in names:
            fn = getattr(mod, name, None)
            if fn is None or not callable(fn):
                lines.append(f"  {name}")
                continue
            try:
                sig = str(inspect.signature(fn))
            except (ValueError, TypeError):
                sig = "(...)"
            doc = inspect.getdoc(fn)
            first_line = doc.split("\n", 1)[0] if doc else ""
            lines.append(f"  {name}{sig}")
            if first_line:
                lines.append(f"      {first_line}")
        return truncate_output("\n".join(lines))

    lines = []
    for name in sorted(modules.keys()):
        lines.append(f"{name}: {len(modules[name])} functions")
    return "\n".join(lines)


@mcp.tool()
def get_program_info() -> str:
    """Retrieve basic information about the loaded drgn program.

    Use this to check the architecture, platform, and whether the loaded dump
    is a Linux kernel.

    Returns:
        A multi-line string detailing the program flags, platform, and kernel status.
    """
    return state.format_program_info()
