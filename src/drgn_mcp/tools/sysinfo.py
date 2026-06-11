import drgn
from drgn.helpers.linux.kconfig import get_kconfig as _get_kconfig
from drgn.helpers.linux.locking import mutex_owner, rwsem_locked, rwsem_owner
from drgn.helpers.linux.mm import cmdline, environ
from drgn.helpers.linux.pid import find_task as _find_task

from drgn_mcp._app import EVAL_ERRORS, _eval_expr, mcp
from drgn_mcp.state import state
from drgn_mcp.tools._helpers import truncate_output


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

    try:
        lock_obj = _eval_expr(lock_expr)
    except EVAL_ERRORS as e:
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
            lines: list[str] = [f"RW semaphore: {locked.name}"]
            if owner and owner.value_():
                pid = owner.pid.value_()
                comm = owner.comm.string_().decode(errors="replace")
                lines.append(f"Owner: pid={pid} comm={comm}")
            return "\n".join(lines)
    except drgn.FaultError as e:
        return f"Memory fault reading lock state: {e}"

    return f"Unrecognized lock type: {type_name}. Expected mutex or rw_semaphore."


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

    config = _get_kconfig(prog)

    if key:
        value = config.get(key)
        return f"{key}={value}" if value is not None else f"{key} is not set"

    lines = [f"{k}={v}" for k, v in sorted(config.items())]
    return truncate_output("\n".join(lines))


@mcp.tool()
def get_cmdline(pid: int) -> str:
    """Get the command line arguments of a process.

    Use this to see how a process was invoked, including all its arguments.
    Returns None-equivalent for kernel threads (which have no userspace
    command line).

    Args:
        pid: The PID of the task whose command line to retrieve.

    Returns:
        The command line as a space-separated string of arguments.
        Returns an error if the task is not found or is a kernel thread.

    Examples:
        get_cmdline(1)
        get_cmdline(1234)
    """
    prog = state.require_loaded()

    task = _find_task(prog, pid)
    if task is None:
        return f"No task found with PID {pid}"

    try:
        args = cmdline(task)
    except drgn.FaultError as e:
        return f"Memory fault reading command line for PID {pid}: {e}"
    if args is None:
        return f"Task {pid} is a kernel thread (no command line)"

    return " ".join(a.decode(errors="replace") for a in args)


@mcp.tool()
def get_environ(pid: int) -> str:
    """Get the environment variables of a process.

    Use this to inspect the environment a process was running with at
    crash time. Returns None-equivalent for kernel threads.

    Args:
        pid: The PID of the task whose environment to retrieve.

    Returns:
        The environment variables, one per line as KEY=VALUE pairs.
        Truncated at 8KB. Returns an error if the task is not found
        or is a kernel thread.

    Examples:
        get_environ(1)
        get_environ(1234)
    """
    prog = state.require_loaded()

    task = _find_task(prog, pid)
    if task is None:
        return f"No task found with PID {pid}"

    try:
        env = environ(task)
    except drgn.FaultError as e:
        return f"Memory fault reading environment for PID {pid}: {e}"
    if env is None:
        return f"Task {pid} is a kernel thread (no environment)"

    return truncate_output("\n".join(e.decode(errors="replace") for e in env))
