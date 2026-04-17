import contextlib
import io

import drgn

from drgn_mcp._app import mcp, _eval_expr
from drgn_mcp.state import state


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
        stdout_capture.write(f"\n... Annotation aborted due to memory fault: {e}")

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
    except (
        drgn.FaultError,
        LookupError,
        ValueError,
        SyntaxError,
        AttributeError,
        TypeError,
    ) as e:
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
