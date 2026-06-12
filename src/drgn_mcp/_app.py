from typing import Any

import drgn
from mcp.server.fastmcp import FastMCP

from drgn_mcp.state import state

EVAL_ERRORS = (
    drgn.FaultError,
    LookupError,
    ValueError,
    SyntaxError,
    AttributeError,
    TypeError,
)

_INSTRUCTIONS = """
You are connected to a drgn debugger session for Linux kernel crash
dump analysis.

Workflow: always call load_core_dump first to load a vmcore and
optional vmlinux. Then investigate with the structured tools. Prefer
structured tools over eval_expression — they handle errors, truncate
output, and provide better context. Fall back to eval_expression for
anything not covered by a dedicated tool, or when you need to combine
multiple helpers in a single expression. Use list_helpers to discover
available helper functions before writing eval_expression calls.

Tool categories:
- Inspection: threads, tasks, symbols, modules, stack traces
- Memory: hex dumps, typed reads, address translation, page/slab/VMA
- Subsystems: networking, filesystems, BPF, cgroups, scheduler, IRQs,
  timers, kconfig
- Traversal: linked lists, rbtrees, xarrays, IDRs (use format_expr
  to extract specific fields instead of dumping full structs)
- Utilities: identify_address, annotated_stack, per-CPU variables

Key drgn concepts:
- Program: the debugged kernel crash dump
- Object: a typed value (variable, struct member, pointer)
- Type: a C type definition (struct, enum, typedef)
- StackTrace/StackFrame: call stack information
- Thread: a kernel thread/task

Available in eval context: prog (the Program), cast, sizeof,
container_of, offsetof, and all drgn.helpers.linux.* helpers
(for_each_task, list_for_each_entry, virt_to_phys, etc.).

Output from all tools is truncated at 8 KB to preserve context
window space. Use limits and filters to narrow results.
"""

mcp = FastMCP("drgn-mcp", instructions=_INSTRUCTIONS)


def _eval_expr(expr: str) -> Any:
    """Evaluate a drgn Python expression and return the resulting object.

    Internal helper used by tools to resolve string expressions into drgn
    Objects. Uses the global drgn state context. Intentional use of the
    eval builtin — this is a programmable debugger.

    Args:
        expr: A valid drgn Python expression string.

    Returns:
        The evaluated Python object (typically a drgn.Object).
    """
    return eval(compile(expr, "<eval>", "eval"), state.globals)
