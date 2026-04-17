from typing import Any

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
    return eval(  # noqa: S307
        compile(expr, "<eval>", "eval"), state.globals
    )
