"""Every public tool except load_core_dump must refuse calls before a dump is loaded."""

from collections.abc import Callable
from typing import Any

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from drgn_mcp._app import mcp
from drgn_mcp.state import state
from drgn_mcp.tools import (
    bpf,
    cgroup,
    core,
    fs,
    inspection,
    memory,
    net,
    sched,
    sysinfo,
    traversal,
    utils,
)

UNLOADED_MESSAGE = "No program loaded. Use load_core_dump first."

# The only public tool that may run with state.prog unset.
_LOAD_TOOL = "load_core_dump"

# Every registered sync tool except load_core_dump. Each row is
# (name, function, make_args): name matches mcp.list_tools() (pytest id +
# coverage), function is the real tool, make_args is a lambda returning dummy
# positional args that only need to match the signature. require_loaded() must
# raise ToolError before those values are interpreted. Async tools belong in
# _ASYNC_UNLOADED_TOOLS.
_SYNC_UNLOADED_TOOLS: list[tuple[str, Callable[..., str], Callable[[], tuple[Any, ...]]]] = [
    ("list_helpers", core.list_helpers, lambda: ()),
    ("get_program_info", core.get_program_info, lambda: ()),
    ("get_crashed_thread", inspection.get_crashed_thread, lambda: ()),
    ("get_stack_trace", inspection.get_stack_trace, lambda: (1,)),
    ("list_threads", inspection.list_threads, lambda: ()),
    ("get_thread", inspection.get_thread, lambda: (1,)),
    ("lookup_object", inspection.lookup_object, lambda: ("jiffies",)),
    ("lookup_type", inspection.lookup_type, lambda: ("struct task_struct",)),
    ("lookup_symbol", inspection.lookup_symbol, lambda: ("schedule",)),
    ("list_tasks", inspection.list_tasks, lambda: ()),
    ("find_task", inspection.find_task, lambda: (1,)),
    ("list_modules", inspection.list_modules, lambda: ()),
    ("get_panic_info", inspection.get_panic_info, lambda: ()),
    ("read_memory", memory.read_memory, lambda: (0,)),
    ("get_dmesg", memory.get_dmesg, lambda: ()),
    ("search_memory", memory.search_memory, lambda: ("placeholder",)),
    ("get_source_location", memory.get_source_location, lambda: (0,)),
    ("read_typed_memory", memory.read_typed_memory, lambda: (0,)),
    ("translate_address", memory.translate_address, lambda: (0,)),
    ("get_page_info", memory.get_page_info, lambda: (0,)),
    ("get_slab_info", memory.get_slab_info, lambda: ()),
    ("get_vma_info", memory.get_vma_info, lambda: (1,)),
    ("get_memory_summary", memory.get_memory_summary, lambda: ()),
    ("get_task_memory", memory.get_task_memory, lambda: (1,)),
    ("read_process_memory", memory.read_process_memory, lambda: (1, 0)),
    ("traverse_list", traversal.traverse_list, lambda: ("head", "struct task_struct", "sibling")),
    (
        "traverse_rbtree",
        traversal.traverse_rbtree,
        lambda: ("root", "struct vm_area_struct", "vm_rb"),
    ),
    ("traverse_xarray", traversal.traverse_xarray, lambda: ("xa",)),
    ("traverse_idr", traversal.traverse_idr, lambda: ("idr", "struct cgroup_root")),
    ("get_cpu_info", sched.get_cpu_info, lambda: ()),
    ("list_irqs", sched.list_irqs, lambda: ()),
    ("list_timers", sched.list_timers, lambda: ()),
    ("get_running_tasks", sched.get_running_tasks, lambda: ()),
    ("get_runqueue", sched.get_runqueue, lambda: (0,)),
    ("get_loadavg", sched.get_loadavg, lambda: ()),
    ("get_lock_info", sysinfo.get_lock_info, lambda: ("lock",)),
    ("get_kconfig", sysinfo.get_kconfig, lambda: ()),
    ("get_cmdline", sysinfo.get_cmdline, lambda: (1,)),
    ("get_environ", sysinfo.get_environ, lambda: (1,)),
    ("list_mounts", fs.list_mounts, lambda: ()),
    ("list_files", fs.list_files, lambda: (1,)),
    ("list_netdevs", net.list_netdevs, lambda: ()),
    ("get_cgroup", cgroup.get_cgroup, lambda: ()),
    ("list_cgroups", cgroup.list_cgroups, lambda: ()),
    ("list_bpf", bpf.list_bpf, lambda: ()),
    ("get_bpf_prog", bpf.get_bpf_prog, lambda: (1,)),
    ("get_bpf_map", bpf.get_bpf_map, lambda: (1,)),
    ("get_bpf_prog_maps", bpf.get_bpf_prog_maps, lambda: (1,)),
    ("get_cgroup_bpf", bpf.get_cgroup_bpf, lambda: ()),
    ("identify_address", utils.identify_address, lambda: (0,)),
    ("annotated_stack", utils.annotated_stack, lambda: (1,)),
    ("read_percpu", utils.read_percpu, lambda: ("prog['runqueues']",)),
]

_ASYNC_UNLOADED_TOOLS: list[tuple[str, Callable[..., Any], Callable[[], tuple[Any, ...]]]] = [
    ("eval_expression", core.eval_expression, lambda: ("1",)),
]


def _covered_tool_names() -> set[str]:
    return {name for name, _, _ in _SYNC_UNLOADED_TOOLS} | {
        name for name, _, _ in _ASYNC_UNLOADED_TOOLS
    }


async def test_unloaded_table_covers_every_registered_tool_except_load_core_dump() -> None:
    registered = {tool.name for tool in await mcp.list_tools()}
    assert _LOAD_TOOL in registered
    assert _covered_tool_names() == registered - {_LOAD_TOOL}


@pytest.mark.parametrize(
    ("tool", "make_args"),
    [(fn, make_args) for _, fn, make_args in _SYNC_UNLOADED_TOOLS],
    ids=[name for name, _, _ in _SYNC_UNLOADED_TOOLS],
)
def test_sync_tool_raises_before_using_placeholder_args(
    tool: Callable[..., str],
    make_args: Callable[[], tuple[Any, ...]],
) -> None:
    assert state.prog is None
    with pytest.raises(ToolError) as excinfo:
        tool(*make_args())
    assert str(excinfo.value) == UNLOADED_MESSAGE


@pytest.mark.parametrize(
    ("tool", "make_args"),
    [(fn, make_args) for _, fn, make_args in _ASYNC_UNLOADED_TOOLS],
    ids=[name for name, _, _ in _ASYNC_UNLOADED_TOOLS],
)
async def test_async_tool_raises_before_using_placeholder_args(
    tool: Callable[..., Any],
    make_args: Callable[[], tuple[Any, ...]],
) -> None:
    assert state.prog is None
    with pytest.raises(ToolError) as excinfo:
        await tool(*make_args())
    assert str(excinfo.value) == UNLOADED_MESSAGE
