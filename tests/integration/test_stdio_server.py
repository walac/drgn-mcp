"""End-to-end contract tests for the MCP stdio server."""

import asyncio
import sys
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.types import CallToolResult, TextContent

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
UNLOADED_MESSAGE = "No program loaded. Use load_core_dump first."

EXPECTED_TOOL_NAMES = {
    "annotated_stack",
    "eval_expression",
    "find_task",
    "get_bpf_map",
    "get_bpf_prog",
    "get_bpf_prog_maps",
    "get_cgroup",
    "get_cgroup_bpf",
    "get_cmdline",
    "get_cpu_info",
    "get_crashed_thread",
    "get_dmesg",
    "get_environ",
    "get_kconfig",
    "get_loadavg",
    "get_lock_info",
    "get_memory_summary",
    "get_page_info",
    "get_panic_info",
    "get_program_info",
    "get_running_tasks",
    "get_runqueue",
    "get_slab_info",
    "get_source_location",
    "get_stack_trace",
    "get_task_memory",
    "get_thread",
    "get_vma_info",
    "identify_address",
    "list_bpf",
    "list_cgroups",
    "list_files",
    "list_helpers",
    "list_irqs",
    "list_modules",
    "list_mounts",
    "list_netdevs",
    "list_sysfs",
    "lookup_sysfs",
    "list_tasks",
    "list_threads",
    "list_timers",
    "load_core_dump",
    "lookup_object",
    "lookup_symbol",
    "lookup_type",
    "read_memory",
    "read_percpu",
    "read_process_memory",
    "read_typed_memory",
    "search_memory",
    "translate_address",
    "traverse_idr",
    "traverse_list",
    "traverse_rbtree",
    "traverse_xarray",
}


def _assert_unloaded_error(result: CallToolResult) -> None:
    assert result.is_error
    assert any(
        isinstance(content, TextContent) and UNLOADED_MESSAGE in content.text
        for content in result.content
    )


@pytest.mark.asyncio
async def test_stdio_server_protocol_contract() -> None:
    """The installed server initializes, advertises its API, and returns MCP errors."""
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "drgn_mcp.server"],
        cwd=str(REPOSITORY_ROOT),
    )

    async with asyncio.timeout(10):
        async with stdio_client(params) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                listed_tools = await session.list_tools()
                tools_by_name = {tool.name: tool for tool in listed_tools.tools}

                assert set(tools_by_name) == EXPECTED_TOOL_NAMES

                load_schema = tools_by_name["load_core_dump"].input_schema
                assert "core_path" in load_schema["required"]

                eval_schema = tools_by_name["eval_expression"].input_schema
                assert "timeout" in eval_schema["properties"]

                memory_schema = tools_by_name["read_memory"].input_schema
                assert {"address", "size"} <= memory_schema["properties"].keys()

                program_info = await session.call_tool("get_program_info")
                assert isinstance(program_info, CallToolResult)
                _assert_unloaded_error(program_info)

                memory = await session.call_tool(
                    "read_memory",
                    {"address": "0x1000", "size": 16},
                )
                assert isinstance(memory, CallToolResult)
                _assert_unloaded_error(memory)
