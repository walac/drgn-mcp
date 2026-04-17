# drgn-mcp

MCP server for [drgn](https://github.com/osandov/drgn), the programmable debugger.
Enables Claude (or any MCP client) to debug Linux kernel crash dumps using natural
language.

## Prerequisites

- Linux system with drgn build dependencies (`elfutils-devel`, etc.)
- Python 3.12+
- [uv](https://docs.astral.sh/uv/)

## Usage with Claude Code

Add to your `.mcp.json` (project or user level):

```json
{
  "mcpServers": {
    "drgn": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/walac/drgn-mcp", "drgn-mcp"]
    }
  }
}
```

Then ask Claude to load and investigate a crash dump:

```
Load the crash dump at /path/to/vmcore with vmlinux at /path/to/vmlinux
and tell me why the kernel crashed.
```

## Security

This server evaluates arbitrary Python code by design (via `eval_expression`
and the drgn expression helpers). It is intended to run locally over stdio
transport only. Do not expose it over network transports without
authentication — any connected client has full host access through the
Python interpreter.

## Tools

| Tool               | Description                                      |
|--------------------|--------------------------------------------------|
| load_core_dump     | Load vmcore + optional vmlinux                   |
| eval_expression    | Evaluate arbitrary drgn Python expressions       |
| get_program_info   | Show program flags, platform, type               |
| get_crashed_thread | Get crashed thread + stack trace                 |
| get_stack_trace    | Get stack trace by thread ID                     |
| list_threads       | List all threads (tid, name)                     |
| get_thread         | Get detailed thread info + stack trace           |
| lookup_object      | Look up variables/functions via DWARF debug info |
| lookup_type        | Look up C type definitions                       |
| lookup_symbol      | Search ELF symbol table by name or address       |
| list_tasks         | List all kernel tasks (pid, comm, state)         |
| find_task          | Find a task by PID                               |
| list_modules       | List loaded kernel modules                       |
| read_memory        | Hex dump at an address                           |
| read_typed_memory  | Read typed values (u8/u16/u32/u64/c_string)      |
| search_memory      | Search memory for patterns, values, or regex     |
| get_source_location| Map address to source file:line (addr2line)      |
| translate_address  | Convert between virtual/physical/page/PFN        |
| get_page_info      | Inspect page flags, compound, slab membership    |
| get_slab_info      | Slab cache usage statistics                      |
| get_vma_info       | Inspect virtual memory areas for a task          |
| get_dmesg          | Get kernel log buffer                            |
| get_panic_info     | Get panic message + crashed thread trace         |
| traverse_list      | Traverse kernel linked lists (list/hlist)        |
| traverse_rbtree    | Traverse red-black trees in sorted order         |
| traverse_xarray    | Traverse XArray index-to-pointer mappings        |
| traverse_idr       | Traverse IDR integer-to-pointer mappings         |
| list_netdevs       | List network devices with IP addresses           |
| list_mounts        | List mounted filesystems                         |
| list_files         | List open files for a process                    |
| get_lock_info      | Inspect mutex/rwsem lock state                   |
| list_irqs          | List IRQ descriptors with handlers               |
| list_bpf           | List BPF programs, maps, or links                |
| get_cpu_info       | CPU topology and online/offline state            |
| get_kconfig        | Kernel build configuration                       |
| identify_address   | Classify what a memory address refers to         |
| annotated_stack    | Stack trace with annotated memory values         |
| read_percpu        | Read per-CPU variables                           |
