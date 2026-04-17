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

## Example Session

A typical workflow when debugging a kernel crash dump:

**1. Load the crash dump**
> Load the vmcore at /var/crash/vmcore using the vmlinux at
> /usr/lib/debug/boot/vmlinux-6.1.0

**2. Get basic crash info**
> Why did the kernel panic? Show me the panic message and the crashed
> thread.

**3. Inspect the stack**
> Give me the annotated stack trace for the crashed thread and show
> the exact source code line where the fault occurred.

**4. Check system state**
> Are there any other tasks stuck in uninterruptible sleep (D state)?

**5. Deep dive into memory**
> Inspect the VMAs for the crashed task. Does the faulting address
> belong to a valid mapping?

**6. Check locks and allocator state**
> Check the slab stats for kmalloc-512 and see if the crashed thread
> was holding any mutexes.

**7. Traverse kernel data structures**
> Walk the children list of init_task and show me the PID and comm
> for each child process.

## Tools

| Tool               | Description                                      |
|--------------------|--------------------------------------------------|
| load_core_dump     | Load vmcore + optional vmlinux                   |
| eval_expression    | Evaluate arbitrary drgn Python expressions       |
| list_helpers       | Discover available drgn helper functions         |
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
| get_memory_summary | System-wide RAM, committed memory, commit limit  |
| get_task_memory    | Per-task RSS and virtual size                    |
| read_process_memory| Read userspace memory via task page tables       |
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
| list_bpf           | List BPF programs, maps, links, or BTF objects   |
| get_bpf_prog       | Look up a BPF program by ID                      |
| get_bpf_map        | Look up a BPF map by ID                          |
| get_bpf_prog_maps  | List maps used by a BPF program                  |
| get_cgroup_bpf     | List BPF programs attached to a cgroup           |
| get_cpu_info       | CPU topology and online/offline state            |
| get_kconfig        | Kernel build configuration                       |
| get_cmdline        | Get process command line arguments               |
| get_environ        | Get process environment variables                |
| list_timers        | List timer wheel and hrtimer entries             |
| get_cgroup         | Look up a cgroup by path                         |
| list_cgroups       | Traverse the cgroup tree                         |
| get_running_tasks  | Show task running on each CPU                    |
| get_runqueue       | Inspect CPU runqueue (CFS + RT tasks)            |
| get_loadavg        | System load averages (1/5/15 min)                |
| identify_address   | Classify what a memory address refers to         |
| annotated_stack    | Stack trace with annotated memory values         |
| read_percpu        | Read per-CPU variables                           |
