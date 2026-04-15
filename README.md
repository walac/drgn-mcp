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

## Tools

| Tool              | Description                                     |
|-------------------|-------------------------------------------------|
| load_core_dump    | Load vmcore + optional vmlinux                  |
| eval_expression   | Evaluate arbitrary drgn Python expressions      |
| get_program_info  | Show program flags, platform, type              |
| get_crashed_thread| Get crashed thread + stack trace                |
| get_stack_trace   | Get stack trace by thread ID                    |
| list_threads      | List all threads (tid, name)                    |
| lookup_object     | Look up global variables/functions by name      |
| lookup_type       | Look up type definitions                        |
| list_tasks        | List all kernel tasks (pid, comm, state)        |
| find_task         | Find a task by PID                              |
| list_modules      | List loaded kernel modules                      |
| read_memory       | Hex dump at an address                          |
| get_dmesg         | Get kernel log buffer                           |
| get_panic_info    | Get panic message + crashed thread trace        |
