import drgn
from drgn.helpers.linux.fs import (
    d_path,
    for_each_file,
    for_each_mount,
    mount_dst,
    mount_fstype,
    mount_src,
)
from drgn.helpers.linux.pid import find_task as _find_task

from drgn_mcp._app import mcp
from drgn_mcp.state import state
from drgn_mcp.tools._helpers import paginated_lines


@mcp.tool()
def list_mounts(limit: int = 200, offset: int = 0) -> str:
    """List all mounted filesystems.

    Use this to see the mount table at the time of the crash, including
    source device, mount point, and filesystem type.

    Args:
        limit: Maximum number of mounts to return.
        offset: Number of mounts to skip (for pagination).

    Returns:
        A multi-line string listing each mount with source, destination,
        and filesystem type. Appends a truncation notice if mounts
        exceed limit.

    Examples:
        list_mounts()
    """
    prog = state.require_loaded()

    def fmt(mnt):
        src = mount_src(mnt).decode(errors="replace")
        dst = mount_dst(mnt).decode(errors="replace")
        fstype = mount_fstype(mnt).decode(errors="replace")
        return f"{src} on {dst} type {fstype}"

    lines = paginated_lines(
        for_each_mount(prog, None),  # type: ignore[call-overload]  # ty: ignore[no-matching-overload]
        fmt,
        offset=offset,
        limit=limit,
        label="mounts",
    )
    return "\n".join(lines) if lines else "No mounts found"


@mcp.tool()
def list_files(pid: int, limit: int = 100, offset: int = 0) -> str:
    """List all open files for a kernel task by PID.

    Use this to inspect a process's open file descriptors at crash time,
    showing the file descriptor number and the file path.

    Args:
        pid: The PID of the task whose files to list.
        limit: Maximum number of files to return.
        offset: Number of files to skip (for pagination).

    Returns:
        A multi-line string listing each open file with its fd number and
        path. Returns an error if the task is not found.

    Examples:
        list_files(1)
        list_files(1234, limit=50)
    """
    prog = state.require_loaded()

    task = _find_task(prog, pid)
    if task is None:
        return f"No task found with PID {pid}"

    def fmt(item):
        fd, file = item
        try:
            path = d_path(file).decode(errors="replace")
        except drgn.FaultError:
            path = "<fault>"
        return f"fd={fd} {path}"

    lines = paginated_lines(
        for_each_file(task), fmt, offset=offset, limit=limit, label="files"
    )
    return "\n".join(lines) if lines else "No open files"
