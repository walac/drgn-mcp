import drgn
from drgn.helpers.linux.sysfs import (
    kobject_path,
    sysfs_listdir,
    sysfs_lookup,
    sysfs_lookup_kobject,
    sysfs_lookup_node,
)

from drgn_mcp._app import mcp
from drgn_mcp.state import state
from drgn_mcp.tools._helpers import paginated_lines


@mcp.tool()
def list_sysfs(path: str = "/sys", limit: int = 200, offset: int = 0) -> str:
    """List the children of a sysfs directory from the dumped kernel.

    Walks the in-memory kernfs tree (not the host /sys). Use this to explore
    devices, modules, classes, and buses as they existed at crash time.
    Attribute file *contents* are not stored in kernfs; use lookup_sysfs to
    resolve a path to the underlying kernel object, then read struct fields.

    Args:
        path: Sysfs directory, absolute (``/sys/block``) or relative to
            ``/sys`` (``block``). Defaults to the sysfs root.
        limit: Maximum number of entries to return.
        offset: Number of entries to skip (for pagination).

    Returns:
        One child name per line. Appends a truncation notice if entries
        exceed limit. Returns an error if the path is missing or is not
        a directory.

    Examples:
        list_sysfs()
        list_sysfs("/sys/block")
        list_sysfs("module", limit=50)
    """
    prog = state.require_loaded()

    try:
        try:
            names = sysfs_listdir(prog, path)
        except ValueError:
            if not sysfs_lookup_node(prog, path):
                return f"No sysfs entry at path '{path}'"
            return f"'{path}' is not a sysfs directory"
    except drgn.FaultError as e:
        return f"Memory fault listing sysfs '{path}': {e}"

    def fmt(name: bytes) -> str:
        return name.decode(errors="replace")

    lines = paginated_lines(names, fmt, offset=offset, limit=limit, label="entries")
    return "\n".join(lines) if lines else "No sysfs entries"


@mcp.tool()
def lookup_sysfs(path: str) -> str:
    """Resolve a sysfs path to the kernel object it represents.

    Looks up the kernfs node in the dumped kernel and, when possible,
    returns the containing structure (device, class, bus, driver, or
    module kobject). Does not read sysfs attribute file contents.

    Args:
        path: Sysfs path, absolute (``/sys/block/nvme0n1``) or relative
            to ``/sys`` (``block/nvme0n1``).

    Returns:
        Type name, pointer address, and canonical ``/sys/...`` path when
        a kobject is available. Returns an error if the path does not
        exist.

    Examples:
        lookup_sysfs("/sys/block/nvme0n1")
        lookup_sysfs("module/ext4")
    """
    prog = state.require_loaded()

    try:
        obj = sysfs_lookup(prog, path)
        if not obj:
            if sysfs_lookup_node(prog, path):
                return f"Sysfs entry at path '{path}' has no associated kernel object"
            return f"No sysfs entry at path '{path}'"
        type_name = obj.type_.type_name()
        address = obj.value_()
    except drgn.FaultError as e:
        return f"Memory fault looking up sysfs '{path}': {e}"

    lines = [f"Type: {type_name}", f"Address: {address:#x}"]

    try:
        kobj = sysfs_lookup_kobject(prog, path)
        if kobj:
            canonical = kobject_path(kobj).decode(errors="replace")
            lines.append(f"Sysfs path: {canonical}")
    except drgn.FaultError as e:
        lines.append(f"Sysfs path: <fault: {e}>")

    return "\n".join(lines)
