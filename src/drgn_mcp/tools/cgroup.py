import drgn
from drgn import container_of
from drgn.helpers.linux.cgroup import (
    cgroup_get_from_path,
    cgroup_name,
    cgroup_parent,
    cgroup_path,
    css_for_each_descendant_pre,
)

from drgn_mcp._app import mcp
from drgn_mcp.state import state


@mcp.tool()
def get_cgroup(path: str = "/") -> str:
    """Look up a cgroup by its default hierarchy path and show its details.

    Use this to inspect a specific cgroup's name, full path, and parent.
    Only cgroup v2 (unified hierarchy) is supported.

    Args:
        path: The cgroup path in the default hierarchy (e.g., "/", "/system.slice",
            "/user.slice/user-1000.slice"). Defaults to the root cgroup.

    Returns:
        A multi-line string showing the cgroup's name, full path, and parent
        path. Returns an error if the path does not exist.

    Examples:
        get_cgroup("/")
        get_cgroup("/system.slice")
    """
    prog = state.require_loaded()

    try:
        cgrp = cgroup_get_from_path(prog, path)
    except (drgn.FaultError, LookupError) as e:
        return f"Error looking up cgroup '{path}': {e}"

    if not cgrp:
        return f"No cgroup found at path '{path}'"

    name = cgroup_name(cgrp).decode(errors="replace")
    full_path = cgroup_path(cgrp).decode(errors="replace")
    parent = cgroup_parent(cgrp)
    if parent:
        parent_path = cgroup_path(parent).decode(errors="replace")
    else:
        parent_path = "(none)"

    return f"Name: {name}\nPath: {full_path}\nParent: {parent_path}"


@mcp.tool()
def list_cgroups(path: str = "/", limit: int = 100, offset: int = 0) -> str:
    """List cgroups in the default hierarchy starting from a given path.

    Traverses the cgroup tree in pre-order from the specified root path,
    listing all descendant cgroups. Only cgroup v2 is supported.

    Args:
        path: The root cgroup path to start traversal from (e.g., "/",
            "/system.slice"). Defaults to the root.
        limit: Maximum number of cgroups to return.
        offset: Number of cgroups to skip (for pagination).

    Returns:
        A multi-line string listing each cgroup's full path. Appends a
        truncation notice if cgroups exceed limit. Returns an error if
        the starting path does not exist.

    Examples:
        list_cgroups("/")
        list_cgroups("/system.slice", limit=50)
    """
    prog = state.require_loaded()
    offset = max(0, offset)
    limit = max(1, limit)

    try:
        cgrp = cgroup_get_from_path(prog, path)
    except (drgn.FaultError, LookupError) as e:
        return f"Error looking up cgroup '{path}': {e}"

    if not cgrp:
        return f"No cgroup found at path '{path}'"

    lines: list[str] = []
    skipped = 0
    count = 0
    try:
        for css in css_for_each_descendant_pre(cgrp.self.address_of_()):
            if skipped < offset:
                skipped += 1
                continue
            if count >= limit:
                lines.append(
                    f"... (limited to {limit} cgroups, use offset={offset + limit} for next page)"
                )
                break
            child_cgrp = container_of(css, "struct cgroup", "self")
            child_path = cgroup_path(child_cgrp).decode(errors="replace")
            lines.append(child_path)
            count += 1
    except drgn.FaultError as e:
        lines.append(f"... Traversal aborted due to memory fault: {e}")

    return "\n".join(lines) if lines else "No cgroups found"
