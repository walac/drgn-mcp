import drgn
from drgn.helpers.linux.bpf import (
    bpf_btf_for_each,
    bpf_link_for_each,
    bpf_map_by_id,
    bpf_map_for_each,
    bpf_prog_by_id,
    bpf_prog_for_each,
    bpf_prog_used_maps,
    cgroup_bpf_prog_for_each,
    cgroup_bpf_prog_for_each_effective,
)
from drgn.helpers.linux.cgroup import cgroup_get_from_path

from drgn_mcp._app import mcp
from drgn_mcp.state import state


@mcp.tool()
def list_bpf(bpf_type: str = "progs", limit: int = 100, offset: int = 0) -> str:
    """List BPF programs, maps, or links loaded in the kernel.

    Use this to inspect the BPF subsystem state at crash time.

    Args:
        bpf_type: What to list. Must be one of:
            - "progs": BPF programs (default)
            - "maps": BPF maps
            - "links": BPF links
            - "btf": BTF (BPF Type Format) objects
        limit: Maximum number of entries to return.
        offset: Number of entries to skip (for pagination).

    Returns:
        A multi-line string listing BPF objects with their IDs and types.
        Returns an error for unknown bpf_type values.

    Examples:
        list_bpf()
        list_bpf("maps")
        list_bpf("links")
        list_bpf("btf")
    """
    prog = state.require_loaded()
    offset = max(0, offset)
    limit = max(1, limit)
    lines: list[str] = []
    skipped = 0
    count = 0
    hint = f"... (limited to {limit} {bpf_type}, use offset={offset + limit} for next page)"

    match bpf_type:
        case "progs":
            try:
                for bpf_prog in bpf_prog_for_each(prog):
                    if skipped < offset:
                        skipped += 1
                        continue
                    if count >= limit:
                        lines.append(hint)
                        break
                    try:
                        prog_id = bpf_prog.aux.id.value_()
                        prog_type = bpf_prog.type.value_()
                        lines.append(f"prog id={prog_id} type={prog_type}")
                    except drgn.FaultError as e:
                        lines.append(f"prog <fault: {e}>")
                    count += 1
            except drgn.FaultError as e:
                lines.append(f"... Traversal aborted due to memory fault: {e}")
        case "maps":
            try:
                for bpf_map in bpf_map_for_each(prog):
                    if skipped < offset:
                        skipped += 1
                        continue
                    if count >= limit:
                        lines.append(hint)
                        break
                    try:
                        map_id = bpf_map.id.value_()
                        map_type = bpf_map.map_type.value_()
                        name = bpf_map.name.string_().decode(errors="replace")
                        lines.append(f"map id={map_id} type={map_type} name={name}")
                    except drgn.FaultError as e:
                        lines.append(f"map <fault: {e}>")
                    count += 1
            except drgn.FaultError as e:
                lines.append(f"... Traversal aborted due to memory fault: {e}")
        case "links":
            try:
                for bpf_link in bpf_link_for_each(prog):
                    if skipped < offset:
                        skipped += 1
                        continue
                    if count >= limit:
                        lines.append(hint)
                        break
                    try:
                        link_id = bpf_link.id.value_()
                        link_type = bpf_link.type.value_()
                        lines.append(f"link id={link_id} type={link_type}")
                    except drgn.FaultError as e:
                        lines.append(f"link <fault: {e}>")
                    count += 1
            except drgn.FaultError as e:
                lines.append(f"... Traversal aborted due to memory fault: {e}")
        case "btf":
            try:
                for btf in bpf_btf_for_each(prog):
                    if skipped < offset:
                        skipped += 1
                        continue
                    if count >= limit:
                        lines.append(hint)
                        break
                    try:
                        btf_id = btf.id.value_()
                        name = btf.name.string_().decode(errors="replace") if btf.name else ""
                        lines.append(f"btf id={btf_id} name={name}")
                    except drgn.FaultError as e:
                        lines.append(f"btf <fault: {e}>")
                    count += 1
            except drgn.FaultError as e:
                lines.append(f"... Traversal aborted due to memory fault: {e}")
        case _:
            return f"Unknown BPF type '{bpf_type}'. Use: progs, maps, links, btf."

    return "\n".join(lines) if lines else f"No BPF {bpf_type} found"


@mcp.tool()
def get_bpf_prog(prog_id: int) -> str:
    """Look up a BPF program by its ID and show detailed information.

    Use this after list_bpf to inspect a specific BPF program. Shows the
    program's ID, type, and name.

    Args:
        prog_id: The numeric BPF program ID.

    Returns:
        A multi-line string showing the BPF program details. Returns an
        error if no program exists with the given ID.

    Examples:
        get_bpf_prog(42)
    """
    prog = state.require_loaded()

    try:
        bpf_prog = bpf_prog_by_id(prog, prog_id)
    except (drgn.FaultError, LookupError) as e:
        return f"Error looking up BPF program {prog_id}: {e}"

    if not bpf_prog:
        return f"No BPF program found with ID {prog_id}"

    try:
        prog_type = bpf_prog.type.value_()
        name = bpf_prog.aux.name.string_().decode(errors="replace")
    except drgn.FaultError as e:
        return f"Memory fault reading BPF program {prog_id}: {e}"
    return f"BPF program ID={prog_id}\nType: {prog_type}\nName: {name}"


@mcp.tool()
def get_bpf_map(map_id: int) -> str:
    """Look up a BPF map by its ID and show detailed information.

    Use this after list_bpf("maps") to inspect a specific BPF map.

    Args:
        map_id: The numeric BPF map ID.

    Returns:
        A multi-line string showing the BPF map details including type,
        name, key size, value size, and max entries. Returns an error
        if no map exists with the given ID.

    Examples:
        get_bpf_map(10)
    """
    prog = state.require_loaded()

    try:
        bpf_map = bpf_map_by_id(prog, map_id)
    except (drgn.FaultError, LookupError) as e:
        return f"Error looking up BPF map {map_id}: {e}"

    if not bpf_map:
        return f"No BPF map found with ID {map_id}"

    try:
        map_type = bpf_map.map_type.value_()
        name = bpf_map.name.string_().decode(errors="replace")
        key_size = bpf_map.key_size.value_()
        value_size = bpf_map.value_size.value_()
        max_entries = bpf_map.max_entries.value_()
    except drgn.FaultError as e:
        return f"Memory fault reading BPF map {map_id}: {e}"
    return (
        f"BPF map ID={map_id}\n"
        f"Type: {map_type}\n"
        f"Name: {name}\n"
        f"Key size: {key_size}\n"
        f"Value size: {value_size}\n"
        f"Max entries: {max_entries}"
    )


@mcp.tool()
def get_bpf_prog_maps(prog_id: int, limit: int = 100) -> str:
    """List the BPF maps used by a specific BPF program.

    Use this to understand the data structures a BPF program interacts
    with. Requires the BPF program ID (from list_bpf or get_bpf_prog).

    Args:
        prog_id: The numeric BPF program ID.
        limit: Maximum number of maps to return.

    Returns:
        A multi-line string listing each map with its ID, type, and name.
        Returns an error if the program is not found.

    Examples:
        get_bpf_prog_maps(42)
    """
    prog = state.require_loaded()

    try:
        bpf_prog = bpf_prog_by_id(prog, prog_id)
    except (drgn.FaultError, LookupError) as e:
        return f"Error looking up BPF program {prog_id}: {e}"

    if not bpf_prog:
        return f"No BPF program found with ID {prog_id}"

    lines = []
    count = 0
    try:
        for bpf_map in bpf_prog_used_maps(bpf_prog):
            if count >= limit:
                lines.append(f"... (limited to {limit} maps)")
                break
            map_id = bpf_map.id.value_()
            map_type = bpf_map.map_type.value_()
            name = bpf_map.name.string_().decode(errors="replace")
            lines.append(f"map id={map_id} type={map_type} name={name}")
            count += 1
    except drgn.FaultError as e:
        lines.append(f"... Traversal aborted due to memory fault: {e}")

    return "\n".join(lines) if lines else f"No maps used by BPF program {prog_id}"


@mcp.tool()
def get_cgroup_bpf(
    path: str = "/",
    attach_type: int = 0,
    effective: bool = False,
    limit: int = 100,
) -> str:
    """List BPF programs attached to a cgroup.

    Use this to see which BPF programs are attached to a specific cgroup,
    optionally filtering by attach type. Can show either directly attached
    or effective (inherited) programs.

    Args:
        path: The cgroup path in the default hierarchy (e.g., "/",
            "/system.slice"). Defaults to root.
        attach_type: The BPF attach type number (enum bpf_attach_type).
            Defaults to 0 (BPF_CGROUP_INET_INGRESS).
        effective: If True, show effective programs (including inherited
            from parent cgroups). If False, show only directly attached.
        limit: Maximum number of programs to return.

    Returns:
        A multi-line string listing BPF programs attached to the cgroup.
        Returns an error if the cgroup path is not found.

    Examples:
        get_cgroup_bpf("/")
        get_cgroup_bpf("/system.slice", attach_type=2, effective=True)
    """
    prog = state.require_loaded()

    try:
        cgrp = cgroup_get_from_path(prog, path)
    except (drgn.FaultError, LookupError) as e:
        return f"Error looking up cgroup '{path}': {e}"

    if not cgrp:
        return f"No cgroup found at path '{path}'"

    iterator = (
        cgroup_bpf_prog_for_each_effective(cgrp, attach_type)
        if effective
        else cgroup_bpf_prog_for_each(cgrp, attach_type)
    )

    lines = []
    count = 0
    try:
        for bpf_prog in iterator:
            if count >= limit:
                lines.append(f"... (limited to {limit} programs)")
                break
            try:
                prog_id = bpf_prog.aux.id.value_()
                prog_type = bpf_prog.type.value_()
                lines.append(f"prog id={prog_id} type={prog_type}")
            except drgn.FaultError as e:
                lines.append(f"prog <fault: {e}>")
            count += 1
    except drgn.FaultError as e:
        lines.append(f"... Traversal aborted due to memory fault: {e}")

    mode = "effective" if effective else "attached"
    return (
        "\n".join(lines)
        if lines
        else f"No {mode} BPF programs on cgroup '{path}' for attach type {attach_type}"
    )
