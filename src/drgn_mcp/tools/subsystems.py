import drgn

from drgn_mcp._app import mcp, _eval_expr
from drgn_mcp.state import state


@mcp.tool()
def list_netdevs(limit: int = 100) -> str:
    """List all network devices with their names and IP addresses.

    Use this to see network interfaces that were active at the time of the
    crash, including their IPv4 and IPv6 addresses.

    Args:
        limit: Maximum number of devices to return.

    Returns:
        A multi-line string listing each network device with its name and
        assigned IP addresses. Appends a truncation notice if devices
        exceed limit.

    Examples:
        list_netdevs()
    """
    prog = state.require_loaded()
    from drgn.helpers.linux.net import (
        for_each_netdev,
        netdev_ipv4_addrs,
        netdev_ipv6_addrs,
        netdev_name,
    )

    lines = []
    count = 0
    for dev in for_each_netdev(prog, None):
        if count >= limit:
            lines.append(f"... (limited to {limit} devices)")
            break
        name = netdev_name(dev).decode(errors="replace")
        ipv4 = [str(a) for a in netdev_ipv4_addrs(dev)]
        ipv6 = [str(a) for a in netdev_ipv6_addrs(dev)]
        addrs = ", ".join(ipv4 + ipv6) or "no addresses"
        lines.append(f"{name}: {addrs}")
        count += 1

    return "\n".join(lines) if lines else "No network devices found"


@mcp.tool()
def list_mounts(limit: int = 200) -> str:
    """List all mounted filesystems.

    Use this to see the mount table at the time of the crash, including
    source device, mount point, and filesystem type.

    Args:
        limit: Maximum number of mounts to return.

    Returns:
        A multi-line string listing each mount with source, destination,
        and filesystem type. Appends a truncation notice if mounts
        exceed limit.

    Examples:
        list_mounts()
    """
    prog = state.require_loaded()
    from drgn.helpers.linux.fs import (
        for_each_mount,
        mount_dst,
        mount_fstype,
        mount_src,
    )

    lines = []
    count = 0
    for mnt in for_each_mount(prog, None):
        if count >= limit:
            lines.append(f"... (limited to {limit} mounts)")
            break
        src = mount_src(mnt).decode(errors="replace")
        dst = mount_dst(mnt).decode(errors="replace")
        fstype = mount_fstype(mnt).decode(errors="replace")
        lines.append(f"{src} on {dst} type {fstype}")
        count += 1

    return "\n".join(lines) if lines else "No mounts found"


@mcp.tool()
def list_files(pid: int, limit: int = 100) -> str:
    """List all open files for a kernel task by PID.

    Use this to inspect a process's open file descriptors at crash time,
    showing the file descriptor number and the file path.

    Args:
        pid: The PID of the task whose files to list.
        limit: Maximum number of files to return.

    Returns:
        A multi-line string listing each open file with its fd number and
        path. Returns an error if the task is not found.

    Examples:
        list_files(1)
        list_files(1234, limit=50)
    """
    prog = state.require_loaded()
    from drgn.helpers.linux.fs import d_path, for_each_file
    from drgn.helpers.linux.pid import find_task as _find_task

    task = _find_task(prog, pid)
    if task is None:
        return f"No task found with PID {pid}"

    lines = []
    count = 0
    for fd, file in for_each_file(task):
        if count >= limit:
            lines.append(f"... (limited to {limit} files)")
            break
        try:
            path = d_path(file).decode(errors="replace")
        except drgn.FaultError:
            path = "<fault>"
        lines.append(f"fd={fd} {path}")
        count += 1

    return "\n".join(lines) if lines else "No open files"


@mcp.tool()
def get_lock_info(lock_expr: str) -> str:
    """Inspect the state of a kernel lock (mutex or read-write semaphore).

    Use this to determine who holds a lock and whether it is contended.
    Accepts a drgn expression that evaluates to a mutex or rwsem object.

    Args:
        lock_expr: A drgn Python expression evaluating to a struct mutex
            or struct rw_semaphore (e.g., "prog['my_mutex']",
            "task.mm.mmap_lock").

    Returns:
        Lock state information: owner task (if any), and for rwsem whether
        it is read-locked, write-locked, or unlocked. Returns an error
        if the expression cannot be evaluated or the type is unrecognized.

    Examples:
        get_lock_info("prog['namespace_sem']")
        get_lock_info("find_task(prog, 1).mm.mmap_lock")
    """
    state.require_loaded()
    from drgn.helpers.linux.locking import (
        mutex_owner,
        rwsem_locked,
        rwsem_owner,
    )

    try:
        lock_obj = _eval_expr(lock_expr)
    except (drgn.FaultError, LookupError, ValueError, SyntaxError, AttributeError, TypeError) as e:
        return f"Error evaluating lock expression: {e}"

    type_name = lock_obj.type_.type_name()

    # Substring matching instead of match/case because type_name may
    # include pointer qualifiers (e.g., "struct mutex *").
    try:
        if "mutex" in type_name:
            owner = mutex_owner(lock_obj)
            if not owner:
                return "Mutex: unlocked (no owner)"
            pid = owner.pid.value_()
            comm = owner.comm.string_().decode(errors="replace")
            return f"Mutex: locked by pid={pid} comm={comm}"

        if "rw_semaphore" in type_name:
            locked = rwsem_locked(lock_obj)
            owner = rwsem_owner(lock_obj)
            lines = [f"RW semaphore: {locked.name}"]
            if owner and owner.value_():
                pid = owner.pid.value_()
                comm = owner.comm.string_().decode(errors="replace")
                lines.append(f"Owner: pid={pid} comm={comm}")
            return "\n".join(lines)
    except drgn.FaultError as e:
        return f"Memory fault reading lock state: {e}"

    return f"Unrecognized lock type: {type_name}. Expected mutex or rw_semaphore."


@mcp.tool()
def list_irqs(limit: int = 256) -> str:
    """List all allocated interrupt descriptors.

    Use this to see IRQ numbers, controller chip names, and action handler
    names for all interrupts in the system.

    Args:
        limit: Maximum number of IRQs to return.

    Returns:
        A multi-line string listing each IRQ with its number, chip name,
        and registered action names.

    Examples:
        list_irqs()
    """
    prog = state.require_loaded()
    from drgn.helpers.linux.irq import (
        for_each_irq_desc,
        irq_desc_action_names,
        irq_desc_chip_name,
    )

    lines = []
    count = 0
    for irq_num, desc in for_each_irq_desc(prog):
        if count >= limit:
            lines.append(f"... (limited to {limit} IRQs)")
            break
        chip = irq_desc_chip_name(desc)
        chip_str = chip.decode(errors="replace") if chip else "none"
        actions = irq_desc_action_names(desc)
        action_str = ", ".join(
            a.decode(errors="replace") for a in actions
        ) if actions else "none"
        lines.append(f"IRQ {irq_num}: chip={chip_str} actions=[{action_str}]")
        count += 1

    return "\n".join(lines) if lines else "No IRQs found"


@mcp.tool()
def list_bpf(bpf_type: str = "progs", limit: int = 100) -> str:
    """List BPF programs, maps, or links loaded in the kernel.

    Use this to inspect the BPF subsystem state at crash time.

    Args:
        bpf_type: What to list. Must be one of:
            - "progs": BPF programs (default)
            - "maps": BPF maps
            - "links": BPF links
        limit: Maximum number of entries to return.

    Returns:
        A multi-line string listing BPF objects with their IDs and types.
        Returns an error for unknown bpf_type values.

    Examples:
        list_bpf()
        list_bpf("maps")
        list_bpf("links")
    """
    prog = state.require_loaded()
    from drgn.helpers.linux.bpf import (
        bpf_link_for_each,
        bpf_map_for_each,
        bpf_prog_for_each,
    )

    lines = []
    count = 0

    match bpf_type:
        case "progs":
            for bpf_prog in bpf_prog_for_each(prog):
                if count >= limit:
                    lines.append(f"... (limited to {limit} programs)")
                    break
                prog_id = bpf_prog.aux.id.value_()
                prog_type = bpf_prog.type.value_()
                lines.append(f"prog id={prog_id} type={prog_type}")
                count += 1
        case "maps":
            for bpf_map in bpf_map_for_each(prog):
                if count >= limit:
                    lines.append(f"... (limited to {limit} maps)")
                    break
                map_id = bpf_map.id.value_()
                map_type = bpf_map.map_type.value_()
                name = bpf_map.name.string_().decode(errors="replace")
                lines.append(f"map id={map_id} type={map_type} name={name}")
                count += 1
        case "links":
            for bpf_link in bpf_link_for_each(prog):
                if count >= limit:
                    lines.append(f"... (limited to {limit} links)")
                    break
                link_id = bpf_link.id.value_()
                link_type = bpf_link.type.value_()
                lines.append(f"link id={link_id} type={link_type}")
                count += 1
        case _:
            return (
                f"Unknown BPF type '{bpf_type}'. "
                "Use: progs, maps, links."
            )

    return "\n".join(lines) if lines else f"No BPF {bpf_type} found"


@mcp.tool()
def get_cpu_info() -> str:
    """Get CPU topology and online/offline state.

    Use this to understand the CPU configuration at crash time, including
    which CPUs were online and how many are possible.

    Returns:
        A multi-line string showing the number of online and possible CPUs
        and listing the individual online CPU IDs.

    Examples:
        get_cpu_info()
    """
    prog = state.require_loaded()
    from drgn.helpers.linux.cpumask import (
        for_each_online_cpu,
        num_online_cpus,
        num_possible_cpus,
    )

    online = num_online_cpus(prog)
    possible = num_possible_cpus(prog)
    online_cpus = list(for_each_online_cpu(prog))

    return (
        f"Online CPUs: {online}/{possible}\n"
        f"Online CPU IDs: {online_cpus}"
    )


@mcp.tool()
def get_kconfig(key: str = "") -> str:
    """Get the kernel build configuration (kconfig).

    Use this to check specific kernel configuration options or dump the
    entire config. Useful for understanding kernel capabilities and
    enabled features at build time.

    Args:
        key: Optional config option name to look up (e.g., "CONFIG_SMP").
            If empty, returns all configuration options.

    Returns:
        If key is provided: the value of that config option, or "not set".
        If key is empty: all config options as "KEY=VALUE" lines.

    Examples:
        get_kconfig("CONFIG_SMP")
        get_kconfig("CONFIG_PREEMPT")
        get_kconfig()
    """
    prog = state.require_loaded()
    from drgn.helpers.linux.kconfig import get_kconfig as _get_kconfig

    config = _get_kconfig(prog)

    if key:
        value = config.get(key)
        return f"{key}={value}" if value is not None else f"{key} is not set"

    lines = [f"{k}={v}" for k, v in sorted(config.items())]
    max_len = 8000
    output = "\n".join(lines)
    if len(output) > max_len:
        output = output[:max_len] + f"\n... (truncated, {len(output)} total chars)"
    return output
