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
    for dev in for_each_netdev(prog, None):  # type: ignore[call-overload]
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
    for mnt in for_each_mount(prog, None):  # type: ignore[call-overload]
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
    except (
        drgn.FaultError,
        LookupError,
        ValueError,
        SyntaxError,
        AttributeError,
        TypeError,
    ) as e:
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
        action_str = ", ".join(a.decode(errors="replace") for a in actions) if actions else "none"
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
            return f"Unknown BPF type '{bpf_type}'. Use: progs, maps, links."

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

    return f"Online CPUs: {online}/{possible}\nOnline CPU IDs: {online_cpus}"


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


@mcp.tool()
def get_cmdline(pid: int) -> str:
    """Get the command line arguments of a process.

    Use this to see how a process was invoked, including all its arguments.
    Returns None-equivalent for kernel threads (which have no userspace
    command line).

    Args:
        pid: The PID of the task whose command line to retrieve.

    Returns:
        The command line as a space-separated string of arguments.
        Returns an error if the task is not found or is a kernel thread.

    Examples:
        get_cmdline(1)
        get_cmdline(1234)
    """
    prog = state.require_loaded()
    from drgn.helpers.linux.mm import cmdline
    from drgn.helpers.linux.pid import find_task as _find_task

    task = _find_task(prog, pid)
    if task is None:
        return f"No task found with PID {pid}"

    try:
        args = cmdline(task)
    except drgn.FaultError as e:
        return f"Memory fault reading command line for PID {pid}: {e}"
    if args is None:
        return f"Task {pid} is a kernel thread (no command line)"

    return " ".join(a.decode(errors="replace") for a in args)


@mcp.tool()
def get_environ(pid: int) -> str:
    """Get the environment variables of a process.

    Use this to inspect the environment a process was running with at
    crash time. Returns None-equivalent for kernel threads.

    Args:
        pid: The PID of the task whose environment to retrieve.

    Returns:
        The environment variables, one per line as KEY=VALUE pairs.
        Truncated at 8KB. Returns an error if the task is not found
        or is a kernel thread.

    Examples:
        get_environ(1)
        get_environ(1234)
    """
    prog = state.require_loaded()
    from drgn.helpers.linux.mm import environ
    from drgn.helpers.linux.pid import find_task as _find_task

    task = _find_task(prog, pid)
    if task is None:
        return f"No task found with PID {pid}"

    try:
        env = environ(task)
    except drgn.FaultError as e:
        return f"Memory fault reading environment for PID {pid}: {e}"
    if env is None:
        return f"Task {pid} is a kernel thread (no environment)"

    output = "\n".join(e.decode(errors="replace") for e in env)
    max_len = 8000
    if len(output) > max_len:
        output = output[:max_len] + f"\n... (truncated, {len(output)} total chars)"
    return output


@mcp.tool()
def list_timers(timer_type: str = "wheel", limit: int = 100) -> str:
    """List active kernel timers (timer wheel or high-resolution timers).

    Use this to inspect pending timer callbacks at crash time. Shows the
    timer callback function and expiration for each active timer across
    all online CPUs.

    Args:
        timer_type: Type of timers to list. Must be one of:
            - "wheel": standard timer wheel timers (default)
            - "hrtimer": high-resolution timers
        limit: Maximum number of timers to return.

    Returns:
        A multi-line string listing active timers with their CPU, base
        name, callback function, and expiration. Returns an error for
        unknown timer types.

    Examples:
        list_timers()
        list_timers("hrtimer")
    """
    prog = state.require_loaded()
    from drgn.helpers.linux.cpumask import for_each_online_cpu
    from drgn.helpers.linux.percpu import per_cpu

    lines = []
    count = 0

    match timer_type:
        case "wheel":
            from drgn.helpers.linux.timer import (
                timer_base_for_each,
                timer_base_names,
            )

            base_names = timer_base_names(prog)
            for cpu in for_each_online_cpu(prog):
                bases = per_cpu(prog["timer_bases"], cpu)
                for i, name in enumerate(base_names):
                    try:
                        for timer in timer_base_for_each(bases[i].address_of_()):
                            if count >= limit:
                                lines.append(f"... (limited to {limit} timers)")
                                return "\n".join(lines)
                            fn = timer.function
                            expires = timer.expires.value_()
                            lines.append(f"cpu={cpu} base={name} fn={fn} expires={expires}")
                            count += 1
                    except drgn.FaultError as e:
                        lines.append(f"cpu={cpu} base={name}: <fault: {e}>")
        case "hrtimer":
            from drgn.helpers.linux.timer import (
                hrtimer_clock_base_for_each,
            )

            for cpu in for_each_online_cpu(prog):
                try:
                    cpu_base = per_cpu(prog["hrtimer_bases"], cpu)
                except drgn.FaultError as e:
                    lines.append(f"cpu={cpu}: <fault: {e}>")
                    continue
                for idx, clock_base in enumerate(cpu_base.clock_base):
                    try:
                        for hrt in hrtimer_clock_base_for_each(clock_base.address_of_()):
                            if count >= limit:
                                lines.append(f"... (limited to {limit} timers)")
                                return "\n".join(lines)
                            fn = hrt.function
                            softexpires = hrt._softexpires.value_()
                            lines.append(
                                f"cpu={cpu} clock_base={idx} fn={fn} softexpires={softexpires}"
                            )
                            count += 1
                    except drgn.FaultError as e:
                        lines.append(f"cpu={cpu} clock_base={idx}: <fault: {e}>")
        case _:
            return f"Unknown timer type '{timer_type}'. Use: wheel, hrtimer."

    return "\n".join(lines) if lines else f"No {timer_type} timers found"


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
    from drgn.helpers.linux.cgroup import (
        cgroup_get_from_path,
        cgroup_name,
        cgroup_parent,
        cgroup_path,
    )

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
def list_cgroups(path: str = "/", limit: int = 100) -> str:
    """List cgroups in the default hierarchy starting from a given path.

    Traverses the cgroup tree in pre-order from the specified root path,
    listing all descendant cgroups. Only cgroup v2 is supported.

    Args:
        path: The root cgroup path to start traversal from (e.g., "/",
            "/system.slice"). Defaults to the root.
        limit: Maximum number of cgroups to return.

    Returns:
        A multi-line string listing each cgroup's full path. Appends a
        truncation notice if cgroups exceed limit. Returns an error if
        the starting path does not exist.

    Examples:
        list_cgroups("/")
        list_cgroups("/system.slice", limit=50)
    """
    prog = state.require_loaded()
    from drgn import container_of
    from drgn.helpers.linux.cgroup import (
        cgroup_get_from_path,
        cgroup_path,
        css_for_each_descendant_pre,
    )

    try:
        cgrp = cgroup_get_from_path(prog, path)
    except (drgn.FaultError, LookupError) as e:
        return f"Error looking up cgroup '{path}': {e}"

    if not cgrp:
        return f"No cgroup found at path '{path}'"

    lines = []
    count = 0
    try:
        for css in css_for_each_descendant_pre(cgrp.self.address_of_()):
            if count >= limit:
                lines.append(f"... (limited to {limit} cgroups)")
                break
            child_cgrp = container_of(css, "struct cgroup", "self")
            child_path = cgroup_path(child_cgrp).decode(errors="replace")
            lines.append(child_path)
            count += 1
    except drgn.FaultError as e:
        lines.append(f"... Traversal aborted due to memory fault: {e}")

    return "\n".join(lines) if lines else "No cgroups found"


@mcp.tool()
def get_running_tasks() -> str:
    """Show the task running on each online CPU at crash time.

    Use this to quickly see what every CPU was doing when the system
    crashed. Shows the currently scheduled task per CPU with its PID,
    command name, and state.

    Returns:
        A multi-line table showing CPU number, PID, comm (name), and
        task state for the task that was running on each online CPU.

    Examples:
        get_running_tasks()
    """
    prog = state.require_loaded()
    from drgn.helpers.linux.cpumask import for_each_online_cpu
    from drgn.helpers.linux.sched import cpu_curr, task_state_to_char

    lines = []
    for cpu in for_each_online_cpu(prog):
        try:
            task = cpu_curr(prog, cpu)
            pid = task.pid.value_()
            comm = task.comm.string_().decode(errors="replace")
            state_char = task_state_to_char(task)
            lines.append(f"cpu={cpu} pid={pid} comm={comm} state={state_char}")
        except drgn.FaultError as e:
            lines.append(f"cpu={cpu}: <fault: {e}>")

    return "\n".join(lines) if lines else "No online CPUs found"


@mcp.tool()
def get_runqueue(cpu: int) -> str:
    """Inspect the runqueue for a specific CPU.

    Shows all runnable tasks on the given CPU's runqueue, separated by
    scheduling class (CFS/EEVDF fair tasks and RT realtime tasks).

    Args:
        cpu: The CPU number whose runqueue to inspect.

    Returns:
        A multi-line string listing runnable tasks grouped by scheduling
        class, showing PID and comm for each. Shows task counts per class.

    Examples:
        get_runqueue(0)
        get_runqueue(3)
    """
    prog = state.require_loaded()
    from drgn.helpers.linux.sched import (
        cpu_rq,
        rq_for_each_fair_task,
        rq_for_each_rt_task,
        task_state_to_char,
    )

    try:
        rq = cpu_rq(prog, cpu)
    except drgn.FaultError as e:
        return f"Cannot access runqueue for CPU {cpu}: {e}"

    lines = [f"Runqueue for CPU {cpu}:"]

    fair_tasks = []
    fair_count = 0
    try:
        for task in rq_for_each_fair_task(rq):
            pid = task.pid.value_()
            comm = task.comm.string_().decode(errors="replace")
            state_char = task_state_to_char(task)
            fair_tasks.append(f"  pid={pid} comm={comm} state={state_char}")
            fair_count += 1
    except drgn.FaultError as e:
        fair_tasks.append(f"  <fault: {e}>")

    lines.append(f"Fair tasks ({fair_count}):")
    lines.extend(fair_tasks)

    rt_tasks = []
    rt_count = 0
    try:
        for task in rq_for_each_rt_task(rq):
            pid = task.pid.value_()
            comm = task.comm.string_().decode(errors="replace")
            state_char = task_state_to_char(task)
            rt_tasks.append(f"  pid={pid} comm={comm} state={state_char}")
            rt_count += 1
    except drgn.FaultError as e:
        rt_tasks.append(f"  <fault: {e}>")

    lines.append(f"RT tasks ({rt_count}):")
    lines.extend(rt_tasks)

    return "\n".join(lines)


@mcp.tool()
def get_loadavg() -> str:
    """Get the system load averages at crash time.

    Returns the 1, 5, and 15 minute load averages, similar to the
    output of the uptime command or /proc/loadavg.

    Returns:
        A string showing the three load average values.

    Examples:
        get_loadavg()
    """
    prog = state.require_loaded()
    from drgn.helpers.linux.sched import loadavg

    avg1, avg5, avg15 = loadavg(prog)
    return f"Load average: {avg1:.2f}, {avg5:.2f}, {avg15:.2f}"


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
    from drgn.helpers.linux.bpf import bpf_prog_by_id

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
    from drgn.helpers.linux.bpf import bpf_map_by_id

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
    from drgn.helpers.linux.bpf import bpf_prog_by_id, bpf_prog_used_maps

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
