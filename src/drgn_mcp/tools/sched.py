import drgn
from drgn.helpers.linux.cpumask import (
    for_each_online_cpu,
    num_online_cpus,
    num_possible_cpus,
)
from drgn.helpers.linux.irq import (
    for_each_irq_desc,
    irq_desc_action_names,
    irq_desc_chip_name,
)
from drgn.helpers.linux.percpu import per_cpu
from drgn.helpers.linux.sched import (
    cpu_curr,
    cpu_rq,
    loadavg,
    rq_for_each_fair_task,
    rq_for_each_rt_task,
    task_state_to_char,
)
from drgn.helpers.linux.timer import (
    hrtimer_clock_base_for_each,
    timer_base_for_each,
    timer_base_names,
)

from drgn_mcp._app import mcp
from drgn_mcp.state import state
from drgn_mcp.tools._helpers import paginated_lines


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
    online = num_online_cpus(prog)
    possible = num_possible_cpus(prog)
    online_cpus = list(for_each_online_cpu(prog))

    return f"Online CPUs: {online}/{possible}\nOnline CPU IDs: {online_cpus}"


@mcp.tool()
def list_irqs(limit: int = 256, offset: int = 0) -> str:
    """List all allocated interrupt descriptors.

    Use this to see IRQ numbers, controller chip names, and action handler
    names for all interrupts in the system.

    Args:
        limit: Maximum number of IRQs to return.
        offset: Number of IRQs to skip (for pagination).

    Returns:
        A multi-line string listing each IRQ with its number, chip name,
        and registered action names.

    Examples:
        list_irqs()
    """
    prog = state.require_loaded()

    def fmt(item):
        irq_num, desc = item
        chip = irq_desc_chip_name(desc)
        chip_str = chip.decode(errors="replace") if chip else "none"
        actions = irq_desc_action_names(desc)
        action_str = ", ".join(a.decode(errors="replace") for a in actions) if actions else "none"
        return f"IRQ {irq_num}: chip={chip_str} actions=[{action_str}]"

    lines = paginated_lines(for_each_irq_desc(prog), fmt, offset=offset, limit=limit, label="IRQs")
    return "\n".join(lines) if lines else "No IRQs found"


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

    lines = []
    count = 0

    match timer_type:
        case "wheel":
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

    try:
        avg1, avg5, avg15 = loadavg(prog)
    except drgn.FaultError as e:
        return f"Memory fault reading load averages: {e}"

    return f"Load average: {avg1:.2f}, {avg5:.2f}, {avg15:.2f}"
