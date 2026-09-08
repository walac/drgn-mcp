"""Characterize scheduler, timer, lock, and process-information tools."""

from collections.abc import Callable
from types import SimpleNamespace

import pytest

from drgn_mcp.tools import sched, sysinfo
from drgn_mcp.tools._helpers import truncate_output
from tests.conftest import FakeBytes, FakeValue, mark_loaded


class _SymbolProgram:
    """Minimal program stand-in for scheduler tools indexing global symbols."""

    def __init__(self, **symbols: object) -> None:
        self._symbols = symbols

    def __getitem__(self, name: str) -> object:
        return self._symbols[name]


def _task(pid: int, comm: bytes) -> SimpleNamespace:
    return SimpleNamespace(pid=FakeValue(pid), comm=FakeBytes(comm))


# --- scheduler ---------------------------------------------------------------


def test_get_cpu_info_formats_online_cpu_topology(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sched, "num_online_cpus", lambda prog: 2)
    monkeypatch.setattr(sched, "num_possible_cpus", lambda prog: 4)
    monkeypatch.setattr(sched, "for_each_online_cpu", lambda prog: iter([0, 3]))
    mark_loaded()

    assert sched.get_cpu_info() == "Online CPUs: 2/4\nOnline CPU IDs: [0, 3]"


def test_get_cpu_info_formats_empty_topology(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sched, "num_online_cpus", lambda prog: 0)
    monkeypatch.setattr(sched, "num_possible_cpus", lambda prog: 0)
    monkeypatch.setattr(sched, "for_each_online_cpu", lambda prog: [])
    mark_loaded()

    assert sched.get_cpu_info() == "Online CPUs: 0/0\nOnline CPU IDs: []"


def test_list_irqs_paginates_and_decodes_names(monkeypatch: pytest.MonkeyPatch) -> None:
    descriptors = [(7, object()), (8, object()), (9, object())]
    monkeypatch.setattr(sched, "for_each_irq_desc", lambda prog: descriptors)
    monkeypatch.setattr(sched, "irq_desc_chip_name", lambda desc: b"io\xffapic")
    monkeypatch.setattr(sched, "irq_desc_action_names", lambda desc: [b"eth0", b"rx\xff"])
    mark_loaded()

    assert sched.list_irqs(offset=1, limit=1) == "\n".join(
        [
            "IRQ 8: chip=io\ufffdapic actions=[eth0, rx\ufffd]",
            "... (limited to 1 IRQs, use offset=2 for next page)",
        ]
    )


def test_list_irqs_continues_after_descriptor_fault(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    fault = drgn_error("fault", "missing chip", address=0x10)
    descriptors = [(1, object()), (2, object())]
    monkeypatch.setattr(sched, "for_each_irq_desc", lambda prog: descriptors)
    monkeypatch.setattr(
        sched,
        "irq_desc_chip_name",
        lambda desc: (_ for _ in ()).throw(fault) if desc is descriptors[0][1] else b"msi",
    )
    monkeypatch.setattr(sched, "irq_desc_action_names", lambda desc: [])
    mark_loaded()

    assert sched.list_irqs() == f"<fault: {fault}>\nIRQ 2: chip=msi actions=[none]"


def test_list_irqs_reports_empty_collection(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sched, "for_each_irq_desc", lambda prog: [])
    mark_loaded()

    assert sched.list_irqs() == "No IRQs found"


def test_list_irqs_formats_missing_chip_name(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sched, "for_each_irq_desc", lambda prog: [(4, object())])
    monkeypatch.setattr(sched, "irq_desc_chip_name", lambda desc: None)
    monkeypatch.setattr(sched, "irq_desc_action_names", lambda desc: [])
    mark_loaded()

    assert sched.list_irqs() == "IRQ 4: chip=none actions=[none]"


def test_list_timers_limits_wheel_timers(monkeypatch: pytest.MonkeyPatch) -> None:
    bases = [SimpleNamespace(address_of_=lambda: "base")]
    timer_one = SimpleNamespace(function="call_timer_fn", expires=FakeValue(42))
    timer_two = SimpleNamespace(function="expire_timers", expires=FakeValue(43))
    timer_bases = object()
    seen_per_cpu: list[tuple[object, int]] = []

    def get_bases(symbol: object, cpu: int) -> list[SimpleNamespace]:
        seen_per_cpu.append((symbol, cpu))
        return bases

    monkeypatch.setattr(sched, "for_each_online_cpu", lambda prog: [1])
    monkeypatch.setattr(sched, "timer_base_names", lambda prog: ["BASE_STD"])
    monkeypatch.setattr(sched, "per_cpu", get_bases)
    monkeypatch.setattr(sched, "timer_base_for_each", lambda base: [timer_one, timer_two])
    mark_loaded(_SymbolProgram(timer_bases=timer_bases))

    assert sched.list_timers(limit=1) == "\n".join(
        ["cpu=1 base=BASE_STD fn=call_timer_fn expires=42", "... (limited to 1 timers)"]
    )
    assert seen_per_cpu == [(timer_bases, 1)]


def test_list_timers_continues_after_wheel_base_fault(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    fault = drgn_error("fault", "bad base", address=0x20)
    bases = [
        SimpleNamespace(address_of_=lambda: "bad"),
        SimpleNamespace(address_of_=lambda: "good"),
    ]
    timer = SimpleNamespace(function="run_timer", expires=FakeValue(99))
    timer_bases = object()
    seen_per_cpu: list[tuple[object, int]] = []

    def get_bases(symbol: object, cpu: int) -> list[SimpleNamespace]:
        seen_per_cpu.append((symbol, cpu))
        return bases

    monkeypatch.setattr(sched, "for_each_online_cpu", lambda prog: [0])
    monkeypatch.setattr(sched, "timer_base_names", lambda prog: ["BASE0", "BASE1"])
    monkeypatch.setattr(sched, "per_cpu", get_bases)
    monkeypatch.setattr(
        sched,
        "timer_base_for_each",
        lambda base: (_ for _ in ()).throw(fault) if base == "bad" else [timer],
    )
    mark_loaded(_SymbolProgram(timer_bases=timer_bases))

    assert (
        sched.list_timers()
        == f"cpu=0 base=BASE0: <fault: {fault}>\ncpu=0 base=BASE1 fn=run_timer expires=99"
    )
    assert seen_per_cpu == [(timer_bases, 0)]


def test_list_timers_formats_hrtimers_and_skips_faulty_cpu(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    fault = drgn_error("fault", "missing hrtimer base", address=0x21)
    clock_base = SimpleNamespace(address_of_=lambda: "clock-base")
    hrtimer = SimpleNamespace(function="hrtimer_wakeup", _softexpires=FakeValue(100))
    hrtimer_bases = object()
    seen_per_cpu: list[tuple[object, int]] = []

    def get_cpu_base(symbol: object, cpu: int) -> SimpleNamespace:
        seen_per_cpu.append((symbol, cpu))
        if cpu == 0:
            raise fault
        return SimpleNamespace(clock_base=[clock_base])

    def walk_clock_base(base: str) -> list[SimpleNamespace]:
        assert base == "clock-base"
        return [hrtimer]

    monkeypatch.setattr(sched, "for_each_online_cpu", lambda prog: [0, 1])
    monkeypatch.setattr(sched, "per_cpu", get_cpu_base)
    monkeypatch.setattr(sched, "hrtimer_clock_base_for_each", walk_clock_base)
    mark_loaded(_SymbolProgram(hrtimer_bases=hrtimer_bases))

    assert sched.list_timers("hrtimer") == (
        f"cpu=0: <fault: {fault}>\ncpu=1 clock_base=0 fn=hrtimer_wakeup softexpires=100"
    )
    assert seen_per_cpu == [(hrtimer_bases, 0), (hrtimer_bases, 1)]


def test_list_timers_limits_hrtimers(monkeypatch: pytest.MonkeyPatch) -> None:
    clock_base = SimpleNamespace(address_of_=lambda: "limit-base")
    first = SimpleNamespace(function="first_hrtimer", _softexpires=FakeValue(100))
    second = SimpleNamespace(function="second_hrtimer", _softexpires=FakeValue(101))
    hrtimer_bases = object()
    seen_per_cpu: list[tuple[object, int]] = []

    def get_cpu_base(symbol: object, cpu: int) -> SimpleNamespace:
        seen_per_cpu.append((symbol, cpu))
        return SimpleNamespace(clock_base=[clock_base])

    def walk_clock_base(base: str) -> list[SimpleNamespace]:
        assert base == "limit-base"
        return [first, second]

    monkeypatch.setattr(sched, "for_each_online_cpu", lambda prog: [2])
    monkeypatch.setattr(sched, "per_cpu", get_cpu_base)
    monkeypatch.setattr(sched, "hrtimer_clock_base_for_each", walk_clock_base)
    mark_loaded(_SymbolProgram(hrtimer_bases=hrtimer_bases))

    assert sched.list_timers("hrtimer", limit=1) == "\n".join(
        ["cpu=2 clock_base=0 fn=first_hrtimer softexpires=100", "... (limited to 1 timers)"]
    )
    assert seen_per_cpu == [(hrtimer_bases, 2)]


def test_list_timers_continues_after_hrtimer_clock_base_fault(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    fault = drgn_error("fault", "bad clock base", address=0x22)
    clock_bases = [
        SimpleNamespace(address_of_=lambda: "bad-clock-base"),
        SimpleNamespace(address_of_=lambda: "good-clock-base"),
    ]
    hrtimer = SimpleNamespace(function="good_hrtimer", _softexpires=FakeValue(102))
    hrtimer_bases = object()
    seen_per_cpu: list[tuple[object, int]] = []

    def get_cpu_base(symbol: object, cpu: int) -> SimpleNamespace:
        seen_per_cpu.append((symbol, cpu))
        return SimpleNamespace(clock_base=clock_bases)

    def walk_clock_base(base: str) -> list[SimpleNamespace]:
        if base == "bad-clock-base":
            raise fault
        assert base == "good-clock-base"
        return [hrtimer]

    monkeypatch.setattr(sched, "for_each_online_cpu", lambda prog: [3])
    monkeypatch.setattr(sched, "per_cpu", get_cpu_base)
    monkeypatch.setattr(sched, "hrtimer_clock_base_for_each", walk_clock_base)
    mark_loaded(_SymbolProgram(hrtimer_bases=hrtimer_bases))

    assert sched.list_timers("hrtimer") == (
        f"cpu=3 clock_base=0: <fault: {fault}>\n"
        "cpu=3 clock_base=1 fn=good_hrtimer softexpires=102"
    )
    assert seen_per_cpu == [(hrtimer_bases, 3)]


def test_list_timers_rejects_unknown_type() -> None:
    mark_loaded()

    assert sched.list_timers("bogus") == "Unknown timer type 'bogus'. Use: wheel, hrtimer."


@pytest.mark.parametrize("timer_type", ["wheel", "hrtimer"])
def test_list_timers_reports_empty_collection(
    monkeypatch: pytest.MonkeyPatch, timer_type: str
) -> None:
    monkeypatch.setattr(sched, "for_each_online_cpu", lambda prog: [])
    monkeypatch.setattr(sched, "timer_base_names", lambda prog: [])
    mark_loaded()

    assert sched.list_timers(timer_type) == f"No {timer_type} timers found"


def test_get_running_tasks_formats_cpus_and_continues_after_fault(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    fault = drgn_error("fault", "offline memory", address=0x30)
    monkeypatch.setattr(sched, "for_each_online_cpu", lambda prog: [0, 1])
    monkeypatch.setattr(
        sched,
        "cpu_curr",
        lambda prog, cpu: _task(1, b"swapper\xff") if cpu == 0 else (_ for _ in ()).throw(fault),
    )
    monkeypatch.setattr(sched, "task_state_to_char", lambda task: "R")
    mark_loaded()

    assert (
        sched.get_running_tasks()
        == f"cpu=0 pid=1 comm=swapper\ufffd state=R\ncpu=1: <fault: {fault}>"
    )


def test_get_running_tasks_reports_no_online_cpus(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sched, "for_each_online_cpu", lambda prog: [])
    mark_loaded()

    assert sched.get_running_tasks() == "No online CPUs found"


def test_get_runqueue_formats_fair_and_rt_tasks(monkeypatch: pytest.MonkeyPatch) -> None:
    runqueue = object()
    monkeypatch.setattr(sched, "cpu_rq", lambda prog, cpu: runqueue)
    monkeypatch.setattr(sched, "rq_for_each_fair_task", lambda rq: [_task(10, b"fair\xff")])
    monkeypatch.setattr(sched, "rq_for_each_rt_task", lambda rq: [_task(20, b"rt")])
    monkeypatch.setattr(sched, "task_state_to_char", lambda task: "R")
    mark_loaded()

    assert sched.get_runqueue(2) == "\n".join(
        [
            "Runqueue for CPU 2:",
            "Fair tasks (1):",
            "  pid=10 comm=fair\ufffd state=R",
            "RT tasks (1):",
            "  pid=20 comm=rt state=R",
        ]
    )


def test_get_runqueue_keeps_other_class_after_walk_fault(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    fault = drgn_error("fault", "fair tree", address=0x31)
    monkeypatch.setattr(sched, "cpu_rq", lambda prog, cpu: object())
    monkeypatch.setattr(sched, "rq_for_each_fair_task", lambda rq: (_ for _ in ()).throw(fault))
    monkeypatch.setattr(sched, "rq_for_each_rt_task", lambda rq: [])
    mark_loaded()

    assert sched.get_runqueue(0) == "\n".join(
        ["Runqueue for CPU 0:", "Fair tasks (0):", f"  <fault: {fault}>", "RT tasks (0):"]
    )


def test_get_runqueue_reports_rt_walk_fault(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    fault = drgn_error("fault", "rt queue", address=0x34)
    monkeypatch.setattr(sched, "cpu_rq", lambda prog, cpu: object())
    monkeypatch.setattr(sched, "rq_for_each_fair_task", lambda rq: [])
    monkeypatch.setattr(sched, "rq_for_each_rt_task", lambda rq: (_ for _ in ()).throw(fault))
    mark_loaded()

    assert sched.get_runqueue(0) == "\n".join(
        ["Runqueue for CPU 0:", "Fair tasks (0):", "RT tasks (0):", f"  <fault: {fault}>"]
    )


def test_get_runqueue_reports_missing_cpu(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    fault = drgn_error("fault", "no rq", address=0x32)
    monkeypatch.setattr(sched, "cpu_rq", lambda prog, cpu: (_ for _ in ()).throw(fault))
    mark_loaded()

    assert sched.get_runqueue(7) == f"Cannot access runqueue for CPU 7: {fault}"


def test_get_loadavg_formats_values_and_reports_fault(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    monkeypatch.setattr(sched, "loadavg", lambda prog: (1, 2.345, 0.1))
    mark_loaded()
    assert sched.get_loadavg() == "Load average: 1.00, 2.35, 0.10"

    fault = drgn_error("fault", "loadavg unavailable", address=0x33)
    monkeypatch.setattr(sched, "loadavg", lambda prog: (_ for _ in ()).throw(fault))
    assert sched.get_loadavg() == f"Memory fault reading load averages: {fault}"


# --- system information ------------------------------------------------------


def test_get_lock_info_formats_mutex_owner(monkeypatch: pytest.MonkeyPatch) -> None:
    lock = SimpleNamespace(type_=SimpleNamespace(type_name=lambda: "struct mutex *"))
    seen_expr: list[str] = []

    def eval_lock(expr: str) -> SimpleNamespace:
        seen_expr.append(expr)
        return lock

    monkeypatch.setattr(sysinfo, "_eval_expr", eval_lock)
    monkeypatch.setattr(sysinfo, "mutex_owner", lambda obj: _task(42, b"worker\xff"))
    mark_loaded()

    assert sysinfo.get_lock_info("lock") == "Mutex: locked by pid=42 comm=worker\ufffd"
    assert seen_expr == ["lock"]


def test_get_lock_info_formats_unlocked_mutex(monkeypatch: pytest.MonkeyPatch) -> None:
    lock = SimpleNamespace(type_=SimpleNamespace(type_name=lambda: "struct mutex"))
    monkeypatch.setattr(sysinfo, "_eval_expr", lambda expr: lock)
    monkeypatch.setattr(sysinfo, "mutex_owner", lambda obj: None)
    mark_loaded()

    assert sysinfo.get_lock_info("lock") == "Mutex: unlocked (no owner)"


def test_get_lock_info_formats_rwsem_and_unrecognized_types(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rwsem = SimpleNamespace(type_=SimpleNamespace(type_name=lambda: "struct rw_semaphore"))
    monkeypatch.setattr(sysinfo, "_eval_expr", lambda expr: rwsem)
    monkeypatch.setattr(sysinfo, "rwsem_locked", lambda obj: SimpleNamespace(name="READ_LOCKED"))
    monkeypatch.setattr(sysinfo, "rwsem_owner", lambda obj: FakeValue(0))
    mark_loaded()
    assert sysinfo.get_lock_info("rwsem") == "RW semaphore: READ_LOCKED"

    monkeypatch.setattr(
        sysinfo,
        "_eval_expr",
        lambda expr: SimpleNamespace(type_=SimpleNamespace(type_name=lambda: "struct spinlock")),
    )
    assert sysinfo.get_lock_info("spin") == (
        "Unrecognized lock type: struct spinlock. Expected mutex or rw_semaphore."
    )


def test_get_lock_info_formats_rwsem_owner(monkeypatch: pytest.MonkeyPatch) -> None:
    rwsem = SimpleNamespace(type_=SimpleNamespace(type_name=lambda: "struct rw_semaphore"))
    owner = _task(43, b"reader\xff")
    owner.value_ = lambda: 1
    monkeypatch.setattr(sysinfo, "_eval_expr", lambda expr: rwsem)
    monkeypatch.setattr(sysinfo, "rwsem_locked", lambda obj: SimpleNamespace(name="READ_LOCKED"))
    monkeypatch.setattr(sysinfo, "rwsem_owner", lambda obj: owner)
    mark_loaded()

    assert (
        sysinfo.get_lock_info("rwsem")
        == "RW semaphore: READ_LOCKED\nOwner: pid=43 comm=reader\ufffd"
    )


def test_get_lock_info_skips_rwsem_owner_when_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    rwsem = SimpleNamespace(type_=SimpleNamespace(type_name=lambda: "struct rw_semaphore"))
    monkeypatch.setattr(sysinfo, "_eval_expr", lambda expr: rwsem)
    monkeypatch.setattr(sysinfo, "rwsem_locked", lambda obj: SimpleNamespace(name="UNLOCKED"))
    monkeypatch.setattr(sysinfo, "rwsem_owner", lambda obj: None)
    mark_loaded()

    assert sysinfo.get_lock_info("rwsem") == "RW semaphore: UNLOCKED"


def test_get_lock_info_reports_expression_and_memory_errors(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    eval_error = drgn_error("value", "unknown lock")
    monkeypatch.setattr(sysinfo, "_eval_expr", lambda expr: (_ for _ in ()).throw(eval_error))
    mark_loaded()
    assert sysinfo.get_lock_info("missing") == f"Error evaluating lock expression: {eval_error}"

    fault = drgn_error("fault", "owner unreadable", address=0x40)
    mutex = SimpleNamespace(type_=SimpleNamespace(type_name=lambda: "struct mutex"))
    monkeypatch.setattr(sysinfo, "_eval_expr", lambda expr: mutex)
    monkeypatch.setattr(sysinfo, "mutex_owner", lambda obj: (_ for _ in ()).throw(fault))
    assert sysinfo.get_lock_info("mutex") == f"Memory fault reading lock state: {fault}"


def test_get_kconfig_looks_up_keys_and_sorts_full_listing(monkeypatch: pytest.MonkeyPatch) -> None:
    config = {"CONFIG_Z": "y", "CONFIG_A": "n"}
    monkeypatch.setattr(sysinfo, "_get_kconfig", lambda prog: config)
    mark_loaded()

    assert sysinfo.get_kconfig("CONFIG_Z") == "CONFIG_Z=y"
    assert sysinfo.get_kconfig("CONFIG_MISSING") == "CONFIG_MISSING is not set"
    assert sysinfo.get_kconfig() == "CONFIG_A=n\nCONFIG_Z=y"


def test_get_kconfig_formats_empty_listing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sysinfo, "_get_kconfig", lambda prog: {})
    mark_loaded()

    assert sysinfo.get_kconfig() == ""


def test_get_kconfig_truncates_long_listing(monkeypatch: pytest.MonkeyPatch) -> None:
    config = {f"CONFIG_{index:04d}": "x" * 20 for index in range(500)}
    monkeypatch.setattr(sysinfo, "_get_kconfig", lambda prog: config)
    mark_loaded()

    listing = "\n".join(f"{key}={value}" for key, value in sorted(config.items()))
    assert sysinfo.get_kconfig() == truncate_output(listing)


@pytest.mark.parametrize(
    ("tool", "helper_name", "suffix", "values", "expected"),
    [
        (
            sysinfo.get_cmdline,
            "cmdline",
            "command line",
            [b"/bin/app", b"bad\xff"],
            "/bin/app bad\ufffd",
        ),
        (
            sysinfo.get_environ,
            "environ",
            "environment",
            [b"LANG=C", b"BAD=\xff"],
            "LANG=C\nBAD=\ufffd",
        ),
    ],
)
def test_process_info_decodes_bytes_and_reports_missing_or_kernel_thread(
    monkeypatch: pytest.MonkeyPatch,
    tool: Callable[[int], str],
    helper_name: str,
    suffix: str,
    values: list[bytes],
    expected: str,
) -> None:
    task = object()
    monkeypatch.setattr(sysinfo, "_find_task", lambda prog, pid: task if pid == 1 else None)
    monkeypatch.setattr(sysinfo, helper_name, lambda found_task: values)
    mark_loaded()
    assert tool(1) == expected
    assert tool(2) == "No task found with PID 2"

    monkeypatch.setattr(sysinfo, helper_name, lambda found_task: None)
    assert tool(1) == f"Task 1 is a kernel thread (no {suffix})"


@pytest.mark.parametrize(
    ("tool", "helper_name", "noun"),
    [
        (sysinfo.get_cmdline, "cmdline", "command line"),
        (sysinfo.get_environ, "environ", "environment"),
    ],
)
def test_process_info_reports_read_faults(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
    tool: Callable[[int], str],
    helper_name: str,
    noun: str,
) -> None:
    fault = drgn_error("fault", "task memory gone", address=0x50)
    monkeypatch.setattr(sysinfo, "_find_task", lambda prog, pid: object())
    monkeypatch.setattr(sysinfo, helper_name, lambda task: (_ for _ in ()).throw(fault))
    mark_loaded()

    assert tool(5) == f"Memory fault reading {noun} for PID 5: {fault}"


def test_get_environ_truncates_long_output(monkeypatch: pytest.MonkeyPatch) -> None:
    env = [b"VALUE=" + b"x" * 9000]
    monkeypatch.setattr(sysinfo, "_find_task", lambda prog, pid: object())
    monkeypatch.setattr(sysinfo, "environ", lambda task: env)
    mark_loaded()

    listing = "\n".join(value.decode(errors="replace") for value in env)
    assert sysinfo.get_environ(1) == truncate_output(listing)


def test_get_cmdline_does_not_truncate_long_output(monkeypatch: pytest.MonkeyPatch) -> None:
    args = [b"/bin/app", b"x" * 9000]
    monkeypatch.setattr(sysinfo, "_find_task", lambda prog, pid: object())
    monkeypatch.setattr(sysinfo, "cmdline", lambda task: args)
    mark_loaded()

    assert sysinfo.get_cmdline(1) == " ".join(arg.decode(errors="replace") for arg in args)
