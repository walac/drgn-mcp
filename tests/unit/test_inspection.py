"""Characterize thread, task, object, type, symbol, module, and panic tools."""

from collections.abc import Callable, Iterator
from types import SimpleNamespace

import pytest

from drgn_mcp.tools import inspection
from tests.conftest import FakeBytes, FakeValue, Stringable, mark_loaded


def _symbol(
    *,
    name: str,
    address: int,
    size: int = 16,
    binding: str = "GLOBAL",
    kind: str = "FUNC",
) -> SimpleNamespace:
    return SimpleNamespace(
        name=name,
        address=address,
        size=size,
        binding=SimpleNamespace(name=binding),
        kind=SimpleNamespace(name=kind),
    )


# --- get_crashed_thread -------------------------------------------------------


def test_get_crashed_thread_formats_tid_name_and_stack(
    fake_program: Callable[..., SimpleNamespace],
) -> None:
    thread = SimpleNamespace(tid=1, name="swapper/0", stack_trace=lambda: "#0 panic")
    mark_loaded(fake_program(crashed_thread=lambda: thread))

    assert inspection.get_crashed_thread() == (
        "Crashed thread: tid=1, name=swapper/0\n\nStack trace:\n#0 panic"
    )


def test_get_crashed_thread_reports_missing_thread(
    fake_program: Callable[..., SimpleNamespace],
) -> None:
    def crashed_thread() -> None:
        raise ValueError("no crashed thread")

    mark_loaded(fake_program(crashed_thread=crashed_thread))

    assert (
        inspection.get_crashed_thread() == "Could not determine crashed thread: no crashed thread"
    )


@pytest.mark.parametrize("kind", ["fault", "value"])
def test_get_crashed_thread_keeps_metadata_when_stack_fails(
    fake_program: Callable[..., SimpleNamespace],
    drgn_error: Callable[..., BaseException],
    kind: str,
) -> None:
    error = drgn_error(kind, "unwind failed", address=0x20)

    def stack_trace() -> str:
        raise error

    thread = SimpleNamespace(tid=42, name="kthreadd", stack_trace=stack_trace)
    mark_loaded(fake_program(crashed_thread=lambda: thread))

    assert inspection.get_crashed_thread() == (
        f"Crashed thread: tid=42, name=kthreadd\n\nCould not get stack trace: {error}"
    )


# --- get_stack_trace ----------------------------------------------------------


def test_get_stack_trace_returns_trace_string(
    fake_program: Callable[..., SimpleNamespace],
) -> None:
    mark_loaded(fake_program(stack_trace=lambda thread_id: f"#0 foo tid={thread_id}"))

    assert inspection.get_stack_trace(4096) == "#0 foo tid=4096"


def test_get_stack_trace_reports_missing_thread(
    fake_program: Callable[..., SimpleNamespace],
) -> None:
    def stack_trace(thread_id: int) -> str:
        raise LookupError(thread_id)

    mark_loaded(fake_program(stack_trace=stack_trace))

    assert inspection.get_stack_trace(99) == "No thread found with id=99"


@pytest.mark.parametrize("kind", ["fault", "value"])
def test_get_stack_trace_reports_unwind_errors(
    fake_program: Callable[..., SimpleNamespace],
    drgn_error: Callable[..., BaseException],
    kind: str,
) -> None:
    error = drgn_error(kind, "bad frame", address=0x30)

    def stack_trace(thread_id: int) -> str:
        raise error

    mark_loaded(fake_program(stack_trace=stack_trace))

    assert inspection.get_stack_trace(7) == f"Cannot get stack trace for thread 7: {error}"


# --- list_threads -------------------------------------------------------------


def test_list_threads_formats_tid_and_name(
    fake_program: Callable[..., SimpleNamespace],
) -> None:
    threads = [
        SimpleNamespace(tid=1, name="swapper/0"),
        SimpleNamespace(tid=2, name="kthreadd"),
    ]
    mark_loaded(fake_program(threads=lambda: threads))

    assert inspection.list_threads() == "tid=1 name=swapper/0\ntid=2 name=kthreadd"


def test_list_threads_reports_empty_program(
    fake_program: Callable[..., SimpleNamespace],
) -> None:
    mark_loaded(fake_program(threads=lambda: []))

    assert inspection.list_threads() == "No threads found"


def test_list_threads_appends_next_page_hint(
    fake_program: Callable[..., SimpleNamespace],
) -> None:
    threads = [SimpleNamespace(tid=i, name=f"t{i}") for i in range(1, 5)]
    mark_loaded(fake_program(threads=lambda: threads))

    assert inspection.list_threads(limit=2, offset=1) == "\n".join(
        [
            "tid=2 name=t2",
            "tid=3 name=t3",
            "... (limited to 2 threads, use offset=3 for next page)",
        ]
    )


class _FaultyThread:
    def __init__(self, error: BaseException) -> None:
        self._error = error

    @property
    def tid(self) -> int:
        raise self._error

    @property
    def name(self) -> str:
        return "unused"


class _FaultyValue:
    def __init__(self, error: BaseException) -> None:
        self._error = error

    def value_(self) -> int:
        raise self._error


def test_list_threads_formats_item_fault(
    fake_program: Callable[..., SimpleNamespace],
    drgn_error: Callable[..., BaseException],
) -> None:
    fault = drgn_error("fault", "bad thread", address=0x40)
    good = SimpleNamespace(tid=1, name="ok")
    mark_loaded(fake_program(threads=lambda: [good, _FaultyThread(fault)]))

    assert inspection.list_threads() == f"tid=1 name=ok\n<fault: {fault}>"


def test_list_threads_aborts_on_iterator_fault(
    fake_program: Callable[..., SimpleNamespace],
    drgn_error: Callable[..., BaseException],
) -> None:
    fault = drgn_error("fault", "walk failed", address=0x41)
    good = SimpleNamespace(tid=1, name="ok")

    def threads() -> Iterator[SimpleNamespace]:
        yield good
        raise fault

    mark_loaded(fake_program(threads=threads))

    assert inspection.list_threads() == (
        f"tid=1 name=ok\n... Traversal aborted due to memory fault: {fault}"
    )


# --- get_thread ---------------------------------------------------------------


def test_get_thread_formats_metadata_and_stack(
    fake_program: Callable[..., SimpleNamespace],
) -> None:
    mark_loaded(
        fake_program(
            thread=lambda tid: SimpleNamespace(
                tid=tid, name="init", stack_trace=lambda: "#0 rest_init"
            )
        )
    )

    assert inspection.get_thread(4096) == (
        "Thread: tid=4096, name=init\n\nStack trace:\n#0 rest_init"
    )


def test_get_thread_reports_missing_tid(
    fake_program: Callable[..., SimpleNamespace],
) -> None:
    def thread(tid: int) -> SimpleNamespace:
        raise LookupError(tid)

    mark_loaded(fake_program(thread=thread))

    assert inspection.get_thread(1234) == "No thread found with tid=1234"


@pytest.mark.parametrize("kind", ["fault", "value"])
def test_get_thread_reports_stack_failure(
    fake_program: Callable[..., SimpleNamespace],
    drgn_error: Callable[..., BaseException],
    kind: str,
) -> None:
    error = drgn_error(kind, "no unwind", address=0x50)

    def stack_trace() -> str:
        raise error

    def thread(tid: int) -> SimpleNamespace:
        return SimpleNamespace(tid=tid, name="kworker", stack_trace=stack_trace)

    mark_loaded(fake_program(thread=thread))

    assert inspection.get_thread(10) == (
        f"Thread: tid=10, name=kworker\n\nCould not get stack trace: {error}"
    )


# --- lookup_object ------------------------------------------------------------


class _ObjectProgram:
    def __init__(self, objects: dict[str, object]) -> None:
        self._objects = objects

    def __getitem__(self, name: str) -> object:
        try:
            value = self._objects[name]
        except KeyError:
            raise LookupError(name) from None
        if isinstance(value, BaseException):
            raise value
        return value


def test_lookup_object_returns_object_string() -> None:
    mark_loaded(_ObjectProgram({"jiffies": Stringable("(unsigned long)jiffies = 12345")}))

    assert inspection.lookup_object("jiffies") == "(unsigned long)jiffies = 12345"


def test_lookup_object_reports_missing_name() -> None:
    mark_loaded(_ObjectProgram({}))

    assert inspection.lookup_object("no_such_var") == (
        "No object found with name 'no_such_var'. Check spelling or use lookup_symbol to search."
    )


def test_lookup_object_reports_memory_fault(drgn_error: Callable[..., BaseException]) -> None:
    fault = drgn_error("fault", "unmapped", address=0x60)
    mark_loaded(_ObjectProgram({"init_task": fault}))

    assert inspection.lookup_object("init_task") == f"Memory fault reading 'init_task': {fault}"


# --- lookup_type --------------------------------------------------------------


def test_lookup_type_returns_type_string(fake_program: Callable[..., SimpleNamespace]) -> None:
    def type_lookup(type_name: str) -> Stringable:
        if type_name == "struct task_struct":
            return Stringable("struct task_struct {\n    pid_t pid;\n}")
        raise LookupError(type_name)

    mark_loaded(fake_program(type=type_lookup))

    assert inspection.lookup_type("struct task_struct") == (
        "struct task_struct {\n    pid_t pid;\n}"
    )


def test_lookup_type_reports_missing_name(fake_program: Callable[..., SimpleNamespace]) -> None:
    def type_lookup(type_name: str) -> str:
        raise LookupError(type_name)

    mark_loaded(fake_program(type=type_lookup))

    assert inspection.lookup_type("struct missing") == (
        "No type found with name 'struct missing'. Check spelling (e.g., 'struct task_struct')."
    )


# --- lookup_symbol ------------------------------------------------------------


def test_lookup_symbol_by_address_without_offset(
    fake_program: Callable[..., SimpleNamespace],
) -> None:
    sym = _symbol(name="schedule", address=0xFFFFFFFF81000000, size=128)
    mark_loaded(fake_program(symbol=lambda address: sym))

    assert inspection.lookup_symbol(0xFFFFFFFF81000000) == "\n".join(
        [
            "name=schedule",
            "address=0xffffffff81000000",
            "size=128",
            "binding=GLOBAL",
            "kind=FUNC",
        ]
    )


def test_lookup_symbol_by_address_appends_offset(
    fake_program: Callable[..., SimpleNamespace],
) -> None:
    sym = _symbol(name="schedule", address=0xFFFFFFFF81000000, size=128)
    mark_loaded(fake_program(symbol=lambda address: sym))

    assert inspection.lookup_symbol(0xFFFFFFFF81000010) == (
        "name=schedule+0x10\n"
        "address=0xffffffff81000000\n"
        "size=128\n"
        "binding=GLOBAL\n"
        "kind=FUNC"
    )


def test_lookup_symbol_hex_string_uses_address_path(
    fake_program: Callable[..., SimpleNamespace],
) -> None:
    sym = _symbol(name="kmalloc", address=0x1000, size=32, binding="LOCAL", kind="OBJECT")
    mark_loaded(fake_program(symbol=lambda address: sym))

    assert inspection.lookup_symbol("0x1000") == (
        "name=kmalloc\naddress=0x1000\nsize=32\nbinding=LOCAL\nkind=OBJECT"
    )


def test_lookup_symbol_by_address_reports_missing(
    fake_program: Callable[..., SimpleNamespace],
) -> None:
    def symbol(address: int) -> SimpleNamespace:
        raise LookupError(address)

    mark_loaded(fake_program(symbol=symbol))

    assert inspection.lookup_symbol(0xABCD) == "No symbol found containing address 0xabcd"


def test_lookup_symbol_by_name_lists_matches(fake_program: Callable[..., SimpleNamespace]) -> None:
    syms = [
        _symbol(name="foo", address=0x1000, size=8),
        _symbol(name="foo", address=0x2000, size=16, binding="WEAK", kind="OBJECT"),
    ]
    mark_loaded(fake_program(symbols=lambda name: syms))

    assert inspection.lookup_symbol("foo") == (
        "name=foo address=0x1000 size=8 binding=GLOBAL kind=FUNC\n"
        "name=foo address=0x2000 size=16 binding=WEAK kind=OBJECT"
    )


def test_lookup_symbol_by_name_reports_missing(
    fake_program: Callable[..., SimpleNamespace],
) -> None:
    mark_loaded(fake_program(symbols=lambda name: []))

    assert inspection.lookup_symbol("nope") == "No symbol found with name 'nope'"


def test_lookup_symbol_by_name_truncates_at_limit(
    fake_program: Callable[..., SimpleNamespace],
) -> None:
    syms = [_symbol(name="bar", address=0x1000 + i, size=4) for i in range(3)]
    mark_loaded(fake_program(symbols=lambda name: syms))

    assert inspection.lookup_symbol("bar", limit=1) == (
        "name=bar address=0x1000 size=4 binding=GLOBAL kind=FUNC\n"
        "... (2 more symbols, use higher limit to see all)"
    )


# --- list_tasks ---------------------------------------------------------------


def test_list_tasks_formats_pid_comm_and_state(monkeypatch: pytest.MonkeyPatch) -> None:
    task = SimpleNamespace(pid=FakeValue(1), comm=FakeBytes(b"systemd"))
    monkeypatch.setattr("drgn.helpers.linux.pid.for_each_task", lambda prog: [task])
    monkeypatch.setattr("drgn.helpers.linux.sched.task_state_to_char", lambda t: "S")
    mark_loaded()

    assert inspection.list_tasks() == "pid=1 comm=systemd state=S"


def test_list_tasks_replaces_invalid_comm_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    task = SimpleNamespace(pid=FakeValue(1), comm=FakeBytes(b"kthreadd\xff"))
    monkeypatch.setattr("drgn.helpers.linux.pid.for_each_task", lambda prog: [task])
    monkeypatch.setattr("drgn.helpers.linux.sched.task_state_to_char", lambda t: "S")
    mark_loaded()

    assert inspection.list_tasks() == "pid=1 comm=kthreadd\ufffd state=S"


def test_list_tasks_reports_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("drgn.helpers.linux.pid.for_each_task", lambda prog: [])
    mark_loaded()

    assert inspection.list_tasks() == "No tasks found"


def test_list_tasks_appends_next_page_hint(monkeypatch: pytest.MonkeyPatch) -> None:
    tasks = [
        SimpleNamespace(pid=FakeValue(pid), comm=FakeBytes(f"t{pid}".encode())) for pid in (1, 2, 3)
    ]
    monkeypatch.setattr("drgn.helpers.linux.pid.for_each_task", lambda prog: tasks)
    monkeypatch.setattr("drgn.helpers.linux.sched.task_state_to_char", lambda t: "R")
    mark_loaded()

    assert inspection.list_tasks(limit=1, offset=1) == (
        "pid=2 comm=t2 state=R\n... (limited to 1 tasks, use offset=2 for next page)"
    )


def test_list_tasks_formats_item_fault(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    fault = drgn_error("fault", "bad pid", address=0x70)
    good = SimpleNamespace(pid=FakeValue(1), comm=FakeBytes(b"ok"))
    bad = SimpleNamespace(pid=_FaultyValue(fault))
    monkeypatch.setattr("drgn.helpers.linux.pid.for_each_task", lambda prog: [good, bad])
    monkeypatch.setattr("drgn.helpers.linux.sched.task_state_to_char", lambda t: "R")
    mark_loaded()

    assert inspection.list_tasks() == f"pid=1 comm=ok state=R\n<fault: {fault}>"


def test_list_tasks_aborts_on_iterator_fault(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    fault = drgn_error("fault", "walk failed", address=0x80)
    good = SimpleNamespace(pid=FakeValue(1), comm=FakeBytes(b"ok"))

    def tasks(prog: object) -> Iterator[SimpleNamespace]:
        yield good
        raise fault

    monkeypatch.setattr("drgn.helpers.linux.pid.for_each_task", tasks)
    monkeypatch.setattr("drgn.helpers.linux.sched.task_state_to_char", lambda t: "R")
    mark_loaded()

    assert inspection.list_tasks() == (
        f"pid=1 comm=ok state=R\n... Traversal aborted due to memory fault: {fault}"
    )


# --- find_task ----------------------------------------------------------------


def test_find_task_returns_formatted_struct(monkeypatch: pytest.MonkeyPatch) -> None:
    task = SimpleNamespace(
        format_=lambda dereference=True: Stringable("struct task_struct { pid = 1 }")
    )
    monkeypatch.setattr("drgn.helpers.linux.pid.find_task", lambda prog, pid: task)
    mark_loaded()

    assert inspection.find_task(1) == "struct task_struct { pid = 1 }"


def test_find_task_reports_missing_pid(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("drgn.helpers.linux.pid.find_task", lambda prog, pid: None)
    mark_loaded()

    assert inspection.find_task(99) == "No task found with PID 99"


def test_find_task_reports_format_fault(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    fault = drgn_error("fault", "unmapped task", address=0x90)

    def format_(dereference: bool = True) -> str:
        raise fault

    monkeypatch.setattr(
        "drgn.helpers.linux.pid.find_task",
        lambda prog, pid: SimpleNamespace(format_=format_),
    )
    mark_loaded()

    assert inspection.find_task(5) == f"Task 5 found but memory fault during inspection: {fault}"


# --- list_modules -------------------------------------------------------------


def test_list_modules_formats_names(monkeypatch: pytest.MonkeyPatch) -> None:
    modules = [SimpleNamespace(name=FakeBytes(b"ext4")), SimpleNamespace(name=FakeBytes(b"xfs"))]
    monkeypatch.setattr("drgn.helpers.linux.module.for_each_module", lambda prog: modules)
    mark_loaded()

    assert inspection.list_modules() == "ext4\nxfs"


def test_list_modules_replaces_invalid_name_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    modules = [SimpleNamespace(name=FakeBytes(b"ext4\xff"))]
    monkeypatch.setattr("drgn.helpers.linux.module.for_each_module", lambda prog: modules)
    mark_loaded()

    assert inspection.list_modules() == "ext4\ufffd"


def test_list_modules_reports_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("drgn.helpers.linux.module.for_each_module", lambda prog: [])
    mark_loaded()

    assert inspection.list_modules() == "No modules loaded"


def test_list_modules_appends_traversal_fault(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    fault = drgn_error("fault", "mod list", address=0xA0)
    good = SimpleNamespace(name=FakeBytes(b"ext4"))

    def modules(prog: object) -> Iterator[SimpleNamespace]:
        yield good
        raise fault

    monkeypatch.setattr("drgn.helpers.linux.module.for_each_module", modules)
    mark_loaded()

    assert inspection.list_modules() == f"ext4\n... Traversal aborted due to memory fault: {fault}"


# --- get_panic_info -----------------------------------------------------------


def test_get_panic_info_formats_message_and_crashed_thread(
    monkeypatch: pytest.MonkeyPatch,
    fake_program: Callable[..., SimpleNamespace],
) -> None:
    thread = SimpleNamespace(tid=1, stack_trace=lambda: "#0 sysrq_handle_crash")
    monkeypatch.setattr(
        inspection, "panic_message", lambda prog: "Kernel panic - not syncing: sysrq"
    )
    mark_loaded(fake_program(crashed_thread=lambda: thread))

    assert inspection.get_panic_info() == (
        "Panic message: Kernel panic - not syncing: sysrq\n"
        "\n"
        "Crashed thread: tid=1\n"
        "Stack trace:\n"
        "#0 sysrq_handle_crash"
    )


@pytest.mark.parametrize("kind", ["fault", "lookup", "value"])
def test_get_panic_info_reports_panic_message_errors(
    monkeypatch: pytest.MonkeyPatch,
    fake_program: Callable[..., SimpleNamespace],
    drgn_error: Callable[..., BaseException],
    kind: str,
) -> None:
    error = drgn_error(kind, "no panic text", address=0xB0)

    def panic_message(prog: object) -> str:
        raise error

    thread = SimpleNamespace(tid=2, stack_trace=lambda: "#0 oops")
    monkeypatch.setattr(inspection, "panic_message", panic_message)
    mark_loaded(fake_program(crashed_thread=lambda: thread))

    assert inspection.get_panic_info() == (
        f"Could not retrieve panic message: {error}\n"
        "\n"
        "Crashed thread: tid=2\n"
        "Stack trace:\n"
        "#0 oops"
    )


def test_get_panic_info_reports_missing_crashed_thread(
    monkeypatch: pytest.MonkeyPatch,
    fake_program: Callable[..., SimpleNamespace],
) -> None:
    def crashed_thread() -> None:
        raise ValueError("no PT_REGS")

    monkeypatch.setattr(inspection, "panic_message", lambda prog: "Oops")
    mark_loaded(fake_program(crashed_thread=crashed_thread))

    assert inspection.get_panic_info() == (
        "Panic message: Oops\n\nCould not retrieve crashed thread: no PT_REGS"
    )


def test_get_panic_info_propagates_stack_unwind_fault(
    monkeypatch: pytest.MonkeyPatch,
    fake_program: Callable[..., SimpleNamespace],
    drgn_error: Callable[..., BaseException],
) -> None:
    fault = drgn_error("fault", "unwind failed", address=0xC0)

    def stack_trace() -> str:
        raise fault

    thread = SimpleNamespace(tid=1, stack_trace=stack_trace)
    monkeypatch.setattr(inspection, "panic_message", lambda prog: "Oops")
    mark_loaded(fake_program(crashed_thread=lambda: thread))

    with pytest.raises(type(fault)) as caught:
        inspection.get_panic_info()
    assert caught.value is fault
