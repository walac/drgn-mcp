"""Characterize core tools, helper discovery, and async evaluation."""

import inspect
import threading
from collections.abc import Callable
from types import SimpleNamespace

import pytest

from drgn_mcp.state import state
from drgn_mcp.tools import core
from drgn_mcp.tools._helpers import truncate_output
from tests.conftest import make_fake_program


class _Uninspectable:
    """Cannot introspect."""

    def __call__(self) -> None:
        return None

    @property
    def __signature__(self) -> inspect.Signature:
        raise ValueError("no signature")


def _mark_loaded() -> None:
    state.prog = make_fake_program()  # type: ignore[assignment]


def _install_fake_linux_helpers(
    monkeypatch: pytest.MonkeyPatch,
    modules: dict[str, object],
) -> None:
    """Replace package discovery so tests never scan the installed drgn tree."""

    imported = {f"drgn.helpers.linux.{name}": module for name, module in modules.items()}

    def fake_iter_modules(path: object, prefix: str = "") -> list[SimpleNamespace]:
        return [SimpleNamespace(name=full_name) for full_name in imported]

    monkeypatch.setattr(core.pkgutil, "iter_modules", fake_iter_modules)
    monkeypatch.setattr(core.importlib, "import_module", imported.__getitem__)


def test_load_core_dump_delegates_blank_optionals_as_none(monkeypatch: pytest.MonkeyPatch) -> None:
    recorded: dict[str, object] = {}

    def fake_load(
        core_path: str,
        vmlinux_path: str | None = None,
        extra_symbols: list[str] | None = None,
    ) -> str:
        recorded["core_path"] = core_path
        recorded["vmlinux_path"] = vmlinux_path
        recorded["extra_symbols"] = extra_symbols
        return "loaded"

    monkeypatch.setattr(state, "load", fake_load)

    assert core.load_core_dump("/tmp/vmcore", vmlinux_path="", extra_symbols=[]) == "loaded"
    assert recorded == {
        "core_path": "/tmp/vmcore",
        "vmlinux_path": None,
        "extra_symbols": None,
    }


def test_load_core_dump_preserves_nonempty_extra_symbols(monkeypatch: pytest.MonkeyPatch) -> None:
    recorded: dict[str, object] = {}
    symbols = ["/tmp/module.ko", "/tmp/other.ko"]

    def fake_load(
        core_path: str,
        vmlinux_path: str | None = None,
        extra_symbols: list[str] | None = None,
    ) -> str:
        recorded["args"] = (core_path, vmlinux_path, extra_symbols)
        return "loaded"

    monkeypatch.setattr(state, "load", fake_load)

    assert (
        core.load_core_dump(
            "/tmp/vmcore",
            vmlinux_path="/boot/vmlinux",
            extra_symbols=symbols,
        )
        == "loaded"
    )
    assert recorded["args"] == ("/tmp/vmcore", "/boot/vmlinux", symbols)


def test_get_program_info_delegates_formatting(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(state, "format_program_info", lambda: "delegated-info")
    assert core.get_program_info() == "delegated-info"


def test_list_helpers_summary_lists_sorted_module_counts(monkeypatch: pytest.MonkeyPatch) -> None:
    _mark_loaded()
    _install_fake_linux_helpers(
        monkeypatch,
        {
            "net": SimpleNamespace(__all__=["for_each_netdev"]),
            "mm": SimpleNamespace(__all__=["pfn_to_page", "virt_to_page"]),
        },
    )

    assert core.list_helpers() == "mm: 2 functions\nnet: 1 functions"


def test_list_helpers_module_shows_signature_and_first_doc_line(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def walk_page(prog: object, limit: int = 10) -> str:
        """Walk page tables.

        Extra paragraph that must not appear.
        """
        return "ok"

    _mark_loaded()
    _install_fake_linux_helpers(
        monkeypatch,
        {
            "mm": SimpleNamespace(
                __all__=["missing", "not_callable", "walk_page"],
                walk_page=walk_page,
                not_callable=123,
            ),
        },
    )

    assert core.list_helpers("mm") == (
        "mm (3 functions):\n"
        "  missing\n"
        "  not_callable\n"
        f"  walk_page{inspect.signature(walk_page)}\n"
        "      Walk page tables."
    )


def test_list_helpers_rejects_unknown_module(monkeypatch: pytest.MonkeyPatch) -> None:
    _mark_loaded()
    _install_fake_linux_helpers(
        monkeypatch,
        {
            "mm": SimpleNamespace(__all__=["pfn_to_page"]),
            "net": SimpleNamespace(__all__=["for_each_netdev"]),
        },
    )

    assert core.list_helpers("sched") == "Unknown module 'sched'. Available: mm, net"


def test_list_helpers_uses_ellipsis_for_uninspectable_callable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _mark_loaded()
    _install_fake_linux_helpers(
        monkeypatch,
        {
            "mm": SimpleNamespace(__all__=["opaque"], opaque=_Uninspectable()),
        },
    )

    assert core.list_helpers("mm") == (
        "mm (1 functions):\n" "  opaque(...)\n" "      Cannot introspect."
    )


def test_list_helpers_truncates_long_module_output(monkeypatch: pytest.MonkeyPatch) -> None:
    def huge() -> None:
        return None

    huge.__doc__ = "H" * 9000

    _mark_loaded()
    _install_fake_linux_helpers(
        monkeypatch,
        {"mm": SimpleNamespace(__all__=["huge"], huge=huge)},
    )

    expected = "\n".join(
        [
            "mm (1 functions):",
            f"  huge{inspect.signature(huge)}",
            "      " + ("H" * 9000),
        ]
    )
    assert core.list_helpers("mm") == truncate_output(expected)


def test_eval_in_thread_evaluates_an_expression() -> None:
    capture = core._BoundedStringIO()
    assert core._eval_in_thread("1 + 2", capture) == 3
    assert capture.getvalue() == ""


def test_eval_in_thread_falls_back_to_exec_for_a_statement() -> None:
    state._globals = {}
    capture = core._BoundedStringIO()
    assert core._eval_in_thread("value = 41\nvalue += 1", capture) is None
    assert state._globals["value"] == 42


def test_eval_in_thread_captures_stdout() -> None:
    capture = core._BoundedStringIO()
    assert core._eval_in_thread("print('hello')", capture) is None
    assert capture.getvalue() == "hello\n"


def test_eval_in_thread_propagates_expression_failures() -> None:
    capture = core._BoundedStringIO()
    with pytest.raises(ZeroDivisionError):
        core._eval_in_thread("1 / 0", capture)


@pytest.mark.parametrize(
    ("exc", "error_type", "hint_fragment"),
    [
        (LookupError("missing symbol"), "LookupError", "lookup_symbol"),
        (TypeError("mismatch"), "TypeError", "list_helpers"),
        (SyntaxError("bad syntax"), "SyntaxError", "unmatched parentheses"),
        (NameError("n"), "NameError", "eval context"),
    ],
)
def test_format_eval_error_includes_typed_hint(
    exc: BaseException, error_type: str, hint_fragment: str
) -> None:
    result = core._format_eval_error(exc, "expr", "")
    assert result.startswith(f"Error ({error_type}): {exc}")
    assert "Expression: expr" in result
    assert hint_fragment in result


def test_format_eval_error_for_fault_error(drgn_error: Callable[..., BaseException]) -> None:
    fault = drgn_error("fault", "unmapped", address=0x20)
    result = core._format_eval_error(fault, "ptr.member", "")
    assert result.startswith("Error (FaultError): unmapped: 0x20")
    assert "Expression: ptr.member" in result
    assert "identify_address" in result


def test_format_eval_error_rewrites_timeout() -> None:
    result = core._format_eval_error(core._EvalTimeout(), "spin()", "")
    assert result.startswith("Error (TimeoutError): Expression exceeded the execution time limit.")
    assert "Expression: spin()" in result
    assert "itertools.islice" in result


def test_format_eval_error_includes_traceback_for_unexpected_exception() -> None:
    try:
        raise RuntimeError("boom")
    except RuntimeError as exc:
        result = core._format_eval_error(exc, "raise_boom()", "")

    assert result.startswith("Error (RuntimeError):")
    assert "Traceback (most recent call last):" in result
    assert "RuntimeError: boom" in result
    assert "Expression: raise_boom()" in result
    assert "Hint:" not in result


def test_format_eval_error_truncates_partial_output() -> None:
    partial = "p" * 2001
    result = core._format_eval_error(NameError("n"), "n", partial)
    assert "Partial output before error:\n" + ("p" * 2000) + "\n... (partial output truncated)" in (
        result
    )
    assert ("p" * 2001) not in result


async def test_eval_expression_returns_value_and_allows_a_second_call() -> None:
    _mark_loaded()
    assert await core.eval_expression("1") == "1"
    assert await core.eval_expression("2") == "2"


async def test_eval_expression_includes_stdout_and_value() -> None:
    def answer() -> int:
        print("computing")
        return 42

    _mark_loaded()
    state._globals = {"answer": answer}
    assert await core.eval_expression("answer()") == "computing\n\n42"


async def test_eval_expression_reports_no_output() -> None:
    _mark_loaded()
    assert await core.eval_expression("None") == "(no output)"


async def test_eval_expression_returns_error_string_instead_of_raising() -> None:
    _mark_loaded()
    result = await core.eval_expression("missing")
    assert result.startswith("Error (NameError):")
    assert "Expression: missing" in result
    assert "list_helpers" in result


async def test_eval_expression_times_out_python_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force the timeout path without waiting the configured 5s join."""

    entered = threading.Event()
    stop = threading.Event()

    def spin() -> None:
        entered.set()
        while not stop.is_set():
            pass

    _mark_loaded()
    state._globals = {"spin": spin}

    joins = 0
    real_join = core._join_thread

    async def first_join_times_out(thread: threading.Thread, timeout: float | None) -> None:
        nonlocal joins
        joins += 1
        if joins == 1:
            assert entered.wait(timeout=1.0)
            return
        await real_join(thread, timeout)

    monkeypatch.setattr(core, "_join_thread", first_join_times_out)

    try:
        result = await core.eval_expression("spin()", timeout=5)
    finally:
        stop.set()
        worker = core._active_eval_thread
        if worker is not None and worker.is_alive():
            worker.join(timeout=1.0)
        assert worker is None or not worker.is_alive()

    assert result.startswith("Error (TimeoutError): Expression exceeded the execution time limit.")
    assert "Expression: spin()" in result
    assert joins == 2


async def test_eval_expression_rejects_a_live_worker() -> None:
    started = threading.Event()
    release = threading.Event()

    def linger() -> None:
        started.set()
        release.wait()

    worker = threading.Thread(target=linger, name="drgn-eval", daemon=True)
    worker.start()
    assert started.wait(timeout=1.0)

    _mark_loaded()
    core._active_eval_thread = worker
    try:
        result = await core.eval_expression("1")
        assert result == (
            "Error: a previous eval_expression call is still running, likely "
            "stuck in native code that could not be interrupted. The server "
            "must be restarted before eval_expression can be used again."
        )
    finally:
        release.set()
        worker.join(timeout=1.0)
        assert not worker.is_alive()
        core._active_eval_thread = None
