"""Characterize DrgnState lifecycle and ToolError translation.

These tests construct a fresh ``DrgnState``. The process-wide singleton is
never the subject under test.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import drgn
import pytest
from mcp.server.mcpserver.exceptions import ToolError

from drgn_mcp import state as state_module
from drgn_mcp.state import DrgnState
from tests.conftest import make_fake_program


@dataclass
class RecordingProgram:
    """Stand-in for ``drgn.Program`` that captures how ``DrgnState.load()`` drives it.

    ``load()`` always constructs a Program, calls ``set_core_dump``, then takes
    exactly one debug-info branch: ``load_debug_info`` when a vmlinux path or
    extra symbols were supplied, otherwise ``load_default_debug_info``. Tests
    assert those recorded arguments instead of mock call order, and read
    ``flags`` / ``platform`` because ``format_program_info()`` includes them in
    the success string.

    Sentinel values (``None`` / ``0``) mean a method was never entered, so a
    test can prove the unused branch stayed unused. Subclass a method to raise
    ``MissingDebugInfoError``, ``OSError``, ``FaultError``, or ``ValueError``.
    """

    flags = drgn.ProgramFlags(0)
    platform = "test-platform"
    core_path: str | None = None
    debug_info_symbols: list[str] | None = None
    debug_info_kwargs: dict[str, bool] | None = None
    default_debug_info_calls = 0

    def set_core_dump(self, path: str) -> None:
        """Store the vmcore path ``load()`` passed; production calls this first."""
        self.core_path = path

    def load_debug_info(
        self,
        symbols: list[str],
        default: bool = False,
        main: bool = False,
    ) -> None:
        """Record an explicit symbol load (vmlinux first, then extra modules).

        Production always passes ``default=True, main=True``. The stored list is
        a copy so later mutation of the caller's ``symbols`` cannot hide what
        ``load()`` actually handed over.
        """
        self.debug_info_symbols = list(symbols)
        self.debug_info_kwargs = {"default": default, "main": main}

    def load_default_debug_info(self) -> None:
        """Count the no-symbols branch (no vmlinux path and no extra modules)."""
        self.default_debug_info_calls += 1


def _patch_load(
    monkeypatch: pytest.MonkeyPatch,
    program_cls: type[Any] = RecordingProgram,
) -> None:
    """Replace the two module-level names ``DrgnState.load()`` looks up.

    ``load()`` calls ``drgn.Program()`` and ``drgn.cli.default_globals(prog)``
    through ``state``'s imports, so the patches must land on
    ``drgn_mcp.state.drgn``, not a different copy of the ``drgn`` package.
    Instance methods (``set_core_dump``, debug-info loads) are not patched
    here: they live on ``program_cls``.

    ``program_cls`` defaults to ``RecordingProgram``. Pass a subclass to raise
    from a specific method. ``default_globals`` is stubbed because the real
    helper expects a genuine Program and would fail on the fake; the returned
    dict is what tests compare against ``session.globals``.
    """
    eval_globals = {"prog": "eval-context"}
    monkeypatch.setattr(state_module.drgn, "Program", program_cls)
    monkeypatch.setattr(
        state_module.drgn.cli,
        "default_globals",
        lambda _: eval_globals,
    )


def test_new_state_is_not_loaded() -> None:
    session = DrgnState()
    assert session.is_loaded is False
    assert session.prog is None
    assert session.globals == {}


def test_require_loaded_raises_until_a_program_is_present() -> None:
    session = DrgnState()
    with pytest.raises(ToolError, match="No program loaded. Use load_core_dump first."):
        session.require_loaded()

    program = make_fake_program(flags=drgn.ProgramFlags(0), platform="x86_64")
    session.prog = program  # type: ignore[assignment]
    assert session.is_loaded is True
    assert session.require_loaded() is program


def test_format_program_info_reports_flags_and_platform() -> None:
    session = DrgnState()
    session.prog = make_fake_program(  # type: ignore[assignment]
        flags=drgn.ProgramFlags(0),
        platform="x86_64",
    )
    assert session.format_program_info() == (
        "Program loaded successfully\nFlags: ProgramFlags(0)\nPlatform: x86_64"
    )


def test_format_program_info_labels_linux_kernel_dumps() -> None:
    session = DrgnState()
    session.prog = make_fake_program(  # type: ignore[assignment]
        flags=drgn.ProgramFlags.IS_LINUX_KERNEL,
        platform="x86_64",
    )
    assert session.format_program_info() == (
        "Program loaded successfully\n"
        "Flags: ProgramFlags.IS_LINUX_KERNEL\n"
        "Platform: x86_64\n"
        "Type: Linux kernel"
    )


def test_load_uses_default_debug_info_without_symbols(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_load(monkeypatch)
    session = DrgnState()

    result = session.load("/tmp/vmcore")

    program = session.require_loaded()
    assert isinstance(program, RecordingProgram)
    assert program.core_path == "/tmp/vmcore"
    assert program.default_debug_info_calls == 1
    assert program.debug_info_symbols is None
    assert session.globals == {"prog": "eval-context"}
    assert result == "\n".join(
        [
            "Program loaded successfully",
            "Flags: ProgramFlags(0)",
            "Platform: test-platform",
        ]
    )
    assert state_module.state.prog is None


def test_load_selects_vmlinux_when_no_extra_symbols(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_load(monkeypatch)
    session = DrgnState()

    session.load("/tmp/vmcore", vmlinux_path="/boot/vmlinux")

    program = session.require_loaded()
    assert isinstance(program, RecordingProgram)
    assert program.default_debug_info_calls == 0
    assert program.debug_info_symbols == ["/boot/vmlinux"]
    assert program.debug_info_kwargs == {"default": True, "main": True}


def test_load_orders_vmlinux_before_extra_symbols(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_load(monkeypatch)
    session = DrgnState()

    session.load(
        "/tmp/vmcore",
        vmlinux_path="/boot/vmlinux",
        extra_symbols=["module.ko", "other.ko"],
    )

    program = session.require_loaded()
    assert isinstance(program, RecordingProgram)
    assert program.debug_info_symbols == ["/boot/vmlinux", "module.ko", "other.ko"]
    assert program.debug_info_kwargs == {"default": True, "main": True}


def test_load_uses_extra_symbols_without_vmlinux(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_load(monkeypatch)
    session = DrgnState()

    session.load("/tmp/vmcore", extra_symbols=["only.ko"])

    program = session.require_loaded()
    assert isinstance(program, RecordingProgram)
    assert program.debug_info_symbols == ["only.ko"]
    assert program.default_debug_info_calls == 0


def test_load_appends_missing_debug_info_warning(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    class MissingDebugProgram(RecordingProgram):
        def load_debug_info(
            self,
            symbols: list[str],
            default: bool = False,
            main: bool = False,
        ) -> None:
            raise drgn_error("missing_debug_info", "missing vmlinux debug")

    _patch_load(monkeypatch, MissingDebugProgram)
    session = DrgnState()

    result = session.load("/tmp/vmcore", vmlinux_path="/boot/vmlinux")

    assert session.is_loaded is True
    assert result.endswith("\nWarning: missing vmlinux debug")
    assert result.startswith("Program loaded successfully")


def test_load_rejects_a_second_program(monkeypatch: pytest.MonkeyPatch) -> None:
    constructions = {"count": 0}

    class CountingProgram(RecordingProgram):
        def __init__(self) -> None:
            constructions["count"] += 1
            super().__init__()

    _patch_load(monkeypatch, CountingProgram)
    session = DrgnState()
    session.load("/tmp/first")

    with pytest.raises(
        ToolError,
        match="A program is already loaded. Restart the server to load a new one.",
    ):
        session.load("/tmp/second")

    assert constructions["count"] == 1
    program = session.require_loaded()
    assert isinstance(program, CountingProgram)
    assert program.core_path == "/tmp/first"


@pytest.mark.parametrize(
    "error",
    [
        OSError("cannot open core"),
        ValueError("invalid core"),
    ],
)
def test_load_converts_oserror_and_valueerror_to_tool_error(
    monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    class FailingProgram(RecordingProgram):
        def set_core_dump(self, path: str) -> None:
            raise error

    _patch_load(monkeypatch, FailingProgram)
    session = DrgnState()

    with pytest.raises(ToolError, match=str(error)):
        session.load("/tmp/vmcore")

    assert session.is_loaded is False


def test_load_converts_fault_error_to_tool_error(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    fault = drgn_error("fault", "bad dump", address=0x10)

    class FailingProgram(RecordingProgram):
        def set_core_dump(self, path: str) -> None:
            raise fault

    _patch_load(monkeypatch, FailingProgram)
    session = DrgnState()

    with pytest.raises(ToolError, match="bad dump: 0x10"):
        session.load("/tmp/vmcore")

    assert session.is_loaded is False
