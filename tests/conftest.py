"""Shared test primitives and isolation for drgn-mcp unit tests."""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterator
from types import SimpleNamespace
from typing import Any

import drgn
import pytest

from drgn_mcp.state import state
from drgn_mcp.tools import core


class FakeValue:
    """Stand-in for a drgn object whose integer payload is read via value_()."""

    def __init__(self, value: int) -> None:
        self._value = value

    def value_(self) -> int:
        return self._value


class FakeBytes:
    """Stand-in for a drgn object whose bytes payload is read via string_()."""

    def __init__(self, value: bytes) -> None:
        self._value = value

    def string_(self) -> bytes:
        return self._value


class Stringable:
    """Stand-in whose text appears only through ``str()``.

    Tools that format results with ``str(...)`` or f-string interpolation would
    still pass if the fake returned a plain string and production dropped that
    call. This wrapper fails the equality assert unless the tool actually
    stringifies the object.
    """

    def __init__(self, text: str) -> None:
        self._text = text

    def __str__(self) -> str:
        return self._text


def make_fake_program(**attrs: Any) -> SimpleNamespace:
    """Minimal Program stand-in exposing only attributes the caller needs.

    Defaults cover the fields ``DrgnState.format_program_info`` reads. Pass
    extra keyword arguments to add or override attributes for a single test
    rather than growing a shared fake kernel model.
    """
    program = SimpleNamespace(flags=0, platform=None)
    for name, value in attrs.items():
        setattr(program, name, value)
    return program


def mark_loaded(program: object | None = None) -> None:
    """Mark the session as holding a dump so tools skip the unloaded gate.

    Pass a program stand-in when the tool under test reads ``state.prog``.
    Defaults to ``make_fake_program()`` so tools that only call
    ``require_loaded()`` still see a loaded session.
    """
    state.prog = program if program is not None else make_fake_program()  # type: ignore[assignment]


def make_drgn_error(
    kind: str,
    message: str = "synthetic error",
    *,
    address: int = 0,
) -> BaseException:
    """Build a drgn or builtin exception without callers knowing constructors.

    ``drgn.FaultError`` requires both a message and an address; this factory
    keeps that detail out of individual tests.
    """
    match kind:
        case "fault":
            return drgn.FaultError(message, address)
        case "missing_debug_info":
            return drgn.MissingDebugInfoError(message)
        case "lookup":
            return LookupError(message)
        case "value":
            return ValueError(message)
        case _:
            raise ValueError(f"unknown synthetic error kind: {kind}")


@pytest.fixture
def fake_program() -> Callable[..., SimpleNamespace]:
    return make_fake_program


@pytest.fixture
def drgn_error() -> Callable[..., BaseException]:
    return make_drgn_error


def restore_isolated_drgn_state(
    previous_prog: Any,
    previous_globals: dict[str, Any],
    previous_thread: threading.Thread | None,
) -> None:
    """Fail if an eval worker is still running, then restore session globals.

    The assert runs first so restoring ``_active_eval_thread`` cannot hide a
    leaked daemon.
    """
    active = core._active_eval_thread
    assert active is None or not active.is_alive(), "eval worker still running at test teardown"
    state.prog = previous_prog
    state._globals = previous_globals
    core._active_eval_thread = previous_thread


@pytest.fixture(autouse=True)
def isolate_drgn_state() -> Iterator[None]:
    """Reset the process-wide drgn session around every test.

    The server keeps one ``state`` singleton and at most one eval worker
    thread. Without this reset, a loaded fake program or a leaked daemon
    would bleed into the next test.
    """
    previous_prog = state.prog
    previous_globals = state._globals
    previous_thread = core._active_eval_thread

    state.prog = None
    state._globals = {}
    core._active_eval_thread = None

    yield

    restore_isolated_drgn_state(previous_prog, previous_globals, previous_thread)
