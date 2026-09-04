"""Prove that the autouse isolation fixture starts each test from a clean session."""

import threading

import pytest

from drgn_mcp.state import state
from drgn_mcp.tools import core
from tests.conftest import restore_isolated_drgn_state


def test_harness_starts_with_no_loaded_program() -> None:
    assert state.prog is None
    assert state.is_loaded is False


def test_harness_starts_with_empty_eval_globals() -> None:
    assert state._globals == {}
    assert core._active_eval_thread is None


def test_teardown_restores_session_when_eval_worker_is_idle() -> None:
    previous_prog = object()
    previous_globals = {"kept": True}
    state.prog = object()  # type: ignore[assignment]
    state._globals = {"dirty": True}
    core._active_eval_thread = None

    restore_isolated_drgn_state(previous_prog, previous_globals, None)

    assert state.prog is previous_prog
    assert state._globals is previous_globals
    assert core._active_eval_thread is None


def test_teardown_does_not_restore_while_eval_worker_is_alive() -> None:
    started = threading.Event()
    release = threading.Event()

    def linger() -> None:
        started.set()
        release.wait()

    worker = threading.Thread(target=linger, name="drgn-eval", daemon=True)
    worker.start()
    assert started.wait(timeout=1.0)

    leaked_prog = object()
    leaked_globals = {"leaked": True}
    saved_prog = object()
    saved_globals = {"saved": True}
    state.prog = leaked_prog  # type: ignore[assignment]
    state._globals = leaked_globals
    core._active_eval_thread = worker

    try:
        with pytest.raises(AssertionError, match="eval worker still running at test teardown"):
            restore_isolated_drgn_state(saved_prog, saved_globals, None)
        assert state.prog is leaked_prog
        assert state._globals is leaked_globals
        assert core._active_eval_thread is worker
    finally:
        release.set()
        worker.join(timeout=1.0)
        assert not worker.is_alive()
        core._active_eval_thread = None
