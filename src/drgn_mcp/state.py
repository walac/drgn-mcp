from typing import Any, Optional

import drgn
import drgn.cli


class DrgnState:
    """Global state for the drgn debugging session.

    Manages the lifecycle of a single drgn Program loaded from a kernel
    crash dump. Only one program can be loaded per server lifetime; all
    MCP tools share this instance via the module-level ``state`` singleton.
    """

    def __init__(self):
        self.prog: Optional[drgn.Program] = None
        self._globals: dict[str, Any] = {}

    @property
    def is_loaded(self) -> bool:
        """Return True if a crash dump has been loaded."""
        return self.prog is not None

    def require_loaded(self) -> drgn.Program:
        """Return the loaded Program, or raise if none is loaded.

        Every MCP tool calls this before accessing the program.
        """
        if self.prog is None:
            raise RuntimeError("No program loaded. Use load_core_dump first.")
        return self.prog

    @property
    def globals(self) -> dict[str, Any]:
        """Return the eval context dict for expression evaluation.

        Contains ``prog``, all drgn module attributes, and all
        ``drgn.helpers.linux.*`` helpers, populated by
        ``drgn.cli.default_globals()`` at load time.
        """
        return self._globals

    def load(
        self,
        core_path: str,
        vmlinux_path: Optional[str] = None,
        extra_symbols: Optional[list[str]] = None,
    ) -> str:
        """Load a vmcore crash dump and initialize the debugging session.

        Can only be called once. Subsequent calls raise RuntimeError.
        Missing debug info is reported as a warning rather than aborting
        the load, allowing inspection with partial symbol information.
        """
        if self.prog is not None:
            raise RuntimeError(
                "A program is already loaded. Restart the server to load a new one."
            )

        prog = drgn.Program()
        prog.set_core_dump(core_path)

        symbols: list[str] = []
        if vmlinux_path:
            symbols.append(vmlinux_path)
        if extra_symbols:
            symbols.extend(extra_symbols)

        missing_info = ""
        try:
            if symbols:
                prog.load_debug_info(symbols, default=True, main=True)
            else:
                prog.load_default_debug_info()
        except drgn.MissingDebugInfoError as e:
            missing_info = f"\nWarning: {e}"

        self.prog = prog
        self._globals = drgn.cli.default_globals(prog)
        return self.format_program_info() + missing_info

    def format_program_info(self) -> str:
        """Format a summary of the loaded program's flags and platform."""
        prog = self.require_loaded()
        lines = ["Program loaded successfully"]
        lines.append(f"Flags: {prog.flags}")
        lines.append(f"Platform: {prog.platform}")
        if prog.flags & drgn.ProgramFlags.IS_LINUX_KERNEL:
            lines.append("Type: Linux kernel")
        return "\n".join(lines)


state = DrgnState()
