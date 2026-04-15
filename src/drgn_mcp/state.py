from typing import Any, Optional

import drgn
import drgn.cli


class DrgnState:
    def __init__(self):
        self.prog: Optional[drgn.Program] = None
        self._globals: dict[str, Any] = {}

    @property
    def is_loaded(self) -> bool:
        return self.prog is not None

    def require_loaded(self) -> drgn.Program:
        if self.prog is None:
            raise RuntimeError("No program loaded. Use load_core_dump first.")
        return self.prog

    @property
    def globals(self) -> dict[str, Any]:
        return self._globals

    def load(
        self,
        core_path: str,
        vmlinux_path: Optional[str] = None,
        extra_symbols: Optional[list[str]] = None,
    ) -> str:
        if self.prog is not None:
            raise RuntimeError(
                "A program is already loaded. Restart the server to load a new one."
            )

        prog = drgn.Program()
        prog.set_core_dump(core_path)

        symbols = []
        if vmlinux_path:
            symbols.append(vmlinux_path)
        if extra_symbols:
            symbols.extend(extra_symbols)

        if symbols:
            prog.load_debug_info(symbols, default=True, main=True)
        else:
            prog.load_default_debug_info()

        self.prog = prog
        self._globals = drgn.cli.default_globals(prog)
        return self.format_program_info()

    def format_program_info(self) -> str:
        prog = self.require_loaded()
        lines = ["Program loaded successfully"]
        lines.append(f"Flags: {prog.flags}")
        lines.append(f"Platform: {prog.platform}")
        if prog.flags & drgn.ProgramFlags.IS_LINUX_KERNEL:
            lines.append("Type: Linux kernel")
        return "\n".join(lines)


state = DrgnState()
