from drgn_mcp._app import mcp

import drgn_mcp.tools.core  # noqa: F401
import drgn_mcp.tools.inspection  # noqa: F401
import drgn_mcp.tools.memory  # noqa: F401
import drgn_mcp.tools.subsystems  # noqa: F401
import drgn_mcp.tools.traversal  # noqa: F401
import drgn_mcp.tools.utils  # noqa: F401


def main():
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
