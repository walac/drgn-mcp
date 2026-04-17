from drgn_mcp._app import mcp

import drgn_mcp.tools  # noqa: F401  # registers all 38 MCP tools


def main():
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
