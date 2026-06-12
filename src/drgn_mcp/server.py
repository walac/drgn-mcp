import drgn_mcp.tools  # registers all 54 MCP tools
from drgn_mcp._app import mcp


def main():
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
