from drgn.helpers.linux.net import (
    for_each_netdev,
    netdev_ipv4_addrs,
    netdev_ipv6_addrs,
    netdev_name,
)

from drgn_mcp._app import mcp
from drgn_mcp.state import state
from drgn_mcp.tools._helpers import paginated_lines


@mcp.tool()
def list_netdevs(limit: int = 100, offset: int = 0) -> str:
    """List all network devices with their names and IP addresses.

    Use this to see network interfaces that were active at the time of the
    crash, including their IPv4 and IPv6 addresses.

    Args:
        limit: Maximum number of devices to return.
        offset: Number of devices to skip (for pagination).

    Returns:
        A multi-line string listing each network device with its name and
        assigned IP addresses. Appends a truncation notice if devices
        exceed limit.

    Examples:
        list_netdevs()
    """
    prog = state.require_loaded()

    def fmt(dev):
        name = netdev_name(dev).decode(errors="replace")
        ipv4 = [str(a) for a in netdev_ipv4_addrs(dev)]
        ipv6 = [str(a) for a in netdev_ipv6_addrs(dev)]
        addrs = ", ".join(ipv4 + ipv6) or "no addresses"
        return f"{name}: {addrs}"

    lines = paginated_lines(
        for_each_netdev(prog, None),  # type: ignore[call-overload]  # ty: ignore[no-matching-overload]
        fmt,
        offset=offset,
        limit=limit,
        label="devices",
    )
    return "\n".join(lines) if lines else "No network devices found"
