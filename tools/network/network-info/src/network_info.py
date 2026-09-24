"""Read-only local network interface information."""

import socket

import psutil


def get_network_interfaces() -> list[dict[str, str]]:
    """Return local network interface names and their addresses."""
    interfaces: list[dict[str, str]] = []

    for name, addresses in psutil.net_if_addrs().items():
        ipv4_addresses: list[str] = []
        ipv6_addresses: list[str] = []

        for address in addresses:
            if address.family == socket.AF_INET:
                ipv4_addresses.append(address.address)
            elif address.family == socket.AF_INET6:
                ipv6_addresses.append(address.address)

        interfaces.append(
            {
                "name": name,
                "ipv4": ", ".join(ipv4_addresses),
                "ipv6": ", ".join(ipv6_addresses),
            }
        )

    return interfaces


if __name__ == "__main__":
    for interface in get_network_interfaces():
        print(
            f"{interface['name']}: "
            f"IPv4={interface['ipv4'] or '-'} "
            f"IPv6={interface['ipv6'] or '-'}"
        )
