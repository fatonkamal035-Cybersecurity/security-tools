import sys
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC_DIR))

from network_info import get_network_interfaces


def test_get_network_interfaces_returns_expected_structure():
    interfaces = get_network_interfaces()

    assert isinstance(interfaces, list)
    assert interfaces

    for interface in interfaces:
        assert set(interface) == {"name", "ipv4", "ipv6"}
        assert interface["name"]
        assert isinstance(interface["ipv4"], str)
        assert isinstance(interface["ipv6"], str)
