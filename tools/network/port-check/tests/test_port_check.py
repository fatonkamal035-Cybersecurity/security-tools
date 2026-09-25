import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from port_check import check_tcp_port


def test_check_tcp_port_reachable():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)

    host, port = server.getsockname()

    try:
        result = check_tcp_port(host, port)

        assert result == {
            "host": host,
            "port": port,
            "reachable": True,
        }
    finally:
        server.close()


def test_check_tcp_port_connection_refused():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    port = server.getsockname()[1]
    server.close()

    result = check_tcp_port("127.0.0.1", port)

    assert result == {
        "host": "127.0.0.1",
        "port": port,
        "reachable": False,
    }


def test_check_tcp_port_rejects_empty_host():
    try:
        check_tcp_port("", 80)
    except ValueError as exc:
        assert str(exc) == "host must not be empty"
    else:
        raise AssertionError("Expected ValueError")


def test_check_tcp_port_rejects_invalid_port():
    for port in (0, 65536):
        try:
            check_tcp_port("127.0.0.1", port)
        except ValueError as exc:
            assert str(exc) == "port must be between 1 and 65535"
        else:
            raise AssertionError("Expected ValueError")


def test_check_tcp_port_rejects_invalid_timeout():
    try:
        check_tcp_port("127.0.0.1", 80, timeout=0)
    except ValueError as exc:
        assert str(exc) == "timeout must be greater than zero"
    else:
        raise AssertionError("Expected ValueError")
