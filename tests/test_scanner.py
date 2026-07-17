"""Unit tests for the scanner utilities and a live loopback scan."""

import socket
import threading

import pytest

from vulnscan.scanner import Scanner, parse_ports


def test_parse_ports_default_is_common():
    ports = parse_ports(None)
    assert 22 in ports and 80 in ports and 443 in ports


def test_parse_ports_range_and_list():
    assert parse_ports("22,80") == [22, 80]
    assert parse_ports("20-22") == [20, 21, 22]
    assert parse_ports("25-23") == [23, 24, 25]  # reversed range normalised


def test_parse_ports_invalid_raises():
    with pytest.raises(ValueError):
        parse_ports("99999")


def test_scan_detects_open_loopback_port():
    # Spin up a throwaway TCP server on an ephemeral port.
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def _accept():
        try:
            conn, _ = server.accept()
            conn.close()
        except OSError:
            pass

    threading.Thread(target=_accept, daemon=True).start()

    scanner = Scanner(timeout=1.0, workers=4)
    result = scanner.scan("127.0.0.1", [port])
    server.close()

    assert len(result.ports) == 1
    assert result.ports[0].port == port


def test_scan_unresolvable_host_raises():
    scanner = Scanner()
    with pytest.raises(ValueError):
        scanner.scan("this-host-does-not-exist.invalid", [80])
