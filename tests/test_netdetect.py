"""Network auto-detection: report real RFC1918 LANs, never virtual/VPN ranges."""

from __future__ import annotations

from agent.netdetect import networks_from_interfaces


def test_reports_real_lan_collapsed_to_covering_cidr() -> None:
    nets = networks_from_interfaces([("eth0", "192.168.1.37", 24)])
    assert nets == ["192.168.1.0/24"]


def test_excludes_docker_bridge_and_virtual_interfaces() -> None:
    rows = [
        ("docker0", "172.17.0.1", 16),
        ("br-abc123", "172.18.0.1", 16),
        ("veth9f2", "172.19.0.2", 16),
        ("eth0", "10.10.5.20", 24),
    ]
    assert networks_from_interfaces(rows) == ["10.10.5.0/24"]


def test_excludes_loopback_link_local_and_vpn_interfaces() -> None:
    rows = [
        ("lo", "127.0.0.1", 8),
        ("eth0", "169.254.1.1", 16),  # link-local
        ("wg0", "10.200.0.7", 16),  # a VPN interface, skipped by name
        ("eth1", "10.0.0.5", 24),
    ]
    assert networks_from_interfaces(rows) == ["10.0.0.0/24"]


def test_excludes_public_addresses() -> None:
    assert networks_from_interfaces([("eth0", "8.8.8.8", 24)]) == []


def test_dedupes_multiple_addresses_on_same_subnet() -> None:
    rows = [("eth0", "192.168.1.10", 24), ("eth0", "192.168.1.11", 24)]
    assert networks_from_interfaces(rows) == ["192.168.1.0/24"]
