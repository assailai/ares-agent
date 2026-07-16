"""Network auto-detection: report real RFC1918 LANs, never virtual/VPN ranges."""

from __future__ import annotations

from agent.netdetect import (
    apply_scope,
    docker_networks_from_interfaces,
    host_all_targets,
    networks_from_interfaces,
)


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


# --- scope widening (scan_targets / apply_scope) ------------------------------------------------


def test_supernet16_widens_attached_subnet_to_its_slash16() -> None:
    assert apply_scope(["192.168.1.0/24"], "supernet16") == ["192.168.0.0/16"]


def test_supernet16_collapses_subnets_that_share_a_slash16() -> None:
    # two /24s in the same /16 widen to one covering /16, not two duplicates.
    assert apply_scope(["10.5.3.0/24", "10.5.4.0/24"], "supernet16") == ["10.5.0.0/16"]


def test_supernet16_keeps_a_prefix_already_broader_than_slash16() -> None:
    assert apply_scope(["10.0.0.0/8"], "supernet16") == ["10.0.0.0/8"]


def test_attached_scope_keeps_interface_prefixes() -> None:
    assert apply_scope(["192.168.1.0/24"], "attached") == ["192.168.1.0/24"]


def test_rfc1918_scope_scans_all_private_space() -> None:
    assert apply_scope([], "rfc1918") == ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]


def test_unknown_scope_falls_back_to_supernet16() -> None:
    assert apply_scope(["192.168.1.0/24"], "not-a-scope") == ["192.168.0.0/16"]


# --- host-all scope (docker bridges + loopback, for host-networked containers) ------------------


def test_docker_networks_returns_bridge_subnets_only() -> None:
    # given the LAN, docker0, a compose bridge and loopback; when we ask for docker subnets; then
    # only the two bridge networks come back.
    rows = [
        ("eth0", "192.168.1.10", 24),
        ("docker0", "172.17.0.1", 16),
        ("br-abc123", "172.18.0.1", 16),
        ("lo", "127.0.0.1", 8),
    ]
    assert docker_networks_from_interfaces(rows) == ["172.17.0.0/16", "172.18.0.0/16"]


def test_host_all_folds_in_loopback_lan_and_docker() -> None:
    # a host-networked container's view: host-all sweeps the loopback, the LAN widened to /16, and
    # the docker bridge subnet.
    rows = [("eth0", "192.168.1.10", 24), ("docker0", "172.17.0.1", 16)]
    assert host_all_targets(rows) == ["127.0.0.1/32", "172.17.0.0/16", "192.168.0.0/16"]


def test_host_all_without_docker_is_just_loopback_and_lan() -> None:
    # no bridge present (agent not on a docker host) -> loopback + the widened LAN, nothing else.
    assert host_all_targets([("eth0", "10.2.3.4", 24)]) == ["10.2.0.0/16", "127.0.0.1/32"]
