"""Reachability discovery: find every private network the agent can reach, not just its own.

The parsers are pure and tested against real command output. The probe is tested against a fake
connector rather than a socket, so the two-stage shape (thin sweep, then a dense pass inside the
/16s that showed life) is asserted directly instead of inferred from timing.
"""

from __future__ import annotations

import ipaddress

import pytest

from agent import reachability


# --- private-space membership -------------------------------------------------------------------


@pytest.mark.parametrize(
    "cidr",
    ["10.0.0.0/8", "10.20.5.0/24", "172.16.0.0/12", "172.23.0.0/16", "192.168.1.0/24",
     "100.64.0.0/10", "100.70.3.0/24"],
)
def test_private_space_includes_rfc1918_and_shared_address_space(cidr: str) -> None:
    assert reachability.is_private_v4(ipaddress.ip_network(cidr))


@pytest.mark.parametrize(
    "cidr",
    [
        "8.8.8.0/24",  # public
        "127.0.0.0/8",  # loopback: is_private says yes, and it is not a customer network
        "169.254.0.0/16",  # link-local, same reason
        "0.0.0.0/8",  # unspecified, same reason
        "172.32.0.0/16",  # just outside 172.16/12, the classic off-by-one in a hand-written list
    ],
)
def test_private_space_excludes_what_is_not_a_customer_network(cidr: str) -> None:
    assert not reachability.is_private_v4(ipaddress.ip_network(cidr))


# --- routing table ------------------------------------------------------------------------------

_IP_ROUTE = """default via 172.23.0.1 dev eth0
10.20.0.0/16 via 172.23.0.1 dev eth0
10.30.4.0/24 via 172.23.0.1 dev eth0
172.23.0.0/16 dev eth0 proto kernel scope link src 172.23.104.119
192.0.2.0/24 via 172.23.0.1 dev eth0
"""


def test_routes_report_private_destinations_reached_through_a_gateway() -> None:
    # The customer case exactly: the agent is attached to 172.23 and holds routes to 10.20 and
    # 10.30 through the corporate router. Those are reachable and were previously invisible.
    assert reachability.routes_from_ip_route(_IP_ROUTE) == [
        "10.20.0.0/16",
        "10.30.4.0/24",
        "172.23.0.0/16",
    ]


def test_routes_skip_the_default_route_and_public_destinations() -> None:
    # "default" is not a destination anyone can enumerate, and 192.0.2.0/24 is public: neither
    # belongs in a list of networks to sweep.
    parsed = reachability.routes_from_ip_route(_IP_ROUTE)
    assert "0.0.0.0/0" not in parsed
    assert "192.0.2.0/24" not in parsed


def test_routes_from_netstat_pads_a_partial_bsd_destination() -> None:
    # BSD writes 10.20.0.0/16 as "10.20", which a naive parser reads as the address 10.20.0.0/32
    # and so scans one host instead of a /16.
    output = """Routing tables

Internet:
Destination        Gateway            Flags
default            192.168.1.1        UGSc
10.20              192.168.1.1        UGSc
192.168.1          link#4             UCS
"""
    assert reachability.routes_from_netstat(output) == ["10.20.0.0/16", "192.168.1.0/24"]


def test_neighbour_table_reports_the_slash24_of_each_on_link_address() -> None:
    # Anything the machine has exchanged a frame with is on-link whatever the routing table says.
    output = """10.20.1.4 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
10.20.1.9 dev eth0 lladdr aa:bb:cc:dd:ee:00 STALE
8.8.8.8 dev eth0 lladdr aa:bb:cc:dd:ee:11 REACHABLE
fe80::1 dev eth0 lladdr aa:bb:cc:dd:ee:22 router REACHABLE
"""
    assert reachability.neighbours_from_ip_neigh(output) == ["10.20.1.0/24"]


def test_parsers_survive_empty_or_unreadable_output() -> None:
    # The collectors return "" when the command is missing (a slim image with no iproute2), so
    # every parser has to read that as "nothing found" rather than raise on the agent's startup.
    assert reachability.routes_from_ip_route("") == []
    assert reachability.routes_from_netstat("") == []
    assert reachability.neighbours_from_ip_neigh("not a routing table at all") == []


# --- the active probe ---------------------------------------------------------------------------


@pytest.fixture
def _fake_network(monkeypatch: pytest.MonkeyPatch):
    """Answer for a chosen set of addresses; record everything that was probed."""

    def install(live: set[str]) -> list[str]:
        probed: list[str] = []

        async def _answers(ip: str, port: int, timeout: float) -> bool:
            probed.append(ip)
            return ip in live

        monkeypatch.setattr(reachability, "_answers", _answers)
        return probed

    return install


async def test_probe_reports_only_the_subnets_that_answered(_fake_network) -> None:
    # One host on a gateway address in 10.20.5.x. Nothing else in 86,272 candidate /24s answers,
    # so exactly one network comes back rather than the whole of private space.
    _fake_network({"10.20.5.1"})
    found = await reachability.probe_private_space(spaces=["10.20.0.0/16"])
    assert found == ["10.20.5.0/24"]


async def test_probe_finds_a_sparse_subnet_inside_a_populated_range(_fake_network) -> None:
    # The reason for stage 2. 10.20.7.137 is on none of the sampled addresses, but 10.20.5.1 puts
    # the whole /16 in play, and the dense pass then samples .150 in every one of its /24s.
    _fake_network({"10.20.5.1", "10.20.7.150"})
    found = await reachability.probe_private_space(spaces=["10.20.0.0/16"])
    assert found == ["10.20.5.0/24", "10.20.7.0/24"]


async def test_probe_does_not_pay_for_a_dense_pass_over_dead_space(_fake_network) -> None:
    # Stage 2 must run only inside /16s stage 1 found something in, or the whole two-stage shape
    # buys nothing: a dense pass over all of private space is the cost this design exists to avoid.
    probed = _fake_network(set())
    assert await reachability.probe_private_space(spaces=["10.20.0.0/16"]) == []
    sampled_octets = {ip.rsplit(".", 1)[1] for ip in probed}
    assert sampled_octets == {"1", "254"}


async def test_probe_stops_when_its_budget_is_spent(_fake_network, monkeypatch) -> None:
    # A slow network must yield a partial map rather than run until something kills the container.
    _fake_network({"10.20.5.1"})
    clock = iter([0.0, 0.0, 1_000.0, 1_000.0, 1_000.0, 1_000.0])
    monkeypatch.setattr(reachability.time, "monotonic", lambda: next(clock, 1_000.0))
    found = await reachability.probe_private_space(spaces=["10.20.0.0/16"], budget_seconds=1.0)
    assert found == []  # nothing reached before the budget went


async def test_probe_treats_a_refusal_as_proof_the_network_is_there(monkeypatch) -> None:
    # A host that RSTs is a host: the packet arrived, so the address is routed. Only silence is
    # evidence of absence, and reading a refusal as "dead" would hide every firewalled segment.
    async def _open_connection(ip: str, port: int):
        raise ConnectionRefusedError

    monkeypatch.setattr(reachability.asyncio, "open_connection", _open_connection)
    assert await reachability._answers("10.20.5.1", 443, 0.1) is True


async def test_discover_adds_to_the_attached_subnets_and_never_replaces_them(
    monkeypatch: pytest.MonkeyPatch, _fake_network
) -> None:
    # The ordering that makes this safe to ship as a default: an agent that advertised
    # 172.23.0.0/16 still advertises it, and now also advertises what it can reach.
    _fake_network(set())
    monkeypatch.setattr(reachability, "kernel_reachable", lambda: ["10.20.0.0/16"])
    found = await reachability.discover(attached=["172.23.0.0/16"], probe=False)
    assert found == ["10.20.0.0/16", "172.23.0.0/16"]


async def test_discover_collapses_a_network_reported_by_two_sources(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The routing table and the interface both name the attached subnet, and a /24 inside an
    # advertised /16 is already covered: without collapsing, the agent enqueues a task per
    # duplicate and scans the same addresses two and three times over.
    monkeypatch.setattr(
        reachability, "kernel_reachable", lambda: ["172.23.0.0/16", "172.23.104.0/24"]
    )
    found = await reachability.discover(attached=["172.23.0.0/16"], probe=False)
    assert found == ["172.23.0.0/16"]


async def test_discover_survives_a_failing_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    # Discovery is an enrichment of what the interfaces already say. A probe that blows up must
    # narrow the result, never stop the agent from enrolling.
    async def _explode(**_kwargs: object) -> list[str]:
        raise OSError("no network")

    monkeypatch.setattr(reachability, "probe_private_space", _explode)
    monkeypatch.setattr(reachability, "kernel_reachable", list)
    assert await reachability.discover(attached=["172.23.0.0/16"]) == ["172.23.0.0/16"]
