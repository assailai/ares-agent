"""Auto-detect the host's internal LAN(s) so the client never types a CIDR by hand.

Reports only RFC1918 networks on real interfaces. Container, VPN, and virtual interfaces
(docker0, br-*, veth*, wg*, tun*, loopback) are excluded so we never advertise the
container bridge (172.17.0.0/16) as a target. The parsing is split from the OS calls so
the filtering logic is unit-testable.

``scan_targets(scope)`` turns the detected attached subnets into the CIDRs the agent actually
advertises and scans, so an operator never has to set ARES_NETWORKS: ``supernet16`` (the default)
widens each attached subnet to its enclosing /16 to sweep the flat local network, ``attached``
keeps the interface prefixes as-is, ``rfc1918`` scans all private space (opt-in, slow), and
``host-all`` also folds in the docker bridge subnets and the host loopback so a host-networked
container sweeps the container networks and localhost-bound services too.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import subprocess

logger = logging.getLogger("ares.agent.netdetect")

# the private space, used by the (opt-in) ``rfc1918`` scope.
_RFC1918 = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
# widening scopes apply_scope understands; "host-all" is handled a level up in scan_targets.
VALID_SCOPES = ("attached", "supernet16", "rfc1918")
DEFAULT_SCOPE = "supernet16"
# the host's own loopback, added by "host-all" so localhost-bound services are found (a /32, not
# the whole /8: services on 0.0.0.0 or the LAN ip are already caught by the LAN sweep).
_HOST_LOOPBACK = "127.0.0.1/32"
# host-side docker bridge interfaces, whose subnets "host-all" sweeps to reach containers.
_DOCKER_IFACE_PREFIXES = ("docker", "br-")

# interfaces that are never a customer LAN.
_SKIP_IFACE_PREFIXES = (
    "lo",
    "docker",
    "br-",
    "veth",
    "wg",
    "tun",
    "tap",
    "tailscale",
    "cni",
    "flannel",
    "kube",
    "cali",
    "vxlan",
    "utun",
)


def _skip_iface(name: str) -> bool:
    return any(name.startswith(p) for p in _SKIP_IFACE_PREFIXES)


def networks_from_interfaces(interfaces: list[tuple[str, str, int]]) -> list[str]:
    """Collapse ``(iface, ipv4, prefixlen)`` rows into covering RFC1918 CIDRs.

    Pure: the testable core. Excludes virtual/VPN interfaces and any non-private /
    loopback / link-local range; dedupes on the covering network.
    """
    found: dict[str, None] = {}
    for name, ip, prefix in interfaces:
        if _skip_iface(name):
            continue
        try:
            net = ipaddress.ip_interface(f"{ip}/{prefix}").network
        except ValueError:
            continue
        if net.version != 4 or not net.is_private or net.is_loopback or net.is_link_local:
            continue
        found[str(net)] = None
    return sorted(found)


def _collect_linux() -> list[tuple[str, str, int]]:
    out = subprocess.run(
        ["ip", "-o", "-f", "inet", "addr", "show"],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    rows: list[tuple[str, str, int]] = []
    for line in out.stdout.splitlines():
        # e.g. "2: eth0    inet 192.168.1.37/24 brd 192.168.1.255 scope global eth0"
        m = re.search(r"^\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
        if m:
            rows.append((m.group(1), m.group(2), int(m.group(3))))
    return rows


def _collect_bsd() -> list[tuple[str, str, int]]:
    out = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=5, check=False)
    rows: list[tuple[str, str, int]] = []
    iface = ""
    for line in out.stdout.splitlines():
        head = re.match(r"^(\w[\w.]*?):\s", line)
        if head:
            iface = head.group(1)
            continue
        m = re.search(r"\binet (\d+\.\d+\.\d+\.\d+)\s+netmask (0x[0-9a-fA-F]+)", line)
        if m and iface:
            prefix = bin(int(m.group(2), 16)).count("1")
            rows.append((iface, m.group(1), prefix))
    return rows


def _interface_rows() -> list[tuple[str, str, int]]:
    """Raw ``(iface, ipv4, prefixlen)`` rows from the first collector that returns any (Linux
    iproute2, then BSD/macOS ifconfig). Unfiltered, so callers can pick out docker / loopback too."""
    for collector in (_collect_linux, _collect_bsd):
        try:
            rows = collector()
        except (OSError, subprocess.SubprocessError):
            continue
        if rows:
            return rows
    return []


def detect_networks() -> list[str]:
    """Best-effort host LAN detection (the attached RFC1918 subnets, bridges/VPNs excluded)."""
    return networks_from_interfaces(_interface_rows())


def docker_networks_from_interfaces(interfaces: list[tuple[str, str, int]]) -> list[str]:
    """Private subnets on the host's docker bridge interfaces (``docker0``, ``br-*``) -- the inverse
    of the bridge exclusion in :func:`networks_from_interfaces`, so ``host-all`` can also reach the
    container networks. Pure/testable."""
    found: dict[str, None] = {}
    for name, ip, prefix in interfaces:
        if not name.startswith(_DOCKER_IFACE_PREFIXES):
            continue
        try:
            net = ipaddress.ip_interface(f"{ip}/{prefix}").network
        except ValueError:
            continue
        if net.version == 4 and net.is_private and not net.is_loopback:
            found[str(net)] = None
    return sorted(found)


def host_all_targets(interfaces: list[tuple[str, str, int]]) -> list[str]:
    """Everything a host-networked agent can reach: the attached LANs widened to /16, the docker
    bridge subnets, and the host loopback. Pure/testable. Only meaningful when the container runs
    with host networking -- otherwise these interfaces are the container's own namespace."""
    nets = [ipaddress.ip_network(_HOST_LOOPBACK)]
    nets += [ipaddress.ip_network(c) for c in apply_scope(networks_from_interfaces(interfaces), "supernet16")]
    nets += [ipaddress.ip_network(c) for c in docker_networks_from_interfaces(interfaces)]
    return [str(n) for n in ipaddress.collapse_addresses(nets)]


def apply_scope(attached: list[str], scope: str) -> list[str]:
    """Widen detected attached subnets into scan targets by breadth (pure, unit-testable).

    Overlapping / duplicate results are collapsed so a /16 supernet never coexists with a /24 it
    already covers. An unknown scope falls back to the default with a warning.
    """
    if scope not in VALID_SCOPES:
        logger.warning("Unknown ARES_SCAN_SCOPE=%r; falling back to %s.", scope, DEFAULT_SCOPE)
        scope = DEFAULT_SCOPE

    if scope == "rfc1918":
        nets = [ipaddress.ip_network(c) for c in _RFC1918]
    else:
        nets = []
        for cidr in attached:
            net = ipaddress.ip_network(cidr, strict=False)
            if scope == "supernet16" and net.prefixlen > 16:
                net = net.supernet(new_prefix=16)
            nets.append(net)

    collapsed = ipaddress.collapse_addresses(n for n in nets if isinstance(n, ipaddress.IPv4Network))
    return [str(n) for n in collapsed]


def scan_targets(scope: str = DEFAULT_SCOPE) -> list[str]:
    """The CIDRs to advertise + scan, derived from auto-detected interfaces at the given breadth.

    ``host-all`` reads the raw interface set (so it can also see the docker bridges + loopback);
    the other scopes widen only the attached LANs.
    """
    if scope == "host-all":
        return host_all_targets(_interface_rows())
    return apply_scope(detect_networks(), scope)
