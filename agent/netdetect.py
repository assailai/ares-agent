"""Auto-detect the host's internal LAN(s) so the client never types a CIDR by hand.

Reports only RFC1918 networks on real interfaces. Container, VPN, and virtual interfaces
(docker0, br-*, veth*, wg*, tun*, loopback) are excluded so we never advertise the
container bridge (172.17.0.0/16) as a target. The parsing is split from the OS calls so
the filtering logic is unit-testable.
"""

from __future__ import annotations

import ipaddress
import re
import subprocess

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


def detect_networks() -> list[str]:
    """Best-effort host LAN detection (Linux iproute2, then BSD/macOS ifconfig)."""
    for collector in (_collect_linux, _collect_bsd):
        try:
            rows = collector()
        except (OSError, subprocess.SubprocessError):
            continue
        nets = networks_from_interfaces(rows)
        if nets:
            return nets
    return []
