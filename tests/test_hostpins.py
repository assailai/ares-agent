"""Static hostname pins: parsing the host's /etc/hosts, ARES_HOST_ALIASES, and live reload.

These exist because "I added it to /etc/hosts and nothing changed" is the failure this module was
written for, so the cases that matter are the ones where a pin silently does not apply.
"""

from __future__ import annotations

import os
import time

from agent.hostpins import HostPins, parse_hosts_file

HOSTS_SAMPLE = """
# a normal hosts file
127.0.0.1   localhost
::1         localhost ip6-localhost ip6-loopback
167.127.118.229  agtacc.allstate.com  agtacc
10.1.2.3    sso.acme.internal   # trailing comment
not-an-address  bogus.example.com
10.9.9.9
"""


def test_parses_addresses_names_and_comments() -> None:
    pins = parse_hosts_file(HOSTS_SAMPLE)
    assert pins["agtacc.allstate.com"] == ["167.127.118.229"]
    assert pins["agtacc"] == ["167.127.118.229"]
    assert pins["sso.acme.internal"] == ["10.1.2.3"]


def test_skips_loopback_boilerplate_and_malformed_lines() -> None:
    pins = parse_hosts_file(HOSTS_SAMPLE)
    # localhost / ip6-* are never destinations worth pinning
    assert "localhost" not in pins
    assert "ip6-localhost" not in pins
    # a line whose first field is not an address is not a hosts line
    assert "bogus.example.com" not in pins
    # an address with no names contributes nothing, and must not crash the parse
    assert all(names for names in pins.values())


def test_a_name_is_matched_case_and_trailing_dot_insensitively(tmp_path) -> None:
    path = tmp_path / "hosts"
    path.write_text("10.0.0.7 Portal.Acme.Internal\n")
    pins = HostPins(path=path)
    assert pins.lookup("portal.acme.internal") == ["10.0.0.7"]
    assert pins.lookup("PORTAL.ACME.INTERNAL.") == ["10.0.0.7"]


def test_missing_mount_is_not_an_error(tmp_path) -> None:
    """The ordinary case: nothing mounted, so nothing pinned, and the resolver decides."""
    pins = HostPins(path=tmp_path / "nope")
    assert pins.lookup("anything.example.com") == []
    assert pins.summary() == "none"


def test_aliases_apply_without_any_file(tmp_path) -> None:
    pins = HostPins(aliases="a.example.com=10.0.0.1, b.example.com=10.0.0.2", path=tmp_path / "nope")
    assert pins.lookup("a.example.com") == ["10.0.0.1"]
    assert pins.lookup("b.example.com") == ["10.0.0.2"]


def test_aliases_win_over_the_host_file(tmp_path) -> None:
    """The explicit escape hatch beats the file, because it is reached for when the file is wrong."""
    path = tmp_path / "hosts"
    path.write_text("10.0.0.1 host.example.com\n")
    pins = HostPins(aliases="host.example.com=10.9.9.9", path=path)
    assert pins.lookup("host.example.com") == ["10.9.9.9"]


def test_a_malformed_alias_is_dropped_not_fatal(tmp_path) -> None:
    pins = HostPins(aliases="good.example.com=10.0.0.1,garbage,bad.example.com=not-an-ip",
                    path=tmp_path / "nope")
    assert pins.lookup("good.example.com") == ["10.0.0.1"]
    assert pins.lookup("bad.example.com") == []


def test_an_edit_is_picked_up_without_a_restart(tmp_path) -> None:
    """The whole reason we mount the file instead of using --add-host: a pin costs an edit."""
    path = tmp_path / "hosts"
    path.write_text("10.0.0.1 first.example.com\n")
    pins = HostPins(path=path)
    assert pins.lookup("second.example.com") == []

    path.write_text("10.0.0.1 first.example.com\n10.0.0.2 second.example.com\n")
    # mtime has one-second granularity on some filesystems; make the change unambiguous.
    future = time.time() + 10
    os.utime(path, (future, future))

    assert pins.lookup("second.example.com") == ["10.0.0.2"]
    assert pins.lookup("first.example.com") == ["10.0.0.1"]
