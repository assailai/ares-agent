"""The bootstrap installer, where it makes decisions the agent then depends on.

Only the CA detection is pinned here, and deliberately: the same candidate list is written a
second time in the other repo, in the install command the dashboard hands operators
(``apps/web/src/lib/agent-install.ts``, ``caDetection``). Two copies of one list across two
repositories is a drift trap, and nothing can fail the build in *both* of them, so each side pins
its own copy. That does not detect cross-repo drift, but it does mean neither list can change by
accident: whoever edits one gets a failure telling them the other exists.
"""

from __future__ import annotations

import re
from pathlib import Path

BOOTSTRAP = Path(__file__).resolve().parents[1] / "scripts" / "bootstrap.sh"

# The order matters as much as the membership. /etc/ssl/certs is a symlink into /etc/pki on RHEL,
# so checking it first and resolving with `readlink -f` lands on the real bundle on every distro;
# checking the pki path first would work too, but only by accident on Debian.
EXPECTED_CA_CANDIDATES = [
    "/etc/ssl/certs/ca-certificates.crt",  # Debian, Ubuntu, Alpine, SUSE
    "/etc/pki/tls/certs/ca-bundle.crt",  # RHEL, Fedora, Amazon Linux
]


def _candidates() -> list[str]:
    match = re.search(r"for bundle in (.+?); do", BOOTSTRAP.read_text())
    assert match, "host_ca_dir no longer loops over a list of candidate bundles"
    return match.group(1).split()


def test_the_ca_candidates_match_the_dashboard_install_command() -> None:
    assert _candidates() == EXPECTED_CA_CANDIDATES, (
        "The host CA candidate list changed. The dashboard's install command carries the same "
        "list in ares-v2 (apps/web/src/lib/agent-install.ts, caDetection), and the two must stay "
        "identical or the same host gets diagnosed differently depending on how it was installed."
    )


def test_the_host_ca_mount_is_read_only_and_never_exposes_private_keys() -> None:
    body = BOOTSTRAP.read_text()

    assert ":/host-ca:ro" in body, "the host CA mount must be read-only"
    assert "/host-ca:rw" not in body
    # /etc/ssl/private sits beside the certificate directory on Debian and holds host private
    # keys. Mounting the parent, or that path, would hand them to a container that has no use
    # for them.
    assert "/etc/ssl/private" not in body
    assert '-v "/etc/ssl:' not in body
