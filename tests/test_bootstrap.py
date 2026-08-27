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


def test_the_kept_identity_marker_is_matched_before_agent_online() -> None:
    # Ordering, not membership, is the bug here. On a re-install that could not re-enroll, BOTH
    # strings are in the log by the time wait_until_online reads it: the agent really is online,
    # just as the agent it already was. Matching "Agent online" first is precisely how a failed
    # re-enrollment used to be reported as a successful install.
    body = BOOTSTRAP.read_text()

    kept = body.find('*"Keeping the existing agent identity"*)')
    online = body.find('*"Agent online"*)')

    assert kept != -1, "wait_until_online no longer detects a re-install that kept its identity"
    assert online != -1, "wait_until_online no longer detects the agent coming online"
    assert kept < online, (
        "the kept-identity case must be matched before 'Agent online', which is also in the log "
        "by then; otherwise a re-install that failed to re-enroll exits 0 as a success."
    )


def test_the_reset_flag_removes_both_containers_before_the_volume() -> None:
    # The engine refuses to remove a volume any container still references, and ares-updater
    # mounts this one read-only. Removing the agent alone would leave `volume rm` failing, which
    # (before the guard below) meant starting the agent on the very identity ARES_RESET was asked
    # to discard.
    body = BOOTSTRAP.read_text()
    reset = body[body.index("reset_state() {") : body.index("# Echo this host's CA directory")]

    rm_containers = reset.index('rm -f "$CONTAINER_NAME" "$UPDATER_CONTAINER_NAME"')
    rm_volume = reset.index('volume rm "$VOLUME_NAME"')

    assert rm_containers < rm_volume, "both containers must be removed before the volume"
    # And a volume that will not go away has to stop the install rather than be shrugged off.
    assert "exit 1" in reset, "a failed volume removal must abort instead of enrolling anyway"


def test_the_reset_is_opt_in() -> None:
    # The data volume is deliberately kept across a re-install: it is what lets an agent survive
    # being recreated, and the agent re-enrolls on its own when handed a token it was not minted
    # from. Discarding it by default would turn every upgrade into a brand-new agent.
    body = BOOTSTRAP.read_text()

    assert '[ -n "${ARES_RESET:-}" ] || return 0' in body, (
        "reset_state must return early unless ARES_RESET is set"
    )
