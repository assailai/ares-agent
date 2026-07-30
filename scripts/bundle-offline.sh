#!/usr/bin/env bash
# =============================================================================
# Ares Docker Agent - offline bundle builder
# =============================================================================
# Builds a registry-free install bundle for a host that cannot reach Docker Hub: one gzipped image
# archive per architecture plus a checksum file. The customer copies over the archive matching their
# `uname -m`, runs `docker load`, and runs the agent. See docs/offline-install.md for that side.
#
# One archive per architecture, deliberately, rather than one multi-platform archive: a multi-platform
# OCI index is the case an older `docker load` handles worst, and picking a file by `uname -m` is
# simpler for the operator than explaining platform selection.
#
# Usage:
#   scripts/bundle-offline.sh                      # current release, both arches, into ./dist
#   VERSION=3.4.0 scripts/bundle-offline.sh        # a specific version
#   ARCHES=amd64 OUT=/tmp/b scripts/bundle-offline.sh
#   INCLUDE_UPDATER=1 scripts/bundle-offline.sh    # also bundle ares-updater (see below)
#
# The updater is left out by default: a host that cannot reach Docker Hub cannot pull a new image, and
# the updater verifies signatures against Sigstore, which is equally unreachable. It fails closed, so
# it would sit there doing nothing. Bundle it once the firewall allowlist is in place.
# =============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Read the version from agent/__version__.py rather than pinning it here, using the same expression
# auto-tag.yml does. That file is the single source of truth, and the release ritual in the README
# lists the pins to move on a bump; a pin added here would not be on that list and would silently
# keep bundling the previous release.
default_version() {
    local version
    version="$(sed -n 's/^__version__ = "\(.*\)"/\1/p' "$REPO_ROOT/agent/__version__.py")"
    if [ -z "$version" ]; then
        echo "Could not parse __version__ from agent/__version__.py" >&2
        exit 1
    fi
    printf '%s' "$version"
}

VERSION="${VERSION:-$(default_version)}"
ARCHES="${ARCHES:-amd64 arm64}"
OUT="${OUT:-$REPO_ROOT/dist}"
IMAGE_REPO="${IMAGE_REPO:-assailai/ares-agent}"
UPDATER_REPO="${UPDATER_REPO:-assailai/ares-updater}"
INCLUDE_UPDATER="${INCLUDE_UPDATER:-}"

RT="$(command -v docker || command -v podman || echo docker)"
# Prefer coreutils sha256sum, which is what docs/offline-install.md tells the customer to verify with.
# macOS only ships shasum, so fall back to it; both write the same format.
SHASUM="$(command -v sha256sum || echo "shasum -a 256")"

info() { printf "[INFO]  %s\n" "$1"; }
step() { printf "\n==> %s\n" "$1"; }

# Basenames of the archives written, in order, so the checksum step names exactly those rather than
# globbing for archives an earlier run may have left behind.
archives=()

# One image, one architecture, one archive.
bundle_one() {
    local repo="$1" arch="$2"
    local name archive
    name="$(basename "$repo")-${VERSION}-${arch}.tar.gz"
    archive="$OUT/$name"
    archives+=("$name")

    step "Pulling ${repo}:${VERSION} (linux/${arch})"
    "$RT" pull --platform "linux/${arch}" "${repo}:${VERSION}"

    step "Saving to ${archive}"
    # --platform on save is what keeps the archive single-arch: the local store holds every platform
    # pulled so far, and `docker image inspect` reports whichever one it considers current, so it
    # cannot be used to confirm this. Verify by reading the architecture out of the archive itself.
    # gzip -n drops the timestamp header, the only thing that differs between two runs over the same
    # digest, so the archive and its checksum are reproducible.
    "$RT" save --platform "linux/${arch}" "${repo}:${VERSION}" | gzip -9n > "$archive"
    info "$(du -h "$archive" | cut -f1) written."
}

repos=("$IMAGE_REPO")
[ -n "$INCLUDE_UPDATER" ] && repos+=("$UPDATER_REPO")

mkdir -p "$OUT"

for arch in $ARCHES; do
    for repo in "${repos[@]}"; do
        bundle_one "$repo" "$arch"
    done
done

step "Checksums"
# Run from OUT, and name the archives rather than globbing, so the file holds plain filenames that the
# customer's `sha256sum -c` resolves against their own directory.
(cd "$OUT" && $SHASUM "${archives[@]}" > SHA256SUMS && cat SHA256SUMS)

step "Done"
info "Bundle in ${OUT}. Send the archive matching the target host's 'uname -m',"
info "SHA256SUMS, docs/offline-install.md and docs/network-requirements.md."
