#!/usr/bin/env bash
# =============================================================================
# Ares Docker Agent - offline bundle builder
# =============================================================================
# Builds a registry-free install bundle for a host that cannot reach Docker Hub: one gzipped image
# archive per architecture, a checksum file, and the operator instructions. The customer scp's the
# archive matching their `uname -m`, runs `docker load`, and runs the agent. See
# docs/offline-install.md for the operator side.
#
# One archive per architecture, deliberately, rather than one multi-platform archive: a multi-platform
# OCI index is the case an older `docker load` handles worst, and picking a file by `uname -m` is
# simpler for the operator than explaining platform selection.
#
# Usage:
#   scripts/bundle-offline.sh                      # current pinned version, both arches, into ./dist
#   VERSION=3.4.0 scripts/bundle-offline.sh        # a specific version
#   ARCHES=amd64 OUT=/tmp/b scripts/bundle-offline.sh
#   INCLUDE_UPDATER=1 scripts/bundle-offline.sh    # also bundle ares-updater (see the caveat below)
#
# The updater is left out by default: on a host that cannot reach Docker Hub it cannot pull a new
# image, and it verifies signatures against Sigstore, which is also unreachable. It fails closed, so
# it would sit there doing nothing. Bundle it once the firewall allowlist is in place.
# =============================================================================

set -euo pipefail

VERSION="${VERSION:-3.3.3}"
ARCHES="${ARCHES:-amd64 arm64}"
OUT="${OUT:-dist}"
IMAGE_REPO="${IMAGE_REPO:-assailai/ares-agent}"
UPDATER_REPO="${UPDATER_REPO:-assailai/ares-updater}"
INCLUDE_UPDATER="${INCLUDE_UPDATER:-}"

RT="$(command -v docker || command -v podman || echo docker)"

info() { printf "[INFO]  %s\n" "$1"; }
step() { printf "\n==> %s\n" "$1"; }

repos=("$IMAGE_REPO")
[ -n "$INCLUDE_UPDATER" ] && repos+=("$UPDATER_REPO")

mkdir -p "$OUT"

for arch in $ARCHES; do
    for repo in "${repos[@]}"; do
        name="$(basename "$repo")"
        archive="$OUT/${name}-${VERSION}-${arch}.tar.gz"

        step "Pulling ${repo}:${VERSION} (linux/${arch})"
        "$RT" pull --platform "linux/${arch}" "${repo}:${VERSION}"

        step "Saving to ${archive}"
        # --platform on save keeps the archive single-arch even though the local store may hold both.
        # gzip -n drops the timestamp header, which is the only thing that differs between two runs
        # over the same digest, so the archive and its checksum are reproducible. That lets us hand a
        # customer a checksum out of band and have it still match a rebuild of the same version.
        "$RT" save --platform "linux/${arch}" "${repo}:${VERSION}" | gzip -9n > "$archive"
        info "$(du -h "$archive" | cut -f1) written."
    done
done

step "Checksums"
# cd so the checksum file holds bare filenames, which is what `sha256sum -c` wants on the far side.
(cd "$OUT" && shasum -a 256 ./*.tar.gz > SHA256SUMS && cat SHA256SUMS)

step "Done"
info "Bundle in ${OUT}. Send the archive matching the target host's 'uname -m',"
info "SHA256SUMS, and docs/offline-install.md."
