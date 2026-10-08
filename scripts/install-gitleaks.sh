#!/usr/bin/env bash
# Official release: https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1
# The SHA-256 is pinned independently of the downloaded release/checksum files.
set -euo pipefail
test "$(uname -s)" = Linux && test "$(uname -m)" = x86_64 || {
  echo 'This installer supports Linux x86_64; install Gitleaks 8.30.1 for your platform.' >&2
  exit 1
}
destination=${1:?Usage: install-gitleaks.sh DESTINATION_DIRECTORY}
archive=$(mktemp)
trap 'rm -f "$archive"' EXIT
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --retry 3 \
  https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz \
  --output "$archive"
printf '%s  %s\n' '551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb' "$archive" | sha256sum --check --status
mkdir -p "$destination"
tar -xzf "$archive" -C "$destination" gitleaks
test "$("$destination/gitleaks" version)" = 8.30.1
