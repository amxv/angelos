#!/bin/sh
# Only used with the pinned upstream URL and http.followRedirects=false.
# Public fetches do not prompt. Refuse credentials unless private access was
# explicitly configured, and never answer a prompt for another host.
test -n "${ANGELOS_UPSTREAM_TOKEN:-}" || exit 1
case "$1" in
  "Username for 'https://github.com': "*) printf '%s\n' x-access-token ;;
  "Password for 'https://x-access-token@github.com': "*) printf '%s\n' "$ANGELOS_UPSTREAM_TOKEN" ;;
  *) exit 1 ;;
esac
