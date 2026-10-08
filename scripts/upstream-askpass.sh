#!/bin/sh
# Only used with the pinned upstream URL and http.followRedirects=false.
case "$1" in
  *Username*) printf '%s\n' x-access-token ;;
  *Password*) printf '%s\n' "$ANGELOS_UPSTREAM_TOKEN" ;;
  *) exit 1 ;;
esac
