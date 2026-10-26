#!/bin/sh
# Only for a post-deployment, non-forced push of a verified upstream commit to
# this owner's private GitHub repository, with http.followRedirects=false.
# GitHub Actions scopes GH_TOKEN to the repository running this workflow.
test -n "${GH_TOKEN:-}" || exit 1
case "$1" in
  "Username for 'https://github.com': "*) printf '%s\n' x-access-token ;;
  "Password for 'https://x-access-token@github.com': "*) printf '%s\n' "$GH_TOKEN" ;;
  *) exit 1 ;;
esac
