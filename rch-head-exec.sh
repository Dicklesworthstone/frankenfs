#!/usr/bin/env bash
# RCH_BIN wrapper: forces every `rch exec` issued by e2e scripts to use the
# current committed HEAD as a clean-overlay baseline, so remote builds test the
# committed build identity instead of a stale recorded project base.
set -u
HEAD=$(git rev-parse --short HEAD 2>/dev/null)
if [ -z "$HEAD" ]; then
  exec rch "$@"
fi
if [ "${1:-}" = "exec" ]; then
  shift
  exec rch exec --clean-overlay -b "$HEAD" "$@"
fi
exec rch "$@"
