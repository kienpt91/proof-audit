#!/bin/sh
# Exercise the default mode (a throwaway container driven through `docker exec psql`) for real.
#
# Node runs in a container with no network, no docker CLI and no docker socket. Its docker calls are written
# to out/relay and executed on the host by scripts/docker-relay.py, which only accepts the exact command
# shapes the provider issues (hardened `docker run`, `exec ... psql`, `inspect`, `logs`, `rm`). Afterwards
# no container labelled proof-audit may remain.
set -eu
cd "$(dirname "$0")/.."
repo=$(pwd)
dnode=${DNODE:-"$repo/../_tools/dnode"}

rm -rf out/relay
mkdir -p out/relay
python3 scripts/docker-relay.py "$repo/out/relay" &
relay=$!
cleanup() {
  touch out/relay/stop
  wait "$relay" 2>/dev/null || true
  rm -rf out/relay
}
trap cleanup EXIT INT TERM

status=0
DNODE_NET=none "$dnode" "$repo" "PROOF_AUDIT_RELAY_DIR=/work/out/relay npm run test:smoke --silent" || status=$?

left=$(docker ps -a --filter label=proof-audit=1 -q | wc -l | tr -d ' ')
echo "docker-smoke: containers left behind: $left"
[ "$left" = "0" ] || status=1
exit "$status"
