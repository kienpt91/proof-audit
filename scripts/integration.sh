#!/bin/sh
# Run the integration suite against a throwaway PostgreSQL container.
#
# The database is the official postgres:16.14 image pinned by digest, started on a user-defined internal
# docker network (no route out). The test process runs in a Node container that joins the database
# container's network namespace, so the server is reached at 127.0.0.1: the loopback-only rule of the
# tool applies to the tests exactly as it does to users. The password is generated here, written to a
# mode-600 file under out/ (ignored by git), and removed with the containers and the network on exit.
#
# usage: scripts/integration.sh [vitest arguments...]
#        DNODE_NODE=24 scripts/integration.sh
set -eu
cd "$(dirname "$0")/.."
repo=$(pwd)
dnode=${DNODE:-"$repo/../_tools/dnode"}
image=postgres@sha256:95206741a5b214807675e14165369d05b93a9cf692223b616d07cca227e74b0b
suffix=$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')
net=proof-audit-it-$suffix
pg=proof-audit-it-pg-$suffix

mkdir -p out
( umask 077; od -An -N16 -tx1 /dev/urandom | tr -d ' \n' > out/.it-secret )

cleanup() {
  docker rm -f -v "$pg" >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
  rm -f out/.it-secret
}
trap cleanup EXIT INT TERM

docker network create --internal "$net" >/dev/null
POSTGRES_PASSWORD=$(cat out/.it-secret) docker run -d --name "$pg" --network "$net" \
  --pull never --cap-drop ALL --security-opt no-new-privileges --pids-limit 256 --memory 1g --cpus 2 \
  --user 999:999 --read-only \
  --tmpfs /var/lib/postgresql/data:rw,uid=999,gid=999,mode=0700 \
  --tmpfs /var/run/postgresql:rw,uid=999,gid=999,mode=0755 --tmpfs /tmp:rw,mode=1777 \
  -e POSTGRES_PASSWORD "$image" -c fsync=off -c synchronous_commit=off -c full_page_writes=off -c max_connections=50 >/dev/null

i=0
until docker exec "$pg" pg_isready -q -h 127.0.0.1 -U postgres; do
  i=$((i + 1))
  if [ "$i" -gt 120 ]; then echo "integration: database did not become ready" >&2; docker logs "$pg" >&2 || true; exit 1; fi
  sleep 0.5
done

args=""
for a in "$@"; do args="$args '$a'"; done
DNODE_NET="container:$pg" "$dnode" "$repo" \
  "PROOF_AUDIT_DATABASE_URL=\"postgres://postgres:\$(cat out/.it-secret)@127.0.0.1:5432/postgres\" npm run test:integration --silent -- $args"
