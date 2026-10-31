#!/bin/sh
# Run proof-audit without Node, npm or a database on your machine: everything happens in throwaway containers.
#
#   1. Node 22 (pinned by digest) installs the locked dependencies with --ignore-scripts and builds, once,
#      into a docker volume. This is the only step with network access.
#   2. A PostgreSQL container (pinned by digest) starts on an internal docker network: no route out.
#   3. proof-audit runs in a second container that shares the database container's network namespace, so the
#      database is at 127.0.0.1 (the only address the tool accepts). The code is mounted read-only; your
#      current directory is mounted at /audit and only --out writes there.
#
# usage: scripts/run-contained.sh rls supabase/migrations [--out out/audit] [other options]
#        scripts/run-contained.sh verify out/audit/proofs.jsonl [--against supabase/migrations]
# Paths are relative to the directory you run it from. Exit codes are the tool's.
set -eu
repo=$(cd "$(dirname "$0")/.." && pwd)
node_image=node@sha256:e21fc383b50d5347dc7a9f1cae45b8f4e2f0d39f7ade28e4eef7d2934522b752
pg_image=postgres@sha256:95206741a5b214807675e14165369d05b93a9cf692223b616d07cca227e74b0b
vol=proof-audit-node-modules
suffix=$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')
net=proof-audit-run-$suffix
pg=proof-audit-run-pg-$suffix
secret=$(mktemp)
chmod 600 "$secret"
od -An -N16 -tx1 /dev/urandom | tr -d ' \n' > "$secret"

cleanup() {
  docker rm -f -v "$pg" >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
  rm -f "$secret"
}
trap cleanup EXIT INT TERM

docker volume create "$vol" >/dev/null
docker run --rm -u 0 -v "$vol:/nm" "$node_image" chown "$(id -u):$(id -g)" /nm >/dev/null
if [ ! -f "$repo/dist/bin.js" ] || [ "$repo/package-lock.json" -nt "$repo/dist/bin.js" ]; then
  docker run --rm --user "$(id -u):$(id -g)" --cap-drop ALL --security-opt no-new-privileges \
    -e HOME=/tmp/home -e npm_config_cache=/tmp/npm-cache -e npm_config_update_notifier=false \
    -v "$repo:/work" -v "$vol:/work/node_modules" -w /work "$node_image" \
    sh -c 'npm ci --ignore-scripts --silent && npm run build --silent' >&2
fi

docker network create --internal "$net" >/dev/null
POSTGRES_PASSWORD=$(cat "$secret") docker run -d --name "$pg" --network "$net" \
  --pull never --cap-drop ALL --security-opt no-new-privileges --pids-limit 256 --memory 1g --cpus 2 \
  --user 999:999 --read-only \
  --tmpfs /var/lib/postgresql/data:rw,uid=999,gid=999,mode=0700 \
  --tmpfs /var/run/postgresql:rw,uid=999,gid=999,mode=0755 --tmpfs /tmp:rw,mode=1777 \
  -e POSTGRES_PASSWORD "$pg_image" -c fsync=off -c synchronous_commit=off -c full_page_writes=off >/dev/null

i=0
until docker exec "$pg" pg_isready -q -h 127.0.0.1 -U postgres; do
  i=$((i + 1))
  if [ "$i" -gt 120 ]; then echo "run-contained: the database did not become ready" >&2; exit 3; fi
  sleep 0.5
done

# The URL is built inside the container from a read-only mounted secret file, never put on a command line.
docker run --rm --network "container:$pg" --user "$(id -u):$(id -g)" \
  --cap-drop ALL --security-opt no-new-privileges --read-only --tmpfs /tmp \
  -e HOME=/tmp -v "$repo:/app:ro" -v "$vol:/app/node_modules:ro" -v "$secret:/run/pa-secret:ro" \
  -v "$PWD:/audit" -w /audit "$node_image" \
  sh -c 'PROOF_AUDIT_DATABASE_URL="postgres://postgres:$(cat /run/pa-secret)@127.0.0.1:5432/postgres" exec node /app/dist/bin.js "$@"' sh "$@"
