#!/bin/sh
# Generate docs/sample-report.md: a client-style audit report produced by running proof-audit on the repo's own
# vulnerable example (examples/vulnerable-app). Nothing in the report is typed by hand except the fixed
# sections that explain the scope, the method and the limits: every finding, reproduction, fix and result is
# copied from the tool's own output, and the file is not edited afterwards. Running the script again gives the
# same bytes.
#
# The runs happen in the throwaway containers of scripts/run-contained.sh (Docker is the only requirement):
#   1. audit the vulnerable migrations (Markdown report, proofs, fix.sql)
#   2. replay the recorded proofs against the same migrations (they must still reproduce)
#   3. append the proposed fix.sql to the migrations as a last migration and audit the result from scratch
#   4. replay the recorded proofs against the patched migrations (every attack must now fail)
#
# usage: scripts/make-sample-report.sh
set -eu
cd "$(dirname "$0")/.."

src=examples/vulnerable-app/supabase/migrations
work=out/sample-report
audit=$work/audit
patched=$work/patched/supabase/migrations
target=docs/sample-report.md

rm -rf "$work"
mkdir -p "$audit" "$patched"

run() { scripts/run-contained.sh "$@"; }

# 1. the audit
cmd1="scripts/run-contained.sh rls $src --markdown --out $audit"
run rls "$src" --markdown --out "$audit" > "$work/audit.md" 2> "$work/audit.err" && rc1=0 || rc1=$?
if [ "$rc1" -ne 1 ]; then cat "$work/audit.err" >&2; echo "make-sample-report: the audit of the vulnerable example exited $rc1, expected 1" >&2; exit 1; fi

# 2. replay of the recorded proofs
cmd2="scripts/run-contained.sh verify $audit/proofs.jsonl"
run verify "$audit/proofs.jsonl" > "$work/replay.txt" 2> "$work/replay.err" && rc2=0 || rc2=$?
if [ "$rc2" -ne 0 ]; then cat "$work/replay.txt" "$work/replay.err" >&2; echo "make-sample-report: the replay exited $rc2, expected 0" >&2; exit 1; fi

# 3. the proposed fix, applied as a last migration
cp "$src"/*.sql "$patched"/
cp "$audit/fix.sql" "$patched/20260107000000_proof_audit_fix.sql"
cmd3="scripts/run-contained.sh rls $patched"
run rls "$patched" --out "$work/after" > "$work/after.txt" 2> "$work/after.err" && rc3=0 || rc3=$?
if [ "$rc3" -ne 0 ]; then cat "$work/after.err" >&2; echo "make-sample-report: the audit of the patched migrations exited $rc3, expected 0" >&2; exit 1; fi

# 4. the recorded proofs against the patched migrations
cmd4="scripts/run-contained.sh verify $audit/proofs.jsonl --against $patched"
run verify "$audit/proofs.jsonl" --against "$patched" > "$work/against.txt" 2> "$work/against.err" && rc4=0 || rc4=$?
if [ "$rc4" -ne 0 ]; then cat "$work/against.txt" "$work/against.err" >&2; echo "make-sample-report: the verification against the patched migrations exited $rc4, expected 0" >&2; exit 1; fi

# the body of one "## name" section of the tool's Markdown report (without its heading)
section() {
  awk -v name="$1" '
    $0 == "## " name { on = 1; next }
    /^## / { on = 0 }
    on { print }
  ' "$work/audit.md"
}

# the part of a plain-language report that precedes the first blank line (the header and the result line)
head_of() { awk 'NF == 0 { exit } { print }' "$1"; }

# one summary line per finding, from the finding headings: "### 1. PROVEN · critical · `public.profiles`"
summary() {
  awk '
    /^### [0-9]+\. / {
      line = $0
      sub(/^### [0-9]+\. /, "", line)
      n = split(line, p, " · ")
      subject = p[3]
      gsub(/`/, "", subject)
      printf "| %s | `%s` | %s | %s |\n", ++i, subject, p[2], p[1]
    }
  ' "$work/audit.md"
}

tmp=$work/sample-report.md
{
  cat <<'EOF'
# Sample audit report: row level security

This is what a client receives. It was produced by `scripts/make-sample-report.sh`, which runs `proof-audit` in throwaway containers on the repository's own deliberately vulnerable example (`examples/vulnerable-app`, a small notes-and-invoices app with six access-control mistakes). Apart from the explanatory sections (scope, method, limits) and the table that summarises the findings, everything below is the tool's own output, copied without editing; the file is regenerated, never edited by hand. The example uses synthetic data only. No real project was involved.

## Scope

**Reviewed:** the SQL migrations of one Supabase-style project, nothing else: the tables and views they create in the `public` schema, and the policies, privileges and views that apply to them.

**Questions asked:** can someone holding only the public key (the `anon` role) read, add, change or delete rows? Can a signed-in user reach another user's rows, or give a row away? Can anyone read protected rows through a view? After the fix: are all of those attacks refused, and can a normal user still use their own data?

**Not in scope:** the live project, application code, secrets, storage, auth settings. The list is repeated at the end of this report.

EOF
  echo "**Run details:**"
  awk '
    /^# / { on = 1; next }
    /^## / { on = 0 }
    on { print }
  ' "$work/audit.md"
  cat <<'EOF'

## Method

1. The migrations are read as plain SQL. No live system, key or `.env` file is touched.
2. A fresh PostgreSQL 16 database is created inside a container with no network, with the roles and helper functions of a Supabase project (`anon`, `authenticated`, `service_role`, `auth.uid()` and friends). The migrations are applied as the non-superuser role that Supabase calls `postgres`.
3. One row per synthetic user (Alice, Bob) is seeded in every table.
4. Every table and view is attacked as the anonymous role and as Alice, who is signed in with a JWT whose `sub` is Alice's id: she tries to read, add, change and delete Bob's rows, to add a row with no owner and to hand one of her own rows to Bob. Every statement runs in a transaction that is rolled back. The exact SQL, the role, the claims and what the database answered are recorded.
5. Legitimate use is tested too: Alice reads, adds, changes and deletes her own rows.
6. A result is **PROVEN** only when the database itself let an attack through. **CLEAN** means every attack was refused. Anything that could not be run is **INCONCLUSIVE**, never silently clean.
7. A fix is proposed, applied to a fresh copy of the database and the same probes are run again. It counts as verified only if every attack that worked now fails *and* the legitimate actions still work.
8. The recorded proofs can be replayed by anyone with `scripts/run-contained.sh verify`.

## Summary

| # | Table or view | Severity | Evidence |
|---|---|---|---|
EOF
  summary
  echo
  echo "## Result"
  section "Result"
  echo "## Findings"
  section "What we found"
  echo "## Looked fine"
  section "Looked fine"
  echo "## Proposed fix"
  echo
  echo "The proposed SQL is a starting point: review every statement before running it on a real project."
  section "How to fix"
  echo "## Fix check inside the audit run"
  section "Fix check"
  cat <<EOF
## Before and after

**Before.** The recorded proofs are replayed against the original migrations, in a fresh database. They reproduce:

\`\`\`console
\$ $cmd2
$(cat "$work/replay.txt")
exit code: $rc2
\`\`\`

**After.** The proposed SQL is added to the migrations as a last migration (\`20260107000000_proof_audit_fix.sql\`, byte for byte the SQL above) and the whole audit is run again from scratch:

\`\`\`console
\$ $cmd3
$(head_of "$work/after.txt")
...
exit code: $rc3
\`\`\`

The same recorded attacks, replayed against the patched migrations:

\`\`\`console
\$ $cmd4
$(cat "$work/against.txt")
exit code: $rc4
\`\`\`

Exit code 0 means every attack that worked before is refused now and the normal-use probes still pass. Run against the unpatched migrations, the same command reports the six tables as still vulnerable and exits 1.

## Limits of the method

EOF
  cat <<'EOF'
This report is evidence about the SQL that was supplied, for the synthetic users that were used. It is not a penetration test and not a guarantee that the project is secure.

- **Only row level security is judged.** What the tool did not look at is listed below, as the tool prints it in every report.
- **Synthetic identities.** Two users and an anonymous caller, with the claims `sub`, `role`, `tenant_id` and `org_id`. A policy that depends on other claims or on data the tool does not create is not exercised. One row is seeded per user, so policies that depend on many rows are not exercised either.
- **An approximation of Supabase, not Supabase.** The roles, `auth.*` functions and default privileges are rebuilt in plain PostgreSQL 16. Which schemas the API exposes, the real JWT contents, storage, realtime and extensions beyond `uuid-ossp` and `pgcrypto` are not modelled.
- **Table-level privileges only.** Column-level privileges, materialized views and functions called as RPC (including `SECURITY DEFINER` functions) are not probed.
- **The fix is a starting point.** It is checked against the same synthetic users. It needs a human decision wherever a table has no clear owner column.
- **A re-run proves the listed attacks are closed**, not that no other attack exists.

EOF
  echo "## What was not checked"
  section "What was not checked"
  echo "## Evidence files"
  echo
  echo "Written next to this report by the same run (\`$audit/\`, not committed): \`report.json\`, \`proofs.jsonl\` (every probe with its exact SQL, role, claims, answer and content hash), \`verification-contract.json\` and \`fix.sql\`. The committed copies for the same example, produced by the same tool, are in \`examples/vulnerable-app/sample-output/\`."
} > "$tmp.raw"
cat -s "$tmp.raw" > "$tmp"
rm -f "$tmp.raw"

mkdir -p docs
mv "$tmp" "$target"
echo "wrote $target ($(wc -l < "$target" | tr -d ' ') lines)"
