# 0008. A purpose-built SQL reader, and the catalog as the source of truth

Status: accepted

## Decision

The reader is a tolerant tokenizer (comments, nested block comments, dollar quotes, `E''` strings, quoted identifiers, psql meta-commands, unterminated input) plus a statement splitter (handles `BEGIN ATOMIC` bodies, transaction-control statements, caps) and a parser for the access-relevant statements: `CREATE TABLE`, `ALTER TABLE` (RLS, columns, constraints, renames), `CREATE/ALTER/DROP POLICY`, `GRANT`/`REVOKE`, `ALTER DEFAULT PRIVILEGES`, views with `security_invoker`. Unsupported statements are skipped with a warning and never abort a run. It is not a PostgreSQL parser and does not try to be.

The model used for probing is not the parsed one. After the migrations ran, the sandbox reports tables, columns, policies, privileges (`has_table_privilege` for `anon` and `authenticated`, including schema `USAGE`) and views from `pg_catalog`. That catches tables created by DO blocks or functions and is immune to parser gaps. The parsed model is used for the splitter's statements, warnings, and to flag tables the migrations declare but the database does not have.

## Consequences

Policy expressions come back normalised by `pg_get_expr` (`( SELECT auth.uid() AS uid)`), so the expression analysis (always true/false, caller-bound columns) is tested on both hand-written and normalised text.
