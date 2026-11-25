#!/usr/bin/env python3
"""One-off: rename a legacy (pre-OraSec) database schema to OraSec names, in place.

Every identifier and Django bookkeeping value containing the legacy product name is
rewritten with the same case-preserving rule used to rebrand the code base, so the
database and the code stay in step. Runs in a single transaction; dry-run by default.

    orasec_db_rename.py --psql "docker exec -i orasec-test-db psql -U orasec -d orasec" [--apply]

Afterwards run:  manage.py migrate --plan   (must say "No planned migration operations")
                 manage.py makemigrations --check --dry-run   (must report no changes)
                 manage.py pgtrigger install
"""
import argparse
import json
import os
import re
import shlex
import subprocess
import sys

LEGACY = "d" + "ojo"  # spelled in two parts so the rebrand tool leaves it alone
PAT = re.compile(r"(?:defect[-_ ]?)?" + LEGACY, re.IGNORECASE)


def _case(m):
    s = m.group(0)
    letters = [c for c in s if c.isalpha()]
    if all(c.isupper() for c in letters):
        return "ORASEC"
    if all(c.islower() for c in letters):
        return "orasec"
    if s[0].islower():
        return "oraSec"
    return "OraSec"


def t(s):
    return PAT.sub(_case, s)


def q(ident):
    return '"' + ident.replace('"', '""') + '"'


def lit(s):
    return "'" + s.replace("'", "''") + "'"


def rows(psql, sql):
    out = subprocess.run(shlex.split(psql) + ["-At", "-F", "\t", "-c", sql], check=True, capture_output=True, text=True).stdout
    return [line.split("\t") for line in out.splitlines() if line]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--psql", required=True)
    ap.add_argument("--apply", action="store_true")
    a = ap.parse_args()
    like = f"%{LEGACY}%"
    stmts = []

    # pgtrigger-managed triggers/functions embed table names; drop them, `pgtrigger install` recreates them.
    for tbl, trg in rows(a.psql, f"""select c.relname, tg.tgname from pg_trigger tg join pg_class c on c.oid=tg.tgrelid
                                    join pg_namespace n on n.oid=c.relnamespace
                                    where n.nspname='public' and not tg.tgisinternal and tg.tgname like 'pgtrigger_%'"""):
        stmts.append(f"DROP TRIGGER IF EXISTS {q(trg)} ON {q(tbl)};")
    for (fn,) in rows(a.psql, """select p.proname from pg_proc p join pg_namespace n on n.oid=p.pronamespace
                                 where n.nspname='public' and p.proname like 'pgtrigger_%'"""):
        stmts.append(f"DROP FUNCTION IF EXISTS {q(fn)}() CASCADE;")

    # constraints that are not index-backed (index-backed ones follow their index)
    for tbl, con in rows(a.psql, f"""select c.relname, k.conname from pg_constraint k join pg_class c on c.oid=k.conrelid
                                    join pg_namespace n on n.oid=c.relnamespace
                                    where n.nspname='public' and k.conname ilike '{like}' and k.contype not in ('p','u','x')"""):
        stmts.append(f"ALTER TABLE {q(tbl)} RENAME CONSTRAINT {q(con)} TO {q(t(con))};")
    # columns
    for tbl, col in rows(a.psql, f"""select table_name, column_name from information_schema.columns
                                    where table_schema='public' and column_name ilike '{like}'"""):
        stmts.append(f"ALTER TABLE {q(tbl)} RENAME COLUMN {q(col)} TO {q(t(col))};")
    # relations: indexes, sequences, views, then tables
    kinds = {"i": "INDEX", "S": "SEQUENCE", "v": "VIEW", "m": "MATERIALIZED VIEW", "r": "TABLE", "p": "TABLE"}
    for kind in ["i", "S", "v", "m", "r", "p"]:
        for (rel,) in rows(a.psql, f"""select c.relname from pg_class c join pg_namespace n on n.oid=c.relnamespace
                                      where n.nspname='public' and c.relkind='{kind}' and c.relname ilike '{like}'"""):
            stmts.append(f"ALTER {kinds[kind]} {q(rel)} RENAME TO {q(t(rel))};")

    # explicit index/constraint names that exceed Django's 30-char limit once renamed (see orasec_index_shortnames.json)
    short = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "orasec_index_shortnames.json")))
    legacy_of = {}
    for (rel,) in rows(a.psql, f"select c.relname from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relkind='i'"):
        legacy_of[t(rel)] = rel
    cons = {t(c): (tb, c) for tb, c in rows(a.psql, f"""select c.relname, k.conname from pg_constraint k join pg_class c on c.oid=k.conrelid
                                    join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and k.contype not in ('p','u','x')""")}
    for new_long, new_short in short.items():
        if new_long in legacy_of:  # index (also renames a backing unique/pk constraint)
            stmts.append(f"ALTER INDEX {q(t(legacy_of[new_long]))} RENAME TO {q(new_short)};")
        elif new_long in cons:
            tb, c = cons[new_long]
            stmts.append(f"ALTER TABLE {q(t(tb))} RENAME CONSTRAINT {q(t(c))} TO {q(new_short)};")

    # Django bookkeeping
    for table, cols in {
        "django_content_type": ["app_label", "model"],
        "django_migrations": ["app", "name"],
        "auth_permission": ["codename", "name"],
        "django_celery_results_taskresult": ["task_name"],
    }.items():
        for col in cols:
            for (val,) in rows(a.psql, f"select distinct {q(col)} from {q(table)} where {q(col)} ilike '{like}'"):
                stmts.append(f"UPDATE {q(table)} SET {q(col)}={lit(t(val))} WHERE {q(col)}={lit(val)};")

    sql = "BEGIN;\n" + "\n".join(stmts) + "\nCOMMIT;\n"
    print(f"-- {len(stmts)} statements", file=sys.stderr)
    if not a.apply:
        print(sql)
        return
    r = subprocess.run(shlex.split(a.psql) + ["-v", "ON_ERROR_STOP=1", "-q"], input=sql, text=True, capture_output=True)
    sys.stdout.write(r.stdout[-2000:])
    sys.stderr.write(r.stderr[-4000:])
    sys.exit(r.returncode)


if __name__ == "__main__":
    main()

