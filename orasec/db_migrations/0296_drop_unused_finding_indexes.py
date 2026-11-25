"""Drop four `orasec_finding` indexes that no query uses.

`orasec_finding` is the busiest table in the schema and carries close to fifty indexes, every
one of which is maintained on each row written. Import is where that is felt: a scan
creating thousands of findings pays for all of them per row.

These four were measured as completely unused -- `pg_stat_user_indexes.idx_scan = 0` -- on
four long-running production instances, three of which had accumulated statistics for about
seventeen months:

    (epss_percentile)      the largest of them; note (epss_score) IS used, so findings are
                           sorted by score and the percentile is stored and displayed but is
                           never an access path
    (line)
    (known_exploited)
    idx_finding_sev_open_unver   partial: (severity, -numerical_severity)
                                 WHERE active AND NOT verified

Indexes that were unused on *some* instances but not others were deliberately left alone --
they track optional features, and dropping on that evidence would break the installs that do
use them.

Built with DROP INDEX CONCURRENTLY (non-atomic migration, following 0280) so it takes no
exclusive lock on a large `orasec_finding`. IF EXISTS makes it idempotent, and the reverse
rebuilds concurrently, so a downgrade does not lock the table either.
"""
from django.db import migrations, models


class Migration(migrations.Migration):
    atomic = False

    dependencies = [
        ("orasec", "0295_usercontactinfo_language"),
    ]

    operations = [
        # RunSQL does the concurrent DB work; state_operations keeps Django's model state in
        # step with the Meta change, so a later makemigrations stays a no-op.
        migrations.SeparateDatabaseAndState(
            database_operations=[
                migrations.RunSQL(
                    sql="DROP INDEX CONCURRENTLY IF EXISTS orasec_findin_epss_pe_567499_idx",
                    reverse_sql=(
                        "CREATE INDEX CONCURRENTLY IF NOT EXISTS orasec_findin_epss_pe_567499_idx "
                        "ON orasec_finding (epss_percentile)"
                    ),
                ),
                migrations.RunSQL(
                    sql="DROP INDEX CONCURRENTLY IF EXISTS orasec_findin_line_fea329_idx",
                    reverse_sql=(
                        "CREATE INDEX CONCURRENTLY IF NOT EXISTS orasec_findin_line_fea329_idx "
                        "ON orasec_finding (line)"
                    ),
                ),
                migrations.RunSQL(
                    sql="DROP INDEX CONCURRENTLY IF EXISTS orasec_findin_known_e_8c584e_idx",
                    reverse_sql=(
                        "CREATE INDEX CONCURRENTLY IF NOT EXISTS orasec_findin_known_e_8c584e_idx "
                        "ON orasec_finding (known_exploited)"
                    ),
                ),
                migrations.RunSQL(
                    sql="DROP INDEX CONCURRENTLY IF EXISTS idx_finding_sev_open_unver",
                    reverse_sql=(
                        "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_finding_sev_open_unver "
                        "ON orasec_finding (severity, numerical_severity DESC) "
                        "WHERE (active AND NOT verified)"
                    ),
                ),
            ],
            state_operations=[
                migrations.RemoveIndex(model_name="finding", name="os_findin_epss_pe_567499_idx"),
                migrations.RemoveIndex(model_name="finding", name="orasec_findin_line_fea329_idx"),
                migrations.RemoveIndex(model_name="finding", name="os_findin_known_e_8c584e_idx"),
                migrations.RemoveIndex(model_name="finding", name="idx_finding_sev_open_unver"),
            ],
        ),
    ]
