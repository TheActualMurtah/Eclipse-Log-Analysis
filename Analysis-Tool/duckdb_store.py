"""
duckdb_store.py
===============

Proof-of-concept DuckDB integration for the Jenkins log analyzer.

Imports from analyzer.py without modifying it. Parses a Jenkins log file,
stores the events in a persistent DuckDB database, and runs demonstration
queries that mirror what analyzer.py's analytics functions produce.

Usage:
    python duckdb_store.py /path/to/jenkins.log
    python duckdb_store.py /path/to/jenkins.log --db my_logs.duckdb
    python duckdb_store.py /path/to/jenkins.log --query-only     # skip insert, run preset queries
    python duckdb_store.py /path/to/jenkins.log --interactive    # drop into SQL shell after loading
    python duckdb_store.py /path/to/jenkins.log --interactive --query-only  # SQL shell, no insert
"""

from __future__ import annotations

import argparse
import json
from datetime import timedelta
from pathlib import Path
from typing import Optional, Union

import duckdb

# Import from analyzer without touching it
from analyzer import analyze, active, LogEvent, parse_timestamp, TimeLike

# Output directory structure — sits next to this script
# Each category gets its own subfolder matching the categories in the docs.
SCRIPT_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = SCRIPT_DIR / "duckdb_output"

OUT_OVERVIEW   = OUTPUT_DIR / "overview"    # level-counts, top-templates, tag-summary
OUT_DEEP_DIVE  = OUTPUT_DIR / "deep-dive"   # fatal-events, stack-traces, level-WARNING/SEVERE
OUT_TIME       = OUTPUT_DIR / "time"        # time-filter-*
OUT_PATTERN    = OUTPUT_DIR / "pattern"     # logger-*, template-*
OUT_RULES      = OUTPUT_DIR / "rules"       # tag-{tagname} per-tag files
OUT_CROSS_FILE = OUTPUT_DIR / "cross-file"  # cross-file-templates, trend-template-*
OUT_ON_DEMAND  = OUTPUT_DIR / "on-demand"   # compare-*

for _d in (OUTPUT_DIR, OUT_OVERVIEW, OUT_DEEP_DIVE, OUT_TIME,
           OUT_PATTERN, OUT_RULES, OUT_CROSS_FILE, OUT_ON_DEMAND):
    _d.mkdir(exist_ok=True)

# A query's source_file argument can scope to:
#   None        -> every loaded file
#   "a.log"     -> exactly one file
#   ["a", "b"]  -> an arbitrary subset of files
SourceFileArg = Optional[Union[str, list[str]]]


def source_file_clause(source_file: SourceFileArg) -> tuple[str, list]:
    """
    Build the SQL fragment and parameters for filtering by source_file.

    Returns ("", []) when source_file is None — no filter, every file.
    Returns ("AND source_file = ?", [path]) for a single string.
    Returns ("AND source_file IN (?, ?, ...)", [paths]) for a list.

    Every q_* function calls this once instead of repeating the same
    if/elif logic, so list-of-files support only had to be written here.
    """
    if source_file is None:
        return "", []
    if isinstance(source_file, str):
        return "AND source_file = ?", [source_file]
    # list/tuple of paths
    paths = list(source_file)
    if not paths:
        # empty list means "match nothing" rather than "match everything" —
        # an empty IN (...) is invalid SQL, so use a clause that's always false
        return "AND 1 = 0", []
    placeholders = ", ".join("?" for _ in paths)
    return f"AND source_file IN ({placeholders})", paths

# --------------------------------------------------------------------------- #
# Schema
# --------------------------------------------------------------------------- #

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS log_events (
    -- position in source file
    line_start      INTEGER   NOT NULL,
    line_end        INTEGER   NOT NULL,

    -- core event fields
    timestamp       TIMESTAMPTZ,
    level           VARCHAR,
    thread_id       VARCHAR,
    logger          VARCHAR,
    method          VARCHAR,
    message         VARCHAR,
    stack_trace     VARCHAR,   -- NULL when no exception/continuation lines

    -- drain3 templating
    template_id     INTEGER,   -- NULL if drain3 not installed
    template        VARCHAR,

    -- ruleset output
    tags            VARCHAR,   -- JSON array stored as string e.g. '["ssh-failure"]'
    ignored         BOOLEAN    NOT NULL DEFAULT false,

    -- ingestion context
    source_file     VARCHAR    NOT NULL
)
"""

# --------------------------------------------------------------------------- #
# Insertion
# --------------------------------------------------------------------------- #

def _event_to_row(ev: LogEvent, source_file: str) -> tuple:
    """Convert a LogEvent into a flat tuple matching the CREATE TABLE column order."""
    return (
        ev.line_start,
        ev.line_end,
        ev.timestamp,                          # datetime — DuckDB accepts natively
        ev.level,
        ev.thread_id,
        ev.logger,
        ev.method,
        ev.message,
        ev.stack_trace,                        # None becomes SQL NULL
        ev.template_id,
        ev.template,
        json.dumps(ev.tags),                   # list -> JSON string
        ev.ignored,
        source_file,
    )


def insert_events(
    con: duckdb.DuckDBPyConnection,
    events: list[LogEvent],
    source_file: str,
) -> int:
    """
    Bulk-insert a list of LogEvents into log_events.
    Returns the number of rows inserted.
    """
    rows = [_event_to_row(ev, source_file) for ev in events]
    con.executemany(
        """
        INSERT INTO log_events (
            line_start, line_end, timestamp, level, thread_id,
            logger, method, message, stack_trace,
            template_id, template, tags, ignored, source_file
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    return len(rows)


# --------------------------------------------------------------------------- #
# Queries
# --------------------------------------------------------------------------- #

def q_level_counts(con: duckdb.DuckDBPyConnection, source_file: SourceFileArg = None) -> None:
    """Count of active events grouped by log level."""
    clause, params = source_file_clause(source_file)
    where = f"WHERE NOT ignored {clause}"

    rows = con.execute(
        f"""
        SELECT level, count(*) AS n
        FROM log_events
        {where}
        GROUP BY level
        ORDER BY n DESC
        """,
        params,
    ).fetchall()

    out = OUT_OVERVIEW / "level-counts"
    with open(out, "w", encoding="utf-8") as f:
        f.write("Level counts\n")
        f.write("─" * 30 + "\n")
        for level, n in rows:
            f.write(f"  {level:<10} {n:>7}\n")
    print(f"  level counts      → {out}")


def q_top_templates(
    con: duckdb.DuckDBPyConnection,
    n: int = 10,
    source_file: SourceFileArg = None,
) -> None:
    """Most frequent DRAIN3 templates across active, non-null-template events."""
    clause, params = source_file_clause(source_file)
    where = f"WHERE NOT ignored AND template_id IS NOT NULL {clause}"

    rows = con.execute(
        f"""
        SELECT template_id, template, count(*) AS n
        FROM log_events
        {where}
        GROUP BY template_id, template
        ORDER BY n DESC
        LIMIT ?
        """,
        params + [n],
    ).fetchall()

    out = OUT_OVERVIEW / f"top-{n}-templates"
    with open(out, "w", encoding="utf-8") as f:
        f.write(f"Top {n} templates by frequency\n")
        f.write("─" * 60 + "\n")
        for i, (tid, tmpl, count) in enumerate(rows, 1):
            f.write(f"  [{i:>2}] #{tid:<4} x{count:<6}  {tmpl}\n")
    print(f"  top {n} templates    → {out}")


def q_fatal_events(
    con: duckdb.DuckDBPyConnection,
    source_file: SourceFileArg = None,
) -> None:
    """All SEVERE / FATAL / ERROR events that aren't ignored."""
    clause, params = source_file_clause(source_file)
    where = f"WHERE NOT ignored AND level IN ('SEVERE', 'FATAL', 'ERROR') {clause}"

    rows = con.execute(
        f"""
        SELECT line_start, timestamp, level, message, stack_trace
        FROM log_events
        {where}
        ORDER BY timestamp
        """,
        params,
    ).fetchall()

    out = OUT_DEEP_DIVE / "fatal-events"
    with open(out, "w", encoding="utf-8") as f:
        f.write("Fatal events (SEVERE / FATAL / ERROR)\n")
        f.write("─" * 60 + "\n")
        if not rows:
            f.write("  (none)\n")
        else:
            for line, ts, level, msg, stack in rows:
                f.write(f"  line {line} at {ts}  [{level}]\n")
                f.write(f"    {msg}\n")
                if stack:
                    for stack_line in stack.splitlines():
                        f.write(f"    {stack_line}\n")
                f.write("\n")
    print(f"  fatal events       → {out}")


def q_time_filter(
    con: duckdb.DuckDBPyConnection,
    lo: Optional[str] = None,
    hi: Optional[str] = None,
    source_file: SourceFileArg = None,
) -> None:
    """
    Events in a time range.

    lo / hi are ISO or Jenkins timestamp strings.
    If neither is given, defaults to the last 12 hours of data within the
    requested scope (i.e. relative to the selected file(s), not the whole DB).
    If only lo is given, returns everything from lo onward.
    If only hi is given, returns everything up to hi.
    """
    clause, scope_params = source_file_clause(source_file)

    # ── resolve lo/hi against the data range within scope ────────────────── #
    data_min, data_max = con.execute(
        f"SELECT min(timestamp), max(timestamp) FROM log_events WHERE 1=1 {clause}",
        scope_params,
    ).fetchone()

    if lo is None and hi is None:
        # default: last 12 hours of whatever is in scope
        hi_dt  = data_max
        lo_dt  = data_max - timedelta(hours=12)
        label  = "last-12h"
    else:
        lo_dt = parse_timestamp(lo) if lo else data_min
        hi_dt = parse_timestamp(hi) if hi else data_max
        # build a short label for the filename
        lo_tag = str(lo_dt).replace(" ", "T").replace(":", "-")[:19]
        hi_tag = str(hi_dt).replace(" ", "T").replace(":", "-")[:19]
        label  = f"{lo_tag}_to_{hi_tag}"

    where  = f"WHERE NOT ignored AND timestamp BETWEEN ? AND ? {clause}"
    params: list = [lo_dt, hi_dt] + scope_params

    rows = con.execute(
        f"""
        SELECT line_start, timestamp, level, message
        FROM log_events
        {where}
        ORDER BY timestamp
        """,
        params,
    ).fetchall()

    out = OUT_TIME / f"time-filter-{label}"
    with open(out, "w", encoding="utf-8") as f:
        f.write(f"Time filter: {lo_dt}  →  {hi_dt}\n")
        f.write("─" * 60 + "\n")
        if not rows:
            f.write("  (no events in this range)\n")
        else:
            for line, ts, level, msg in rows:
                f.write(f"  line {line:<7} {ts}  [{level:<8}]  {msg}\n")
            f.write(f"\n  ({len(rows)} events total)\n")
    print(f"  time filter        → {out}")


def q_by_level(
    con: duckdb.DuckDBPyConnection,
    level: str,
    source_file: SourceFileArg = None,
) -> None:
    """
    Every active event at the given log level.
    level should be one of: INFO, WARNING, SEVERE, ERROR, FATAL.
    """
    level_upper = level.upper()

    clause, scope_params = source_file_clause(source_file)
    where  = f"WHERE NOT ignored AND level = ? {clause}"
    params: list = [level_upper] + scope_params

    rows = con.execute(
        f"""
        SELECT line_start, timestamp, level, logger, message, stack_trace
        FROM log_events
        {where}
        ORDER BY timestamp
        """,
        params,
    ).fetchall()

    out = OUT_DEEP_DIVE / f"level-{level_upper}"
    with open(out, "w", encoding="utf-8") as f:
        f.write(f"All {level_upper} events ({len(rows)} total)\n")
        f.write("─" * 60 + "\n")
        if not rows:
            f.write("  (none)\n")
        else:
            for line, ts, lvl, logger, msg, stack in rows:
                f.write(f"\n  line {line} at {ts}\n")
                f.write(f"  logger:  {logger}\n")
                f.write(f"  message: {msg}\n")
                if stack:
                    for stack_line in stack.splitlines():
                        f.write(f"    {stack_line}\n")
    print(f"  level={level_upper:<8}       → {out}")


def q_by_logger(
    con: duckdb.DuckDBPyConnection,
    logger_pattern: str,
    source_file: SourceFileArg = None,
) -> None:
    """
    Every active event whose logger contains logger_pattern (case-insensitive).
    e.g. logger_pattern="SSHLauncher" matches h.plugins.sshslaves.SSHLauncher
    """
    clause, scope_params = source_file_clause(source_file)
    where  = f"WHERE NOT ignored AND lower(logger) LIKE lower(?) {clause}"
    params: list = [f"%{logger_pattern}%"] + scope_params

    rows = con.execute(
        f"""
        SELECT line_start, timestamp, level, logger, message, stack_trace
        FROM log_events
        {where}
        ORDER BY timestamp
        """,
        params,
    ).fetchall()

    # safe filename — strip characters that are bad in filenames
    safe_pattern = logger_pattern.replace("/", "-").replace("\\", "-")
    out = OUT_PATTERN / f"logger-{safe_pattern}"
    with open(out, "w", encoding="utf-8") as f:
        f.write(f"Events from logger matching '{logger_pattern}' ({len(rows)} total)\n")
        f.write("─" * 60 + "\n")
        if not rows:
            f.write("  (none)\n")
        else:
            for line, ts, level, logger, msg, stack in rows:
                f.write(f"\n  line {line} at {ts}  [{level}]\n")
                f.write(f"  logger:  {logger}\n")
                f.write(f"  message: {msg}\n")
                if stack:
                    for stack_line in stack.splitlines():
                        f.write(f"    {stack_line}\n")
    print(f"  logger='{logger_pattern}'    → {out}")


def q_by_template(
    con: duckdb.DuckDBPyConnection,
    template_id: int,
    source_file: SourceFileArg = None,
) -> None:
    """
    Every active event belonging to a given DRAIN3 template cluster.
    Use q_top_templates first to find the template_id you want.
    """
    clause, params = source_file_clause(source_file)
    where = f"WHERE NOT ignored AND template_id = ? {clause}"
    params = [template_id] + params

    rows = con.execute(
        f"""
        SELECT line_start, timestamp, level, message, stack_trace, template, source_file
        FROM log_events
        {where}
        ORDER BY timestamp
        """,
        params,
    ).fetchall()

    template_str = rows[0][5] if rows else "unknown"

    # per-file breakdown — only meaningful once more than one file is involved
    files_seen = sorted(set(r[6] for r in rows))

    out = OUT_PATTERN / f"template-{template_id}"
    with open(out, "w", encoding="utf-8") as f:
        f.write(f"Template #{template_id} — {len(rows)} occurrences\n")
        f.write(f"Pattern: {template_str}\n")
        if len(files_seen) > 1:
            f.write(f"Appears in {len(files_seen)} files:\n")
            for fpath in files_seen:
                count = sum(1 for r in rows if r[6] == fpath)
                f.write(f"  {count:>6}  {fpath}\n")
        f.write("─" * 60 + "\n")
        if not rows:
            f.write("  (none)\n")
        else:
            for line, ts, level, msg, stack, tmpl, fpath in rows:
                f.write(f"\n  line {line} at {ts}  [{level}]\n")
                f.write(f"  message: {msg}\n")
                if stack:
                    for stack_line in stack.splitlines():
                        f.write(f"    {stack_line}\n")
    print(f"  template #{template_id:<5}       → {out}")


def q_by_tag(
    con: duckdb.DuckDBPyConnection,
    tag: str,
    source_file: SourceFileArg = None,
) -> None:
    """
    Every active event carrying the given tag.
    Tags are populated by RuleSet during analyze() and stored as a JSON
    array string, e.g. '["ssh-failure"]' — this does a substring match
    on that string, which is safe because tag names don't contain quotes.
    """
    clause, scope_params = source_file_clause(source_file)
    where  = f"WHERE NOT ignored AND tags LIKE ? {clause}"
    params: list = [f'%"{tag}"%'] + scope_params

    rows = con.execute(
        f"""
        SELECT line_start, timestamp, level, logger, message, stack_trace, tags
        FROM log_events
        {where}
        ORDER BY timestamp
        """,
        params,
    ).fetchall()

    out = OUT_RULES / f"tag-{tag}"
    with open(out, "w", encoding="utf-8") as f:
        f.write(f"Events tagged '{tag}' ({len(rows)} total)\n")
        f.write("─" * 60 + "\n")
        if not rows:
            f.write("  (none — check that a rules file was loaded with --rules)\n")
        else:
            for line, ts, level, logger, msg, stack, tags_raw in rows:
                f.write(f"\n  line {line} at {ts}  [{level}]\n")
                f.write(f"  logger: {logger}\n")
                f.write(f"  message: {msg}\n")
                f.write(f"  tags: {tags_raw}\n")
                if stack:
                    for stack_line in stack.splitlines():
                        f.write(f"    {stack_line}\n")
    print(f"  tag='{tag}'           → {out}")


def q_tag_summary(
    con: duckdb.DuckDBPyConnection,
    source_file: SourceFileArg = None,
) -> None:
    """
    Breakdown of how many events carry each tag.
    Useful as a quick check that rules actually did something.
    """
    clause, params = source_file_clause(source_file)
    where = f"WHERE NOT ignored AND tags != '[]' {clause}"

    rows = con.execute(
        f"SELECT tags, count(*) AS n FROM log_events {where} GROUP BY tags ORDER BY n DESC",
        params,
    ).fetchall()

    # also report ignored count, since suppression doesn't show up as a tag
    ignored_clause, ignored_params = source_file_clause(source_file)
    ignored_where = f"WHERE ignored {ignored_clause}"
    ignored_count = con.execute(
        f"SELECT count(*) FROM log_events {ignored_where}", ignored_params
    ).fetchone()[0]

    out = OUT_OVERVIEW / "tag-summary"
    with open(out, "w", encoding="utf-8") as f:
        f.write("Tag summary\n")
        f.write("─" * 40 + "\n")
        f.write(f"  ignored (suppressed by rules): {ignored_count}\n\n")
        if not rows:
            f.write("  (no tags found — no rules file loaded, or no tag rules matched)\n")
        else:
            for tags_raw, n in rows:
                tag_list = json.loads(tags_raw)
                f.write(f"  {', '.join(tag_list):<30} x{n}\n")
    print(f"  tag summary        → {out}")


def q_stack_traces(
    con: duckdb.DuckDBPyConnection,
    source_file: SourceFileArg = None,
) -> None:
    """Events that have a stack trace — most useful to hand to an LLM."""
    clause, params = source_file_clause(source_file)
    where = f"WHERE NOT ignored AND stack_trace IS NOT NULL {clause}"

    rows = con.execute(
        f"""
        SELECT line_start, timestamp, level, message, stack_trace
        FROM log_events
        {where}
        ORDER BY timestamp
        """,
        params,
    ).fetchall()

    out = OUT_DEEP_DIVE / "stack-traces"
    with open(out, "w", encoding="utf-8") as f:
        f.write(f"Events with stack traces ({len(rows)} total)\n")
        f.write("─" * 60 + "\n")
        if not rows:
            f.write("  (none)\n")
        else:
            for line, ts, level, msg, stack in rows:
                f.write(f"\n  line {line} at {ts}  [{level}]\n")
                f.write(f"  {msg}\n")
                for stack_line in stack.splitlines():
                    f.write(f"    {stack_line}\n")
    print(f"  stack traces       → {out}")


def q_cross_file_templates(
    con: duckdb.DuckDBPyConnection,
    min_files: int = 2,
    source_file: SourceFileArg = None,
) -> None:
    """
    Templates that appear in at least min_files distinct source files,
    with a per-file breakdown. This is the core cross-log correlation query —
    it answers "which error patterns are recurring across multiple builds."

    Skips writing output if fewer than 2 distinct files are in scope,
    since the query is meaningless with only one file.
    """
    clause, params = source_file_clause(source_file)

    # check how many distinct files are in scope before running the full query
    file_count = con.execute(
        f"SELECT count(DISTINCT source_file) FROM log_events WHERE 1=1 {clause}",
        params,
    ).fetchone()[0]

    out = OUT_CROSS_FILE / "cross-file-templates"
    if file_count < 2:
        with open(out, "w", encoding="utf-8") as f:
            f.write("Cross-file templates\n")
            f.write("─" * 60 + "\n")
            f.write(f"  (only {file_count} file in scope — needs 2+ files to correlate)\n")
        print(f"  cross-file templates → {out}  (skipped: only {file_count} file in scope)")
        return

    where = f"WHERE NOT ignored AND template_id IS NOT NULL {clause}"

    rows = con.execute(
        f"""
        SELECT template_id, template,
               count(DISTINCT source_file) AS file_count,
               count(*) AS total
        FROM log_events
        {where}
        GROUP BY template_id, template
        HAVING count(DISTINCT source_file) >= ?
        ORDER BY file_count DESC, total DESC
        """,
        params + [min_files],
    ).fetchall()

    # for each qualifying template, get per-file counts
    per_file: dict[int, list[tuple]] = {}
    for tid, _, _, _ in rows:
        file_rows = con.execute(
            f"""
            SELECT source_file, count(*) AS n
            FROM log_events
            WHERE NOT ignored AND template_id = ? {clause}
            GROUP BY source_file
            ORDER BY n DESC
            """,
            [tid] + params,
        ).fetchall()
        per_file[tid] = file_rows

    out = OUT_CROSS_FILE / "cross-file-templates"
    with open(out, "w", encoding="utf-8") as f:
        f.write(f"Templates appearing in {min_files}+ of {file_count} files\n")
        f.write("─" * 60 + "\n")
        if not rows:
            f.write(f"  (no templates found in {min_files}+ files)\n")
        else:
            for i, (tid, tmpl, fcount, total) in enumerate(rows, 1):
                f.write(f"\n[{i:>2}] #{tid}  {total} total occurrences across {fcount} files\n")
                f.write(f"     {tmpl}\n")
                for fpath, n in per_file[tid]:
                    fname = Path(fpath).name
                    f.write(f"       {n:>6}  {fname}\n")
    print(f"  cross-file templates → {out}")


def q_file_comparison(
    con: duckdb.DuckDBPyConnection,
    file_a: str,
    file_b: str,
) -> None:
    """
    Side-by-side template frequency comparison between exactly two files.
    Produces three sections: templates only in A, only in B, and shared
    (with counts for both). Useful for "what changed between two builds."
    """
    stem_a = Path(file_a).name
    stem_b = Path(file_b).name

    # templates in A
    rows_a = con.execute(
        """
        SELECT template_id, template, count(*) AS n
        FROM log_events
        WHERE NOT ignored AND template_id IS NOT NULL AND source_file = ?
        GROUP BY template_id, template
        ORDER BY n DESC
        """,
        [file_a],
    ).fetchall()

    # templates in B
    rows_b = con.execute(
        """
        SELECT template_id, template, count(*) AS n
        FROM log_events
        WHERE NOT ignored AND template_id IS NOT NULL AND source_file = ?
        GROUP BY template_id, template
        ORDER BY n DESC
        """,
        [file_b],
    ).fetchall()

    counts_a = {tid: (tmpl, n) for tid, tmpl, n in rows_a}
    counts_b = {tid: (tmpl, n) for tid, tmpl, n in rows_b}

    ids_a = set(counts_a)
    ids_b = set(counts_b)
    only_a = ids_a - ids_b
    only_b = ids_b - ids_a
    shared = ids_a & ids_b

    safe_a = stem_a.replace("/", "-").replace("\\", "-")
    safe_b = stem_b.replace("/", "-").replace("\\", "-")
    out = OUT_ON_DEMAND / f"compare-{safe_a}-vs-{safe_b}"
    with open(out, "w", encoding="utf-8") as f:
        f.write(f"File comparison\n")
        f.write(f"  A: {stem_a}\n")
        f.write(f"  B: {stem_b}\n")
        f.write("─" * 60 + "\n")

        f.write(f"\n── Shared ({len(shared)} templates) ──────────────────────\n")
        if not shared:
            f.write("  (none)\n")
        else:
            # sort shared by combined total descending
            shared_sorted = sorted(
                shared,
                key=lambda tid: counts_a[tid][1] + counts_b[tid][1],
                reverse=True,
            )
            for tid in shared_sorted:
                tmpl, na = counts_a[tid]
                _, nb = counts_b[tid]
                f.write(f"\n  #{tid}  {tmpl}\n")
                f.write(f"    A: {na:>6}   B: {nb:>6}   diff: {nb - na:+d}\n")

        f.write(f"\n── Only in A: {stem_a} ({len(only_a)} templates) ─────────\n")
        if not only_a:
            f.write("  (none)\n")
        else:
            for tid in sorted(only_a, key=lambda t: counts_a[t][1], reverse=True):
                tmpl, n = counts_a[tid]
                f.write(f"\n  #{tid}  x{n}  {tmpl}\n")

        f.write(f"\n── Only in B: {stem_b} ({len(only_b)} templates) ─────────\n")
        if not only_b:
            f.write("  (none)\n")
        else:
            for tid in sorted(only_b, key=lambda t: counts_b[t][1], reverse=True):
                tmpl, n = counts_b[tid]
                f.write(f"\n  #{tid}  x{n}  {tmpl}\n")

    print(f"  comparison         → {out}")


def q_template_trend(
    con: duckdb.DuckDBPyConnection,
    template_id: int,
    source_file: SourceFileArg = None,
) -> None:
    """
    Frequency of one template per file, ordered chronologically by each
    file's earliest timestamp. Shows whether a pattern is growing,
    shrinking, or stable across builds over time.

    Only meaningful with 2+ files; writes a note and returns early
    if only one file is in scope.
    """
    clause, params = source_file_clause(source_file)

    file_count = con.execute(
        f"SELECT count(DISTINCT source_file) FROM log_events WHERE 1=1 {clause}",
        params,
    ).fetchone()[0]

    # get the template string for the header
    tmpl_row = con.execute(
        "SELECT template FROM log_events WHERE template_id = ? AND template IS NOT NULL LIMIT 1",
        [template_id],
    ).fetchone()
    template_str = tmpl_row[0] if tmpl_row else "unknown"

    out = OUT_CROSS_FILE / f"trend-template-{template_id}"

    if file_count < 2:
        with open(out, "w", encoding="utf-8") as f:
            f.write(f"Template #{template_id} trend\n")
            f.write(f"Pattern: {template_str}\n")
            f.write("─" * 60 + "\n")
            f.write(f"  (only {file_count} file in scope — needs 2+ files to show a trend)\n")
        print(f"  trend template #{template_id:<5}  → {out}  (skipped: only {file_count} file)")
        return

    rows = con.execute(
        f"""
        SELECT source_file,
               min(timestamp) AS first_ts,
               count(*) AS n
        FROM log_events
        WHERE NOT ignored AND template_id = ? {clause}
        GROUP BY source_file
        ORDER BY first_ts ASC
        """,
        [template_id] + params,
    ).fetchall()

    # also get files in scope that had zero occurrences of this template
    all_files = con.execute(
        f"""
        SELECT source_file, min(timestamp) AS first_ts
        FROM log_events
        WHERE 1=1 {clause}
        GROUP BY source_file
        ORDER BY first_ts ASC
        """,
        params,
    ).fetchall()

    counts_by_file = {r[0]: (r[1], r[2]) for r in rows}

    with open(out, "w", encoding="utf-8") as f:
        f.write(f"Template #{template_id} trend across {file_count} files\n")
        f.write(f"Pattern: {template_str}\n")
        f.write("─" * 60 + "\n")
        for fpath, first_ts in all_files:
            fname = Path(fpath).name
            date_str = str(first_ts)[:10]
            if fpath in counts_by_file:
                _, n = counts_by_file[fpath]
                bar = "█" * min(n // 5, 40)
                f.write(f"  {date_str}  {fname:<40}  {n:>6}  {bar}\n")
            else:
                f.write(f"  {date_str}  {fname:<40}       0\n")
    print(f"  trend template #{template_id:<5}  → {out}")

def open_db(db_path: str) -> duckdb.DuckDBPyConnection:
    """Open (or create) the DuckDB database file and ensure the table exists."""
    con = duckdb.connect(db_path)
    con.execute(CREATE_TABLE_SQL)
    return con


def already_loaded(con: duckdb.DuckDBPyConnection, source_file: str) -> bool:
    """Return True if this source file has already been inserted."""
    count = con.execute(
        "SELECT count(*) FROM log_events WHERE source_file = ?",
        [source_file],
    ).fetchone()[0]
    return count > 0


def resolve_log_paths(inputs: list[str]) -> list[Path]:
    """
    Turn CLI arguments into a concrete, de-duplicated list of log file paths.

    Each argument may be:
      - a path to a single log file -> included directly
      - a path to a directory -> every *.log file inside it (non-recursive),
        sorted by filename so processing order is stable across runs

    Raises FileNotFoundError if an argument doesn't exist, so a typo'd path
    fails loudly instead of silently doing nothing.
    """
    resolved: list[Path] = []
    seen: set[Path] = set()

    for raw in inputs:
        p = Path(raw).resolve()
        if not p.exists():
            raise FileNotFoundError(f"No such file or directory: {raw}")

        if p.is_dir():
            matches = sorted(p.glob("*.log"))
            if not matches:
                print(f"  warning: no *.log files found in directory: {p}")
            for m in matches:
                if m not in seen:
                    resolved.append(m)
                    seen.add(m)
        else:
            if p not in seen:
                resolved.append(p)
                seen.add(p)

    return resolved


def drain_state_path_for(db_path: str) -> Path:
    """
    Derive the DRAIN3 persistence file from the --db path, so the state
    file always travels with its matching database: jenkins_logs.duckdb
    pairs with jenkins_logs.drain3.bin in the same directory.
    """
    db = Path(db_path)
    stem = db.name[: -len(db.suffix)] if db.suffix else db.name
    return db.with_name(f"{stem}.drain3.bin")


def load_rules(rules_path: Optional[str]) -> Optional[list[dict]]:
    """
    Load a rules JSON file for analyzer.py's RuleSet.from_list().

    Expected format — a JSON array of rule objects matching analyzer.Rule's
    fields, e.g.:

        [
          {"name": "suppress_noise", "action": "ignore",
           "logger_regex": "ContextHandler"},
          {"name": "tag_ssh_failures", "action": "tag",
           "logger_regex": "SSHLauncher", "tag": "ssh-failure"}
        ]

    Returns None if rules_path is None (no rules requested).
    Raises a clear error if the file is missing or malformed, rather than
    letting analyzer.py fail with a less obvious error deep in RuleSet.
    """
    if rules_path is None:
        return None

    path = Path(rules_path)
    if not path.exists():
        raise FileNotFoundError(f"Rules file not found: {path}")

    try:
        rules = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise ValueError(f"Rules file is not valid JSON: {path}\n  {e}")

    if not isinstance(rules, list):
        raise ValueError(
            f"Rules file must contain a JSON array of rule objects, got {type(rules).__name__}: {path}"
        )

    valid_actions = {"ignore", "tag", "set_level"}
    for i, rule in enumerate(rules):
        if not isinstance(rule, dict):
            raise ValueError(f"Rule #{i} is not an object: {rule!r}")
        if "name" not in rule:
            raise ValueError(f"Rule #{i} is missing required field 'name': {rule!r}")
        action = rule.get("action", "ignore")
        if action not in valid_actions:
            raise ValueError(
                f"Rule '{rule.get('name')}' has invalid action '{action}'. "
                f"Must be one of: {valid_actions}"
            )
        if action == "tag" and not rule.get("tag"):
            raise ValueError(f"Rule '{rule.get('name')}' has action='tag' but no 'tag' value")
        if action == "set_level" and not rule.get("set_level"):
            raise ValueError(f"Rule '{rule.get('name')}' has action='set_level' but no 'set_level' value")

    return rules


# --------------------------------------------------------------------------- #
# Entry point — defined after run_interactive_shell below
# --------------------------------------------------------------------------- #

SCHEMA_REMINDER = """
Columns on log_events:
  line_start, line_end       INTEGER    position in source file
  timestamp                  TIMESTAMPTZ
  level                      VARCHAR    INFO / WARNING / SEVERE
  thread_id, logger, method  VARCHAR
  message                    VARCHAR    clean message text (drain3 input)
  stack_trace                VARCHAR    exception lines, NULL if none
  template_id                INTEGER    drain3 cluster id
  template                   VARCHAR    drain3 template string
  tags                       VARCHAR    JSON array e.g. '["ssh-failure"]'
  ignored                    BOOLEAN
  source_file                VARCHAR    absolute path of the ingested log file

Dot commands:
  .schema              show this reference
  .files               list ingested files and row counts
  .counts              level breakdown across all loaded data
  .counts <filename>   level breakdown for one specific file (partial name ok)
  .compare <a> <b>     side-by-side template comparison between two files
  .quit                exit
"""


HELP_TEXT = """
Usage
─────
Type any SQL query ending with a semicolon and press Enter to run it.
Multi-line queries are fine — keep typing until you end a line with ;
and the shell will run everything accumulated so far.

  sql> SELECT level, count(*) AS n
  ...> FROM log_events
  ...> GROUP BY level;

Dot commands (no semicolon needed)
────────────────────────────────────
  .help                show this message
  .schema              show all column names and types on log_events
  .files               list loaded source files and their row counts
  .counts              level breakdown across all loaded data
  .counts <filename>   level breakdown for one file (partial name ok)
                       e.g.  .counts build_047
  .compare <a> <b>     side-by-side template comparison between two files
                       (partial names ok, must be unambiguous)
                       e.g.  .compare build_047 build_048
                       writes output file and prints path
  .quit                exit the shell  (also: .exit, Ctrl-D)

Common query patterns
──────────────────────
  -- top templates by frequency
  SELECT template_id, template, count(*) AS n
  FROM log_events
  WHERE NOT ignored AND template_id IS NOT NULL
  GROUP BY template_id, template
  ORDER BY n DESC LIMIT 10;

  -- all fatal events with first stack trace line
  SELECT timestamp, level, message, stack_trace
  FROM log_events
  WHERE level IN ('SEVERE', 'FATAL', 'ERROR')
  ORDER BY timestamp;

  -- everything in a time window (copy timestamp from .counts output)
  SELECT timestamp, level, message
  FROM log_events
  WHERE timestamp BETWEEN '2026-06-03 07:40:00+00' AND '2026-06-03 07:44:00+00'
  ORDER BY timestamp;

  -- spike detection: 5-minute windows with the most warnings
  SELECT time_bucket(INTERVAL 5 MINUTES, timestamp) AS bucket,
         count(*) AS n
  FROM log_events
  WHERE level = 'WARNING'
  GROUP BY bucket ORDER BY n DESC LIMIT 10;

  -- find which hosts appear in SSH failure messages
  SELECT regexp_extract(message, 'SSH Launch of ([^ ]+) on', 1) AS host,
         count(*) AS failures
  FROM log_events
  WHERE message LIKE '%SSH Launch of%failed%'
  GROUP BY host ORDER BY failures DESC;

  -- cross-file: which templates appear in multiple files?
  SELECT template_id, template, count(DISTINCT source_file) AS files, count(*) AS n
  FROM log_events
  WHERE NOT ignored AND template_id IS NOT NULL
  GROUP BY template_id, template
  HAVING count(DISTINCT source_file) > 1
  ORDER BY files DESC, n DESC LIMIT 10;

Notes
──────
  Long values are truncated to 80 chars in display; the full value is in the DB.
  Errors are caught and printed — the shell keeps running.
  All standard DuckDB SQL is supported, including JOINs, CTEs, window functions.
"""


def run_interactive_shell(con: duckdb.DuckDBPyConnection) -> None:
    """
    Simple REPL for typing SQL queries directly against the database.
    Multi-line queries are supported: keep typing until a line ends with ;
    then press Enter to run.
    """
    print("\n── Interactive SQL shell ─────────────────────────────────────")
    print("Type SQL ending with ; to run. .schema for columns. .quit to exit.\n")

    buffer: list[str] = []

    while True:
        prompt = "sql> " if not buffer else "...> "
        try:
            line = input(prompt)
        except (EOFError, KeyboardInterrupt):
            print()
            break

        stripped = line.strip()

        # dot-commands (only valid when buffer is empty)
        if not buffer and stripped.startswith("."):
            # split on whitespace to extract command and any arguments
            # use the original stripped (not lowercased) to preserve filename case
            parts = stripped.split()
            cmd = parts[0].lower()
            cmd_args = parts[1:]   # everything after the command word

            if cmd in (".quit", ".exit"):
                break
            elif cmd in (".help", ".h", "?"):
                print(HELP_TEXT)
            elif cmd == ".schema":
                print(SCHEMA_REMINDER)
            elif cmd == ".files":
                rows = con.execute(
                    "SELECT source_file, count(*) AS rows "
                    "FROM log_events GROUP BY source_file ORDER BY source_file"
                ).fetchall()
                if rows:
                    for path, n in rows:
                        print(f"  {n:>7} rows  {path}")
                else:
                    print("  (no files loaded)")

            elif cmd == ".counts":
                if not cmd_args:
                    # no argument — level breakdown across everything
                    rows = con.execute(
                        "SELECT level, count(*) AS n FROM log_events "
                        "WHERE NOT ignored GROUP BY level ORDER BY n DESC"
                    ).fetchall()
                    for level, n in rows:
                        print(f"  {level:<10} {n:>7}")
                else:
                    # argument is a partial filename — resolve it
                    pattern = cmd_args[0]
                    all_files = con.execute(
                        "SELECT DISTINCT source_file FROM log_events ORDER BY source_file"
                    ).fetchall()
                    matches = [r[0] for r in all_files if pattern in r[0]]
                    if len(matches) == 0:
                        print(f"  No loaded file matches '{pattern}'")
                        print(f"  Use .files to see available files")
                    elif len(matches) > 1:
                        print(f"  Ambiguous — '{pattern}' matches {len(matches)} files:")
                        for m in matches:
                            print(f"    {m}")
                        print(f"  Use a more specific name")
                    else:
                        matched = matches[0]
                        print(f"  {Path(matched).name}")
                        rows = con.execute(
                            "SELECT level, count(*) AS n FROM log_events "
                            "WHERE NOT ignored AND source_file = ? "
                            "GROUP BY level ORDER BY n DESC",
                            [matched],
                        ).fetchall()
                        for level, n in rows:
                            print(f"    {level:<10} {n:>7}")

            elif cmd == ".compare":
                if len(cmd_args) != 2:
                    print("  Usage: .compare <file_a> <file_b>")
                    print("  e.g.   .compare build_047 build_048")
                else:
                    pat_a, pat_b = cmd_args[0], cmd_args[1]
                    all_files = [
                        r[0] for r in con.execute(
                            "SELECT DISTINCT source_file FROM log_events ORDER BY source_file"
                        ).fetchall()
                    ]
                    matches_a = [f for f in all_files if pat_a in f]
                    matches_b = [f for f in all_files if pat_b in f]

                    error = False
                    if len(matches_a) == 0:
                        print(f"  No loaded file matches '{pat_a}'")
                        error = True
                    elif len(matches_a) > 1:
                        print(f"  Ambiguous — '{pat_a}' matches {len(matches_a)} files:")
                        for m in matches_a:
                            print(f"    {m}")
                        error = True
                    if len(matches_b) == 0:
                        print(f"  No loaded file matches '{pat_b}'")
                        error = True
                    elif len(matches_b) > 1:
                        print(f"  Ambiguous — '{pat_b}' matches {len(matches_b)} files:")
                        for m in matches_b:
                            print(f"    {m}")
                        error = True

                    if not error:
                        if matches_a[0] == matches_b[0]:
                            print("  Both patterns resolved to the same file — need two distinct files")
                        else:
                            q_file_comparison(con, matches_a[0], matches_b[0])

            else:
                print(f"  Unknown command: {stripped}  (type .help for usage)")
            continue

        # accumulate lines until the buffer ends with a semicolon
        buffer.append(line)
        full = " ".join(buffer).strip()
        if not full.endswith(";"):
            continue

        query = full[:-1].strip()
        buffer = []

        if not query:
            continue

        try:
            result = con.execute(query)

            if result.description:
                columns = [d[0] for d in result.description]
                rows = result.fetchall()

                if not rows:
                    print("  (no rows returned)\n")
                    continue

                # compute column widths, truncate long values
                widths = [len(c) for c in columns]
                str_rows = []
                for row in rows:
                    str_row = []
                    for i, val in enumerate(row):
                        s = "NULL" if val is None else str(val)
                        if len(s) > 80:
                            s = s[:77] + "..."
                        widths[i] = max(widths[i], len(s))
                        str_row.append(s)
                    str_rows.append(str_row)

                header  = "  " + "  ".join(c.ljust(widths[i]) for i, c in enumerate(columns))
                divider = "  " + "  ".join("-" * w for w in widths)
                print(header)
                print(divider)
                for str_row in str_rows:
                    print("  " + "  ".join(v.ljust(widths[i]) for i, v in enumerate(str_row)))
                print(f"\n  ({len(rows)} row{'s' if len(rows) != 1 else ''})\n")

            else:
                print("  OK\n")

        except Exception as e:
            print(f"  Error: {e}\n")

    print("Exiting shell.")


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

def main() -> None:
    parser = argparse.ArgumentParser(description="Store and query Jenkins logs with DuckDB")
    parser.add_argument(
        "log_files",
        nargs="+",
        help="One or more Jenkins .log files and/or directories containing .log files",
    )
    parser.add_argument(
        "--db",
        default="jenkins_logs.duckdb",
        help="DuckDB database file (default: jenkins_logs.duckdb)",
    )
    parser.add_argument(
        "--query-only",
        action="store_true",
        help="Skip parsing and insertion, just run preset queries against existing data",
    )
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="After loading, drop into an interactive SQL shell",
    )
    parser.add_argument(
        "--rules",
        metavar="PATH",
        help="Path to a JSON rules file (ignore/tag/set_level), applied during parsing. "
             "Only takes effect for files actually being parsed this run.",
    )
    args = parser.parse_args()

    try:
        rules = load_rules(args.rules)
    except (FileNotFoundError, ValueError) as e:
        parser.error(str(e))

    try:
        log_paths = resolve_log_paths(args.log_files)
    except FileNotFoundError as e:
        parser.error(str(e))

    if not log_paths:
        parser.error("No log files found from the given arguments.")

    state_path = drain_state_path_for(args.db)

    con = open_db(args.db)
    print(f"Database: {args.db}")
    print(f"DRAIN3 state: {state_path}")
    print(f"Found {len(log_paths)} log file(s) to consider:")
    for p in log_paths:
        print(f"  {p}")

    # ── Insertion (loop over every resolved file) ──────────────────────────── #
    inserted_any = False
    if not args.query_only:
        print()
        for log_path in log_paths:
            source_file = str(log_path)
            if already_loaded(con, source_file):
                print(f"Already loaded: {log_path.name} — skipping insertion")
                if rules:
                    print("  NOTE: --rules has no effect on already-loaded files.")
                continue

            print(f"Parsing: {log_path.name} ...")
            if rules:
                print(f"  applying rules from: {args.rules}")
            events = analyze(log_path, rules=rules, drain_state_path=state_path)
            print(f"  parsed {len(events)} events")
            n = insert_events(con, events, source_file)
            print(f"  inserted {n} rows into log_events")
            inserted_any = True
    elif rules:
        print("\nNOTE: --rules has no effect with --query-only (no parsing happens).")

    # source_file used by the query section below: None means "all loaded files"
    # unless exactly one file was given, in which case scope to just that file
    # for the same single-file behavior as before.
    source_file = str(log_paths[0]) if len(log_paths) == 1 else None

    # ── Preset queries (always run) ──────────────────────────────────────── #
    print(f"\nWriting query results")
    print(f"  scope: {source_file or f'all {len(log_paths)} files in this run'}")
    print(f"  output dir: {OUTPUT_DIR}/ (organized into subfolders)")

    q_level_counts(con, source_file)
    q_top_templates(con, n=10, source_file=source_file)
    q_fatal_events(con, source_file)
    q_stack_traces(con, source_file)

    # time filter — last 12 hours of data in the DB
    q_time_filter(con, lo=None, hi=None, source_file=source_file)

    # level filters — WARNING and SEVERE always worth having as separate files
    q_by_level(con, "WARNING", source_file)
    q_by_level(con, "SEVERE", source_file)

    # logger filter — top logger by event count among WARNING/SEVERE events
    top_logger = con.execute(
        """
        SELECT logger
        FROM log_events
        WHERE NOT ignored AND level IN ('WARNING', 'SEVERE') AND logger IS NOT NULL
        GROUP BY logger
        ORDER BY count(*) DESC
        LIMIT 1
        """
    ).fetchone()
    if top_logger:
        q_by_logger(con, top_logger[0], source_file)

    # template filter — top template by frequency
    top_template = con.execute(
        """
        SELECT template_id
        FROM log_events
        WHERE NOT ignored AND template_id IS NOT NULL
        GROUP BY template_id
        ORDER BY count(*) DESC
        LIMIT 1
        """
    ).fetchone()
    if top_template:
        q_by_template(con, top_template[0], source_file)

    # tags — summary always runs; per-tag files run for whatever tags exist
    q_tag_summary(con, source_file)

    distinct_tags_clause, distinct_tags_params = source_file_clause(source_file)
    distinct_tags_where = f"WHERE NOT ignored AND tags != '[]' {distinct_tags_clause}"

    tag_rows = con.execute(
        f"SELECT DISTINCT tags FROM log_events {distinct_tags_where}",
        distinct_tags_params,
    ).fetchall()

    seen_tags: set[str] = set()
    for (tags_raw,) in tag_rows:
        for t in json.loads(tags_raw):
            seen_tags.add(t)

    for tag in sorted(seen_tags):
        q_by_tag(con, tag, source_file)

    # ── Cross-file queries (always run; gracefully skip when only 1 file) ── #
    q_cross_file_templates(con, min_files=2, source_file=source_file)

    # template trend — reuse the top template already computed above
    if top_template:
        q_template_trend(con, top_template[0], source_file)

    con.close()
    if inserted_any:
        print(f"\nDone. Database saved to: {args.db}")
    else:
        print(f"\nDone. Queried: {args.db}")

    # ── Interactive shell ────────────────────────────────────────────────── #
    if args.interactive:
        con2 = open_db(args.db)
        run_interactive_shell(con2)
        con2.close()


if __name__ == "__main__":
    main()