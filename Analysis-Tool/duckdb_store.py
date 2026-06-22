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
from typing import Optional

import duckdb

# Import from analyzer without touching it
from analyzer import analyze, active, LogEvent, parse_timestamp, TimeLike

# Output directory for preset query results — sits next to this script
SCRIPT_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = SCRIPT_DIR / "duckdb_output"
OUTPUT_DIR.mkdir(exist_ok=True)

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

def q_level_counts(con: duckdb.DuckDBPyConnection, source_file: Optional[str] = None) -> None:
    """Count of active events grouped by log level."""
    where = "WHERE NOT ignored"
    params = []
    if source_file:
        where += " AND source_file = ?"
        params.append(source_file)

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

    out = OUTPUT_DIR / "level-counts"
    with open(out, "w", encoding="utf-8") as f:
        f.write("Level counts\n")
        f.write("─" * 30 + "\n")
        for level, n in rows:
            f.write(f"  {level:<10} {n:>7}\n")
    print(f"  level counts      → {out}")


def q_top_templates(
    con: duckdb.DuckDBPyConnection,
    n: int = 10,
    source_file: Optional[str] = None,
) -> None:
    """Most frequent DRAIN3 templates across active, non-null-template events."""
    where = "WHERE NOT ignored AND template_id IS NOT NULL"
    params = []
    if source_file:
        where += " AND source_file = ?"
        params.append(source_file)

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

    out = OUTPUT_DIR / f"top-{n}-templates"
    with open(out, "w", encoding="utf-8") as f:
        f.write(f"Top {n} templates by frequency\n")
        f.write("─" * 60 + "\n")
        for i, (tid, tmpl, count) in enumerate(rows, 1):
            f.write(f"  [{i:>2}] #{tid:<4} x{count:<6}  {tmpl}\n")
    print(f"  top {n} templates    → {out}")


def q_fatal_events(
    con: duckdb.DuckDBPyConnection,
    source_file: Optional[str] = None,
) -> None:
    """All SEVERE / FATAL / ERROR events that aren't ignored."""
    where = "WHERE NOT ignored AND level IN ('SEVERE', 'FATAL', 'ERROR')"
    params = []
    if source_file:
        where += " AND source_file = ?"
        params.append(source_file)

    rows = con.execute(
        f"""
        SELECT line_start, timestamp, level, message, stack_trace
        FROM log_events
        {where}
        ORDER BY timestamp
        """,
        params,
    ).fetchall()

    out = OUTPUT_DIR / "fatal-events"
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


def q_in_window(
    con: duckdb.DuckDBPyConnection,
    center: TimeLike,
    before: timedelta,
    after: timedelta,
    source_file: Optional[str] = None,
) -> None:
    """
    Events within [center - before, center + after].
    center may be a datetime or a raw Jenkins timestamp string.
    """
    center_dt = parse_timestamp(center)
    lo = center_dt - before
    hi = center_dt + after

    where = "WHERE timestamp BETWEEN ? AND ?"
    params: list = [lo, hi]
    if source_file:
        where += " AND source_file = ?"
        params.append(source_file)

    rows = con.execute(
        f"""
        SELECT line_start, timestamp, level, message
        FROM log_events
        {where}
        ORDER BY timestamp
        """,
        params,
    ).fetchall()

    out = OUTPUT_DIR / f"window-{str(center_dt).replace(' ', 'T').replace(':', '-')}"
    with open(out, "w", encoding="utf-8") as f:
        f.write(f"Time window: {lo}  →  {hi}\n")
        f.write("─" * 60 + "\n")
        if not rows:
            f.write("  (no events in this window)\n")
        else:
            for line, ts, level, msg in rows:
                f.write(f"  line {line:<7} {ts}  [{level:<8}]  {msg}\n")
            f.write(f"\n  ({len(rows)} events total in window)\n")
    print(f"  time window        → {out}")


def q_stack_traces(
    con: duckdb.DuckDBPyConnection,
    source_file: Optional[str] = None,
) -> None:
    """Events that have a stack trace — most useful to hand to an LLM."""
    where = "WHERE NOT ignored AND stack_trace IS NOT NULL"
    params = []
    if source_file:
        where += " AND source_file = ?"
        params.append(source_file)

    rows = con.execute(
        f"""
        SELECT line_start, timestamp, level, message, stack_trace
        FROM log_events
        {where}
        ORDER BY timestamp
        """,
        params,
    ).fetchall()

    out = OUTPUT_DIR / "stack-traces"
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


# --------------------------------------------------------------------------- #
# Setup helpers
# --------------------------------------------------------------------------- #

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
  .schema     show this reference
  .files      list ingested files and row counts
  .counts     level breakdown across all loaded data
  .quit       exit
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
  .help      show this message
  .schema    show all column names and types on log_events
  .files     list loaded source files and their row counts
  .counts    level breakdown (INFO / WARNING / SEVERE) across all data
  .quit      exit the shell  (also: .exit, Ctrl-D)

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
    print("Type SQL ending with ; to run. .schema for columns. .help for help. .quit to exit.\n")

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
            cmd = stripped.lower()
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
                rows = con.execute(
                    "SELECT level, count(*) AS n FROM log_events "
                    "WHERE NOT ignored GROUP BY level ORDER BY n DESC"
                ).fetchall()
                for level, n in rows:
                    print(f"  {level:<10} {n:>7}")
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
    parser.add_argument("log_file", help="Path to a Jenkins .log file")
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
    args = parser.parse_args()

    log_path = Path(args.log_file).resolve()
    source_file = str(log_path)

    con = open_db(args.db)
    print(f"Database: {args.db}")

    # ── Insertion ────────────────────────────────────────────────────────── #
    inserted = False
    if not args.query_only:
        if already_loaded(con, source_file):
            print(f"Already loaded: {log_path.name} — skipping insertion")
            print("  (pass --query-only to just run queries, or use a fresh DB)")
        else:
            print(f"Parsing: {log_path.name} ...")
            events = analyze(log_path)
            print(f"  parsed {len(events)} events")
            n = insert_events(con, events, source_file)
            print(f"  inserted {n} rows into log_events")
            inserted = True

    # ── Preset queries ───────────────────────────────────────────────────── #
    print(f"\nWriting query results for: {log_path.name}")
    print(f"  output dir: {OUTPUT_DIR}")
    q_level_counts(con, source_file)
    q_top_templates(con, n=10, source_file=source_file)
    q_fatal_events(con, source_file)
    q_stack_traces(con, source_file)
    q_in_window(
        con,
        center="2026-06-03 07:42:13.198+0000",
        before=timedelta(minutes=10),
        after=timedelta(minutes=5),
        source_file=source_file,
    )

    con.close()
    if inserted:
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