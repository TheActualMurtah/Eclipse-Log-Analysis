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


def q_time_filter(
    con: duckdb.DuckDBPyConnection,
    lo: Optional[str] = None,
    hi: Optional[str] = None,
    source_file: Optional[str] = None,
) -> None:
    """
    Events in a time range.

    lo / hi are ISO or Jenkins timestamp strings.
    If neither is given, defaults to the last 12 hours of data in the DB.
    If only lo is given, returns everything from lo onward.
    If only hi is given, returns everything up to hi.
    """
    # ── resolve lo/hi against actual data range if not supplied ─────────── #
    data_min, data_max = con.execute(
        "SELECT min(timestamp), max(timestamp) FROM log_events"
    ).fetchone()

    if lo is None and hi is None:
        # default: last 12 hours of whatever is in the database
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

    where  = "WHERE NOT ignored AND timestamp BETWEEN ? AND ?"
    params: list = [lo_dt, hi_dt]
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

    out = OUTPUT_DIR / f"time-filter-{label}"
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
    source_file: Optional[str] = None,
) -> None:
    """
    Every active event at the given log level.
    level should be one of: INFO, WARNING, SEVERE, ERROR, FATAL.
    """
    level_upper = level.upper()

    where  = "WHERE NOT ignored AND level = ?"
    params: list = [level_upper]
    if source_file:
        where += " AND source_file = ?"
        params.append(source_file)

    rows = con.execute(
        f"""
        SELECT line_start, timestamp, level, logger, message, stack_trace
        FROM log_events
        {where}
        ORDER BY timestamp
        """,
        params,
    ).fetchall()

    out = OUTPUT_DIR / f"level-{level_upper}"
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
    source_file: Optional[str] = None,
) -> None:
    """
    Every active event whose logger contains logger_pattern (case-insensitive).
    e.g. logger_pattern="SSHLauncher" matches h.plugins.sshslaves.SSHLauncher
    """
    where  = "WHERE NOT ignored AND lower(logger) LIKE lower(?)"
    params: list = [f"%{logger_pattern}%"]
    if source_file:
        where += " AND source_file = ?"
        params.append(source_file)

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
    out = OUTPUT_DIR / f"logger-{safe_pattern}"
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
    source_file: Optional[str] = None,
) -> None:
    """
    Every active event belonging to a given DRAIN3 template cluster.
    Use q_top_templates first to find the template_id you want.
    """
    where  = "WHERE NOT ignored AND template_id = ?"
    params: list = [template_id]
    if source_file:
        where += " AND source_file = ?"
        params.append(source_file)

    rows = con.execute(
        f"""
        SELECT line_start, timestamp, level, message, stack_trace, template
        FROM log_events
        {where}
        ORDER BY timestamp
        """,
        params,
    ).fetchall()

    template_str = rows[0][5] if rows else "unknown"

    out = OUTPUT_DIR / f"template-{template_id}"
    with open(out, "w", encoding="utf-8") as f:
        f.write(f"Template #{template_id} — {len(rows)} occurrences\n")
        f.write(f"Pattern: {template_str}\n")
        f.write("─" * 60 + "\n")
        if not rows:
            f.write("  (none)\n")
        else:
            for line, ts, level, msg, stack, tmpl in rows:
                f.write(f"\n  line {line} at {ts}  [{level}]\n")
                f.write(f"  message: {msg}\n")
                if stack:
                    for stack_line in stack.splitlines():
                        f.write(f"    {stack_line}\n")
    print(f"  template #{template_id:<5}       → {out}")


def q_by_tag(
    con: duckdb.DuckDBPyConnection,
    tag: str,
    source_file: Optional[str] = None,
) -> None:
    """
    Every active event carrying the given tag.
    Tags are populated by RuleSet during analyze() and stored as a JSON
    array string, e.g. '["ssh-failure"]' — this does a substring match
    on that string, which is safe because tag names don't contain quotes.
    """
    where  = "WHERE NOT ignored AND tags LIKE ?"
    params: list = [f'%"{tag}"%']
    if source_file:
        where += " AND source_file = ?"
        params.append(source_file)

    rows = con.execute(
        f"""
        SELECT line_start, timestamp, level, logger, message, stack_trace, tags
        FROM log_events
        {where}
        ORDER BY timestamp
        """,
        params,
    ).fetchall()

    out = OUTPUT_DIR / f"tag-{tag}"
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
    source_file: Optional[str] = None,
) -> None:
    """
    Breakdown of how many events carry each tag.
    Useful as a quick check that rules actually did something.
    """
    where = "WHERE NOT ignored AND tags != '[]'"
    params = []
    if source_file:
        where += " AND source_file = ?"
        params.append(source_file)

    rows = con.execute(
        f"SELECT tags, count(*) AS n FROM log_events {where} GROUP BY tags ORDER BY n DESC",
        params,
    ).fetchall()

    # also report ignored count, since suppression doesn't show up as a tag
    ignored_where = "WHERE ignored"
    ignored_params = []
    if source_file:
        ignored_where += " AND source_file = ?"
        ignored_params.append(source_file)
    ignored_count = con.execute(
        f"SELECT count(*) FROM log_events {ignored_where}", ignored_params
    ).fetchone()[0]

    out = OUTPUT_DIR / "tag-summary"
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
    parser.add_argument(
        "--rules",
        metavar="PATH",
        help="Path to a JSON rules file (ignore/tag/set_level), applied during parsing. "
             "Only takes effect when the file is actually being parsed — i.e. not "
             "already loaded and not --query-only.",
    )
    args = parser.parse_args()

    log_path = Path(args.log_file).resolve()
    source_file = str(log_path)

    try:
        rules = load_rules(args.rules)
    except (FileNotFoundError, ValueError) as e:
        parser.error(str(e))

    con = open_db(args.db)
    print(f"Database: {args.db}")

    # ── Insertion ────────────────────────────────────────────────────────── #
    inserted = False
    if not args.query_only:
        if already_loaded(con, source_file):
            print(f"Already loaded: {log_path.name} — skipping insertion")
            print("  (pass --query-only to just run queries, or use a fresh DB)")
            if rules:
                print("  NOTE: --rules was given but this file is already loaded.")
                print("        Rules only apply at parse time. To re-apply rules,")
                print("        use a fresh --db, or delete this file's rows first.")
        else:
            print(f"Parsing: {log_path.name} ...")
            if rules:
                print(f"  applying rules from: {args.rules}")
            events = analyze(log_path, rules=rules)
            print(f"  parsed {len(events)} events")
            n = insert_events(con, events, source_file)
            print(f"  inserted {n} rows into log_events")
            inserted = True
    elif rules:
        print("  NOTE: --rules has no effect with --query-only (no parsing happens).")

    # ── Preset queries (always run) ──────────────────────────────────────── #
    print(f"\nWriting query results for: {log_path.name}")
    print(f"  output dir: {OUTPUT_DIR}")

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

    distinct_tags_where = "WHERE NOT ignored AND tags != '[]'"
    distinct_tags_params = []
    if source_file:
        distinct_tags_where += " AND source_file = ?"
        distinct_tags_params.append(source_file)

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