"""DuckDB-backed store for Jenkins log events and drain3 templates.

analyzer.py uses drain3 with FilePersistence, so the same log pattern
gets the same template_id regardless of which file it's in. This module
just persists that to DuckDB so cross-file queries work.

    store = EventStore()
    ingest_file("jenkins.log", store)
    ingest_file("jenkins_log.crash", store)
    store.top_templates(20)
"""

from __future__ import annotations

import json
import warnings
from datetime import datetime
from pathlib import Path
from typing import Optional

import duckdb

from analyzer import (
    JenkinsLogParser,
    LogEvent,
    RuleSet,
    TemplateExtractor,
    DEFAULT_DRAIN_STATE,
    SCRIPT_DIR,
)

FATAL_LEVELS = {"SEVERE", "FATAL", "ERROR"}
DEFAULT_DB_PATH = SCRIPT_DIR / "jenkins_logs.duckdb"


class EventStore:
    def __init__(self, db_path: Path | str = DEFAULT_DB_PATH):
        self.db_path = Path(db_path)
        self.con = duckdb.connect(str(self.db_path))
        self._init_schema()

    def _init_schema(self) -> None:
        self.con.execute("""
            CREATE TABLE IF NOT EXISTS templates (
                template_id  INTEGER PRIMARY KEY,
                template     TEXT,
                cluster_size INTEGER,
                last_updated TIMESTAMP
            )
        """)
        self.con.execute("""
            CREATE TABLE IF NOT EXISTS events (
                source_file   TEXT,
                line_start    INTEGER,
                line_end      INTEGER,
                timestamp     TIMESTAMPTZ,
                timestamp_raw TEXT,
                thread_id     TEXT,
                level         TEXT,
                logger        TEXT,
                method        TEXT,
                message       TEXT,
                stack_trace   TEXT,
                template_id   INTEGER,
                tags          TEXT,
                ignored       BOOLEAN
            )
        """)

    def already_ingested(self, source_file: str) -> bool:
        count = self.con.execute(
            "SELECT COUNT(*) FROM events WHERE source_file = ?",
            [source_file],
        ).fetchone()[0]
        return count > 0

    def upsert_templates(self, miner) -> None:
        if miner is None:
            return
        now = datetime.utcnow()
        for cluster in miner.drain.id_to_cluster.values():
            template_str = " ".join(cluster.log_template_tokens)
            self.con.execute(
                """
                INSERT OR REPLACE INTO templates
                    (template_id, template, cluster_size, last_updated)
                VALUES (?, ?, ?, ?)
                """,
                [cluster.cluster_id, template_str, cluster.size, now],
            )

    def ingest(self, events: list[LogEvent], source_file: str, miner=None) -> int:
        if miner is not None:
            self.upsert_templates(miner)

        rows = [
            (
                source_file,
                e.line_start,
                e.line_end,
                e.timestamp,
                e.timestamp_raw,
                e.thread_id,
                e.level,
                e.logger,
                e.method,
                e.message,
                e.stack_trace,
                e.template_id,
                json.dumps(e.tags),
                e.ignored,
            )
            for e in events
        ]
        self.con.executemany(
            "INSERT INTO events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
        return len(rows)

    def top_templates(
        self, n: int = 20, source_file: Optional[str] = None, include_ignored: bool = False
    ) -> list[dict]:
        conditions = [] if include_ignored else ["e.ignored = false"]
        if source_file:
            conditions.append(f"e.source_file = '{source_file}'")
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

        rows = self.con.execute(f"""
            SELECT
                e.template_id,
                t.template,
                COUNT(*) AS count,
                COUNT(DISTINCT e.source_file) AS file_count
            FROM events e
            LEFT JOIN templates t ON e.template_id = t.template_id
            {where}
            GROUP BY e.template_id, t.template
            ORDER BY count DESC
            LIMIT {n}
        """).fetchall()

        return [
            {"rank": i + 1, "template_id": r[0], "template": r[1], "count": r[2], "file_count": r[3]}
            for i, r in enumerate(rows)
        ]

    def fatal_events(self, source_file: Optional[str] = None) -> list[dict]:
        levels = ", ".join(f"'{l}'" for l in FATAL_LEVELS)
        file_clause = f"AND source_file = '{source_file}'" if source_file else ""
        rows = self.con.execute(f"""
            SELECT source_file, line_start, timestamp, level, message
            FROM events
            WHERE level IN ({levels})
              AND ignored = false
              {file_clause}
            ORDER BY timestamp
        """).fetchall()
        return [
            {"source_file": r[0], "line_start": r[1], "timestamp": r[2], "level": r[3], "message": r[4]}
            for r in rows
        ]

    def level_counts(self, source_file: Optional[str] = None) -> dict[str, int]:
        file_clause = f"AND source_file = '{source_file}'" if source_file else ""
        rows = self.con.execute(f"""
            SELECT level, COUNT(*)
            FROM events
            WHERE ignored = false
              {file_clause}
            GROUP BY level
            ORDER BY COUNT(*) DESC
        """).fetchall()
        return {r[0]: r[1] for r in rows}

    def list_files(self) -> list[dict]:
        rows = self.con.execute("""
            SELECT
                source_file,
                COUNT(*) AS total_events,
                SUM(CASE WHEN ignored THEN 1 ELSE 0 END) AS ignored_events,
                MIN(timestamp) AS earliest,
                MAX(timestamp) AS latest
            FROM events
            GROUP BY source_file
            ORDER BY earliest
        """).fetchall()
        return [
            {"source_file": r[0], "total_events": r[1], "ignored_events": r[2], "earliest": r[3], "latest": r[4]}
            for r in rows
        ]

    def template_summary(self) -> list[dict]:
        rows = self.con.execute("""
            SELECT
                t.template_id,
                t.template,
                t.cluster_size,
                COUNT(e.template_id) AS total_events,
                COUNT(DISTINCT e.source_file) AS file_count
            FROM templates t
            LEFT JOIN events e ON t.template_id = e.template_id AND e.ignored = false
            GROUP BY t.template_id, t.template, t.cluster_size
            ORDER BY total_events DESC
        """).fetchall()
        return [
            {
                "template_id": r[0],
                "template": r[1],
                "cluster_size": r[2],
                "total_events": r[3],
                "file_count": r[4],
            }
            for r in rows
        ]

    def close(self) -> None:
        self.con.close()


def ingest_file(
    path: Path | str,
    store: EventStore,
    rules: Optional[list[dict]] = None,
    persistence_path: Optional[Path] = None,
    force: bool = False,
) -> list[LogEvent]:
    """Parse a file, assign drain3 templates, apply rules, write to the store.

    Skips files already in the store unless force=True. persistence_path
    overrides the drain3 snapshot location (defaults to drain3_state.bin).
    """
    source_file = str(Path(path).resolve())

    if not force and store.already_ingested(source_file):
        warnings.warn(f"{source_file!r} already in store, skipping (force=True to re-ingest)")
        return []

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()

    events = JenkinsLogParser().parse(text)

    extractor = TemplateExtractor(persistence_path=persistence_path)
    extractor.assign(events)

    if rules:
        RuleSet.from_list(rules).apply(events)

    n = store.ingest(events, source_file, miner=extractor.miner)
    print(f"ingested {n} events from {Path(path).name!r}")
    return events