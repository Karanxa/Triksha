"""
PostgreSQL database handler for Triksha.

Triksha recommends PostgreSQL as the robust, multi-user default — and it
doubles as the vector store via the `pgvector` extension (see VectorStore mixin).

DESIGN: PostgresDatabase subclasses RelationalDatabase and inherits ~160 standard
`%s`-parameterised queries UNCHANGED (psycopg2 shares the same placeholder).
Only the dialect boundary is swapped:

  * `_get_connection()`  → psycopg2 wrapped to mimic a dict-row cursor API
    (`.cursor()` → dict rows, `.commit()/.rollback()/.close()`, `cursor.lastrowid`).
  * Every statement passes through `translate_mysql_to_pg()` at the cursor layer,
    so the inherited MySQL-flavoured DDL/DML runs against Postgres — no duplicated
    schema in a second file.

Translations handled: AUTO_INCREMENT→SERIAL, LONGTEXT→TEXT, TINYINT(1)→SMALLINT,
ENGINE/CHARSET options stripped, inline KEY/INDEX → separate CREATE INDEX,
UNIQUE KEY → UNIQUE constraint, ON UPDATE CURRENT_TIMESTAMP stripped,
INSERT IGNORE → ON CONFLICT DO NOTHING, ON DUPLICATE KEY UPDATE → ON CONFLICT
DO UPDATE (with VALUES()→EXCLUDED and IF()→CASE), and RETURNING-id injection so
`cursor.lastrowid` keeps working.
"""
from __future__ import annotations

import os
import re
import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import psycopg2
import psycopg2.extras

from relational_database import RelationalDatabase

logger = logging.getLogger(__name__)


# ── SQL dialect translation ─────────────────────────────────────────────────
# Tables whose upserts (ON DUPLICATE KEY UPDATE) need an explicit conflict
# target in Postgres. Maps table → conflict column (its PK / unique key).
_UPSERT_CONFLICT_TARGET = {
    "prd_reviews": "review_id",
    "harden_jobs": "job_id",
    "skill_harden_jobs": "job_id",
    "jira_auto_harden_log": "ticket_key",
}

# MySQL `REPLACE INTO` → Postgres `INSERT ... ON CONFLICT (<key>) DO UPDATE`.
# Each table's natural key (the column REPLACE de-dupes on).
_REPLACE_CONFLICT_TARGET = {
    "scan_sessions": "scan_id",
    "agent_scans": "scan_id",
    "mcp_scans": "scan_id",
    "model_inventory": "model_id",
    "dataset_analyses": "analysis_id",
    "custom_agent_configs": "id",
    "model_configs": "model_name",
    "mcp_tools_inventory": "id",
    "manual_target_models": "id",
    "benchmark_results": "scan_id",
}


def _split_top_level_commas(s: str) -> List[str]:
    """Split on commas that are not nested inside parentheses."""
    parts, depth, cur = [], 0, []
    for ch in s:
        if ch == "(":
            depth += 1
            cur.append(ch)
        elif ch == ")":
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if cur:
        parts.append("".join(cur))
    return parts


def _translate_if(expr: str) -> str:
    """MySQL IF(cond, a, b) → Postgres CASE WHEN cond THEN a ELSE b END.

    Paren-aware, innermost-first so nested IFs translate correctly.
    """
    while True:
        m = re.search(r"(?<![A-Za-z0-9_])IF\s*\(", expr, re.IGNORECASE)
        if not m:
            return expr
        start = m.start()
        open_paren = expr.index("(", m.start())
        # find the matching close paren
        depth, i = 0, open_paren
        while i < len(expr):
            if expr[i] == "(":
                depth += 1
            elif expr[i] == ")":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        inner = expr[open_paren + 1:i]
        args = _split_top_level_commas(inner)
        if len(args) != 3:
            # not a 3-arg IF we understand; bail to avoid corrupting SQL
            return expr
        cond, a, b = (x.strip() for x in args)
        # recurse into branches in case of nested IFs
        replacement = f"CASE WHEN {cond} THEN {_translate_if(a)} ELSE {_translate_if(b)} END"
        expr = expr[:start] + replacement + expr[i + 1:]


def _balanced_call_args(text: str, open_paren: int):
    """Given index of '(' return (inner_str, index_of_matching_close)."""
    depth, i = 0, open_paren
    while i < len(text):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return text[open_paren + 1:i], i
        i += 1
    return text[open_paren + 1:], len(text) - 1


def _rewrite_calls(sql: str, fname: str, builder) -> str:
    """Rewrite every top-level FNAME(...) call (paren-aware) using builder(args)."""
    out = sql
    guard = 0
    while guard < 50:
        guard += 1
        m = re.search(rf"(?<![A-Za-z0-9_]){fname}\s*\(", out, re.IGNORECASE)
        if not m:
            break
        open_p = out.index("(", m.end() - 1)
        inner, close = _balanced_call_args(out, open_p)
        args = [a.strip() for a in _split_top_level_commas(inner)]
        out = out[:m.start()] + builder(args) + out[close + 1:]
    return out


def _json_path_to_pg(path_literal: str) -> str:
    """MySQL JSON path `$.a.b[0].c` → Postgres path-array literal `{a,b,0,c}`."""
    p = path_literal.strip().strip("'\"").lstrip("$").lstrip(".")
    p = re.sub(r"\[(\d+)\]", r".\1", p)  # array index [0] → .0
    parts = [x for x in p.split(".") if x != ""]
    return "{" + ",".join(parts) + "}"


def _translate_json_funcs(sql: str) -> str:
    """Translate MySQL JSON functions to Postgres jsonb equivalents.
    JSON_EXTRACT(col, '$.path') → (col::jsonb #>> '{path}')   [returns text]
    JSON_SET(col, '$.path', v)  → jsonb_set(col::jsonb, '{path}', to_jsonb(v::text))::text
    """
    if "json_extract" not in sql.lower() and "json_set" not in sql.lower():
        return sql
    sql = _rewrite_calls(
        sql, "JSON_EXTRACT",
        lambda a: f"({a[0]}::jsonb #>> '{_json_path_to_pg(a[1])}')",
    )
    sql = _rewrite_calls(
        sql, "JSON_SET",
        lambda a: f"jsonb_set({a[0]}::jsonb, '{_json_path_to_pg(a[1])}', to_jsonb(({a[2]})::text))::text",
    )
    # A json text extraction compared to a bare number would be `text <> integer`
    # (no such operator in PG) — quote the literal so it's a text comparison.
    sql = re.sub(r"(#>>\s*'[^']*'\))\s*(!=|<>|=)\s*(\d+)\b", r"\1 \2 '\3'", sql)
    return sql


def _translate_date_funcs(sql: str) -> str:
    """MySQL DATE_SUB/DATE_ADD(expr, INTERVAL n unit) → Postgres expr -/+ INTERVAL 'n unit'."""
    if "date_sub" not in sql.lower() and "date_add" not in sql.lower():
        return sql

    def _interval(arg: str) -> str:
        return re.sub(r"INTERVAL\s+(\d+)\s+(\w+)", r"INTERVAL '\1 \2'", arg, flags=re.IGNORECASE)

    sql = _rewrite_calls(sql, "DATE_SUB", lambda a: f"({a[0]} - {_interval(a[1])})")
    sql = _rewrite_calls(sql, "DATE_ADD", lambda a: f"({a[0]} + {_interval(a[1])})")
    return sql


def _qualify_existing_refs(update_clause: str, table: str, cols: List[str]) -> str:
    """In a Postgres ON CONFLICT DO UPDATE clause, qualify RHS references to the
    existing row's columns with the table name to avoid ambiguity with EXCLUDED.
    LHS assignment targets (the `col =` part) are left bare, as Postgres requires.
    """
    out = []
    for assignment in _split_top_level_commas(update_clause):
        if "=" not in assignment:
            out.append(assignment)
            continue
        lhs, rhs = assignment.split("=", 1)
        for col in cols:
            # qualify bare `col` not already preceded by `.` (EXCLUDED.col / tbl.col)
            # and not part of a longer identifier.
            rhs = re.sub(
                rf"(?<![\w.]){re.escape(col)}(?![\w.])",
                f"{table}.{col}", rhs,
            )
        out.append(f"{lhs}={rhs}")
    return ",".join(out)


def _translate_create_table(sql: str) -> List[str]:
    """Translate a MySQL CREATE TABLE into Postgres, returning the CREATE
    statement plus any separate CREATE INDEX statements for inline KEYs."""
    tbl_m = re.search(r"CREATE\s+TABLE\s+(IF\s+NOT\s+EXISTS\s+)?[\"`]?(\w+)[\"`]?", sql, re.IGNORECASE)
    table = tbl_m.group(2) if tbl_m else "tbl"

    # isolate the (column-definition, ...) block
    open_idx = sql.index("(")
    depth, i = 0, open_idx
    while i < len(sql):
        if sql[i] == "(":
            depth += 1
        elif sql[i] == ")":
            depth -= 1
            if depth == 0:
                break
        i += 1
    head = sql[:open_idx]
    body = sql[open_idx + 1:i]

    kept, extra_indexes = [], []
    for raw in _split_top_level_commas(body):
        item = raw.strip()
        if not item:
            continue
        low = item.lower()
        # UNIQUE KEY <name> (cols) → UNIQUE (cols)  (strip prefix lengths)
        um = re.match(r"unique\s+key\s+\w+\s*\((.*)\)$", item, re.IGNORECASE | re.DOTALL)
        if um:
            cols = re.sub(r"\(\s*\d+\s*\)", "", um.group(1))
            kept.append(f"UNIQUE ({cols.strip()})")
            continue
        # plain KEY/INDEX <name> (cols) → separate CREATE INDEX
        km = re.match(r"(?:key|index)\s+(\w+)\s*\((.*)\)$", item, re.IGNORECASE | re.DOTALL)
        if km:
            idx_name = f"{table}_{km.group(1)}"
            cols = re.sub(r"\(\s*\d+\s*\)", "", km.group(2)).strip()
            extra_indexes.append(
                f"CREATE INDEX IF NOT EXISTS {idx_name} ON {table} ({cols})"
            )
            continue
        # PRIMARY KEY / UNIQUE constraint lines pass through
        kept.append(item)

    create = head + "(\n  " + ",\n  ".join(kept) + "\n)"
    create = _translate_column_types(create)
    return [create] + extra_indexes


def _translate_column_types(sql: str) -> str:
    """Type/keyword + scalar-function translations applied to every statement."""
    sql = _translate_json_funcs(sql)
    sql = _translate_date_funcs(sql)
    sql = re.sub(r"\bBIGINT\s+AUTO_INCREMENT\b", "BIGSERIAL", sql, flags=re.IGNORECASE)
    sql = re.sub(r"\bINT\s+AUTO_INCREMENT\b", "SERIAL", sql, flags=re.IGNORECASE)
    sql = re.sub(r"\bAUTO_INCREMENT\b", "", sql, flags=re.IGNORECASE)
    sql = re.sub(r"\b(LONG|MEDIUM|TINY)TEXT\b", "TEXT", sql, flags=re.IGNORECASE)
    sql = re.sub(r"\bTINYINT\s*\(\s*\d+\s*\)", "SMALLINT", sql, flags=re.IGNORECASE)
    sql = re.sub(r"\bTINYINT\b", "SMALLINT", sql, flags=re.IGNORECASE)
    sql = re.sub(r"\bDATETIME\b", "TIMESTAMP", sql, flags=re.IGNORECASE)
    # MySQL auto-update timestamp has no inline Postgres equivalent
    sql = re.sub(r"\s+ON\s+UPDATE\s+CURRENT_TIMESTAMP", "", sql, flags=re.IGNORECASE)
    # `DEFAULT CURRENT_TIMESTAMP NULL` → `DEFAULT CURRENT_TIMESTAMP`
    sql = re.sub(r"(DEFAULT\s+CURRENT_TIMESTAMP)\s+NULL\b", r"\1", sql, flags=re.IGNORECASE)
    return sql


def translate_mysql_to_pg(sql: str) -> List[str]:
    """Translate one MySQL statement to one-or-more Postgres statements."""
    s = sql.strip()
    # strip MySQL table options wherever they appear
    s = re.sub(
        r"\)\s*ENGINE\s*=\s*\w+(\s+DEFAULT)?(\s+CHARSET\s*=\s*\w+)?(\s+COLLATE\s*=\s*\w+)?",
        ")", s, flags=re.IGNORECASE,
    )
    s = re.sub(r"`", "", s)  # backticks (defensive; none expected)

    if re.match(r"CREATE\s+TABLE", s, re.IGNORECASE):
        return _translate_create_table(s)

    # REPLACE INTO t (cols) VALUES (...) → INSERT ... ON CONFLICT (key) DO UPDATE
    rep = re.match(
        r"REPLACE\s+INTO\s+[\"`]?(\w+)[\"`]?\s*\((.*?)\)\s*VALUES\s*(.*)$",
        s, re.IGNORECASE | re.DOTALL,
    )
    if rep:
        table = rep.group(1)
        cols = [c.strip() for c in rep.group(2).split(",") if c.strip()]
        values_part = rep.group(3).strip().rstrip(";")
        key = _REPLACE_CONFLICT_TARGET.get(table.lower(), cols[0])
        set_cols = [c for c in cols if c.lower() != key.lower()]
        set_clause = ", ".join(f"{c}=EXCLUDED.{c}" for c in set_cols)
        s = (f"INSERT INTO {table} ({', '.join(cols)}) VALUES {values_part}\n"
             f"ON CONFLICT ({key}) DO UPDATE SET {set_clause}")
        return [_translate_column_types(s)]

    # INSERT IGNORE → INSERT ... ON CONFLICT DO NOTHING
    insert_ignore = bool(re.match(r"INSERT\s+IGNORE\s+INTO", s, re.IGNORECASE))
    if insert_ignore:
        s = re.sub(r"INSERT\s+IGNORE\s+INTO", "INSERT INTO", s, flags=re.IGNORECASE)

    # ON DUPLICATE KEY UPDATE → ON CONFLICT (target) DO UPDATE SET ...
    dup = re.search(r"ON\s+DUPLICATE\s+KEY\s+UPDATE\s+(.*)$", s, re.IGNORECASE | re.DOTALL)
    if dup:
        head = s[:dup.start()]
        update_clause = dup.group(1).strip().rstrip(";")
        tbl_m = re.search(r"INSERT\s+INTO\s+[\"`]?(\w+)", head, re.IGNORECASE)
        table = tbl_m.group(1).lower() if tbl_m else ""
        target = _UPSERT_CONFLICT_TARGET.get(table)
        update_clause = re.sub(r"VALUES\s*\(\s*(\w+)\s*\)", r"EXCLUDED.\1", update_clause, flags=re.IGNORECASE)
        update_clause = _translate_if(update_clause)
        # MySQL's bare column in ON DUPLICATE = the existing row; in Postgres
        # that's ambiguous against EXCLUDED, so qualify RHS refs with the table
        # name (e.g. `status` → `prd_reviews.status`). LHS SET targets stay bare.
        cols_m = re.search(r"INSERT\s+INTO\s+[\"`]?\w+[\"`]?\s*\((.*?)\)", head, re.IGNORECASE | re.DOTALL)
        if cols_m and table:
            insert_cols = [c.strip() for c in cols_m.group(1).split(",") if c.strip()]
            update_clause = _qualify_existing_refs(update_clause, table, insert_cols)
        if target:
            s = head.rstrip() + f"\nON CONFLICT ({target}) DO UPDATE SET " + update_clause
        else:
            s = head.rstrip() + "\nON CONFLICT DO NOTHING"
    elif insert_ignore:
        s = s.rstrip().rstrip(";") + " ON CONFLICT DO NOTHING"

    s = _translate_column_types(s)
    return [s]


def _coerce_params(params):
    """MySQL (pymysql) accepts Python bool for TINYINT(1) columns; in Postgres
    those columns are smallint and psycopg2 won't implicitly cast bool→smallint.
    Coerce bool params to int (0/1) so inherited inserts work unchanged."""
    if params is None:
        return None
    if isinstance(params, dict):
        return {k: (int(v) if isinstance(v, bool) else v) for k, v in params.items()}
    if isinstance(params, (list, tuple)):
        return type(params)(int(p) if isinstance(p, bool) else p for p in params)
    return params


def _wants_returning_id(stmts: List[str]) -> bool:
    """A single INSERT with no ON CONFLICT / RETURNING → inject RETURNING id
    so the inherited code's `cursor.lastrowid` keeps working."""
    if len(stmts) != 1:
        return False
    s = stmts[0].lstrip().lower()
    return s.startswith("insert into") and "on conflict" not in s and "returning" not in s


# ── pymysql-compatible psycopg2 wrappers ────────────────────────────────────
class _HybridRow(dict):
    """Dict row that also supports positional access (row[0]) so the rare
    `cursor.fetchone()[0]` call site keeps working under RealDictCursor."""

    def __getitem__(self, key):
        if isinstance(key, int):
            return list(self.values())[key]
        return super().__getitem__(key)


def _hybridise(row):
    if row is None:
        return None
    return _HybridRow(row)


class _PgCursor:
    """Wraps a psycopg2 RealDictCursor to look like pymysql's DictCursor and
    to translate MySQL SQL on the way in."""

    def __init__(self, conn_wrapper):
        self._cw = conn_wrapper
        self._cur = conn_wrapper._raw.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        self.lastrowid = None

    def execute(self, query: str, params=None):
        stmts = translate_mysql_to_pg(query)
        params = _coerce_params(params)
        inject = _wants_returning_id(stmts)
        if inject:
            stmts = [stmts[0].rstrip().rstrip(";") + " RETURNING id"]
        # In autocommit mode (used during schema init) each statement is
        # independent, so a caught failure can't poison later statements.
        for idx, stmt in enumerate(stmts):
            self._cur.execute(stmt, params if idx == 0 else None)
        if inject:
            try:
                row = self._cur.fetchone()
                if row:
                    self.lastrowid = row.get("id") if isinstance(row, dict) else row[0]
            except Exception:
                self.lastrowid = None
        return self

    def executemany(self, query: str, seq):
        stmts = translate_mysql_to_pg(query)
        self._cur.executemany(stmts[0], [_coerce_params(p) for p in seq])
        return self

    def fetchone(self):
        return _hybridise(self._cur.fetchone())

    def fetchall(self):
        return [_hybridise(r) for r in self._cur.fetchall()]

    def fetchmany(self, size=None):
        rows = self._cur.fetchmany(size) if size is not None else self._cur.fetchmany()
        return [_hybridise(r) for r in rows]

    @property
    def rowcount(self):
        return self._cur.rowcount

    @property
    def description(self):
        return self._cur.description

    def close(self):
        try:
            self._cur.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


class _PgConnection:
    """pymysql.Connection-compatible wrapper around a psycopg2 connection."""

    def __init__(self, raw):
        self._raw = raw

    def cursor(self, *a, **kw):
        return _PgCursor(self)

    def commit(self):
        self._raw.commit()

    def rollback(self):
        try:
            self._raw.rollback()
        except Exception:
            pass

    def close(self):
        try:
            self._raw.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, *a):
        if exc_type:
            self.rollback()
        else:
            self.commit()
        self.close()


# ── Vector store (pgvector) ─────────────────────────────────────────────────
class _VectorStoreMixin:
    """Optional semantic store backed by pgvector. Degrades gracefully (the
    extension/table are skipped) if pgvector isn't installed, so the relational
    side always works. Embeddings default to 384 dims (all-MiniLM-L6-v2)."""

    EMBED_DIM = int(os.getenv("EMBED_DIM", "384"))
    vector_enabled = False

    def _init_vector_store(self):
        try:
            conn = self._get_connection()
            cur = conn.cursor()
            cur.execute("CREATE EXTENSION IF NOT EXISTS vector")
            cur.execute(
                f"""
                CREATE TABLE IF NOT EXISTS embeddings (
                    id BIGSERIAL PRIMARY KEY,
                    namespace VARCHAR(100) NOT NULL,
                    ref_id VARCHAR(255) NOT NULL,
                    content TEXT,
                    metadata_json TEXT,
                    embedding vector({self.EMBED_DIM}),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE (namespace, ref_id)
                )
                """
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS embeddings_ns ON embeddings (namespace)"
            )
            # ivfflat ANN index (cosine). Safe to skip if too few rows yet.
            try:
                cur.execute(
                    "CREATE INDEX IF NOT EXISTS embeddings_vec ON embeddings "
                    "USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100)"
                )
            except Exception:
                conn.rollback()
            conn.commit()
            cur.close()
            conn.close()
            self.vector_enabled = True
            self.console.print("[green]✅ pgvector store initialised[/]")
        except Exception as e:  # pragma: no cover - depends on extension availability
            self.console.print(f"[yellow]⚠️  pgvector unavailable, semantic features disabled: {e}[/]")
            self.vector_enabled = False

    def upsert_embedding(self, namespace: str, ref_id: str, embedding: List[float],
                         content: str = "", metadata_json: str = "") -> bool:
        if not self.vector_enabled:
            return False
        try:
            conn = self._get_connection()
            cur = conn.cursor()
            vec = "[" + ",".join(str(float(x)) for x in embedding) + "]"
            cur._cur.execute(
                """
                INSERT INTO embeddings (namespace, ref_id, content, metadata_json, embedding)
                VALUES (%s, %s, %s, %s, %s::vector)
                ON CONFLICT (namespace, ref_id) DO UPDATE SET
                    content = EXCLUDED.content,
                    metadata_json = EXCLUDED.metadata_json,
                    embedding = EXCLUDED.embedding
                """,
                (namespace, ref_id, content, metadata_json, vec),
            )
            conn.commit()
            cur.close()
            conn.close()
            return True
        except Exception as e:
            logger.warning("upsert_embedding failed: %s", e)
            return False

    def search_embeddings(self, namespace: str, query_embedding: List[float],
                          k: int = 5) -> List[Dict[str, Any]]:
        """Cosine nearest-neighbour search within a namespace."""
        if not self.vector_enabled:
            return []
        try:
            conn = self._get_connection()
            cur = conn.cursor()
            vec = "[" + ",".join(str(float(x)) for x in query_embedding) + "]"
            cur._cur.execute(
                """
                SELECT ref_id, content, metadata_json,
                       1 - (embedding <=> %s::vector) AS similarity
                FROM embeddings
                WHERE namespace = %s
                ORDER BY embedding <=> %s::vector
                LIMIT %s
                """,
                (vec, namespace, vec, k),
            )
            rows = [dict(r) for r in cur.fetchall()]
            cur.close()
            conn.close()
            return rows
        except Exception as e:
            logger.warning("search_embeddings failed: %s", e)
            return []


# ── Handler ──────────────────────────────────────────────────────────────────
class PostgresDatabase(_VectorStoreMixin, RelationalDatabase):
    """PostgreSQL handler. Inherits query logic from RelationalDatabase."""

    def __init__(self, database_url: Optional[str] = None):
        from rich.console import Console
        self.console = Console()
        self._dsn = self._resolve_dsn(database_url)
        self._autocommit_init = False
        masked = re.sub(r":[^:@/]+@", ":****@", self._dsn)
        self.console.print(f"[green]PostgreSQL Database: {masked}[/]")
        self._test_connection()
        self._init_database()

    def _resolve_dsn(self, database_url: Optional[str]) -> str:
        url = database_url or os.getenv("DATABASE_URL", "")
        if url.startswith("postgres://") or url.startswith("postgresql://"):
            return url
        # build from individual vars
        host = os.getenv("DB_HOST", "localhost")
        port = os.getenv("DB_PORT", "5432")
        user = os.getenv("DB_USER", "postgres")
        pwd = os.getenv("DB_PASSWORD", "")
        name = os.getenv("DB_NAME", "triksha")
        return f"postgresql://{user}:{pwd}@{host}:{port}/{name}"

    def _get_connection(self):
        raw = psycopg2.connect(self._dsn)
        # During schema init use autocommit so an expected failure (e.g. a
        # migration ALTER on a column that already exists) doesn't poison the
        # transaction — matching MySQL's forgiving behaviour.
        raw.autocommit = bool(getattr(self, "_autocommit_init", False))
        return _PgConnection(raw)

    def _test_connection(self):
        try:
            conn = self._get_connection()
            conn.close()
            self.console.print("[green]✅ PostgreSQL connection successful[/]")
        except Exception as e:
            self.console.print(f"[red]❌ PostgreSQL connection failed: {e}[/]")
            raise

    def _init_database(self):
        # Run the inherited MySQL DDL through the translator with autocommit so
        # idempotent CREATE/ALTER statements are independent, then set up vectors.
        self._autocommit_init = True
        try:
            super()._init_database()
            self._init_vector_store()
        finally:
            self._autocommit_init = False
