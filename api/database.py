"""
Standalone database handler for the API.
"""

import json
import sqlite3
import uuid
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from functools import lru_cache
from rich.console import Console

# Simple in-memory cache for scan results (speeds up repeated access)
_scan_results_cache: Dict[str, Dict[str, Any]] = {}
_CACHE_MAX_SIZE = 50  # Keep last 50 scan results in memory

# Cache for model inventory (list and individual models)
_model_inventory_list_cache: Optional[List[Dict[str, Any]]] = None
_model_inventory_cache: Dict[str, Dict[str, Any]] = {}
_MODEL_CACHE_MAX_SIZE = 100  # Keep up to 100 models in memory


def safe_json_dumps(obj, **kwargs):
    """Safely serialize objects to JSON, handling Pydantic types and other non-serializable objects"""
    def default(o):
        # Handle Pydantic v2 models
        if hasattr(o, 'model_dump'):
            return o.model_dump()
        # Handle Pydantic v1 models
        elif hasattr(o, 'dict'):
            return o.dict()
        # Handle Pydantic AnyUrl and other URL types
        elif hasattr(o, '__str__') and 'pydantic' in str(type(o).__module__):
            return str(o)
        # Handle other objects with __dict__
        elif hasattr(o, '__dict__'):
            return o.__dict__
        # Fallback to string
        else:
            return str(o)
    return json.dumps(obj, default=default, **kwargs)


class APIDatabase:
    """Standalone database handler for the API"""
    
    def __init__(self, db_path: Optional[str] = None):
        """Initialize the database"""
        self.console = Console()
        
        # Set up database path
        if db_path:
            self.db_path = Path(db_path)
        else:
            # Check for DATABASE_URL environment variable first
            import os
            database_url = os.getenv("DATABASE_URL")
            if database_url and database_url.startswith("sqlite:///"):
                # Extract path from sqlite:///path/to/db
                db_file_path = database_url.replace("sqlite:///", "")
                self.db_path = Path(db_file_path)
                # Ensure directory exists
                self.db_path.parent.mkdir(parents=True, exist_ok=True)
            else:
                # Fallback to home directory
                db_dir = Path.home() / "triksha" / "api_data"
                db_dir.mkdir(parents=True, exist_ok=True)
                self.db_path = db_dir / "triksha.db"
        
        self.console.print(f"[green]Database path: {self.db_path}[/]")
        
        # Initialize database
        self._init_database()
    
    def _init_database(self):
        """Initialize database tables"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Robustness: enable WAL so concurrent scans don't hit
                # "database is locked". journal_mode=WAL is a PERSISTENT,
                # database-level setting — set once here, it applies to every
                # subsequent connection across the app. synchronous=NORMAL is
                # the safe+fast pairing with WAL; busy_timeout makes writers
                # wait (5s) instead of erroring under contention.
                try:
                    cursor.execute("PRAGMA journal_mode=WAL")
                    cursor.execute("PRAGMA synchronous=NORMAL")
                    cursor.execute("PRAGMA busy_timeout=5000")
                    cursor.execute("PRAGMA foreign_keys=ON")
                except sqlite3.OperationalError:
                    pass

                # Benchmark results table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS benchmark_results (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id TEXT UNIQUE NOT NULL,
                        scan_name TEXT NOT NULL,
                        status TEXT NOT NULL,
                        results_json TEXT,
                        metadata_json TEXT,
                        created_by TEXT DEFAULT 'anonymous',
                        reference_id TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Migration: Add created_by column if it doesn't exist
                try:
                    cursor.execute("ALTER TABLE benchmark_results ADD COLUMN created_by TEXT DEFAULT 'anonymous'")
                except sqlite3.OperationalError:
                    # Column already exists, ignore the error
                    pass
                
                # Migration: Add github_url column to agents_inventory if it doesn't exist
                try:
                    cursor.execute("ALTER TABLE agents_inventory ADD COLUMN github_url TEXT")
                except sqlite3.OperationalError:
                    # Column already exists or table doesn't exist yet, ignore the error
                    pass
                
                # Migration: Add reference_id column if it doesn't exist
                try:
                    cursor.execute("ALTER TABLE benchmark_results ADD COLUMN reference_id TEXT")
                except sqlite3.OperationalError:
                    # Column already exists, ignore the error
                    pass
                
                # MCP scans table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS mcp_scans (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id TEXT UNIQUE NOT NULL,
                        file_name TEXT NOT NULL,
                        status TEXT NOT NULL,
                        config_content TEXT,
                        results_json TEXT,
                        message TEXT,
                        created_by TEXT DEFAULT 'anonymous',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        completed_at TIMESTAMP,
                        timeout INTEGER DEFAULT 30
                    )
                """)
                
                # Migration: Add scan_name column to mcp_scans if it doesn't exist
                try:
                    cursor.execute("ALTER TABLE mcp_scans ADD COLUMN scan_name TEXT")
                except sqlite3.OperationalError:
                    # Column already exists, ignore the error
                    pass
                
                # Migration: Add reference_id column to mcp_scans if it doesn't exist
                try:
                    cursor.execute("ALTER TABLE mcp_scans ADD COLUMN reference_id TEXT")
                except sqlite3.OperationalError:
                    # Column already exists, ignore the error
                    pass
                
                # MCP entity tracking table (for poisoning detection)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS mcp_entities (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        server_name TEXT NOT NULL,
                        entity_name TEXT NOT NULL,
                        entity_type TEXT NOT NULL,
                        description_hash TEXT NOT NULL,
                        description TEXT,
                        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        scan_id TEXT,
                        UNIQUE(server_name, entity_name, entity_type)
                    )
                """)
                
                # MCP security findings table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS mcp_security_findings (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id TEXT NOT NULL,
                        server_name TEXT NOT NULL,
                        entity_name TEXT NOT NULL,
                        entity_type TEXT NOT NULL,
                        detector_type TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        finding_details TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (scan_id) REFERENCES mcp_scans(scan_id)
                    )
                """)

                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS mcp_security_reviews (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        repo_full_name TEXT NOT NULL,
                        repo_url TEXT,
                        status TEXT DEFAULT 'pending',
                        critical_count INTEGER DEFAULT 0,
                        high_count INTEGER DEFAULT 0,
                        medium_count INTEGER DEFAULT 0,
                        low_count INTEGER DEFAULT 0,
                        vulnerabilities TEXT,
                        summary TEXT,
                        risk_score INTEGER DEFAULT 0,
                        triggered_by TEXT DEFAULT 'api',
                        error TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # MCP active scan results table (for client simulation / Triksha Agent findings)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS mcp_active_scan_results (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id TEXT NOT NULL,
                        tool_name TEXT NOT NULL,
                        attack_type TEXT,
                        payload TEXT,
                        response TEXT,
                        vulnerability_found BOOLEAN DEFAULT 0,
                        vulnerability_type TEXT,
                        severity TEXT,
                        details TEXT,
                        recommendation TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (scan_id) REFERENCES mcp_scans(scan_id)
                    )
                """)
                
                # MCP inventory table (for tracking scanned MCPs and detecting changes)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS mcp_inventory (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        server_name TEXT NOT NULL,
                        server_config_hash TEXT NOT NULL UNIQUE,
                        server_url TEXT,
                        server_type TEXT,
                        server_config_json TEXT,
                        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_scan_id TEXT,
                        previous_hash TEXT,
                        change_detected BOOLEAN DEFAULT 0,
                        scan_count INTEGER DEFAULT 1,
                        UNIQUE(server_config_hash)
                    )
                """)
                
                # Create index for faster lookups
                try:
                    cursor.execute("CREATE INDEX IF NOT EXISTS idx_mcp_inventory_hash ON mcp_inventory(server_config_hash)")
                    cursor.execute("CREATE INDEX IF NOT EXISTS idx_mcp_inventory_name ON mcp_inventory(server_name)")
                except sqlite3.OperationalError:
                    pass
                
                # Dataset poisoning analyses table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS dataset_analyses (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        analysis_id TEXT UNIQUE NOT NULL,
                        file_name TEXT NOT NULL,
                        status TEXT NOT NULL,
                        file_size INTEGER,
                        results_json TEXT,
                        is_poisoned BOOLEAN,
                        security_score INTEGER,
                        total_entries INTEGER,
                        suspicious_entries INTEGER,
                        message TEXT,
                        created_by TEXT DEFAULT 'anonymous',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        completed_at TIMESTAMP
                    )
                """)
                
                # Migration: Add scan_name column if it doesn't exist
                try:
                    cursor.execute("ALTER TABLE dataset_analyses ADD COLUMN scan_name TEXT")
                except sqlite3.OperationalError:
                    # Column already exists, ignore the error
                    pass
                
                # Agents inventory table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS agents_inventory (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        discovery_id TEXT NOT NULL,
                        repo_url TEXT NOT NULL,
                        repo_name TEXT,
                        branch TEXT DEFAULT 'main',
                        agent_name TEXT NOT NULL,
                        file_path TEXT NOT NULL,
                        github_url TEXT,
                        framework TEXT NOT NULL,
                        description TEXT,
                        capabilities_json TEXT,
                        tools_used_json TEXT,
                        llm_provider TEXT,
                        security_concerns_json TEXT,
                        code_snippet TEXT,
                        discovered_by TEXT DEFAULT 'anonymous',
                        discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(repo_url, file_path, agent_name)
                    )
                """)
                
                # Create indexes for agents inventory
                try:
                    cursor.execute("CREATE INDEX IF NOT EXISTS idx_agents_repo ON agents_inventory(repo_url)")
                    cursor.execute("CREATE INDEX IF NOT EXISTS idx_agents_framework ON agents_inventory(framework)")
                    cursor.execute("CREATE INDEX IF NOT EXISTS idx_agents_discovery ON agents_inventory(discovery_id)")
                except sqlite3.OperationalError:
                    pass
                
                # Dataset inventory table (for storing uploaded datasets)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS dataset_inventory (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        dataset_id TEXT UNIQUE NOT NULL,
                        name TEXT NOT NULL,
                        description TEXT,
                        file_name TEXT NOT NULL,
                        file_path TEXT NOT NULL,
                        file_size INTEGER NOT NULL,
                        file_format TEXT NOT NULL,
                        row_count INTEGER,
                        column_count INTEGER,
                        created_by TEXT DEFAULT 'anonymous',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Model inventory table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS model_inventory (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        model_id TEXT UNIQUE NOT NULL,
                        name TEXT NOT NULL,
                        description TEXT,
                        entry_type TEXT NOT NULL,
                        provider TEXT NOT NULL,
                        model_identifier TEXT,
                        config_json TEXT NOT NULL,
                        metadata_json TEXT,
                        use_case_answers_json TEXT,
                        last_test_status_json TEXT,
                        created_by TEXT DEFAULT 'anonymous',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Manual Target Models table (for manual testing)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS manual_target_models (
                        id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        model_type TEXT NOT NULL,
                        config_json TEXT NOT NULL,
                        description TEXT,
                        use_case_json TEXT,
                        is_default INTEGER DEFAULT 0,
                        created_by TEXT DEFAULT 'system',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # MCP Tools Inventory table (for storing MCP servers from external sources)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS mcp_tools_inventory (
                        id TEXT PRIMARY KEY,
                        tool_id TEXT UNIQUE NOT NULL,
                        tool_name TEXT NOT NULL,
                        description TEXT,
                        server_url TEXT NOT NULL,
                        server_type TEXT NOT NULL DEFAULT 'http',
                        headers_json TEXT,
                        tenant_id TEXT,
                        source_user_id TEXT,
                        created_by TEXT DEFAULT 'system',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Create indexes for MCP tools inventory
                try:
                    cursor.execute("CREATE INDEX IF NOT EXISTS idx_mcp_tools_tool_id ON mcp_tools_inventory(tool_id)")
                    cursor.execute("CREATE INDEX IF NOT EXISTS idx_mcp_tools_name ON mcp_tools_inventory(tool_name)")
                except sqlite3.OperationalError:
                    pass
                
                # Migration: Add created_by column if it doesn't exist
                try:
                    cursor.execute("ALTER TABLE benchmark_results ADD COLUMN created_by TEXT DEFAULT 'anonymous'")
                except sqlite3.OperationalError:
                    # Column already exists, ignore the error
                    pass
                
                # Model configurations table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS model_configs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        model_name TEXT UNIQUE NOT NULL,
                        config_json TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Create roles table for dynamic role management
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS roles (
                        role_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        role_name TEXT UNIQUE NOT NULL,
                        display_name TEXT NOT NULL,
                        description TEXT,
                        permissions_json TEXT NOT NULL,
                        is_system_role INTEGER DEFAULT 0,
                        created_by TEXT DEFAULT 'system',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Create user_role_assignments table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS user_role_assignments (
                        assignment_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id TEXT NOT NULL,
                        role_id INTEGER NOT NULL,
                        assigned_by TEXT,
                        assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (role_id) REFERENCES roles(role_id),
                        UNIQUE(user_id, role_id)
                    )
                """)
                
                # Insert default system roles (admin and normal) if not exists
                cursor.execute("""
                    INSERT OR IGNORE INTO roles (role_name, display_name, description, permissions_json, is_system_role, created_by)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    'admin',
                    'Administrator',
                    'Full system access with all permissions',
                    json.dumps([
                        'scan:run:proxy',
                        'scan:run:opensource',
                        'scan:run:onboarded',
                        'scan:view:own',
                        'scan:view:all',
                        'scan:view:details:own',
                        'scan:view:details:all',
                        'dataset:manage',
                        'model:view:all',
                        'model:edit:all',
                        'model:delete:all',
                    ]),
                    1,
                    'system'
                ))
                
                cursor.execute("""
                    INSERT OR IGNORE INTO roles (role_name, display_name, description, permissions_json, is_system_role, created_by)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    'normal',
                    'Normal User',
                    'Standard user with limited permissions',
                    json.dumps([
                        'scan:run:proxy',
                        'scan:view:own',
                        'scan:view:all',
                        'scan:view:details:own',
                        'model:view:own',
                        'model:edit:own',
                        'model:delete:own'
                    ]),
                    1,
                    'system'
                ))
                
                
                # User activity table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS user_activity (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        api_key_hash TEXT NOT NULL,
                        action TEXT NOT NULL,
                        details_json TEXT,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Scan sessions table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS scan_sessions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id TEXT UNIQUE NOT NULL,
                        session_data_json TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Agent security scans table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS agent_scans (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id TEXT UNIQUE NOT NULL,
                        agent_name TEXT NOT NULL,
                        agent_endpoint TEXT NOT NULL,
                        framework TEXT,
                        hosting_platform TEXT DEFAULT 'custom',
                        agent_context TEXT,
                        status TEXT NOT NULL DEFAULT 'queued',
                        progress INTEGER DEFAULT 0,
                        results_json TEXT,
                        events_json TEXT,
                        request_format TEXT,
                        interaction_mode TEXT,
                        tools_json TEXT,
                        reference_id TEXT,
                        created_by TEXT DEFAULT 'anonymous',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        completed_at TIMESTAMP
                    )
                """)

                # Indexes for agent scans
                try:
                    cursor.execute("CREATE INDEX IF NOT EXISTS idx_agent_scans_status ON agent_scans(status)")
                    cursor.execute("CREATE INDEX IF NOT EXISTS idx_agent_scans_created_by ON agent_scans(created_by)")
                    cursor.execute("CREATE INDEX IF NOT EXISTS idx_agent_scans_created_at ON agent_scans(created_at)")
                except sqlite3.OperationalError:
                    pass

                # Migration: add tools_count column if missing
                try:
                    cursor.execute("ALTER TABLE agent_scans ADD COLUMN tools_count INTEGER DEFAULT 0")
                except sqlite3.OperationalError:
                    pass  # Column already exists

                # Custom (user-onboarded) agent configs for Quick Start
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS custom_agent_configs (
                        id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        description TEXT,
                        endpoint TEXT NOT NULL,
                        base_url TEXT,
                        framework TEXT,
                        hosting_platform TEXT DEFAULT 'custom',
                        headers_json TEXT,
                        request_body_template TEXT,
                        response_json_path TEXT,
                        init_endpoint TEXT,
                        init_body_json TEXT,
                        init_headers_json TEXT,
                        tools_json TEXT,
                        agent_context TEXT,
                        protocol TEXT DEFAULT 'simple',
                        created_by TEXT DEFAULT 'unknown',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)

                # MCP Monitor events table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS mcp_monitor_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ts TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        tool TEXT NOT NULL,
                        risk TEXT NOT NULL DEFAULT 'safe',
                        allowed INTEGER NOT NULL DEFAULT 1,
                        summary TEXT,
                        details_json TEXT,
                        session_id TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                try:
                    cursor.execute("CREATE INDEX IF NOT EXISTS idx_mcp_monitor_ts ON mcp_monitor_events(ts)")
                    cursor.execute("CREATE INDEX IF NOT EXISTS idx_mcp_monitor_risk ON mcp_monitor_events(risk)")
                    cursor.execute("CREATE INDEX IF NOT EXISTS idx_mcp_monitor_event_type ON mcp_monitor_events(event_type)")
                except sqlite3.OperationalError:
                    pass

                # Benchmark data table (row-level benchmark dataset storage)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS benchmark_data (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        benchmark_id TEXT NOT NULL,
                        prompt TEXT NOT NULL,
                        response TEXT,
                        bypass_status TEXT NOT NULL,
                        model TEXT,
                        attack_category TEXT NOT NULL,
                        scan_id TEXT,
                        prompt_hash TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                try:
                    cursor.execute("CREATE INDEX IF NOT EXISTS idx_bd_benchmark ON benchmark_data(benchmark_id)")
                    cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_bd_hash ON benchmark_data(prompt_hash)")
                    cursor.execute("CREATE INDEX IF NOT EXISTS idx_bd_category ON benchmark_data(benchmark_id, attack_category)")
                except sqlite3.OperationalError:
                    pass

                # PRD security reviews table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS prd_reviews (
                        review_id TEXT PRIMARY KEY,
                        document_title TEXT,
                        reference_id TEXT,
                        author TEXT,
                        status TEXT NOT NULL DEFAULT 'queued',
                        progress INTEGER DEFAULT 0,
                        created_by TEXT,
                        created_at TEXT,
                        completed_at TEXT,
                        result_json TEXT,
                        surfaces_json TEXT,
                        sections_md TEXT,
                        summary_md TEXT,
                        reference_link TEXT,
                        error TEXT
                    )
                """)
                try:
                    cursor.execute("CREATE INDEX IF NOT EXISTS idx_prd_status ON prd_reviews(status)")
                    cursor.execute("CREATE INDEX IF NOT EXISTS idx_prd_created_by ON prd_reviews(created_by)")
                    cursor.execute("CREATE INDEX IF NOT EXISTS idx_prd_reference_id ON prd_reviews(reference_id)")
                except sqlite3.OperationalError:
                    pass

                # Prompt hardener jobs table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS harden_jobs (
                        job_id TEXT PRIMARY KEY,
                        prompt_name TEXT,
                        system_prompt TEXT NOT NULL,
                        context TEXT,
                        reference_id TEXT,
                        status TEXT NOT NULL DEFAULT 'queued',
                        progress INTEGER DEFAULT 0,
                        created_by TEXT DEFAULT 'anonymous',
                        created_at TEXT,
                        completed_at TEXT,
                        security_addendum TEXT,
                        error TEXT
                    )
                """)
                # Migrate existing DBs that pre-date the prompt_name column.
                try:
                    cursor.execute("ALTER TABLE harden_jobs ADD COLUMN prompt_name TEXT")
                except sqlite3.OperationalError:
                    pass  # column already exists
                try:
                    cursor.execute("CREATE INDEX IF NOT EXISTS idx_harden_status ON harden_jobs(status)")
                    cursor.execute("CREATE INDEX IF NOT EXISTS idx_harden_created_by ON harden_jobs(created_by)")
                    cursor.execute("CREATE INDEX IF NOT EXISTS idx_harden_reference_id ON harden_jobs(reference_id)")
                except sqlite3.OperationalError:
                    pass

                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS skill_harden_jobs (
                        job_id TEXT PRIMARY KEY,
                        repo_url TEXT NOT NULL,
                        skill_name TEXT NOT NULL,
                        branch TEXT,
                        status TEXT NOT NULL DEFAULT 'queued',
                        progress INTEGER DEFAULT 0,
                        security_guidelines TEXT,
                        full_content_preview TEXT,
                        pr_url TEXT,
                        pr_number INTEGER,
                        created_by TEXT DEFAULT 'anonymous',
                        created_at TEXT,
                        completed_at TEXT,
                        error TEXT,
                        skill_content TEXT
                    )
                """)
                try:
                    cursor.execute("CREATE INDEX IF NOT EXISTS idx_skill_harden_status ON skill_harden_jobs(status)")
                    cursor.execute("CREATE INDEX IF NOT EXISTS idx_skill_harden_created_by ON skill_harden_jobs(created_by)")
                except sqlite3.OperationalError:
                    pass

                # Audit table for the JIRA auto-hardener — one row per ticket we
                # have ever posted a security-prompt comment on. Used as a
                # belt-and-suspenders idempotency gate alongside the JIRA
                # label, so we never re-comment even if the label add failed.
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS jira_auto_harden_log (
                        ticket_key TEXT PRIMARY KEY,
                        commented_at TEXT NOT NULL,
                        marker_label TEXT,
                        prompt_hash TEXT,
                        prompt_preview TEXT
                    )
                """)
                try:
                    cursor.execute(
                        "CREATE INDEX IF NOT EXISTS idx_jira_auto_harden_log_commented_at "
                        "ON jira_auto_harden_log(commented_at)"
                    )
                except sqlite3.OperationalError:
                    pass

                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS sandbox_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ts TEXT NOT NULL,
                        queried_by TEXT,
                        query TEXT NOT NULL,
                        agent_name TEXT,
                        department TEXT,
                        inbound_decision TEXT,
                        outbound_decision TEXT,
                        llm_ok INTEGER,
                        final_response TEXT,
                        steps_json TEXT,
                        created_at TEXT DEFAULT (datetime('now'))
                    )
                """)
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_sl_ts ON sandbox_logs(ts)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_sl_user ON sandbox_logs(queried_by)")

                self._migrate_legacy_identifiers(cursor)

                conn.commit()
                
        except Exception as e:
            self.console.print(f"[red]Error initializing database: {e}[/]")

    def _migrate_legacy_identifiers(self, cursor) -> None:
        """Apply schema renames on existing SQLite DBs."""
        ref_tables = (
            "benchmark_results", "mcp_scans", "agent_scans",
            "prd_reviews", "harden_jobs",
        )
        for table in ref_tables:
            try:
                cursor.execute(
                    f"ALTER TABLE {table} RENAME COLUMN secreview_id TO reference_id"
                )
            except sqlite3.OperationalError:
                pass
        for old_id, new_id in (("aegis", "guardrail-v1"), ("aegis-v2", "guardrail-v2")):
            try:
                cursor.execute(
                    "UPDATE benchmark_data SET benchmark_id = ? WHERE benchmark_id = ?",
                    (new_id, old_id),
                )
            except sqlite3.OperationalError:
                pass
        try:
            cursor.execute(
                "UPDATE model_inventory SET model_id = 'guardrail-v1-default' "
                "WHERE model_id = 'aegis-default'"
            )
        except sqlite3.OperationalError:
            pass
        for table in ("team_poc_config", "poc_config", "chat_digest_log"):
            try:
                cursor.execute(f"DROP TABLE IF EXISTS {table}")
            except sqlite3.OperationalError:
                pass
    
    def save_benchmark_result(
        self, 
        scan_id: str,
        scan_name: str, 
        results: Dict[str, Any], 
        metadata: Optional[Dict[str, Any]] = None,
        created_by: str = "anonymous",
        reference_id: Optional[str] = None,
        status: str = "completed"
    ) -> bool:
        """Save benchmark results to database
        
        Args:
            scan_id: Unique scan identifier
            scan_name: Human-readable scan name
            results: Scan results dictionary
            metadata: Optional metadata dictionary
            created_by: Username who created the scan
            reference_id: Optional security review ID
            status: Scan status ('completed', 'cancelled', 'failed')
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Convert results and metadata to JSON
                results_json = json.dumps(results)
                metadata_json = json.dumps(metadata or {})
                
                # Insert or update
                cursor.execute("""
                    INSERT OR REPLACE INTO benchmark_results 
                    (scan_id, scan_name, status, results_json, metadata_json, created_by, reference_id, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """, (scan_id, scan_name, status, results_json, metadata_json, created_by, reference_id))
                
                conn.commit()
                
                # Invalidate cache for this scan since we just updated it
                self.invalidate_cache(scan_id)
                
                return True
                
        except Exception as e:
            self.console.print(f"[red]Error saving benchmark result: {e}[/]")
            return False
    
    def update_benchmark_status(self, scan_id: str, status: str) -> bool:
        """Update just the status of a benchmark scan
        
        Args:
            scan_id: Unique scan identifier
            status: New status ('queued', 'running', 'completed', 'cancelled', 'failed')
            
        Returns:
            True if update successful, False otherwise
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    UPDATE benchmark_results 
                    SET status = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE scan_id = ?
                """, (status, scan_id))
                
                conn.commit()
                
                # Invalidate cache for this scan since we just updated it
                self.invalidate_cache(scan_id)
                
                print(f"[DB] Updated scan {scan_id} status to {status}")
                return cursor.rowcount > 0
                
        except Exception as e:
            self.console.print(f"[red]Error updating benchmark status: {e}[/]")
            return False
    
    def recover_stuck_scans(self) -> int:
        """
        Recovery function called on server startup.
        Marks any scans with 'queued' or 'running' status as 'cancelled'
        so they can be restarted by admin.
        
        Returns:
            Number of scans recovered
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Find and update stuck scans
                cursor.execute("""
                    UPDATE benchmark_results 
                    SET status = 'cancelled', 
                        updated_at = CURRENT_TIMESTAMP,
                        metadata_json = json_set(
                            COALESCE(metadata_json, '{}'),
                            '$.recovery_reason',
                            'Server restarted while scan was in progress'
                        )
                    WHERE status IN ('queued', 'running')
                """)
                
                recovered_count = cursor.rowcount
                conn.commit()
                
                # Clear entire cache since multiple scans may have been updated
                global _scan_results_cache
                _scan_results_cache.clear()
                
                if recovered_count > 0:
                    print(f"[DB] Recovered {recovered_count} stuck scans (marked as cancelled)")
                
                return recovered_count
                
        except Exception as e:
            self.console.print(f"[red]Error recovering stuck scans: {e}[/]")
            return 0
    
    def recover_stuck_agent_scans(self) -> int:
        """Recovery function called on server startup.

        Marks any agent scans with 'queued' or 'running' status as 'cancelled'
        so they don't block the new worker pool.

        Returns:
            Number of agent scans recovered.
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE agent_scans
                    SET status = 'cancelled',
                        updated_at = CURRENT_TIMESTAMP
                    WHERE status IN ('queued', 'running')
                """)
                recovered_count = cursor.rowcount
                conn.commit()
                if recovered_count > 0:
                    print(f"[DB] Recovered {recovered_count} stuck agent scans (marked as cancelled)")
                return recovered_count
        except Exception as e:
            self.console.print(f"[red]Error recovering stuck agent scans: {e}[/]")
            return 0

    def recover_stuck_mcp_scans(self) -> int:
        """Recovery function called on server startup.

        Marks any MCP scans with 'scanning', 'queued', or 'running' status as 'cancelled'
        so they don't show as active after a server restart.

        Returns:
            Number of MCP scans recovered.
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE mcp_scans
                    SET status = 'cancelled',
                        completed_at = CURRENT_TIMESTAMP
                    WHERE status IN ('scanning', 'queued', 'running')
                """)
                recovered_count = cursor.rowcount
                conn.commit()
                if recovered_count > 0:
                    print(f"[DB] Recovered {recovered_count} stuck MCP scans (marked as cancelled)")
                return recovered_count
        except Exception as e:
            self.console.print(f"[red]Error recovering stuck MCP scans: {e}[/]")
            return 0

    def recover_stuck_prd_reviews(self) -> int:
        """Recovery function called on server startup.

        Marks any PRD reviews with 'queued' or 'running' status as 'failed'
        so they don't stay in the Active Reviews list after a server restart.

        Returns:
            Number of reviews recovered.
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE prd_reviews
                    SET status = 'failed',
                        error = 'Server restarted while review was in progress',
                        completed_at = CURRENT_TIMESTAMP
                    WHERE status IN ('queued', 'running')
                """)
                recovered_count = cursor.rowcount
                conn.commit()
                if recovered_count > 0:
                    print(f"[DB] Recovered {recovered_count} stuck PRD reviews (marked as failed)")
                return recovered_count
        except Exception as e:
            self.console.print(f"[red]Error recovering stuck PRD reviews: {e}[/]")
            return 0

    def get_benchmark_result(self, scan_id: str, use_cache: bool = True) -> Optional[Dict[str, Any]]:
        """Get benchmark result by scan ID.
        
        Args:
            scan_id: The scan ID to look up
            use_cache: If True, check in-memory cache first (default True)
        """
        global _scan_results_cache
        
        # Check cache first
        if use_cache and scan_id in _scan_results_cache:
            return _scan_results_cache[scan_id]
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT scan_id, scan_name, status, results_json, metadata_json, 
                           created_by, reference_id, created_at, updated_at
                    FROM benchmark_results 
                    WHERE scan_id = ?
                """, (scan_id,))
                
                row = cursor.fetchone()
                if row:
                    result = {
                        "scan_id": row[0],
                        "scan_name": row[1],
                        "status": row[2],
                        "results": json.loads(row[3]) if row[3] else {},
                        "metadata": json.loads(row[4]) if row[4] else {},
                        "created_by": row[5],
                        "reference_id": row[6],
                        "created_at": row[7],
                        "updated_at": row[8]
                    }
                    
                    # Cache the result (with LRU eviction)
                    if len(_scan_results_cache) >= _CACHE_MAX_SIZE:
                        # Remove oldest entry (first key)
                        oldest_key = next(iter(_scan_results_cache))
                        del _scan_results_cache[oldest_key]
                    _scan_results_cache[scan_id] = result
                    
                    return result
                
        except Exception as e:
            self.console.print(f"[red]Error getting benchmark result: {e}[/]")
        
        return None
    
    def invalidate_cache(self, scan_id: str = None):
        """Invalidate scan results cache.
        
        Args:
            scan_id: If provided, only invalidate this scan. Otherwise clear all.
        """
        global _scan_results_cache
        if scan_id:
            _scan_results_cache.pop(scan_id, None)
        else:
            _scan_results_cache.clear()
    
    def list_benchmark_results(self, limit: int = 50, offset: int = 0, exclude_playground: bool = False) -> List[Dict[str, Any]]:
        """List benchmark results with pagination.
        
        Args:
            limit: Maximum number of results to return
            offset: Number of results to skip
            exclude_playground: If True, exclude playground scans from results
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Use JSON extraction to get is_playground flag and filter at DB level if needed
                if exclude_playground:
                    cursor.execute("""
                        SELECT scan_id, scan_name, status, created_by, reference_id, created_at, updated_at,
                               json_extract(results_json, '$.metadata.is_playground') as is_playground,
                               json_extract(results_json, '$.summary.average_response_time') as avg_response_time,
                               json_extract(metadata_json, '$.models[0].provider') as provider
                        FROM benchmark_results
                        WHERE json_extract(results_json, '$.metadata.is_playground') IS NOT 1
                        ORDER BY created_at DESC
                        LIMIT ? OFFSET ?
                    """, (limit, offset))
                else:
                    cursor.execute("""
                        SELECT scan_id, scan_name, status, created_by, reference_id, created_at, updated_at,
                               json_extract(results_json, '$.metadata.is_playground') as is_playground,
                               json_extract(results_json, '$.summary.average_response_time') as avg_response_time,
                               json_extract(metadata_json, '$.models[0].provider') as provider
                        FROM benchmark_results
                        ORDER BY created_at DESC
                        LIMIT ? OFFSET ?
                    """, (limit, offset))

                results = []
                for row in cursor.fetchall():
                    results.append({
                        "scan_id": row[0],
                        "scan_name": row[1],
                        "status": row[2],
                        "created_by": row[3],
                        "reference_id": row[4],
                        "created_at": row[5],
                        "updated_at": row[6],
                        "is_playground": bool(row[7]) if row[7] is not None else False,
                        "avg_response_time": float(row[8]) if row[8] is not None else None,
                        "provider": row[9],
                    })
                
                return results
                
        except Exception as e:
            self.console.print(f"[red]Error listing benchmark results: {e}[/]")
            return []
    
    def delete_benchmark_result(self, scan_id: str) -> bool:
        """Delete a contextual scan (benchmark result) from the database.
        
        Args:
            scan_id: The ID of the scan to delete
            
        Returns:
            True if deletion was successful, False otherwise
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Delete from benchmark_results table
                cursor.execute("DELETE FROM benchmark_results WHERE scan_id = ?", (scan_id,))
                
                conn.commit()
                
                # Invalidate cache for this scan
                self.invalidate_cache(scan_id)
                
                self.console.print(f"[green]Deleted contextual scan {scan_id}[/]")
                return True
                
        except Exception as e:
            self.console.print(f"[red]Error deleting contextual scan: {e}[/]")
            return False
    
    # ---------------------------------------------------------------------------
    # benchmark_data — row-level benchmark dataset storage
    # ---------------------------------------------------------------------------

    def insert_benchmark_rows(self, rows: List[Dict[str, Any]], benchmark_id: str) -> int:
        """Bulk insert benchmark rows with dedup via prompt_hash. Returns count inserted."""
        if not rows:
            return 0
        inserted = 0
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                for row in rows:
                    try:
                        cursor.execute("""
                            INSERT OR IGNORE INTO benchmark_data
                            (benchmark_id, prompt, response, bypass_status, model, attack_category, scan_id, prompt_hash)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """, (
                            benchmark_id,
                            row.get("prompt", ""),
                            row.get("response", ""),
                            row.get("bypass_status", ""),
                            row.get("model", ""),
                            row.get("attack_category", ""),
                            row.get("scan_id"),
                            row["prompt_hash"],
                        ))
                        if cursor.rowcount > 0:
                            inserted += 1
                    except sqlite3.IntegrityError:
                        pass
                conn.commit()
        except Exception as e:
            self.console.print(f"[red]Error inserting benchmark rows: {e}[/]")
        return inserted

    def get_benchmark_data_stats(self, benchmark_id: str) -> Dict[str, Any]:
        """Returns per-category counts for a benchmark from the benchmark_data table."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT attack_category,
                           COUNT(*) as total,
                           SUM(CASE WHEN bypass_status = 'yes' THEN 1 ELSE 0 END) as bypassed,
                           SUM(CASE WHEN bypass_status = 'no' THEN 1 ELSE 0 END) as blocked,
                           SUM(CASE WHEN bypass_status = 'error' THEN 1 ELSE 0 END) as errors
                    FROM benchmark_data
                    WHERE benchmark_id = ?
                    GROUP BY attack_category
                """, (benchmark_id,))
                categories = {}
                for row in cursor.fetchall():
                    categories[row[0]] = {
                        "total": row[1], "bypassed": row[2],
                        "blocked": row[3], "errors": row[4],
                    }
                total = sum(c["total"] for c in categories.values())
                bypassed = sum(c["bypassed"] for c in categories.values())
                blocked = sum(c["blocked"] for c in categories.values())
                return {
                    "total": total, "bypassed": bypassed, "blocked": blocked,
                    "categories": categories,
                }
        except Exception as e:
            self.console.print(f"[red]Error getting benchmark data stats: {e}[/]")
            return {"total": 0, "bypassed": 0, "blocked": 0, "categories": {}}

    def get_benchmark_data_rows(self, benchmark_id: str, limit: int = None, offset: int = 0) -> List[Dict[str, Any]]:
        """Returns individual rows for CSV export."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                query = "SELECT prompt, response, bypass_status, model, attack_category FROM benchmark_data WHERE benchmark_id = ? ORDER BY id"
                params: list = [benchmark_id]
                if limit:
                    query += " LIMIT ? OFFSET ?"
                    params.extend([limit, offset])
                cursor.execute(query, params)
                return [
                    {"Prompt": r[0], "Response": r[1], "Bypass Status": r[2], "Model": r[3], "Attack Category": r[4]}
                    for r in cursor.fetchall()
                ]
        except Exception as e:
            self.console.print(f"[red]Error getting benchmark data rows: {e}[/]")
            return []

    def get_benchmark_row_count(self, benchmark_id: str) -> int:
        """Quick count for list endpoint."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM benchmark_data WHERE benchmark_id = ?", (benchmark_id,))
                return cursor.fetchone()[0]
        except Exception:
            return 0

    def has_benchmark_data(self, benchmark_id: str) -> bool:
        """Check if seed data exists for a benchmark."""
        return self.get_benchmark_row_count(benchmark_id) > 0

    def save_model_config(self, model_name: str, config: Dict[str, Any]) -> bool:
        """Save model configuration"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                config_json = json.dumps(config)
                
                cursor.execute("""
                    INSERT OR REPLACE INTO model_configs 
                    (model_name, config_json, updated_at)
                    VALUES (?, ?, CURRENT_TIMESTAMP)
                """, (model_name, config_json))
                
                conn.commit()
                return True
                
        except Exception as e:
            self.console.print(f"[red]Error saving model config: {e}[/]")
            return False
    
    def get_model_config(self, model_name: str) -> Optional[Dict[str, Any]]:
        """Get model configuration"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT config_json FROM model_configs WHERE model_name = ?
                """, (model_name,))
                
                row = cursor.fetchone()
                if row:
                    return json.loads(row[0])
                
        except Exception as e:
            self.console.print(f"[red]Error getting model config: {e}[/]")
        
        return None
    
    def log_user_activity(
        self, 
        api_key_hash: str, 
        action: str, 
        details: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Log user activity"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                details_json = json.dumps(details or {})
                
                cursor.execute("""
                    INSERT INTO user_activity (api_key_hash, action, details_json)
                    VALUES (?, ?, ?)
                """, (api_key_hash, action, details_json))
                
                conn.commit()
                return True
                
        except Exception as e:
            self.console.print(f"[red]Error logging user activity: {e}[/]")
            return False
    
    def save_scan_session(self, scan_id: str, session_data: Dict[str, Any]) -> bool:
        """Save scan session data"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                session_json = json.dumps(session_data)
                
                cursor.execute("""
                    INSERT OR REPLACE INTO scan_sessions 
                    (scan_id, session_data_json, updated_at)
                    VALUES (?, ?, CURRENT_TIMESTAMP)
                """, (scan_id, session_json))
                
                conn.commit()
                return True
                
        except Exception as e:
            self.console.print(f"[red]Error saving scan session: {e}[/]")
            return False
    
    def get_scan_session(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get scan session data"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT session_data_json FROM scan_sessions WHERE scan_id = ?
                """, (scan_id,))
                
                row = cursor.fetchone()
                if row:
                    return json.loads(row[0])
                
        except Exception as e:
            self.console.print(f"[red]Error getting scan session: {e}[/]")
        
        return None
    
    def cleanup_old_data(self, days: int = 30) -> bool:
        """Clean up old data older than specified days"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Clean up old benchmark results
                cursor.execute("""
                    DELETE FROM benchmark_results 
                    WHERE created_at < datetime('now', '-{} days')
                """.format(days))
                
                # Clean up old user activity
                cursor.execute("""
                    DELETE FROM user_activity 
                    WHERE timestamp < datetime('now', '-{} days')
                """.format(days))
                
                # Clean up old scan sessions
                cursor.execute("""
                    DELETE FROM scan_sessions 
                    WHERE created_at < datetime('now', '-{} days')
                """.format(days))
                
                conn.commit()
                
                # Clear cache since we deleted data
                self.invalidate_cache()
                
                return True
                
        except Exception as e:
            self.console.print(f"[red]Error cleaning up old data: {e}[/]")
            return False
    
    # MCP Scan Methods
    def save_mcp_scan(
        self, 
        scan_id: str, 
        file_name: str,
        status: str,
        config_content: str = None,
        results: Dict[str, Any] = None,
        message: str = None,
        created_by: str = "anonymous",
        timeout: int = 30,
        completed_at: str = None,
        scan_name: str = None,
        reference_id: str = None
    ) -> bool:
        """Save MCP scan to database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                results_json = json.dumps(results) if results else None
                
                cursor.execute("""
                    INSERT OR REPLACE INTO mcp_scans 
                    (scan_id, file_name, status, config_content, results_json, message, created_by, timeout, completed_at, scan_name, reference_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (scan_id, file_name, status, config_content, results_json, message, created_by, timeout, completed_at, scan_name, reference_id))
                
                conn.commit()
                return True
                
        except Exception as e:
            self.console.print(f"[red]Error saving MCP scan: {e}[/]")
            return False
    
    def get_mcp_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get MCP scan by ID"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT scan_id, file_name, status, config_content, results_json, message, 
                           created_by, created_at, completed_at, timeout, scan_name, reference_id
                    FROM mcp_scans 
                    WHERE scan_id = ?
                """, (scan_id,))
                
                row = cursor.fetchone()
                if row:
                    results = json.loads(row[4]) if row[4] else None
                    return {
                        "scan_id": row[0],
                        "file_name": row[1],
                        "status": row[2],
                        "config_content": row[3],
                        "results": results,
                        "message": row[5],
                        "created_by": row[6],
                        "created_at": row[7],
                        "completed_at": row[8],
                        "timeout": row[9],
                        "scan_name": row[10] if len(row) > 10 else None,
                        "reference_id": row[11] if len(row) > 11 else None
                    }
                
                return None
                
        except Exception as e:
            self.console.print(f"[red]Error getting MCP scan: {e}[/]")
            return None
    
    def list_mcp_scans(
        self, 
        user_id: str = None,
        status: str = None,
        limit: int = 50, 
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """List MCP scans with pagination and filtering"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                query = """
                    SELECT scan_id, file_name, status, message, created_by, created_at, completed_at, timeout, scan_name, results_json, reference_id, config_content
                    FROM mcp_scans 
                    WHERE 1=1
                """
                params = []
                
                if user_id:
                    query += " AND created_by = ?"
                    params.append(user_id)
                
                if status:
                    query += " AND status = ?"
                    params.append(status)
                
                query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
                params.extend([limit, offset])
                
                cursor.execute(query, params)
                
                results = []
                for row in cursor.fetchall():
                    # Parse results_json if present
                    scan_results = None
                    if len(row) > 9 and row[9]:
                        try:
                            scan_results = json.loads(row[9])
                        except:
                            pass
                    
                    results.append({
                        "scan_id": row[0],
                        "file_name": row[1],
                        "status": row[2],
                        "message": row[3],
                        "created_by": row[4],
                        "created_at": row[5],
                        "completed_at": row[6],
                        "timeout": row[7],
                        "scan_name": row[8] if len(row) > 8 else None,
                        "results": scan_results,
                        "reference_id": row[10] if len(row) > 10 else None,
                        "config_content": row[11] if len(row) > 11 else None
                    })
                
                return results
                
        except Exception as e:
            self.console.print(f"[red]Error listing MCP scans: {e}[/]")
            return []
    
    def update_mcp_scan_status(
        self,
        scan_id: str,
        status: str,
        results: Dict[str, Any] = None,
        message: str = None,
        completed_at: str = None
    ) -> bool:
        """Update MCP scan status and results"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                results_json = safe_json_dumps(results) if results else None
                
                cursor.execute("""
                    UPDATE mcp_scans 
                    SET status = ?, results_json = ?, message = ?, completed_at = ?
                    WHERE scan_id = ?
                """, (status, results_json, message, completed_at, scan_id))
                
                conn.commit()
                return True
                
        except Exception as e:
            self.console.print(f"[red]Error updating MCP scan: {e}[/]")
            return False
    
    def delete_mcp_scan(self, scan_id: str) -> bool:
        """Delete an MCP scan and its associated data from the database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Delete from mcp_scans table
                cursor.execute("DELETE FROM mcp_scans WHERE scan_id = ?", (scan_id,))
                
                # Delete associated security findings
                cursor.execute("DELETE FROM mcp_security_findings WHERE scan_id = ?", (scan_id,))
                
                # Delete associated active scan results
                cursor.execute("DELETE FROM mcp_active_scan_results WHERE scan_id = ?", (scan_id,))
                
                conn.commit()
                self.console.print(f"[green]Deleted MCP scan {scan_id} and associated data[/]")
                return True
                
        except Exception as e:
            self.console.print(f"[red]Error deleting MCP scan: {e}[/]")
            return False
    
    # ------------------------------------------------------------------
    # Agent Security Scan Methods
    # ------------------------------------------------------------------

    def save_agent_scan(
        self,
        scan_id: str,
        agent_name: str,
        agent_endpoint: str,
        status: str = "queued",
        framework: str = None,
        hosting_platform: str = "custom",
        agent_context: str = None,
        progress: int = 0,
        results: Dict[str, Any] = None,
        events: list = None,
        request_format: str = None,
        interaction_mode: str = None,
        tools: list = None,
        reference_id: str = None,
        created_by: str = "anonymous",
        completed_at: str = None,
    ) -> bool:
        """Save or update an agent security scan in the database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                results_json = json.dumps(results) if results else None
                events_json = json.dumps(events) if events else None
                tools_json = json.dumps(tools) if tools else None

                cursor.execute("""
                    INSERT OR REPLACE INTO agent_scans
                    (scan_id, agent_name, agent_endpoint, framework,
                     hosting_platform, agent_context, status, progress,
                     results_json, events_json, request_format,
                     interaction_mode, tools_json, reference_id,
                     created_by, completed_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                            ?, CURRENT_TIMESTAMP)
                """, (
                    scan_id, agent_name, agent_endpoint, framework,
                    hosting_platform, agent_context, status, progress,
                    results_json, events_json, request_format,
                    interaction_mode, tools_json, reference_id,
                    created_by, completed_at,
                ))

                conn.commit()
                return True

        except Exception as e:
            self.console.print(f"[red]Error saving agent scan: {e}[/]")
            return False

    def update_agent_scan(
        self,
        scan_id: str,
        status: str = None,
        progress: int = None,
        results: Dict[str, Any] = None,
        events: list = None,
        request_format: str = None,
        interaction_mode: str = None,
        completed_at: str = None,
        tools: list = None,
        tools_count: int = None,
    ) -> bool:
        """Update specific fields of an agent scan."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                updates = []
                params = []

                if status is not None:
                    updates.append("status = ?")
                    params.append(status)
                if progress is not None:
                    updates.append("progress = ?")
                    params.append(progress)
                if results is not None:
                    updates.append("results_json = ?")
                    params.append(json.dumps(results))
                if events is not None:
                    updates.append("events_json = ?")
                    params.append(json.dumps(events))
                if request_format is not None:
                    updates.append("request_format = ?")
                    params.append(request_format)
                if interaction_mode is not None:
                    updates.append("interaction_mode = ?")
                    params.append(interaction_mode)
                if completed_at is not None:
                    updates.append("completed_at = ?")
                    params.append(completed_at)
                if tools is not None:
                    updates.append("tools_json = ?")
                    params.append(json.dumps(tools))
                if tools_count is not None:
                    updates.append("tools_count = ?")
                    params.append(tools_count)

                updates.append("updated_at = CURRENT_TIMESTAMP")

                if not updates:
                    return True

                params.append(scan_id)
                cursor.execute(
                    f"UPDATE agent_scans SET {', '.join(updates)} WHERE scan_id = ?",
                    params,
                )
                conn.commit()
                return True

        except Exception as e:
            self.console.print(f"[red]Error updating agent scan: {e}[/]")
            return False

    def get_agent_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get a single agent scan by ID."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM agent_scans WHERE scan_id = ?", (scan_id,))
                row = cursor.fetchone()
                if not row:
                    return None
                return self._agent_scan_row_to_dict(row)

        except Exception as e:
            self.console.print(f"[red]Error getting agent scan: {e}[/]")
            return None

    def list_agent_scans(
        self,
        user_id: str = None,
        status: str = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """List agent scans with optional filters."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()

                query = "SELECT * FROM agent_scans WHERE 1=1"
                params: list = []

                if user_id:
                    query += " AND created_by = ?"
                    params.append(user_id)
                if status:
                    query += " AND status = ?"
                    params.append(status)

                query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
                params.extend([limit, offset])

                cursor.execute(query, params)
                return [self._agent_scan_row_to_dict(row) for row in cursor.fetchall()]

        except Exception as e:
            self.console.print(f"[red]Error listing agent scans: {e}[/]")
            return []

    def delete_agent_scan(self, scan_id: str) -> bool:
        """Delete an agent scan from the database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM agent_scans WHERE scan_id = ?", (scan_id,))
                conn.commit()
                return cursor.rowcount > 0

        except Exception as e:
            self.console.print(f"[red]Error deleting agent scan: {e}[/]")
            return False

    @staticmethod
    def _agent_scan_row_to_dict(row) -> Dict[str, Any]:
        """Convert a database Row to a dict matching the in-memory format."""
        d = dict(row)
        # Deserialise JSON columns
        for json_col, key in [
            ("results_json", "results"),
            ("events_json", "events"),
            ("tools_json", "tools"),
        ]:
            raw = d.pop(json_col, None)
            try:
                d[key] = json.loads(raw) if raw else None
            except (json.JSONDecodeError, TypeError):
                d[key] = None

        # Convert tools list-of-dicts back to the shape the frontend expects
        if d.get("tools") is None:
            d["tools"] = []
        d["tools_count"] = len(d["tools"])

        return d
    
    # ── Custom Agent Configs (Quick Start) ────────────────────────────────
    def save_custom_agent_config(self, config: Dict[str, Any]) -> bool:
        """Save a user-provided custom agent config for Quick Start."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """INSERT OR REPLACE INTO custom_agent_configs
                       (id, name, description, endpoint, base_url, framework,
                        hosting_platform, headers_json, request_body_template,
                        response_json_path, init_endpoint, init_body_json,
                        init_headers_json, tools_json, agent_context,
                        protocol, created_by, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)""",
                    (
                        config["id"],
                        config["name"],
                        config.get("description", ""),
                        config["endpoint"],
                        config.get("base_url", ""),
                        config.get("framework", ""),
                        config.get("hosting_platform", "custom"),
                        json.dumps(config.get("headers", {})),
                        config.get("request_body_template", ""),
                        config.get("response_json_path", ""),
                        config.get("init_endpoint", ""),
                        json.dumps(config.get("init_body", {})) if config.get("init_body") else "",
                        json.dumps(config.get("init_headers", {})) if config.get("init_headers") else "",
                        json.dumps(config.get("tools", [])),
                        config.get("agent_context", ""),
                        config.get("protocol", "simple"),
                        config.get("created_by", "unknown"),
                    ),
                )
                conn.commit()
            return True
        except Exception as e:
            self.console.print(f"[red]Error saving custom agent config: {e}[/]")
            return False

    def list_custom_agent_configs(self) -> List[Dict[str, Any]]:
        """List all custom agent configs."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM custom_agent_configs ORDER BY created_at DESC")
                rows = cursor.fetchall()
                results = []
                for row in rows:
                    d = dict(row)
                    # Deserialise JSON columns
                    for col, key in [
                        ("headers_json", "headers"),
                        ("tools_json", "tools"),
                        ("init_body_json", "init_body"),
                        ("init_headers_json", "init_headers"),
                    ]:
                        raw = d.pop(col, None)
                        try:
                            d[key] = json.loads(raw) if raw else ({} if "headers" in key else [])
                        except (json.JSONDecodeError, TypeError):
                            d[key] = {} if "headers" in key else []
                    results.append(d)
                return results
        except Exception as e:
            self.console.print(f"[red]Error listing custom agent configs: {e}[/]")
            return []

    def get_custom_agent_config(self, config_id: str) -> Optional[Dict[str, Any]]:
        """Get a single custom agent config by ID."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM custom_agent_configs WHERE id = ?", (config_id,))
                row = cursor.fetchone()
                if not row:
                    return None
                d = dict(row)
                for col, key in [
                    ("headers_json", "headers"),
                    ("tools_json", "tools"),
                    ("init_body_json", "init_body"),
                    ("init_headers_json", "init_headers"),
                ]:
                    raw = d.pop(col, None)
                    try:
                        d[key] = json.loads(raw) if raw else ({} if "headers" in key else [])
                    except (json.JSONDecodeError, TypeError):
                        d[key] = {} if "headers" in key else []
                return d
        except Exception as e:
            self.console.print(f"[red]Error getting custom agent config: {e}[/]")
            return None

    def delete_custom_agent_config(self, config_id: str) -> bool:
        """Delete a custom agent config."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM custom_agent_configs WHERE id = ?", (config_id,))
                conn.commit()
                return cursor.rowcount > 0
        except Exception as e:
            self.console.print(f"[red]Error deleting custom agent config: {e}[/]")
            return False

    # ── MCP Monitor Events ───────────────────────────────────────────────
    def save_mcp_monitor_event(self, event: Dict[str, Any]) -> bool:
        """Persist a single monitoring event."""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.execute(
                    """INSERT INTO mcp_monitor_events
                       (ts, event_type, tool, risk, allowed, summary, details_json, session_id)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        event.get("ts", ""),
                        event.get("event_type", ""),
                        event.get("tool", ""),
                        event.get("risk", "safe"),
                        1 if event.get("allowed", True) else 0,
                        event.get("summary", ""),
                        json.dumps(event.get("details", {})),
                        event.get("session_id"),
                    ),
                )
                conn.commit()
            return True
        except Exception as e:
            self.console.print(f"[red]Error saving MCP monitor event: {e}[/]")
            return False

    def list_mcp_monitor_events(
        self, limit: int = 100, risk: Optional[str] = None, event_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return the most recent monitor events, newest first."""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.row_factory = sqlite3.Row
                clauses = []
                params: list = []
                if risk:
                    clauses.append("risk = ?")
                    params.append(risk)
                if event_type:
                    clauses.append("event_type = ?")
                    params.append(event_type)
                where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
                rows = conn.execute(
                    f"SELECT * FROM mcp_monitor_events{where} ORDER BY id DESC LIMIT ?",
                    params + [limit],
                ).fetchall()
                results = []
                for row in rows:
                    d = dict(row)
                    raw = d.pop("details_json", None)
                    try:
                        d["details"] = json.loads(raw) if raw else {}
                    except (json.JSONDecodeError, TypeError):
                        d["details"] = {}
                    d["allowed"] = bool(d.get("allowed", 1))
                    results.append(d)
                return results
        except Exception as e:
            self.console.print(f"[red]Error listing MCP monitor events: {e}[/]")
            return []

    def get_mcp_monitor_stats(self) -> Dict[str, Any]:
        """Return aggregate statistics for the monitor dashboard."""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                total = conn.execute("SELECT COUNT(*) FROM mcp_monitor_events").fetchone()[0]
                blocked = conn.execute("SELECT COUNT(*) FROM mcp_monitor_events WHERE allowed = 0").fetchone()[0]
                by_risk = {}
                for row in conn.execute(
                    "SELECT risk, COUNT(*) as cnt FROM mcp_monitor_events GROUP BY risk"
                ).fetchall():
                    by_risk[row[0]] = row[1]
                by_type = {}
                for row in conn.execute(
                    "SELECT event_type, COUNT(*) as cnt FROM mcp_monitor_events GROUP BY event_type"
                ).fetchall():
                    by_type[row[0]] = row[1]
                return {
                    "total_events": total,
                    "blocked": blocked,
                    "allowed": total - blocked,
                    "by_risk": by_risk,
                    "by_type": by_type,
                }
        except Exception as e:
            self.console.print(f"[red]Error getting MCP monitor stats: {e}[/]")
            return {"total_events": 0, "blocked": 0, "allowed": 0, "by_risk": {}, "by_type": {}}

    def clear_mcp_monitor_events(self) -> bool:
        """Clear all monitor events."""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.execute("DELETE FROM mcp_monitor_events")
                conn.commit()
            return True
        except Exception as e:
            self.console.print(f"[red]Error clearing MCP monitor events: {e}[/]")
            return False

    # MCP Active Scan Results Methods (for client simulation / Triksha Agent)
    def save_active_scan_result(
        self,
        scan_id: str,
        tool_name: str,
        attack_type: str,
        payload: str,
        response: str,
        vulnerability_found: bool,
        vulnerability_type: str = None,
        severity: str = None,
        details: str = None,
        recommendation: str = None
    ) -> bool:
        """Save an active scan (client simulation) result"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO mcp_active_scan_results 
                    (scan_id, tool_name, attack_type, payload, response, vulnerability_found,
                     vulnerability_type, severity, details, recommendation)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (scan_id, tool_name, attack_type, payload, response, vulnerability_found,
                      vulnerability_type, severity, details, recommendation))
                conn.commit()
                return True
        except Exception as e:
            self.console.print(f"[red]Error saving active scan result: {e}[/]")
            return False
    
    def get_active_scan_results(self, scan_id: str) -> List[Dict[str, Any]]:
        """Get all active scan results for a scan"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT tool_name, attack_type, payload, response, vulnerability_found,
                           vulnerability_type, severity, details, recommendation, created_at
                    FROM mcp_active_scan_results
                    WHERE scan_id = ?
                    ORDER BY created_at DESC
                """, (scan_id,))
                
                results = []
                for row in cursor.fetchall():
                    results.append({
                        "tool_name": row[0],
                        "attack_type": row[1],
                        "payload": row[2],
                        "response": row[3],
                        "vulnerability_found": bool(row[4]),
                        "vulnerability_type": row[5],
                        "severity": row[6],
                        "details": row[7],
                        "recommendation": row[8],
                        "created_at": row[9]
                    })
                return results
        except Exception as e:
            self.console.print(f"[red]Error getting active scan results: {e}[/]")
            return []
    
    def save_active_scan_batch(self, scan_id: str, findings: List[Dict[str, Any]]) -> bool:
        """Save multiple active scan findings at once"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                for finding in findings:
                    cursor.execute("""
                        INSERT INTO mcp_active_scan_results 
                        (scan_id, tool_name, attack_type, payload, response, vulnerability_found,
                         vulnerability_type, severity, details, recommendation)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        scan_id,
                        finding.get("tool_name", ""),
                        finding.get("attack_type", ""),
                        finding.get("payload", ""),
                        finding.get("response", ""),
                        finding.get("vulnerability_found", False),
                        finding.get("vulnerability_type"),
                        finding.get("severity"),
                        finding.get("details"),
                        finding.get("recommendation")
                    ))
                conn.commit()
                return True
        except Exception as e:
            self.console.print(f"[red]Error saving active scan batch: {e}[/]")
            return False
    
    # MCP Entity Tracking Methods (for poisoning detection)
    def track_mcp_entity(
        self,
        server_name: str,
        entity_name: str,
        entity_type: str,
        description: str,
        description_hash: str,
        scan_id: str
    ) -> Dict[str, Any]:
        """
        Track an MCP entity and detect changes (poisoning detection).
        
        Returns a dict with 'changed' (bool) and 'previous_description' (str or None)
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Check if entity exists
                cursor.execute("""
                    SELECT description_hash, description 
                    FROM mcp_entities 
                    WHERE server_name = ? AND entity_name = ? AND entity_type = ?
                """, (server_name, entity_name, entity_type))
                
                row = cursor.fetchone()
                
                if row:
                    # Entity exists - check if changed
                    old_hash, old_description = row
                    changed = old_hash != description_hash
                    
                    # Update last_seen and scan_id
                    cursor.execute("""
                        UPDATE mcp_entities 
                        SET description_hash = ?, description = ?, last_seen = CURRENT_TIMESTAMP, scan_id = ?
                        WHERE server_name = ? AND entity_name = ? AND entity_type = ?
                    """, (description_hash, description, scan_id, server_name, entity_name, entity_type))
                    
                    conn.commit()
                    
                    return {
                        "changed": changed,
                        "previous_description": old_description if changed else None
                    }
                else:
                    # New entity - insert
                    cursor.execute("""
                        INSERT INTO mcp_entities 
                        (server_name, entity_name, entity_type, description_hash, description, scan_id)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (server_name, entity_name, entity_type, description_hash, description, scan_id))
                    
                    conn.commit()
                    
                    return {
                        "changed": False,
                        "previous_description": None
                    }
                    
        except Exception as e:
            self.console.print(f"[red]Error tracking MCP entity: {e}[/]")
            return {"changed": False, "previous_description": None}
    
    def save_mcp_security_finding(
        self,
        scan_id: str,
        server_name: str,
        entity_name: str,
        entity_type: str,
        detector_type: str,
        severity: str,
        finding_details: Dict[str, Any]
    ) -> bool:
        """Save a security finding from MCP scan"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                details_json = json.dumps(finding_details)
                
                cursor.execute("""
                    INSERT INTO mcp_security_findings 
                    (scan_id, server_name, entity_name, entity_type, detector_type, severity, finding_details)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (scan_id, server_name, entity_name, entity_type, detector_type, severity, details_json))
                
                conn.commit()
                return True
                
        except Exception as e:
            self.console.print(f"[red]Error saving security finding: {e}[/]")
            return False
    
    # ============================================================================
    # MCP Inventory Methods (Hash-based tracking and change detection)
    # ============================================================================
    
    @staticmethod
    def generate_mcp_hash(server_config: Dict[str, Any]) -> str:
        """
        Generate SHA-256 hash for an MCP server configuration.
        
        Normalizes the config by:
        - Sorting keys
        - Removing non-essential fields (like headers with tokens)
        - Standardizing format
        
        Args:
            server_config: MCP server configuration dictionary
            
        Returns:
            SHA-256 hash string (hexdigest)
        """
        # Create a normalized copy for hashing
        normalized = {}
        
        # Include essential identifying fields
        normalized["type"] = server_config.get("type", "").lower()
        normalized["url"] = server_config.get("url", "").lower().rstrip("/")
        
        # For stdio servers, include command and args (sorted)
        if normalized["type"] == "stdio":
            normalized["command"] = server_config.get("command", "")
            args = server_config.get("args", [])
            normalized["args"] = sorted(args) if isinstance(args, list) else args
        
        # Normalize headers (remove sensitive values, sort keys)
        headers = server_config.get("headers", {})
        if headers:
            # Sort header keys and use placeholder for values (to detect header presence)
            normalized["headers_keys"] = sorted(headers.keys())
        
        # Convert to JSON string with sorted keys for consistency
        config_str = json.dumps(normalized, sort_keys=True, separators=(',', ':'))
        
        # Generate SHA-256 hash
        return hashlib.sha256(config_str.encode('utf-8')).hexdigest()
    
    def check_mcp_inventory(
        self, 
        server_config_hash: str
    ) -> Optional[Dict[str, Any]]:
        """
        Check if an MCP server exists in inventory by hash.
        
        Args:
            server_config_hash: SHA-256 hash of the server configuration
            
        Returns:
            Inventory record dict if found, None otherwise
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT id, server_name, server_config_hash, server_url, server_type,
                           server_config_json, first_seen, last_seen, last_scan_id,
                           previous_hash, change_detected, scan_count
                    FROM mcp_inventory
                    WHERE server_config_hash = ?
                """, (server_config_hash,))
                
                row = cursor.fetchone()
                if row:
                    return {
                        "id": row[0],
                        "server_name": row[1],
                        "server_config_hash": row[2],
                        "server_url": row[3],
                        "server_type": row[4],
                        "server_config_json": json.loads(row[5]) if row[5] else None,
                        "first_seen": row[6],
                        "last_seen": row[7],
                        "last_scan_id": row[8],
                        "previous_hash": row[9],
                        "change_detected": bool(row[10]),
                        "scan_count": row[11]
                    }
                
                return None
                
        except Exception as e:
            self.console.print(f"[red]Error checking MCP inventory: {e}[/]")
            return None
    
    def add_to_mcp_inventory(
        self,
        server_name: str,
        server_config: Dict[str, Any],
        server_config_hash: str,
        scan_id: str,
        change_detected: bool = False
    ) -> bool:
        """
        Add or update MCP server in inventory.
        
        Args:
            server_name: Name of the MCP server
            server_config: Full server configuration dictionary
            server_config_hash: SHA-256 hash of the normalized config
            scan_id: ID of the scan that discovered/updated this server
            change_detected: Whether a change was detected from previous scan
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Check if already exists
                existing = self.check_mcp_inventory(server_config_hash)
                
                if existing:
                    # Check if this is actually a different config (different hash)
                    if existing["server_config_hash"] != server_config_hash:
                        # Config changed - update with new hash and mark change
                        cursor.execute("""
                            UPDATE mcp_inventory
                            SET server_name = ?,
                                server_config_hash = ?,
                                server_url = ?,
                                server_type = ?,
                                server_config_json = ?,
                                last_seen = CURRENT_TIMESTAMP,
                                last_scan_id = ?,
                                previous_hash = ?,
                                change_detected = 1,
                                scan_count = scan_count + 1
                            WHERE server_config_hash = ?
                        """, (
                            server_name,
                            server_config_hash,
                            server_config.get("url", ""),
                            server_config.get("type", ""),
                            json.dumps(server_config),
                            scan_id,
                            existing["server_config_hash"],  # Store old hash as previous
                            existing["server_config_hash"]  # WHERE clause - match old hash
                        ))
                    else:
                        # Same config - just update last_seen and scan_count
                        cursor.execute("""
                            UPDATE mcp_inventory
                            SET server_name = ?,
                                last_seen = CURRENT_TIMESTAMP,
                                last_scan_id = ?,
                                change_detected = 0,
                                scan_count = scan_count + 1
                            WHERE server_config_hash = ?
                        """, (
                            server_name,
                            scan_id,
                            server_config_hash
                        ))
                else:
                    # Insert new record
                    cursor.execute("""
                        INSERT INTO mcp_inventory
                        (server_name, server_config_hash, server_url, server_type,
                         server_config_json, last_scan_id, change_detected)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (
                        server_name,
                        server_config_hash,
                        server_config.get("url", ""),
                        server_config.get("type", ""),
                        json.dumps(server_config),
                        scan_id,
                        change_detected
                    ))
                
                conn.commit()
                return True
                
        except Exception as e:
            self.console.print(f"[red]Error adding to MCP inventory: {e}[/]")
            return False
    
    def list_mcp_inventory(
        self,
        limit: int = 50,
        offset: int = 0,
        change_detected_only: bool = False
    ) -> List[Dict[str, Any]]:
        """
        List MCP servers in inventory.
        
        Args:
            limit: Maximum number of records to return
            offset: Number of records to skip
            change_detected_only: If True, only return servers with detected changes
            
        Returns:
            List of inventory records
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                query = """
                    SELECT id, server_name, server_config_hash, server_url, server_type,
                           first_seen, last_seen, last_scan_id, previous_hash,
                           change_detected, scan_count
                    FROM mcp_inventory
                    WHERE 1=1
                """
                params = []
                
                if change_detected_only:
                    query += " AND change_detected = 1"
                
                query += " ORDER BY last_seen DESC LIMIT ? OFFSET ?"
                params.extend([limit, offset])
                
                cursor.execute(query, params)
                
                results = []
                for row in cursor.fetchall():
                    results.append({
                        "id": row[0],
                        "server_name": row[1],
                        "server_config_hash": row[2],
                        "server_url": row[3],
                        "server_type": row[4],
                        "first_seen": row[5],
                        "last_seen": row[6],
                        "last_scan_id": row[7],
                        "previous_hash": row[8],
                        "change_detected": bool(row[9]),
                        "scan_count": row[10]
                    })
                
                return results
                
        except Exception as e:
            self.console.print(f"[red]Error listing MCP inventory: {e}[/]")
            return []
    
    def get_mcp_inventory_by_name(self, server_name: str) -> Optional[Dict[str, Any]]:
        """
        Get MCP inventory record by server name.
        
        Args:
            server_name: Name of the MCP server
            
        Returns:
            Inventory record dict if found, None otherwise
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT id, server_name, server_config_hash, server_url, server_type,
                           server_config_json, first_seen, last_seen, last_scan_id,
                           previous_hash, change_detected, scan_count
                    FROM mcp_inventory
                    WHERE server_name = ?
                    ORDER BY last_seen DESC
                    LIMIT 1
                """, (server_name,))
                
                row = cursor.fetchone()
                if row:
                    return {
                        "id": row[0],
                        "server_name": row[1],
                        "server_config_hash": row[2],
                        "server_url": row[3],
                        "server_type": row[4],
                        "server_config_json": json.loads(row[5]) if row[5] else None,
                        "first_seen": row[6],
                        "last_seen": row[7],
                        "last_scan_id": row[8],
                        "previous_hash": row[9],
                        "change_detected": bool(row[10]),
                        "scan_count": row[11]
                    }
                
                return None
                
        except Exception as e:
            self.console.print(f"[red]Error getting MCP inventory by name: {e}[/]")
            return None
    
    def get_mcp_security_findings(self, scan_id: str) -> List[Dict[str, Any]]:
        """Get all security findings for a scan"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT server_name, entity_name, entity_type, detector_type, severity, finding_details, created_at
                    FROM mcp_security_findings
                    WHERE scan_id = ?
                    ORDER BY 
                        CASE severity 
                            WHEN 'high' THEN 1 
                            WHEN 'medium' THEN 2 
                            WHEN 'low' THEN 3 
                            ELSE 4 
                        END,
                        created_at DESC
                """, (scan_id,))
                
                findings = []
                for row in cursor.fetchall():
                    try:
                        details = json.loads(row[5]) if row[5] else {}
                    except:
                        details = {}
                    
                    findings.append({
                        "server_name": row[0],
                        "entity_name": row[1],
                        "entity_type": row[2],
                        "detector_type": row[3],
                        "severity": row[4],
                        "details": details,
                        "created_at": row[6]
                    })
                
                return findings
                
        except Exception as e:
            self.console.print(f"[red]Error getting security findings: {e}[/]")
            return []
    
    # Dataset Analysis Methods
    def save_dataset_analysis(
        self,
        analysis_id: str,
        file_name: str,
        status: str,
        file_size: int = None,
        results: Dict[str, Any] = None,
        is_poisoned: bool = None,
        security_score: int = None,
        total_entries: int = None,
        suspicious_entries: int = None,
        message: str = None,
        created_by: str = "anonymous",
        completed_at: str = None,
        scan_name: str = None
    ) -> bool:
        """Save dataset analysis to database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                results_json = json.dumps(results) if results else None
                
                cursor.execute("""
                    INSERT OR REPLACE INTO dataset_analyses 
                    (analysis_id, file_name, status, file_size, results_json, is_poisoned, 
                     security_score, total_entries, suspicious_entries, message, created_by, completed_at, scan_name)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (analysis_id, file_name, status, file_size, results_json, is_poisoned,
                      security_score, total_entries, suspicious_entries, message, created_by, completed_at, scan_name))
                
                conn.commit()
                return True
                
        except Exception as e:
            self.console.print(f"[red]Error saving dataset analysis: {e}[/]")
            return False
    
    def get_dataset_analysis(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        """Get dataset analysis by ID"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT analysis_id, file_name, status, file_size, results_json, is_poisoned,
                           security_score, total_entries, suspicious_entries, message,
                           created_by, created_at, completed_at
                    FROM dataset_analyses 
                    WHERE analysis_id = ?
                """, (analysis_id,))
                
                row = cursor.fetchone()
                if row:
                    results = json.loads(row[4]) if row[4] else None
                    return {
                        "analysis_id": row[0],
                        "file_name": row[1],
                        "status": row[2],
                        "file_size": row[3],
                        "results": results,
                        "is_poisoned": bool(row[5]) if row[5] is not None else None,
                        "security_score": row[6],
                        "total_entries": row[7],
                        "suspicious_entries": row[8],
                        "message": row[9],
                        "created_by": row[10],
                        "created_at": row[11],
                        "completed_at": row[12]
                    }
                
                return None
                
        except Exception as e:
            self.console.print(f"[red]Error getting dataset analysis: {e}[/]")
            return None
    
    def list_dataset_analyses(
        self,
        user_id: str = None,
        status: str = None,
        limit: int = 50,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """List dataset analyses with pagination and filtering"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                query = """
                    SELECT analysis_id, file_name, status, file_size, is_poisoned,
                           security_score, total_entries, suspicious_entries, message,
                           created_by, created_at, completed_at, results_json, scan_name
                    FROM dataset_analyses 
                    WHERE 1=1
                """
                params = []
                
                if user_id:
                    query += " AND created_by = ?"
                    params.append(user_id)
                
                if status:
                    query += " AND status = ?"
                    params.append(status)
                
                query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
                params.extend([limit, offset])
                
                cursor.execute(query, params)
                
                results = []
                for row in cursor.fetchall():
                    # Parse results JSON if present
                    analysis_results = None
                    if row[12]:  # results_json column
                        try:
                            analysis_results = json.loads(row[12])
                        except:
                            pass
                    
                    results.append({
                        "analysis_id": row[0],
                        "file_name": row[1],
                        "status": row[2],
                        "file_size": row[3],
                        "is_poisoned": bool(row[4]) if row[4] is not None else None,
                        "security_score": row[5],
                        "total_entries": row[6],
                        "suspicious_entries": row[7],
                        "message": row[8],
                        "created_by": row[9],
                        "created_at": row[10],
                        "completed_at": row[11],
                        "results": analysis_results,
                        "scan_name": row[13] if len(row) > 13 else None  # scan_name column
                    })
                
                return results
                
        except Exception as e:
            self.console.print(f"[red]Error listing dataset analyses: {e}[/]")
            return []
    
    def update_dataset_analysis_status(
        self,
        analysis_id: str,
        status: str,
        results: Dict[str, Any] = None,
        is_poisoned: bool = None,
        security_score: int = None,
        total_entries: int = None,
        suspicious_entries: int = None,
        message: str = None,
        completed_at: str = None
    ) -> bool:
        """Update dataset analysis status and results"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                results_json = json.dumps(results) if results else None
                
                cursor.execute("""
                    UPDATE dataset_analyses 
                    SET status = ?, results_json = ?, is_poisoned = ?, security_score = ?,
                        total_entries = ?, suspicious_entries = ?, message = ?, completed_at = ?
                    WHERE analysis_id = ?
                """, (status, results_json, is_poisoned, security_score, total_entries,
                      suspicious_entries, message, completed_at, analysis_id))
                
                conn.commit()
                return True
                
        except Exception as e:
            self.console.print(f"[red]Error updating dataset analysis: {e}[/]")
            return False
    
    # Dataset Inventory Methods
    def save_dataset_inventory(
        self,
        dataset_id: str,
        name: str,
        file_name: str,
        file_path: str,
        file_size: int,
        file_format: str,
        description: str = None,
        row_count: int = None,
        column_count: int = None,
        created_by: str = "anonymous"
    ) -> bool:
        """Save dataset to inventory"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    INSERT INTO dataset_inventory 
                    (dataset_id, name, description, file_name, file_path, file_size, file_format,
                     row_count, column_count, created_by)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (dataset_id, name, description, file_name, file_path, file_size, file_format,
                      row_count, column_count, created_by))
                
                conn.commit()
                return True
                
        except Exception as e:
            self.console.print(f"[red]Error saving dataset to inventory: {e}[/]")
            return False
    
    def get_dataset_inventory(self, dataset_id: str) -> Optional[Dict[str, Any]]:
        """Get dataset from inventory by ID"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT dataset_id, name, description, file_name, file_path, file_size, file_format,
                           row_count, column_count, created_by, created_at, updated_at
                    FROM dataset_inventory 
                    WHERE dataset_id = ?
                """, (dataset_id,))
                
                row = cursor.fetchone()
                if row:
                    return {
                        "dataset_id": row[0],
                        "name": row[1],
                        "description": row[2],
                        "file_name": row[3],
                        "file_path": row[4],
                        "file_size": row[5],
                        "file_format": row[6],
                        "row_count": row[7],
                        "column_count": row[8],
                        "created_by": row[9],
                        "created_at": row[10],
                        "updated_at": row[11]
                    }
                
        except Exception as e:
            self.console.print(f"[red]Error getting dataset from inventory: {e}[/]")
        
        return None
    
    def list_dataset_inventory(
        self,
        limit: int = 100,
        offset: int = 0,
        created_by: str = None
    ) -> List[Dict[str, Any]]:
        """List datasets in inventory with pagination and filtering"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                query = """
                    SELECT dataset_id, name, description, file_name, file_path, file_size, file_format,
                           row_count, column_count, created_by, created_at, updated_at
                    FROM dataset_inventory 
                    WHERE 1=1
                """
                params = []
                
                if created_by:
                    query += " AND created_by = ?"
                    params.append(created_by)
                
                query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
                params.extend([limit, offset])
                
                cursor.execute(query, params)
                
                results = []
                for row in cursor.fetchall():
                    results.append({
                        "dataset_id": row[0],
                        "name": row[1],
                        "description": row[2],
                        "file_name": row[3],
                        "file_path": row[4],
                        "file_size": row[5],
                        "file_format": row[6],
                        "row_count": row[7],
                        "column_count": row[8],
                        "created_by": row[9],
                        "created_at": row[10],
                        "updated_at": row[11]
                    })
                
                return results
                
        except Exception as e:
            self.console.print(f"[red]Error listing dataset inventory: {e}[/]")
            return []
    
    def delete_dataset_inventory(self, dataset_id: str) -> bool:
        """Delete dataset from inventory"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    DELETE FROM dataset_inventory WHERE dataset_id = ?
                """, (dataset_id,))
                
                conn.commit()
                return True
                
        except Exception as e:
            self.console.print(f"[red]Error deleting dataset from inventory: {e}[/]")
            return False
    
    # Model Inventory Methods
    def invalidate_model_inventory_cache(self, model_id: str = None):
        """Invalidate model inventory cache.
        
        Args:
            model_id: If provided, only invalidate this model. Otherwise clear all.
        """
        global _model_inventory_list_cache, _model_inventory_cache
        # Always clear the list cache when any model changes
        _model_inventory_list_cache = None
        if model_id:
            _model_inventory_cache.pop(model_id, None)
        else:
            _model_inventory_cache.clear()
    
    def save_model_inventory(
        self,
        model_id: str,
        name: str,
        entry_type: str,
        provider: str,
        config: Dict[str, Any],
        description: str = None,
        model_identifier: str = None,
        metadata: Dict[str, Any] = None,
        use_case_answers: Dict[str, Any] = None,
        last_test_status: Dict[str, Any] = None,
        created_by: str = "anonymous"
    ) -> bool:
        """Save model to inventory"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                config_json = json.dumps(config) if config else "{}"
                metadata_json = json.dumps(metadata) if metadata else None
                use_case_answers_json = json.dumps(use_case_answers) if use_case_answers else None
                last_test_status_json = json.dumps(last_test_status) if last_test_status else None
                
                cursor.execute("""
                    INSERT OR REPLACE INTO model_inventory 
                    (model_id, name, description, entry_type, provider, model_identifier, 
                     config_json, metadata_json, use_case_answers_json, last_test_status_json, created_by, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """, (model_id, name, description, entry_type, provider, model_identifier,
                      config_json, metadata_json, use_case_answers_json, last_test_status_json, created_by))
                
                conn.commit()
                
                # Invalidate cache
                self.invalidate_model_inventory_cache(model_id)
                
                return True
                
        except Exception as e:
            self.console.print(f"[red]Error saving model to inventory: {e}[/]")
            return False
    
    def get_model_inventory(self, model_id: str, use_cache: bool = True) -> Optional[Dict[str, Any]]:
        """Get model from inventory by ID.
        
        Args:
            model_id: The model ID to look up
            use_cache: If True, check in-memory cache first (default True)
        """
        global _model_inventory_cache
        
        # Check cache first
        if use_cache and model_id in _model_inventory_cache:
            return _model_inventory_cache[model_id]
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT model_id, name, description, entry_type, provider, model_identifier,
                           config_json, metadata_json, use_case_answers_json, last_test_status_json,
                           created_by, created_at, updated_at
                    FROM model_inventory
                    WHERE model_id = ?
                """, (model_id,))
                
                row = cursor.fetchone()
                if row:
                    result = {
                        "id": row[0],
                        "name": row[1],
                        "description": row[2],
                        "entry_type": row[3],
                        "provider": row[4],
                        "model_id": row[5],
                        "config": json.loads(row[6]) if row[6] else {},
                        "metadata": json.loads(row[7]) if row[7] else {},
                        "use_case_answers": json.loads(row[8]) if row[8] else None,
                        "last_test_status": json.loads(row[9]) if row[9] else None,
                        "created_by": row[10],
                        "created_at": row[11],
                        "updated_at": row[12]
                    }
                    
                    # Cache the result (with LRU eviction)
                    if len(_model_inventory_cache) >= _MODEL_CACHE_MAX_SIZE:
                        oldest_key = next(iter(_model_inventory_cache))
                        del _model_inventory_cache[oldest_key]
                    _model_inventory_cache[model_id] = result
                    
                    return result
                
                return None
                
        except Exception as e:
            self.console.print(f"[red]Error getting model from inventory: {e}[/]")
            return None
    
    def list_model_inventory(self, created_by: str = None, use_cache: bool = True) -> List[Dict[str, Any]]:
        """List all models in inventory with last successful scan info.
        
        Args:
            created_by: Filter by creator (if None, returns all models)
            use_cache: If True and created_by is None, use cached list (default True)
        """
        global _model_inventory_list_cache
        
        # Only use cache for full list (no filter)
        if use_cache and created_by is None and _model_inventory_list_cache is not None:
            return _model_inventory_list_cache
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Simple query to get models with last_reviewed_at from the table itself
                base_query = """
                    SELECT 
                        model_id, name, description, entry_type, provider, model_identifier,
                        config_json, metadata_json, use_case_answers_json, last_test_status_json,
                        created_by, created_at, updated_at, last_reviewed_at
                    FROM model_inventory
                """
                
                if created_by:
                    cursor.execute(base_query + """
                        WHERE created_by = ?
                        ORDER BY created_at DESC
                    """, (created_by,))
                else:
                    cursor.execute(base_query + """
                        ORDER BY created_at DESC
                    """)
                
                models = []
                for row in cursor.fetchall():
                    models.append({
                        "id": row[0],
                        "name": row[1],
                        "description": row[2],
                        "entry_type": row[3],
                        "provider": row[4],
                        "model_id": row[5],
                        "config": json.loads(row[6]) if row[6] else {},
                        "metadata": json.loads(row[7]) if row[7] else {},
                        "use_case_answers": json.loads(row[8]) if row[8] else None,
                        "last_test_status": json.loads(row[9]) if row[9] else None,
                        "created_by": row[10],
                        "created_at": row[11],
                        "updated_at": row[12],
                        "last_reviewed_at": row[13]  # Timestamp of last successful scan (or None)
                    })
                
                # Cache the full list (no filter)
                if created_by is None:
                    _model_inventory_list_cache = models
                
                return models
                
        except Exception as e:
            self.console.print(f"[red]Error listing models from inventory: {e}[/]")
            return []
    
    def delete_model_inventory(self, model_id: str) -> bool:
        """Delete model from inventory"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    DELETE FROM model_inventory WHERE model_id = ?
                """, (model_id,))
                
                conn.commit()
                
                # Invalidate cache
                self.invalidate_model_inventory_cache(model_id)
                
                return True
                
        except Exception as e:
            self.console.print(f"[red]Error deleting model from inventory: {e}[/]")
            return False
    
    def mark_model_reviewed(self, model_id: str) -> bool:
        """Mark a model as reviewed by updating last_reviewed_at timestamp"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    UPDATE model_inventory 
                    SET last_reviewed_at = CURRENT_TIMESTAMP
                    WHERE model_id = ?
                """, (model_id,))
                
                conn.commit()
                
                # Invalidate cache
                self.invalidate_model_inventory_cache(model_id)
                
                return cursor.rowcount > 0
                
        except Exception as e:
            self.console.print(f"[red]Error marking model as reviewed: {e}[/]")
            return False
    
    # ========== MCP Tools Inventory Methods ==========
    
    def save_mcp_tool(
        self,
        id: str,
        tool_id: str,
        tool_name: str,
        server_url: str,
        server_type: str = "http",
        description: str = None,
        headers: Dict[str, str] = None,
        tenant_id: str = None,
        source_user_id: str = None,
        created_by: str = "system"
    ) -> bool:
        """Save an MCP tool to inventory"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                headers_json = json.dumps(headers) if headers else None
                
                cursor.execute("""
                    INSERT OR REPLACE INTO mcp_tools_inventory
                    (id, tool_id, tool_name, description, server_url, server_type, 
                     headers_json, tenant_id, source_user_id, created_by)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (id, tool_id, tool_name, description, server_url, server_type,
                      headers_json, tenant_id, source_user_id, created_by))
                
                conn.commit()
                return True
                
        except Exception as e:
            self.console.print(f"[red]Error saving MCP tool: {e}[/]")
            return False
    
    def get_mcp_tool(self, tool_id: str) -> Optional[Dict[str, Any]]:
        """Get MCP tool from inventory by ID"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT id, tool_id, tool_name, description, server_url, server_type,
                           headers_json, tenant_id, source_user_id, created_by, created_at
                    FROM mcp_tools_inventory
                    WHERE id = ? OR tool_id = ?
                """, (tool_id, tool_id))
                
                row = cursor.fetchone()
                if row:
                    headers = {}
                    if row[6]:
                        try:
                            headers = json.loads(row[6])
                        except:
                            pass
                    
                    return {
                        "id": row[0],
                        "tool_id": row[1],
                        "tool_name": row[2],
                        "description": row[3] or "",
                        "server_url": row[4],
                        "server_type": row[5] or "http",
                        "headers": headers,
                        "tenant_id": row[7] or "",
                        "source_user_id": row[8] or "",
                        "created_by": row[9] or "system",
                        "created_at": row[10] or ""
                    }
                
                return None
                
        except Exception as e:
            self.console.print(f"[red]Error getting MCP tool: {e}[/]")
            return None
    
    def list_mcp_tools(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """List all MCP tools in inventory"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT id, tool_id, tool_name, description, server_url, server_type,
                           headers_json, tenant_id, source_user_id, created_by, created_at
                    FROM mcp_tools_inventory
                    ORDER BY tool_name ASC
                    LIMIT ? OFFSET ?
                """, (limit, offset))
                
                tools = []
                for row in cursor.fetchall():
                    headers = {}
                    if row[6]:
                        try:
                            headers = json.loads(row[6])
                        except:
                            pass
                    
                    tools.append({
                        "id": row[0],
                        "tool_id": row[1],
                        "tool_name": row[2],
                        "description": row[3] or "",
                        "server_url": row[4],
                        "server_type": row[5] or "http",
                        "headers": headers,
                        "tenant_id": row[7] or "",
                        "source_user_id": row[8] or "",
                        "created_by": row[9] or "system",
                        "created_at": row[10] or ""
                    })
                
                return tools
                
        except Exception as e:
            self.console.print(f"[red]Error listing MCP tools: {e}[/]")
            return []
    
    def delete_mcp_tool(self, tool_id: str) -> bool:
        """Delete MCP tool from inventory"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    DELETE FROM mcp_tools_inventory WHERE id = ? OR tool_id = ?
                """, (tool_id, tool_id))
                
                conn.commit()
                return cursor.rowcount > 0
                
        except Exception as e:
            self.console.print(f"[red]Error deleting MCP tool: {e}[/]")
            return False
    
    # ========== Role Management Methods ==========
    
    def list_roles(self) -> List[Dict[str, Any]]:
        """List all roles"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT role_id, role_name, display_name, description, permissions_json,
                           is_system_role, created_by, created_at, updated_at
                    FROM roles
                    ORDER BY is_system_role DESC, display_name ASC
                """)
                
                roles = []
                for row in cursor.fetchall():
                    roles.append({
                        "role_id": row[0],
                        "role_name": row[1],
                        "display_name": row[2],
                        "description": row[3],
                        "permissions": json.loads(row[4]),
                        "is_system_role": bool(row[5]),
                        "created_by": row[6],
                        "created_at": row[7],
                        "updated_at": row[8]
                    })
                
                return roles
        except Exception as e:
            self.console.print(f"[red]Error listing roles: {e}[/]")
            return []
    
    def create_role(self, role_name: str, display_name: str, description: str, 
                   permissions: List[str], created_by: str) -> Optional[int]:
        """Create a new role"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO roles (role_name, display_name, description, permissions_json, is_system_role, created_by)
                    VALUES (?, ?, ?, ?, 0, ?)
                """, (role_name, display_name, description, json.dumps(permissions), created_by))
                
                conn.commit()
                return cursor.lastrowid
        except Exception as e:
            self.console.print(f"[red]Error creating role: {e}[/]")
            return None
    
    def update_role(self, role_id: int, display_name: str, description: str, 
                   permissions: List[str]) -> bool:
        """Update a role (cannot update system roles)"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Check if it's a system role
                cursor.execute("SELECT is_system_role FROM roles WHERE role_id = ?", (role_id,))
                row = cursor.fetchone()
                if not row:
                    return False
                if row[0]:  # is_system_role
                    self.console.print(f"[yellow]Cannot update system role[/]")
                    return False
                
                cursor.execute("""
                    UPDATE roles 
                    SET display_name = ?, description = ?, permissions_json = ?, 
                        updated_at = CURRENT_TIMESTAMP
                    WHERE role_id = ?
                """, (display_name, description, json.dumps(permissions), role_id))
                
                conn.commit()
                return True
        except Exception as e:
            self.console.print(f"[red]Error updating role: {e}[/]")
            return False
    
    def delete_role(self, role_id: int) -> bool:
        """Delete a role (cannot delete system roles)"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Check if it's a system role
                cursor.execute("SELECT is_system_role FROM roles WHERE role_id = ?", (role_id,))
                row = cursor.fetchone()
                if not row:
                    return False
                if row[0]:  # is_system_role
                    self.console.print(f"[yellow]Cannot delete system role[/]")
                    return False
                
                # Delete role and its assignments
                cursor.execute("DELETE FROM user_role_assignments WHERE role_id = ?", (role_id,))
                cursor.execute("DELETE FROM roles WHERE role_id = ?", (role_id,))
                
                conn.commit()
                return True
        except Exception as e:
            self.console.print(f"[red]Error deleting role: {e}[/]")
            return False
    
    def assign_role_to_user(self, user_id: str, role_id: int, assigned_by: str) -> bool:
        """Assign a role to a user"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR IGNORE INTO user_role_assignments (user_id, role_id, assigned_by)
                    VALUES (?, ?, ?)
                """, (user_id, role_id, assigned_by))
                
                conn.commit()
                return True
        except Exception as e:
            self.console.print(f"[red]Error assigning role to user: {e}[/]")
            return False
    
    def remove_role_from_user(self, user_id: str, role_id: int) -> bool:
        """Remove a role from a user"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    DELETE FROM user_role_assignments 
                    WHERE user_id = ? AND role_id = ?
                """, (user_id, role_id))
                
                conn.commit()
                return True
        except Exception as e:
            self.console.print(f"[red]Error removing role from user: {e}[/]")
            return False
    
    def get_user_roles(self, user_id: str) -> List[Dict[str, Any]]:
        """Get all roles assigned to a user"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT r.role_id, r.role_name, r.display_name, r.description, 
                           r.permissions_json, r.is_system_role, ura.assigned_at
                    FROM roles r
                    INNER JOIN user_role_assignments ura ON r.role_id = ura.role_id
                    WHERE ura.user_id = ?
                    ORDER BY r.is_system_role DESC, r.display_name ASC
                """, (user_id,))
                
                roles = []
                for row in cursor.fetchall():
                    roles.append({
                        "role_id": row[0],
                        "role_name": row[1],
                        "display_name": row[2],
                        "description": row[3],
                        "permissions": json.loads(row[4]),
                        "is_system_role": bool(row[5]),
                        "assigned_at": row[6]
                    })
                
                return roles
        except Exception as e:
            self.console.print(f"[red]Error getting user roles: {e}[/]")
            return []
    
    def get_all_user_assignments(self) -> List[Dict[str, Any]]:
        """Get all user-role assignments"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT ura.assignment_id, ura.user_id, r.role_id, r.role_name, 
                           r.display_name, ura.assigned_by, ura.assigned_at
                    FROM user_role_assignments ura
                    INNER JOIN roles r ON ura.role_id = r.role_id
                    ORDER BY ura.user_id ASC, r.display_name ASC
                """)
                
                assignments = []
                for row in cursor.fetchall():
                    assignments.append({
                        "assignment_id": row[0],
                        "user_id": row[1],
                        "role_id": row[2],
                        "role_name": row[3],
                        "display_name": row[4],
                        "assigned_by": row[5],
                        "assigned_at": row[6]
                    })
                
                return assignments
        except Exception as e:
            self.console.print(f"[red]Error getting user assignments: {e}[/]")
            return []
    
    def get_available_permissions(self) -> List[str]:
        """Get list of all available permissions in the system"""
        return [
            'scan:run:proxy',
            'scan:run:opensource',
            'scan:run:onboarded',
            'scan:view:own',
            'scan:view:all',
            'scan:view:details:own',
            'scan:view:details:all',
            'dataset:manage',
            'model:view:own',
            'model:view:all',
            'model:edit:own',
            'model:edit:all',
            'model:delete:own',
            'model:delete:all',
            'mcp:run',
            'mcp:view:own',
            'mcp:view:all',
            'mcp:cancel:own',
            'mcp:cancel:all',
            'dataset:run',
            'dataset:view:own',
            'dataset:view:all',
            'dataset:cancel:own',
            'dataset:cancel:all',
        ]
    
    # ==========================================
    # Agents Inventory Methods
    # ==========================================
    
    def save_discovered_agents(
        self,
        discovery_id: str,
        repo_url: str,
        branch: str,
        agents: List[Dict[str, Any]],
        discovered_by: str = "anonymous"
    ) -> bool:
        """Save discovered agents to database with deduplication"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Extract repo name from URL
                repo_name = repo_url.split("/")[-1].replace(".git", "")
                
                new_agents = 0
                updated_agents = 0
                
                for agent in agents:
                    agent_name = agent.get('name', 'Unknown Agent')
                    file_path = agent.get('file_path', '')
                    
                    # Check if agent already exists (same repo, file, name)
                    cursor.execute("""
                        SELECT id, discovered_at FROM agents_inventory 
                        WHERE repo_url = ? AND file_path = ? AND agent_name = ?
                    """, (repo_url, file_path, agent_name))
                    
                    existing = cursor.fetchone()
                    
                    if existing:
                        # Update existing agent
                        cursor.execute("""
                            UPDATE agents_inventory 
                            SET framework = ?,
                                description = ?,
                                capabilities_json = ?,
                                tools_used_json = ?,
                                llm_provider = ?,
                                security_concerns_json = ?,
                                code_snippet = ?,
                                github_url = ?,
                                branch = ?,
                                last_updated = CURRENT_TIMESTAMP,
                                discovery_id = ?
                            WHERE id = ?
                        """, (
                            agent.get('framework', 'unknown'),
                            agent.get('description'),
                            json.dumps(agent.get('capabilities', [])),
                            json.dumps(agent.get('tools_used', [])),
                            agent.get('llm_provider'),
                            json.dumps(agent.get('security_concerns', [])),
                            agent.get('code_snippet'),
                            agent.get('github_url'),
                            branch,
                            discovery_id,
                            existing[0]
                        ))
                        updated_agents += 1
                    else:
                        # Insert new agent
                        cursor.execute("""
                            INSERT INTO agents_inventory 
                            (discovery_id, repo_url, repo_name, branch, agent_name, file_path, github_url, framework,
                             description, capabilities_json, tools_used_json, llm_provider,
                             security_concerns_json, code_snippet, discovered_by, discovered_at, last_updated)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                        """, (
                            f"{discovery_id}_{agent_name}",
                            repo_url,
                            repo_name,
                            branch,
                            agent_name,
                            file_path,
                            agent.get('github_url'),
                            agent.get('framework', 'unknown'),
                            agent.get('description'),
                            json.dumps(agent.get('capabilities', [])),
                            json.dumps(agent.get('tools_used', [])),
                            agent.get('llm_provider'),
                            json.dumps(agent.get('security_concerns', [])),
                            agent.get('code_snippet'),
                            discovered_by
                        ))
                        new_agents += 1
                
                conn.commit()
                
                if new_agents > 0 and updated_agents > 0:
                    self.console.print(f"[green]✓ Added {new_agents} new agent(s), updated {updated_agents} existing agent(s)[/]")
                elif new_agents > 0:
                    self.console.print(f"[green]✓ Added {new_agents} new agent(s) to inventory[/]")
                elif updated_agents > 0:
                    self.console.print(f"[green]✓ Updated {updated_agents} existing agent(s)[/]")
                else:
                    self.console.print(f"[yellow]⚠ No changes to inventory[/]")
                
                return True
                
        except Exception as e:
            self.console.print(f"[red]Error saving discovered agents: {e}[/]")
            import traceback
            traceback.print_exc()
            return False
    
    def get_agents_inventory(
        self,
        repo_url: str = None,
        framework: str = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """Get agents from inventory with optional filtering"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                query = """
                    SELECT id, discovery_id, repo_url, repo_name, branch, agent_name, file_path,
                           github_url, framework, description, capabilities_json, tools_used_json, llm_provider,
                           security_concerns_json, code_snippet, discovered_by, discovered_at, last_updated
                    FROM agents_inventory 
                    WHERE 1=1
                """
                params = []
                
                if repo_url:
                    query += " AND repo_url = ?"
                    params.append(repo_url)
                
                if framework:
                    query += " AND framework = ?"
                    params.append(framework)
                
                query += " ORDER BY discovered_at DESC LIMIT ? OFFSET ?"
                params.extend([limit, offset])
                
                cursor.execute(query, params)
                
                agents = []
                for row in cursor.fetchall():
                    agents.append({
                        "id": row[0],
                        "discovery_id": row[1],
                        "repo_url": row[2],
                        "repo_name": row[3],
                        "branch": row[4],
                        "name": row[5],
                        "file_path": row[6],
                        "github_url": row[7],
                        "framework": row[8],
                        "description": row[9],
                        "capabilities": json.loads(row[10]) if row[10] else [],
                        "tools_used": json.loads(row[11]) if row[11] else [],
                        "llm_provider": row[12],
                        "security_concerns": json.loads(row[13]) if row[13] else [],
                        "code_snippet": row[14],
                        "discovered_by": row[15],
                        "discovered_at": row[16],
                        "last_updated": row[17]
                    })
                
                return agents
                
        except Exception as e:
            self.console.print(f"[red]Error getting agents inventory: {e}[/]")
            return []
    
    def get_agent_stats(self) -> Dict[str, Any]:
        """Get statistics about discovered agents"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Total agents
                cursor.execute("SELECT COUNT(*) FROM agents_inventory")
                total_agents = cursor.fetchone()[0]
                
                # Agents by framework
                cursor.execute("""
                    SELECT framework, COUNT(*) as count 
                    FROM agents_inventory 
                    GROUP BY framework 
                    ORDER BY count DESC
                """)
                by_framework = {row[0]: row[1] for row in cursor.fetchall()}
                
                # Total repositories
                cursor.execute("SELECT COUNT(DISTINCT repo_url) FROM agents_inventory")
                total_repos = cursor.fetchone()[0]
                
                # Recent discoveries
                cursor.execute("""
                    SELECT COUNT(*) FROM agents_inventory 
                    WHERE discovered_at >= datetime('now', '-7 days')
                """)
                recent_discoveries = cursor.fetchone()[0]
                
                return {
                    "total_agents": total_agents,
                    "total_repositories": total_repos,
                    "by_framework": by_framework,
                    "recent_discoveries": recent_discoveries
                }
                
        except Exception as e:
            self.console.print(f"[red]Error getting agent stats: {e}[/]")
            return {
                "total_agents": 0,
                "total_repositories": 0,
                "by_framework": {},
                "recent_discoveries": 0
            }
    
    # ========== Manual Target Models Methods ==========
    
    def save_manual_target_model(
        self,
        model_id: str,
        name: str,
        model_type: str,
        config: Dict[str, Any],
        description: str = None,
        use_case: Dict[str, Any] = None,
        is_default: bool = False,
        created_by: str = "system"
    ) -> bool:
        """Save or update a manual target model"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    INSERT OR REPLACE INTO manual_target_models 
                    (id, name, model_type, config_json, description, use_case_json, is_default, created_by, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """, (
                    model_id,
                    name,
                    model_type,
                    json.dumps(config),
                    description,
                    json.dumps(use_case) if use_case else None,
                    1 if is_default else 0,
                    created_by
                ))
                
                conn.commit()
                return True
                
        except Exception as e:
            self.console.print(f"[red]Error saving manual target model: {e}[/]")
            return False
    
    def get_manual_target_model(self, model_id: str) -> Optional[Dict[str, Any]]:
        """Get a manual target model by ID"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT id, name, model_type, config_json, description, 
                           use_case_json, is_default, created_by, created_at
                    FROM manual_target_models
                    WHERE id = ?
                """, (model_id,))
                
                row = cursor.fetchone()
                if row:
                    return {
                        "id": row[0],
                        "name": row[1],
                        "model_type": row[2],
                        "config": json.loads(row[3]) if row[3] else {},
                        "description": row[4],
                        "use_case": json.loads(row[5]) if row[5] else {},
                        "is_default": bool(row[6]),
                        "created_by": row[7],
                        "created_at": row[8]
                    }
                return None
                
        except Exception as e:
            self.console.print(f"[red]Error getting manual target model: {e}[/]")
            return None
    
    def list_manual_target_models(self) -> List[Dict[str, Any]]:
        """List all manual target models"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT id, name, model_type, config_json, description, 
                           use_case_json, is_default, created_by, created_at
                    FROM manual_target_models
                    ORDER BY is_default DESC, name ASC
                """)
                
                models = []
                for row in cursor.fetchall():
                    models.append({
                        "id": row[0],
                        "name": row[1],
                        "model_type": row[2],
                        "config": json.loads(row[3]) if row[3] else {},
                        "description": row[4],
                        "use_case": json.loads(row[5]) if row[5] else {},
                        "is_default": bool(row[6]),
                        "created_by": row[7],
                        "created_at": row[8]
                    })
                
                return models
                
        except Exception as e:
            self.console.print(f"[red]Error listing manual target models: {e}[/]")
            return []
    
    def delete_manual_target_model(self, model_id: str) -> bool:
        """Delete a manual target model"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    DELETE FROM manual_target_models WHERE id = ?
                """, (model_id,))
                
                conn.commit()
                return cursor.rowcount > 0
                
        except Exception as e:
            self.console.print(f"[red]Error deleting manual target model: {e}[/]")
            return False
    
    def update_manual_target_model_use_case(self, model_id: str, use_case: Dict[str, Any]) -> bool:
        """Update the use case configuration for a manual target model"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    UPDATE manual_target_models 
                    SET use_case_json = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                """, (json.dumps(use_case), model_id))
                
                conn.commit()
                return cursor.rowcount > 0
                
        except Exception as e:
            self.console.print(f"[red]Error updating manual target model use case: {e}[/]")
            return False
    
    def seed_default_manual_target_models(self) -> int:
        """Seed default manual target models if they don't exist. Returns count of models seeded."""
        default_models = [
            {
                "id": "gemini-2.5-flash",
                "name": "Gemini 2.5 Flash (LLM Proxy)",
                "model_type": "proxy",
                "config": {"model_id": "gemini-2.5-flash"},
                "description": "Google's Gemini 2.5 Flash model via configurable LLM proxy"
            },
            {
                "id": "slap-default",
                "name": "Conversational AI Agent",
                "model_type": "custom_legacy",
                "config": {
                    "custom_type": "slap",
                    "base_url": "",
                    "tenant_id": ""
                },
                "description": "Conversational AI platform"
            },
            {
                "id": "guardrail-v1-default",
                "name": "Guardrail v1",
                "model_type": "custom_legacy",
                "config": {
                    "custom_type": "guardrail-v1",
                    "base_url": ""
                },
                "description": "LLM guardrail service"
            },
            {
                "id": "guardrail-v2-default",
                "name": "Guardrail v2",
                "model_type": "custom_legacy",
                "config": {
                    "custom_type": "guardrail-v2",
                    "base_url": ""
                },
                "description": "Guard-V3 guardrail"
            },
            {
                "id": "llm-guard-default",
                "name": "Guard (Guardrail + LLM)",
                "model_type": "custom_legacy",
                "config": {
                    "custom_type": "llm-guard",
                    "base_url": "",
                    "llm_endpoint": "",
                    "model_name": ""
                },
                "description": "Guardrail service with full LLM integration"
            }
        ]
        
        seeded_count = 0
        for model in default_models:
            # Check if model already exists
            existing = self.get_manual_target_model(model["id"])
            if not existing:
                self.save_manual_target_model(
                    model_id=model["id"],
                    name=model["name"],
                    model_type=model["model_type"],
                    config=model["config"],
                    description=model["description"],
                    is_default=True,
                    created_by="system"
                )
                seeded_count += 1
        
        return seeded_count
    # ── PRD Review Persistence ──────────────────────────────────────────────

    def save_prd_review(self, record: dict) -> bool:
        """Insert or replace a PRD review record."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO prd_reviews
                        (review_id, document_title, reference_id, author, status, progress,
                         created_by, created_at, reference_link)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    record["review_id"],
                    record.get("document_title"),
                    record.get("reference_id"),
                    record.get("author"),
                    record.get("status", "queued"),
                    record.get("progress", 0),
                    record.get("created_by"),
                    record.get("created_at"),
                    record.get("reference_link"),
                ))
                conn.commit()
            return True
        except Exception as e:
            self.console.print(f"[red]Error saving PRD review: {e}[/]")
            return False

    def update_prd_review(self, review_id: str, update: dict) -> bool:
        """Update status/progress/result fields for a PRD review.

        Split into two writes so a large content payload never prevents the
        status from being persisted.
        """
        import json as _json
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                # Step 1: small critical fields first
                cursor.execute("""
                    UPDATE prd_reviews
                    SET status       = ?,
                        progress     = ?,
                        completed_at = ?,
                        error        = ?
                    WHERE review_id = ?
                """, (
                    update.get("status"),
                    update.get("progress", 100),
                    update.get("completed_at"),
                    update.get("error"),
                    review_id,
                ))
                conn.commit()
                # Step 2: large content fields (download-critical first)
                has_content = any(update.get(k) for k in ("result", "_surfaces", "_sections_md", "_summary_md"))
                if has_content:
                    sections_val = update.get("_sections_md")
                    if isinstance(sections_val, list):
                        sections_val = _json.dumps(sections_val)
                    cursor.execute("""
                        UPDATE prd_reviews
                        SET surfaces_json = ?,
                            sections_md   = ?,
                            summary_md    = ?,
                            result_json   = ?
                        WHERE review_id = ?
                    """, (
                        _json.dumps(update["_surfaces"]) if update.get("_surfaces") else None,
                        sections_val,
                        update.get("_summary_md"),
                        _json.dumps(update["result"]) if update.get("result") else None,
                        review_id,
                    ))
                    conn.commit()
            return True
        except Exception as e:
            self.console.print(f"[red]Error updating PRD review: {e}[/]")
            return False

    def list_prd_reviews(self, created_by: str = None, limit: int = 200) -> list:
        """List PRD reviews newest first."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                if created_by:
                    cursor.execute("""
                        SELECT review_id, document_title, reference_id, author, status,
                               progress, created_by, created_at, completed_at, error, reference_link
                        FROM prd_reviews WHERE created_by = ?
                        ORDER BY created_at DESC LIMIT ?
                    """, (created_by, limit))
                else:
                    cursor.execute("""
                        SELECT review_id, document_title, reference_id, author, status,
                               progress, created_by, created_at, completed_at, error, reference_link
                        FROM prd_reviews ORDER BY created_at DESC LIMIT ?
                    """, (limit,))
                return [dict(r) for r in cursor.fetchall()]
        except Exception as e:
            self.console.print(f"[red]Error listing PRD reviews: {e}[/]")
            return []

    def get_prd_review(self, review_id: str) -> dict | None:
        """Fetch a single PRD review including result/surfaces."""
        import json as _json
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM prd_reviews WHERE review_id = ?", (review_id,))
                row = cursor.fetchone()
                if not row:
                    return None
                r = dict(row)
                if r.get("result_json"):
                    try:
                        r["result"] = _json.loads(r.pop("result_json"))
                    except Exception:
                        r.pop("result_json", None)
                if r.get("surfaces_json"):
                    try:
                        r["_surfaces"] = _json.loads(r.pop("surfaces_json"))
                    except Exception:
                        r.pop("surfaces_json", None)
                raw_sections = r.pop("sections_md", None)
                if raw_sections:
                    try:
                        r["_sections_md"] = _json.loads(raw_sections)
                    except Exception:
                        r["_sections_md"] = raw_sections
                else:
                    r["_sections_md"] = None
                r["_summary_md"] = r.pop("summary_md", None)
                return r
        except Exception as e:
            self.console.print(f"[red]Error fetching PRD review: {e}[/]")
            return None

    def delete_prd_review(self, review_id: str) -> bool:
        """Delete a PRD review."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("DELETE FROM prd_reviews WHERE review_id = ?", (review_id,))
                conn.commit()
            return True
        except Exception as e:
            self.console.print(f"[red]Error deleting PRD review: {e}[/]")
            return False

    # ── Harden Jobs ───────────────────────────────────────────────────────────

    def save_harden_job(self, record: dict) -> bool:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO harden_jobs
                    (job_id, prompt_name, system_prompt, context, reference_id, status, progress,
                     created_by, created_at, completed_at, security_addendum, error)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    record.get("job_id"), record.get("prompt_name"),
                    record.get("system_prompt"), record.get("context"),
                    record.get("reference_id"), record.get("status", "queued"),
                    record.get("progress", 0), record.get("created_by", "anonymous"),
                    record.get("created_at"), record.get("completed_at"),
                    record.get("security_addendum"), record.get("error"),
                ))
                conn.commit()
            return True
        except Exception as e:
            self.console.print(f"[red]Error saving harden job: {e}[/]")
            return False

    def update_harden_job(self, job_id: str, update: dict) -> bool:
        allowed = {"status", "progress", "completed_at", "security_addendum", "error"}
        fields = {k: v for k, v in update.items() if k in allowed}
        if not fields:
            return False
        try:
            with sqlite3.connect(self.db_path) as conn:
                set_clause = ", ".join(f"{k} = ?" for k in fields)
                conn.execute(
                    f"UPDATE harden_jobs SET {set_clause} WHERE job_id = ?",
                    (*fields.values(), job_id),
                )
                conn.commit()
            return True
        except Exception as e:
            self.console.print(f"[red]Error updating harden job: {e}[/]")
            return False

    def get_harden_job_by_reference_id(self, reference_id: str) -> Optional[dict]:
        """Return the most-recent harden_jobs row for a reference id, or None.

        Used by the JIRA→DB sync to skip tickets that already have an entry.
        """
        if not reference_id:
            return None
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                row = conn.execute(
                    "SELECT * FROM harden_jobs WHERE reference_id = ? "
                    "ORDER BY created_at DESC LIMIT 1",
                    (reference_id,),
                ).fetchone()
                return dict(row) if row else None
        except Exception as e:
            self.console.print(f"[red]Error reading harden_jobs by reference_id: {e}[/]")
            return None

    def list_harden_jobs(self, created_by: str = None, limit: int = 200) -> list:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                if created_by:
                    rows = conn.execute(
                        "SELECT * FROM harden_jobs WHERE created_by = ? ORDER BY created_at DESC LIMIT ?",
                        (created_by, limit),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM harden_jobs ORDER BY created_at DESC LIMIT ?",
                        (limit,),
                    ).fetchall()
                return [dict(r) for r in rows]
        except Exception as e:
            self.console.print(f"[red]Error listing harden jobs: {e}[/]")
            return []

    def get_harden_job(self, job_id: str) -> dict | None:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                row = conn.execute(
                    "SELECT * FROM harden_jobs WHERE job_id = ?", (job_id,)
                ).fetchone()
                return dict(row) if row else None
        except Exception as e:
            self.console.print(f"[red]Error fetching harden job: {e}[/]")
            return None

    # ── Skill Harden Jobs ─────────────────────────────────────────────────────

    def save_skill_harden_job(self, record: dict) -> bool:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO skill_harden_jobs
                    (job_id, repo_url, skill_name, branch, status, progress,
                     security_guidelines, full_content_preview, pr_url, pr_number, created_by, created_at,
                     completed_at, error, skill_content)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    record.get("job_id"), record.get("repo_url"), record.get("skill_name"),
                    record.get("branch"), record.get("status", "queued"), record.get("progress", 0),
                    record.get("security_guidelines"), record.get("full_content_preview"),
                    record.get("pr_url"), record.get("pr_number"),
                    record.get("created_by", "anonymous"), record.get("created_at"),
                    record.get("completed_at"), record.get("error"),
                    record.get("skill_content"),
                ))
                conn.commit()
            return True
        except Exception as e:
            self.console.print(f"[red]Error saving skill harden job: {e}[/]")
            return False

    def update_skill_harden_job(self, job_id: str, update: dict) -> bool:
        allowed = {"status", "progress", "completed_at", "security_guidelines", "full_content_preview", "pr_url", "pr_number", "error", "skill_content"}
        fields = {k: v for k, v in update.items() if k in allowed}
        if not fields:
            return False
        try:
            with sqlite3.connect(self.db_path) as conn:
                set_clause = ", ".join(f"{k} = ?" for k in fields)
                conn.execute(
                    f"UPDATE skill_harden_jobs SET {set_clause} WHERE job_id = ?",
                    (*fields.values(), job_id),
                )
                conn.commit()
            return True
        except Exception as e:
            self.console.print(f"[red]Error updating skill harden job: {e}[/]")
            return False

    def list_skill_harden_jobs(self, created_by: str = None, limit: int = 200) -> list:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                if created_by:
                    rows = conn.execute(
                        "SELECT * FROM skill_harden_jobs WHERE created_by = ? ORDER BY created_at DESC LIMIT ?",
                        (created_by, limit),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM skill_harden_jobs ORDER BY created_at DESC LIMIT ?",
                        (limit,),
                    ).fetchall()
                return [dict(r) for r in rows]
        except Exception as e:
            self.console.print(f"[red]Error listing skill harden jobs: {e}[/]")
            return []

    def get_skill_harden_job(self, job_id: str) -> dict | None:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                row = conn.execute(
                    "SELECT * FROM skill_harden_jobs WHERE job_id = ?", (job_id,)
                ).fetchone()
                return dict(row) if row else None
        except Exception as e:
            self.console.print(f"[red]Error fetching skill harden job: {e}[/]")
            return None

    def delete_skill_harden_job(self, job_id: str) -> bool:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("DELETE FROM skill_harden_jobs WHERE job_id = ?", (job_id,))
                conn.commit()
            return True
        except Exception as e:
            self.console.print(f"[red]Error deleting skill harden job: {e}[/]")
            return False

    def recover_stuck_skill_harden_jobs(self) -> int:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE skill_harden_jobs
                    SET status = 'failed',
                        error = 'Server restarted while job was in progress',
                        completed_at = CURRENT_TIMESTAMP
                    WHERE status IN ('queued', 'running')
                """)
                recovered_count = cursor.rowcount
                conn.commit()
                return recovered_count
        except Exception as e:
            self.console.print(f"[red]Error recovering stuck skill harden jobs: {e}[/]")
            return 0

    # ── JIRA Auto-Hardener Audit Log ──────────────────────────────────────────
    # One row per (ticket_key) we've ever posted a security-prompt comment on.
    # Acts as a second idempotency gate alongside the JIRA label, so we don't
    # re-comment even if the label add silently failed in a prior run.

    def has_jira_auto_harden_log(self, ticket_key: str, marker_label: Optional[str] = None) -> bool:
        """Return True if we've previously posted a comment for *this label version*.

        When marker_label is given, the DB row must also match that label — so bumping
        AUTO_HARDENER_LABEL forces re-processing even for already-logged tickets.
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                if marker_label:
                    row = conn.execute(
                        "SELECT 1 FROM jira_auto_harden_log WHERE ticket_key = ? AND marker_label = ? LIMIT 1",
                        (ticket_key, marker_label),
                    ).fetchone()
                else:
                    row = conn.execute(
                        "SELECT 1 FROM jira_auto_harden_log WHERE ticket_key = ? LIMIT 1",
                        (ticket_key,),
                    ).fetchone()
                return row is not None
        except Exception as e:
            self.console.print(f"[red]Error reading jira_auto_harden_log: {e}[/]")
            # On read error, prefer NOT to comment — safer to occasionally
            # miss a ticket than to spam the same ticket repeatedly.
            return True

    def insert_jira_auto_harden_log(
        self,
        ticket_key: str,
        commented_at: str,
        marker_label: str = "",
        prompt_hash: str = "",
        prompt_preview: str = "",
    ) -> bool:
        """Insert (or upsert) an audit row after a successful JIRA comment."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO jira_auto_harden_log
                    (ticket_key, commented_at, marker_label, prompt_hash, prompt_preview)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (ticket_key, commented_at, marker_label, prompt_hash, prompt_preview[:500]),
                )
                conn.commit()
            return True
        except Exception as e:
            self.console.print(f"[red]Error writing jira_auto_harden_log: {e}[/]")
            return False

    def list_jira_auto_harden_log(
        self,
        marker_label: Optional[str] = None,
        limit: int = 500,
    ) -> List[Dict[str, Any]]:
        """List jira_auto_harden_log rows, optionally filtered by marker_label.

        Pass marker_label='needs_info_skip' to get the tickets whose
        descriptions the auto-hardener couldn't parse — those need a human to
        look at the JIRA form output and either fix the form or extend the
        parser.
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                if marker_label:
                    rows = conn.execute(
                        "SELECT ticket_key, commented_at, marker_label, prompt_hash, prompt_preview "
                        "FROM jira_auto_harden_log WHERE marker_label = ? "
                        "ORDER BY commented_at DESC LIMIT ?",
                        (marker_label, limit),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT ticket_key, commented_at, marker_label, prompt_hash, prompt_preview "
                        "FROM jira_auto_harden_log "
                        "ORDER BY commented_at DESC LIMIT ?",
                        (limit,),
                    ).fetchall()
                return [dict(r) for r in rows]
        except Exception as e:
            self.console.print(f"[red]Error listing jira_auto_harden_log: {e}[/]")
            return []


    def insert_sandbox_log(self, entry: Dict[str, Any]) -> bool:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """INSERT INTO sandbox_logs
                       (ts, queried_by, query, agent_name, department,
                        inbound_decision, outbound_decision, llm_ok, final_response, steps_json)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        entry.get("ts", ""),
                        entry.get("queried_by", ""),
                        entry.get("query", ""),
                        entry.get("agent_name", ""),
                        entry.get("department", ""),
                        entry.get("inbound_decision", ""),
                        entry.get("outbound_decision", ""),
                        int(bool(entry.get("llm_ok"))),
                        entry.get("final_response", ""),
                        json.dumps(entry.get("steps", [])),
                    ),
                )
                conn.commit()
            return True
        except Exception as e:
            self.console.print(f"[red]Error inserting sandbox_log: {e}[/]")
            return False

    def get_sandbox_logs(self, limit: int = 200, offset: int = 0) -> List[Dict[str, Any]]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    "SELECT * FROM sandbox_logs ORDER BY id DESC LIMIT ? OFFSET ?",
                    (limit, offset),
                ).fetchall()
                result = []
                for r in rows:
                    d = dict(r)
                    try:
                        d["steps"] = json.loads(d.pop("steps_json", "[]"))
                    except Exception:
                        d["steps"] = []
                    result.append(d)
                return result
        except Exception as e:
            self.console.print(f"[red]Error reading sandbox_logs: {e}[/]")
            return []

    def clear_sandbox_logs(self) -> bool:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("DELETE FROM sandbox_logs")
                conn.commit()
            return True
        except Exception as e:
            self.console.print(f"[red]Error clearing sandbox_logs: {e}[/]")
            return False

    # ── MCP Security Reviews ──────────────────────────────────────────────────

    def create_mcp_security_review(
        self,
        repo_full_name: str,
        repo_url: str = "",
        triggered_by: str = "api",
    ) -> Optional[int]:
        """Create a pending security review record. Returns the new ID."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    """INSERT INTO mcp_security_reviews
                       (repo_full_name, repo_url, status, triggered_by)
                       VALUES (?, ?, 'pending', ?)""",
                    (repo_full_name, repo_url or "", triggered_by),
                )
                conn.commit()
                return cursor.lastrowid
        except Exception as e:
            self.console.print(f"[red]Error creating MCP security review: {e}[/]")
            return None

    def update_mcp_security_review(self, review_id: int, update: Dict[str, Any]) -> bool:
        """Update a security review record (status, counts, vulnerabilities JSON, etc.)"""
        if not update:
            return False
        allowed = {
            "status", "critical_count", "high_count", "medium_count", "low_count",
            "vulnerabilities", "summary", "risk_score", "error",
        }
        filtered = {k: v for k, v in update.items() if k in allowed}
        if not filtered:
            return False
        try:
            set_clause = ", ".join(f"{col} = ?" for col in filtered)
            values = list(filtered.values()) + [review_id]
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    f"UPDATE mcp_security_reviews SET {set_clause}, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                    values,
                )
                conn.commit()
            return True
        except Exception as e:
            self.console.print(f"[red]Error updating MCP security review {review_id}: {e}[/]")
            return False

    def get_mcp_security_review(self, repo_full_name: str) -> Optional[Dict[str, Any]]:
        """Get the latest review for a repo."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                row = conn.execute(
                    """SELECT * FROM mcp_security_reviews
                       WHERE repo_full_name = ?
                       ORDER BY created_at DESC LIMIT 1""",
                    (repo_full_name,),
                ).fetchone()
            return dict(row) if row else None
        except Exception as e:
            self.console.print(f"[red]Error fetching MCP security review for {repo_full_name}: {e}[/]")
            return None

    def list_mcp_security_reviews(self, limit: int = 200) -> List[Dict[str, Any]]:
        """List all reviews, latest first."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    "SELECT * FROM mcp_security_reviews ORDER BY created_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            return [dict(r) for r in rows]
        except Exception as e:
            self.console.print(f"[red]Error listing MCP security reviews: {e}[/]")
            return []

    def get_mcp_security_reviews_bulk(self, repo_names: List[str]) -> Dict[str, Dict[str, Any]]:
        """Return {repo_full_name: review} for a list of repos (latest per repo)."""
        if not repo_names:
            return {}
        try:
            placeholders = ", ".join("?" * len(repo_names))
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    f"""SELECT m.*
                        FROM mcp_security_reviews m
                        INNER JOIN (
                            SELECT repo_full_name, MAX(id) AS max_id
                            FROM mcp_security_reviews
                            WHERE repo_full_name IN ({placeholders})
                            GROUP BY repo_full_name
                        ) latest ON m.id = latest.max_id""",
                    repo_names,
                ).fetchall()
            return {r["repo_full_name"]: dict(r) for r in rows}
        except Exception as e:
            self.console.print(f"[red]Error bulk-fetching MCP security reviews: {e}[/]")
            return {}
