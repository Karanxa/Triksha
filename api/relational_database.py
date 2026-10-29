"""
Shared relational CRUD layer for PostgreSQL (via pg_database dialect translation).

Not instantiated directly — use PostgresDatabase or APIDatabase (SQLite).
"""

import json
import uuid
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from functools import lru_cache
from rich.console import Console
import os

# Simple in-memory cache for scan results
_scan_results_cache: Dict[str, Dict[str, Any]] = {}
_CACHE_MAX_SIZE = 50

# Cache for model inventory
_model_inventory_list_cache: Optional[List[Dict[str, Any]]] = None
_model_inventory_cache: Dict[str, Dict[str, Any]] = {}
_MODEL_CACHE_MAX_SIZE = 100


def safe_json_dumps(obj, **kwargs):
    """Safely serialize objects to JSON, handling Pydantic types and other non-serializable objects"""
    def default(o):
        if hasattr(o, 'model_dump'):
            return o.model_dump()
        elif hasattr(o, 'dict'):
            return o.dict()
        elif hasattr(o, '__str__') and 'pydantic' in str(type(o).__module__):
            return str(o)
        elif hasattr(o, '__dict__'):
            return o.__dict__
        else:
            return str(o)
    return json.dumps(obj, default=default, **kwargs)


class RelationalDatabase:
    """Base class for server-side SQL backends (PostgreSQL)."""

    def _get_connection(self):
        raise NotImplementedError("Subclass must implement _get_connection()")

    def _init_database(self):
        """Initialize database tables"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Benchmark results table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS benchmark_results (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    scan_id VARCHAR(255) UNIQUE NOT NULL,
                    scan_name TEXT NOT NULL,
                    status VARCHAR(50) NOT NULL,
                    results_json LONGTEXT,
                    metadata_json LONGTEXT,
                    created_by VARCHAR(255) DEFAULT 'anonymous',
                    reference_id VARCHAR(255),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP NULL,
                    KEY idx_scan_id (scan_id),
                    KEY idx_status (status),
                    KEY idx_created_by (created_by),
                    KEY idx_created_at (created_at)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)
            
            # Model configs table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS model_configs (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    model_name VARCHAR(255) UNIQUE NOT NULL,
                    config_json LONGTEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP NULL
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)
            
            # User activity table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS user_activity (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    api_key_hash VARCHAR(255) NOT NULL,
                    action VARCHAR(255) NOT NULL,
                    details_json LONGTEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP NULL,
                    KEY idx_api_key (api_key_hash),
                    KEY idx_timestamp (timestamp)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)
            
            # Scan sessions table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_sessions (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    scan_id VARCHAR(255) UNIQUE NOT NULL,
                    session_data_json LONGTEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP NULL
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)
            
            # MCP scans table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS mcp_scans (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    scan_id VARCHAR(255) UNIQUE NOT NULL,
                    file_name TEXT NOT NULL,
                    status VARCHAR(50) NOT NULL,
                    config_content LONGTEXT,
                    results_json LONGTEXT,
                    message TEXT,
                    created_by VARCHAR(255) DEFAULT 'anonymous',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NULL,
                    completed_at TIMESTAMP NULL,
                    timeout INT DEFAULT 30,
                    scan_name TEXT,
                    reference_id VARCHAR(255),
                    KEY idx_status (status),
                    KEY idx_created_by (created_by)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)
            
            # Dataset analyses table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS dataset_analyses (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    analysis_id VARCHAR(255) UNIQUE NOT NULL,
                    file_name TEXT NOT NULL,
                    status VARCHAR(50) NOT NULL,
                    file_size INT,
                    results_json LONGTEXT,
                    is_poisoned TINYINT(1),
                    security_score INT,
                    total_entries INT,
                    suspicious_entries INT,
                    message TEXT,
                    created_by VARCHAR(255) DEFAULT 'anonymous',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NULL,
                    completed_at TIMESTAMP NULL,
                    scan_name TEXT
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)
            
            # Dataset inventory table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS dataset_inventory (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    dataset_id VARCHAR(255) UNIQUE NOT NULL,
                    name TEXT NOT NULL,
                    description LONGTEXT,
                    file_name TEXT NOT NULL,
                    file_path VARCHAR(255) NOT NULL,
                    file_size INT NOT NULL,
                    file_format VARCHAR(50) NOT NULL,
                    row_count INT,
                    column_count INT,
                    created_by VARCHAR(255) DEFAULT 'anonymous',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP NULL
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)
            
            # MCP entities table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS mcp_entities (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    server_name VARCHAR(255) NOT NULL,
                    entity_name VARCHAR(255) NOT NULL,
                    entity_type VARCHAR(100) NOT NULL,
                    description_hash VARCHAR(255) NOT NULL,
                    description LONGTEXT,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP NULL,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP NULL,
                    scan_id VARCHAR(255),
                    UNIQUE KEY unique_entity (server_name, entity_name, entity_type),
                    KEY idx_server (server_name),
                    KEY idx_type (entity_type)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)
            
            # MCP security findings table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS mcp_security_findings (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    scan_id VARCHAR(255) NOT NULL,
                    server_name VARCHAR(255) NOT NULL,
                    entity_name VARCHAR(255) NOT NULL,
                    entity_type VARCHAR(100) NOT NULL,
                    detector_type VARCHAR(100) NOT NULL,
                    severity VARCHAR(50) NOT NULL,
                    finding_details LONGTEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NULL,
                    KEY idx_scan_id (scan_id),
                    KEY idx_severity (severity)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)
            
            # Model inventory table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS model_inventory (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    model_id VARCHAR(255) UNIQUE NOT NULL,
                    name TEXT NOT NULL,
                    description LONGTEXT,
                    entry_type VARCHAR(100) NOT NULL,
                    provider VARCHAR(100) NOT NULL,
                    model_identifier VARCHAR(255),
                    config_json LONGTEXT NOT NULL,
                    metadata_json LONGTEXT,
                    use_case_answers_json LONGTEXT,
                    last_test_status_json LONGTEXT,
                    created_by VARCHAR(255) DEFAULT 'anonymous',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP NULL,
                    KEY idx_provider (provider),
                    KEY idx_entry_type (entry_type)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)
            
            # Roles table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS roles (
                    role_id INT AUTO_INCREMENT PRIMARY KEY,
                    role_name VARCHAR(255) UNIQUE NOT NULL,
                    display_name VARCHAR(255) NOT NULL,
                    description TEXT,
                    permissions_json LONGTEXT NOT NULL,
                    is_system_role TINYINT(1) DEFAULT 0,
                    created_by VARCHAR(255) DEFAULT 'system',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP NULL
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)
            
            # User role assignments table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS user_role_assignments (
                    assignment_id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id VARCHAR(255) NOT NULL,
                    role_id INT NOT NULL,
                    assigned_by VARCHAR(255),
                    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NULL,
                    UNIQUE KEY unique_user_role (user_id, role_id),
                    KEY idx_user (user_id),
                    KEY idx_role (role_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)
            
            # MCP active scan results table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS mcp_active_scan_results (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    scan_id VARCHAR(255) NOT NULL,
                    tool_name VARCHAR(255) NOT NULL,
                    attack_type VARCHAR(255),
                    payload LONGTEXT,
                    response LONGTEXT,
                    vulnerability_found TINYINT(1) DEFAULT 0,
                    vulnerability_type VARCHAR(255),
                    severity VARCHAR(50),
                    details LONGTEXT,
                    recommendation LONGTEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NULL,
                    KEY idx_scan_id (scan_id),
                    KEY idx_vulnerability (vulnerability_found),
                    KEY idx_severity (severity)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)
            
            # MCP inventory table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS mcp_inventory (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    server_name VARCHAR(255) NOT NULL,
                    server_config_hash VARCHAR(255) NOT NULL UNIQUE,
                    server_url VARCHAR(255),
                    server_type VARCHAR(100),
                    server_config_json LONGTEXT,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP NULL,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP NULL,
                    last_scan_id VARCHAR(255),
                    previous_hash VARCHAR(255),
                    change_detected TINYINT(1) DEFAULT 0,
                    scan_count INT DEFAULT 1,
                    KEY idx_server_name (server_name),
                    KEY idx_config_hash (server_config_hash)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)
            
            # MCP tools inventory table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS mcp_tools_inventory (
                    id VARCHAR(255) PRIMARY KEY,
                    tool_id VARCHAR(255) UNIQUE NOT NULL,
                    tool_name VARCHAR(255) NOT NULL,
                    description LONGTEXT,
                    server_url VARCHAR(255) NOT NULL,
                    server_type VARCHAR(100) DEFAULT 'http' NOT NULL,
                    headers_json LONGTEXT,
                    tenant_id VARCHAR(255),
                    source_user_id VARCHAR(255),
                    created_by VARCHAR(255) DEFAULT 'system',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NULL,
                    KEY idx_tool_id (tool_id),
                    KEY idx_server_url (server_url(100))
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)
            
            # Agents inventory table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS agents_inventory (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    discovery_id VARCHAR(255) NOT NULL,
                    repo_url VARCHAR(255) NOT NULL,
                    repo_name VARCHAR(255),
                    branch VARCHAR(100) DEFAULT 'main',
                    agent_name VARCHAR(255) NOT NULL,
                    file_path VARCHAR(255) NOT NULL,
                    github_url VARCHAR(255),
                    framework VARCHAR(100) NOT NULL,
                    description LONGTEXT,
                    capabilities_json LONGTEXT,
                    tools_used_json LONGTEXT,
                    llm_provider VARCHAR(100),
                    security_concerns_json LONGTEXT,
                    code_snippet LONGTEXT,
                    discovered_by VARCHAR(255) DEFAULT 'anonymous',
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NULL,
                    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP NULL,
                    UNIQUE KEY unique_agent (repo_url(100), file_path(100), agent_name(100)),
                    KEY idx_framework (framework)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)
            
            # Manual target models table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS manual_target_models (
                    id VARCHAR(255) PRIMARY KEY,
                    name TEXT NOT NULL,
                    model_type VARCHAR(100) NOT NULL,
                    config_json LONGTEXT NOT NULL,
                    description LONGTEXT,
                    use_case_json LONGTEXT,
                    is_default TINYINT(1) DEFAULT 0,
                    created_by VARCHAR(255) DEFAULT 'system',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP NULL
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)
            
            # Agent scans table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS agent_scans (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    scan_id VARCHAR(255) UNIQUE NOT NULL,
                    agent_name VARCHAR(255) NOT NULL,
                    agent_endpoint VARCHAR(255) NOT NULL,
                    framework VARCHAR(100),
                    hosting_platform VARCHAR(100) DEFAULT 'custom',
                    agent_context TEXT,
                    status VARCHAR(50) NOT NULL DEFAULT 'queued',
                    progress INT DEFAULT 0,
                    results_json LONGTEXT,
                    events_json LONGTEXT,
                    request_format VARCHAR(100),
                    interaction_mode VARCHAR(100),
                    tools_json LONGTEXT,
                    tools_count INT DEFAULT 0,
                    reference_id VARCHAR(255),
                    created_by VARCHAR(255) DEFAULT 'anonymous',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP NULL,
                    completed_at TIMESTAMP NULL,
                    KEY idx_scan_id (scan_id),
                    KEY idx_status (status),
                    KEY idx_agent_name (agent_name)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)
            
            # MCP monitor events table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS mcp_monitor_events (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    ts VARCHAR(100) NOT NULL,
                    event_type VARCHAR(100) NOT NULL,
                    tool VARCHAR(255) NOT NULL,
                    risk VARCHAR(50) NOT NULL DEFAULT 'safe',
                    allowed TINYINT(1) NOT NULL DEFAULT 1,
                    summary TEXT,
                    details_json LONGTEXT,
                    session_id VARCHAR(255),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NULL,
                    KEY idx_event_type (event_type),
                    KEY idx_risk (risk),
                    KEY idx_session (session_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)
            
            # Custom agent configs table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS custom_agent_configs (
                    id VARCHAR(255) PRIMARY KEY,
                    name TEXT NOT NULL,
                    description LONGTEXT,
                    endpoint VARCHAR(255) NOT NULL,
                    base_url VARCHAR(255),
                    framework VARCHAR(100),
                    hosting_platform VARCHAR(100) DEFAULT 'custom',
                    headers_json LONGTEXT,
                    request_body_template LONGTEXT,
                    response_json_path VARCHAR(255),
                    init_endpoint VARCHAR(255),
                    init_body_json LONGTEXT,
                    init_headers_json LONGTEXT,
                    tools_json LONGTEXT,
                    agent_context TEXT,
                    protocol VARCHAR(50) DEFAULT 'simple',
                    created_by VARCHAR(255) DEFAULT 'unknown',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP NULL
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)
            
            # Benchmark data table (row-level benchmark dataset storage)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS benchmark_data (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    benchmark_id VARCHAR(100) NOT NULL,
                    prompt TEXT NOT NULL,
                    response LONGTEXT,
                    bypass_status VARCHAR(20) NOT NULL,
                    model VARCHAR(255),
                    attack_category VARCHAR(100) NOT NULL,
                    scan_id VARCHAR(255),
                    prompt_hash VARCHAR(64) NOT NULL UNIQUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NULL,
                    KEY idx_bd_benchmark (benchmark_id),
                    KEY idx_bd_category (benchmark_id, attack_category)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)

            # PRD security reviews table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS prd_reviews (
                    review_id VARCHAR(255) PRIMARY KEY,
                    document_title TEXT,
                    reference_id VARCHAR(255),
                    author VARCHAR(255),
                    status VARCHAR(50) NOT NULL DEFAULT 'queued',
                    progress INT DEFAULT 0,
                    created_by VARCHAR(255),
                    created_at VARCHAR(100),
                    completed_at VARCHAR(100),
                    result_json LONGTEXT,
                    surfaces_json LONGTEXT,
                    sections_md LONGTEXT,
                    summary_md LONGTEXT,
                    reference_link TEXT,
                    error TEXT,
                    KEY idx_prd_status (status),
                    KEY idx_prd_created_by (created_by),
                    KEY idx_prd_reference_id (reference_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)

            # Prompt hardener jobs table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS harden_jobs (
                    job_id VARCHAR(255) PRIMARY KEY,
                    prompt_name VARCHAR(255),
                    system_prompt TEXT NOT NULL,
                    context TEXT,
                    reference_id VARCHAR(255),
                    status VARCHAR(50) NOT NULL DEFAULT 'queued',
                    progress INT DEFAULT 0,
                    created_by VARCHAR(255),
                    created_at VARCHAR(100),
                    completed_at VARCHAR(100),
                    security_addendum LONGTEXT,
                    error TEXT,
                    KEY idx_harden_status (status),
                    KEY idx_harden_created_by (created_by),
                    KEY idx_harden_reference_id (reference_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)
            # Migrate existing DBs that pre-date the prompt_name column.
            try:
                cursor.execute("ALTER TABLE harden_jobs ADD COLUMN prompt_name VARCHAR(255)")
            except Exception:
                pass  # column already exists

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS skill_harden_jobs (
                    job_id VARCHAR(255) PRIMARY KEY,
                    repo_url TEXT NOT NULL,
                    skill_name TEXT NOT NULL,
                    branch VARCHAR(255),
                    status VARCHAR(50) NOT NULL DEFAULT 'queued',
                    progress INT DEFAULT 0,
                    security_guidelines LONGTEXT,
                    full_content_preview LONGTEXT,
                    pr_url TEXT,
                    pr_number INT,
                    created_by VARCHAR(255) DEFAULT 'anonymous',
                    created_at VARCHAR(100),
                    completed_at VARCHAR(100),
                    error TEXT,
                    skill_content LONGTEXT,
                    KEY idx_skill_harden_status (status),
                    KEY idx_skill_harden_created_by (created_by)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)

            # Audit table for the JIRA auto-hardener — second idempotency gate
            # alongside the JIRA label so we never re-comment a ticket.
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS jira_auto_harden_log (
                    ticket_key VARCHAR(64) PRIMARY KEY,
                    commented_at VARCHAR(64) NOT NULL,
                    marker_label VARCHAR(128),
                    prompt_hash VARCHAR(64),
                    prompt_preview TEXT,
                    KEY idx_jah_log_commented_at (commented_at)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)


            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sandbox_logs (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY,
                    ts VARCHAR(64) NOT NULL,
                    queried_by VARCHAR(255),
                    query LONGTEXT NOT NULL,
                    agent_name VARCHAR(255),
                    department VARCHAR(255),
                    inbound_decision VARCHAR(64),
                    outbound_decision VARCHAR(64),
                    llm_ok TINYINT(1) DEFAULT 0,
                    final_response LONGTEXT,
                    steps_json LONGTEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_sl_ts (ts),
                    INDEX idx_sl_user (queried_by)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)


            cursor.execute("""
                CREATE TABLE IF NOT EXISTS mcp_security_reviews (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY,
                    repo_full_name VARCHAR(255) NOT NULL,
                    repo_url VARCHAR(500),
                    status VARCHAR(32) DEFAULT 'pending',
                    critical_count INT DEFAULT 0,
                    high_count INT DEFAULT 0,
                    medium_count INT DEFAULT 0,
                    low_count INT DEFAULT 0,
                    vulnerabilities LONGTEXT,
                    summary TEXT,
                    risk_score INT DEFAULT 0,
                    triggered_by VARCHAR(100) DEFAULT 'api',
                    error TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    INDEX idx_msr_repo (repo_full_name),
                    INDEX idx_msr_status (status)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)

            self._migrate_legacy_identifiers(cursor)

            conn.commit()
            cursor.close()
            conn.close()

            self.console.print("[green]✅ Database tables initialized[/]")

        except Exception as e:
            self.console.print(f"[red]❌ Database initialization failed: {e}[/]")
            raise

    def _migrate_legacy_identifiers(self, cursor) -> None:
        """Apply schema renames on existing Postgres DBs."""
        ref_tables = (
            "benchmark_results", "mcp_scans", "agent_scans",
            "prd_reviews", "harden_jobs",
        )
        for table in ref_tables:
            try:
                cursor.execute(
                    f"ALTER TABLE {table} CHANGE secreview_id reference_id VARCHAR(255)"
                )
            except Exception:
                pass
        for old_id, new_id in (("aegis", "guardrail-v1"), ("aegis-v2", "guardrail-v2")):
            try:
                cursor.execute(
                    "UPDATE benchmark_data SET benchmark_id = %s WHERE benchmark_id = %s",
                    (new_id, old_id),
                )
            except Exception:
                pass
        try:
            cursor.execute(
                "UPDATE model_inventory SET model_id = 'guardrail-v1-default' "
                "WHERE model_id = 'aegis-default'"
            )
        except Exception:
            pass
        for table in ("team_poc_config", "poc_config", "repo_bu_mapping", "chat_digest_log"):
            try:
                cursor.execute(f"DROP TABLE IF EXISTS {table}")
            except Exception:
                pass
    
    def execute_query(self, query: str, params: tuple = (), fetch_one: bool = False, fetch_all: bool = False):
        """Execute a query and return results"""
        conn = None
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute(query, params)
            
            if fetch_one:
                result = cursor.fetchone()
            elif fetch_all:
                result = cursor.fetchall()
            else:
                result = cursor.lastrowid
            
            conn.commit()
            cursor.close()
            conn.close()
            return result
        except Exception as e:
            if conn:
                conn.rollback()
                conn.close()
            raise e
    
    # Compatibility methods to match SQLite interface
    def connect(self):
        """Get a connection (context manager compatible)"""
        return self._get_connection()
    
    def recover_stuck_scans(self) -> int:
        """
        Recovery function called on server startup.
        Marks any scans with 'queued' or 'running' status as 'cancelled'
        so they can be restarted by admin.
        
        Returns:
            Number of scans recovered
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Find and update stuck scans
            cursor.execute("""
                UPDATE benchmark_results 
                SET status = 'cancelled', 
                    updated_at = CURRENT_TIMESTAMP,
                    metadata_json = JSON_SET(
                        COALESCE(metadata_json, '{}'),
                        '$.recovery_reason',
                        'Server restarted while scan was in progress'
                    )
                WHERE status IN ('queued', 'running')
            """)
            
            recovered_count = cursor.rowcount
            conn.commit()
            
            # Clear cache since multiple scans may have been updated
            global _scan_results_cache
            _scan_results_cache.clear()
            
            if recovered_count > 0:
                print(f"[DB] Recovered {recovered_count} stuck scans (marked as cancelled)")
            
            cursor.close()
            conn.close()
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
            conn = self._get_connection()
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
            
            cursor.close()
            conn.close()
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
            conn = self._get_connection()
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

            cursor.close()
            conn.close()
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
            conn = self._get_connection()
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
            cursor.close()
            conn.close()
            return recovered_count
        except Exception as e:
            self.console.print(f"[red]Error recovering stuck PRD reviews: {e}[/]")
            return 0

    def list_mcp_tools(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """List all MCP tools in inventory"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT id, tool_id, tool_name, description, server_url, server_type,
                       headers_json, tenant_id, source_user_id, created_by, created_at
                FROM mcp_tools_inventory
                ORDER BY tool_name ASC
                LIMIT %s OFFSET %s
            """, (limit, offset))
            
            tools = []
            for row in cursor.fetchall():
                headers = {}
                if row.get('headers_json'):
                    try:
                        headers = json.loads(row['headers_json'])
                    except:
                        pass
                
                tools.append({
                    "id": row['id'],
                    "tool_id": row['tool_id'],
                    "tool_name": row['tool_name'],
                    "description": row.get('description') or "",
                    "server_url": row['server_url'],
                    "server_type": row.get('server_type') or "http",
                    "headers": headers,
                    "tenant_id": row.get('tenant_id') or "",
                    "source_user_id": row.get('source_user_id') or "",
                    "created_by": row.get('created_by') or "system",
                    "created_at": row.get('created_at') or ""
                })
            
            cursor.close()
            conn.close()
            return tools
            
        except Exception as e:
            self.console.print(f"[red]Error listing MCP tools: {e}[/]")
            return []
    
    def list_benchmark_results(self, limit: int = 50, offset: int = 0, exclude_playground: bool = False) -> List[Dict[str, Any]]:
        """List benchmark results with pagination.
        
        Args:
            limit: Maximum number of results to return
            offset: Number of results to skip
            exclude_playground: If True, exclude playground scans from results
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Use JSON extraction to get is_playground flag and filter at DB level if needed
            if exclude_playground:
                cursor.execute("""
                    SELECT scan_id, scan_name, status, created_by, reference_id, created_at, updated_at,
                           JSON_EXTRACT(results_json, '$.metadata.is_playground') as is_playground,
                           JSON_EXTRACT(results_json, '$.summary.average_response_time') as avg_response_time,
                           JSON_EXTRACT(metadata_json, '$.models[0].provider') as provider
                    FROM benchmark_results
                    WHERE JSON_EXTRACT(results_json, '$.metadata.is_playground') IS NULL
                       OR JSON_EXTRACT(results_json, '$.metadata.is_playground') != 1
                    ORDER BY created_at DESC
                    LIMIT %s OFFSET %s
                """, (limit, offset))
            else:
                cursor.execute("""
                    SELECT scan_id, scan_name, status, created_by, reference_id, created_at, updated_at,
                           JSON_EXTRACT(results_json, '$.metadata.is_playground') as is_playground,
                           JSON_EXTRACT(results_json, '$.summary.average_response_time') as avg_response_time,
                           JSON_EXTRACT(metadata_json, '$.models[0].provider') as provider
                    FROM benchmark_results
                    ORDER BY created_at DESC
                    LIMIT %s OFFSET %s
                """, (limit, offset))

            results = []
            for row in cursor.fetchall():
                results.append({
                    "scan_id": row['scan_id'],
                    "scan_name": row['scan_name'],
                    "status": row['status'],
                    "created_by": row['created_by'],
                    "reference_id": row.get('reference_id'),
                    "created_at": row['created_at'],
                    "updated_at": row.get('updated_at'),
                    "is_playground": bool(row['is_playground']) if row.get('is_playground') is not None else False,
                    "avg_response_time": float(row['avg_response_time']) if row.get('avg_response_time') is not None else None,
                    "provider": row.get('provider'),
                })
            
            cursor.close()
            conn.close()
            return results
            
        except Exception as e:
            self.console.print(f"[red]Error listing benchmark results: {e}[/]")
            return []

    # ==================================================================
    # Converted Methods (76 total)
    # ==================================================================

    def log_user_activity(
        self, 
        api_key_hash: str, 
        action: str, 
        details: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Log user activity"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            details_json = json.dumps(details or {})
            
            cursor.execute("""
                INSERT INTO user_activity (api_key_hash, action, details_json)
                VALUES (%s, %s, %s)
            """, (api_key_hash, action, details_json))
            
            conn.commit()
            return True
            
        except Exception as e:
            self.console.print(f"[red]Error logging user activity: {e}[/]")
            return False
    

    def save_scan_session(self, scan_id: str, session_data: Dict[str, Any]) -> bool:
        """Save scan session data"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            session_json = json.dumps(session_data)
            
            cursor.execute("""
                REPLACE INTO scan_sessions 
                (scan_id, session_data_json, updated_at)
                VALUES (%s, %s, CURRENT_TIMESTAMP)
            """, (scan_id, session_json))
            
            conn.commit()
            return True
            
        except Exception as e:
            self.console.print(f"[red]Error saving scan session: {e}[/]")
            return False
    

    def get_scan_session(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get scan session data"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT session_data_json FROM scan_sessions WHERE scan_id = %s
            """, (scan_id,))
            
            row = cursor.fetchone()
            if row:
                return json.loads(row.get("session_data_json", ""))
            
        except Exception as e:
            self.console.print(f"[red]Error getting scan session: {e}[/]")
        
        return None
    

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
            conn = self._get_connection()
            cursor = conn.cursor()

            results_json = json.dumps(results) if results else None
            events_json = json.dumps(events) if events else None
            tools_json = json.dumps(tools) if tools else None

            cursor.execute("""
                REPLACE INTO agent_scans
                (scan_id, agent_name, agent_endpoint, framework,
                 hosting_platform, agent_context, status, progress,
                 results_json, events_json, request_format,
                 interaction_mode, tools_json, reference_id,
                 created_by, completed_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, CURRENT_TIMESTAMP)
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


    def get_agent_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get a single agent scan by ID."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM agent_scans WHERE scan_id = %s", (scan_id,))
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
            conn = self._get_connection()
            cursor = conn.cursor()

            query = "SELECT * FROM agent_scans WHERE 1=1"
            params: list = []

            if user_id:
                query += " AND created_by = %s"
                params.append(user_id)
            if status:
                query += " AND status = %s"
                params.append(status)

            query += " ORDER BY created_at DESC LIMIT %s OFFSET %s"
            params.extend([limit, offset])

            cursor.execute(query, params)
            return [self._agent_scan_row_to_dict(row) for row in cursor.fetchall()]

        except Exception as e:
            self.console.print(f"[red]Error listing agent scans: {e}[/]")
            return []


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
            conn = self._get_connection()
            cursor = conn.cursor()

            updates = []
            params = []

            if status is not None:
                updates.append("status = %s")
                params.append(status)
            if progress is not None:
                updates.append("progress = %s")
                params.append(progress)
            if results is not None:
                updates.append("results_json = %s")
                params.append(json.dumps(results))
            if events is not None:
                updates.append("events_json = %s")
                params.append(json.dumps(events))
            if request_format is not None:
                updates.append("request_format = %s")
                params.append(request_format)
            if interaction_mode is not None:
                updates.append("interaction_mode = %s")
                params.append(interaction_mode)
            if completed_at is not None:
                updates.append("completed_at = %s")
                params.append(completed_at)
            if tools is not None:
                updates.append("tools_json = %s")
                params.append(json.dumps(tools))
            if tools_count is not None:
                updates.append("tools_count = %s")
                params.append(tools_count)

            updates.append("updated_at = CURRENT_TIMESTAMP")

            if not updates:
                return True

            params.append(scan_id)
            cursor.execute(
                f"UPDATE agent_scans SET {', '.join(updates)} WHERE scan_id = %s",
                params,
            )
            conn.commit()
            return True

        except Exception as e:
            self.console.print(f"[red]Error updating agent scan: {e}[/]")
            return False


    def delete_agent_scan(self, scan_id: str) -> bool:
        """Delete an agent scan from the database."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM agent_scans WHERE scan_id = %s", (scan_id,))
            conn.commit()
            return cursor.rowcount > 0

        except Exception as e:
            self.console.print(f"[red]Error deleting agent scan: {e}[/]")
            return False

    @staticmethod

    def get_agent_stats(self) -> Dict[str, Any]:
        """Get statistics about discovered agents"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Total agents
            cursor.execute("SELECT COUNT(*) as cnt FROM agents_inventory")
            total_agents = cursor.fetchone().get("cnt", 0)
            
            # Agents by framework
            cursor.execute("""
                SELECT framework, COUNT(*) as count 
                FROM agents_inventory 
                GROUP BY framework 
                ORDER BY count DESC
            """)
            by_framework = {row.get("framework", ""): row.get("count", 0) for row in cursor.fetchall()}
            
            # Total repositories
            cursor.execute("SELECT COUNT(DISTINCT repo_url) as cnt FROM agents_inventory")
            total_repos = cursor.fetchone().get("cnt", 0)
            
            # Recent discoveries
            cursor.execute("""
                SELECT COUNT(*) as cnt FROM agents_inventory 
                WHERE discovered_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
            """)
            recent_discoveries = cursor.fetchone().get("cnt", 0)
            
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
    

    def _agent_scan_row_to_dict(self, row) -> Dict[str, Any]:
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

        # Normalise datetime columns to ISO strings so they match the
        # in-memory format and can be compared / serialised safely.
        from datetime import datetime as _dt
        for dt_col in ("created_at", "updated_at", "completed_at"):
            val = d.get(dt_col)
            if isinstance(val, _dt):
                d[dt_col] = val.isoformat()

        # Convert tools list-of-dicts back to the shape the frontend expects
        if d.get("tools") is None:
            d["tools"] = []
        d["tools_count"] = len(d["tools"])

        return d
    
    # ── Custom Agent Configs (Quick Start) ────────────────────────────────

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
            conn = self._get_connection()
            cursor = conn.cursor()
            
            results_json = json.dumps(results) if results else None
            
            cursor.execute("""
                REPLACE INTO mcp_scans 
                (scan_id, file_name, status, config_content, results_json, message, created_by, timeout, completed_at, scan_name, reference_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (scan_id, file_name, status, config_content, results_json, message, created_by, timeout, completed_at, scan_name, reference_id))
            
            conn.commit()
            return True
            
        except Exception as e:
            self.console.print(f"[red]Error saving MCP scan: {e}[/]")
            return False
    

    def get_mcp_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get MCP scan by ID"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT scan_id, file_name, status, config_content, results_json, message, 
                       created_by, created_at, completed_at, timeout, scan_name, reference_id
                FROM mcp_scans 
                WHERE scan_id = %s
            """, (scan_id,))
            
            row = cursor.fetchone()
            if row:
                results = json.loads(row.get("results_json", "")) if row.get("results_json", "") else None
                return {
                    "scan_id": row.get("scan_id", ""),
                    "file_name": row.get("file_name", ""),
                    "status": row.get("status", ""),
                    "config_content": row.get("config_content", ""),
                    "results": results,
                    "message": row.get("message", ""),
                    "created_by": row.get("created_by", ""),
                    "created_at": row.get("created_at", ""),
                    "completed_at": row.get("completed_at", ""),
                    "timeout": row.get("timeout", ""),
                    "scan_name": row.get("scan_name"),
                    "reference_id": row.get("reference_id")
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
            conn = self._get_connection()
            cursor = conn.cursor()
            
            query = """
                SELECT scan_id, file_name, status, message, created_by, created_at, completed_at, timeout, scan_name, results_json, reference_id, config_content
                FROM mcp_scans 
                WHERE 1=1
            """
            params = []
            
            if user_id:
                query += " AND created_by = %s"
                params.append(user_id)
            
            if status:
                query += " AND status = %s"
                params.append(status)
            
            query += " ORDER BY created_at DESC LIMIT %s OFFSET %s"
            params.extend([limit, offset])
            
            cursor.execute(query, params)
            
            results = []
            for row in cursor.fetchall():
                # Parse results_json if present
                scan_results = None
                if row.get("results_json"):
                    try:
                        scan_results = json.loads(row["results_json"])
                    except:
                        pass
                
                results.append({
                    "scan_id": row.get("scan_id", ""),
                    "file_name": row.get("file_name", ""),
                    "status": row.get("status", ""),
                    "message": row.get("message", ""),
                    "created_by": row.get("created_by", ""),
                    "created_at": str(row.get("created_at", "")),
                    "completed_at": str(row.get("completed_at", "")) if row.get("completed_at") else None,
                    "timeout": row.get("timeout", 30),
                    "scan_name": row.get("scan_name"),
                    "results": scan_results,
                    "reference_id": row.get("reference_id"),
                    "config_content": row.get("config_content")
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
            conn = self._get_connection()
            cursor = conn.cursor()
            
            results_json = safe_json_dumps(results) if results else None
            
            cursor.execute("""
                UPDATE mcp_scans 
                SET status = %s, results_json = %s, message = %s, completed_at = %s
                WHERE scan_id = %s
            """, (status, results_json, message, completed_at, scan_id))
            
            conn.commit()
            return True
            
        except Exception as e:
            self.console.print(f"[red]Error updating MCP scan: {e}[/]")
            return False
    

    def delete_mcp_scan(self, scan_id: str) -> bool:
        """Delete an MCP scan and its associated data from the database"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Delete from mcp_scans table
            cursor.execute("DELETE FROM mcp_scans WHERE scan_id = %s", (scan_id,))
            
            # Delete associated security findings
            cursor.execute("DELETE FROM mcp_security_findings WHERE scan_id = %s", (scan_id,))
            
            # Delete associated active scan results
            cursor.execute("DELETE FROM mcp_active_scan_results WHERE scan_id = %s", (scan_id,))
            
            conn.commit()
            self.console.print(f"[green]Deleted MCP scan {scan_id} and associated data[/]")
            return True
            
        except Exception as e:
            self.console.print(f"[red]Error deleting MCP scan: {e}[/]")
            return False
    
    # ------------------------------------------------------------------
    # Agent Security Scan Methods
    # ------------------------------------------------------------------


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
            conn = self._get_connection()
            cursor = conn.cursor()
            
            config_json = json.dumps(config) if config else "{}"
            metadata_json = json.dumps(metadata) if metadata else None
            use_case_answers_json = json.dumps(use_case_answers) if use_case_answers else None
            last_test_status_json = json.dumps(last_test_status) if last_test_status else None
            
            cursor.execute("""
                REPLACE INTO model_inventory 
                (model_id, name, description, entry_type, provider, model_identifier, 
                 config_json, metadata_json, use_case_answers_json, last_test_status_json, created_by, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
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
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT model_id, name, description, entry_type, provider, model_identifier,
                       config_json, metadata_json, use_case_answers_json, last_test_status_json,
                       created_by, created_at, updated_at
                FROM model_inventory
                WHERE model_id = %s
            """, (model_id,))
            
            row = cursor.fetchone()
            if row:
                result = {
                    "id": row.get("model_id", ""),
                    "name": row.get("name", ""),
                    "description": row.get("description", ""),
                    "entry_type": row.get("entry_type", ""),
                    "provider": row.get("provider", ""),
                    "model_id": row.get("model_identifier", ""),
                    "config": json.loads(row.get("config_json", "")) if row.get("config_json", "") else {},
                    "metadata": json.loads(row.get("metadata_json", "")) if row.get("metadata_json", "") else {},
                    "use_case_answers": json.loads(row.get("use_case_answers_json", "")) if row.get("use_case_answers_json", "") else None,
                    "last_test_status": json.loads(row.get("last_test_status_json", "")) if row.get("last_test_status_json", "") else None,
                    "created_by": row.get("created_by", ""),
                    "created_at": row.get("created_at", ""),
                    "updated_at": row.get("updated_at", "")
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
            conn = self._get_connection()
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
                    WHERE created_by = %s
                    ORDER BY created_at DESC
                """, (created_by,))
            else:
                cursor.execute(base_query + """
                    ORDER BY created_at DESC
                """)
            
            models = []
            for row in cursor.fetchall():
                models.append({
                    "id": row.get("model_id", ""),
                    "name": row.get("name", ""),
                    "description": row.get("description", ""),
                    "entry_type": row.get("entry_type", ""),
                    "provider": row.get("provider", ""),
                    "model_id": row.get("model_identifier", ""),
                    "config": json.loads(row.get("config_json", "")) if row.get("config_json", "") else {},
                    "metadata": json.loads(row.get("metadata_json", "")) if row.get("metadata_json", "") else {},
                    "use_case_answers": json.loads(row.get("use_case_answers_json", "")) if row.get("use_case_answers_json", "") else None,
                    "last_test_status": json.loads(row.get("last_test_status_json", "")) if row.get("last_test_status_json", "") else None,
                    "created_by": row.get("created_by", ""),
                    "created_at": row.get("created_at", ""),
                    "updated_at": row.get("updated_at", ""),
                    "last_reviewed_at": row.get("last_reviewed_at", "")  # Timestamp of last successful scan (or None)
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
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                DELETE FROM model_inventory WHERE model_id = %s
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
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                UPDATE model_inventory 
                SET last_reviewed_at = CURRENT_TIMESTAMP
                WHERE model_id = %s
            """, (model_id,))
            
            conn.commit()
            
            # Invalidate cache
            self.invalidate_model_inventory_cache(model_id)
            
            return cursor.rowcount > 0
            
        except Exception as e:
            self.console.print(f"[red]Error marking model as reviewed: {e}[/]")
            return False
    
    # ========== MCP Tools Inventory Methods ==========
    

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
            conn = self._get_connection()
            cursor = conn.cursor()
            
            results_json = json.dumps(results) if results else None
            
            cursor.execute("""
                REPLACE INTO dataset_analyses 
                (analysis_id, file_name, status, file_size, results_json, is_poisoned, 
                 security_score, total_entries, suspicious_entries, message, created_by, completed_at, scan_name)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT analysis_id, file_name, status, file_size, results_json, is_poisoned,
                       security_score, total_entries, suspicious_entries, message,
                       created_by, created_at, completed_at
                FROM dataset_analyses 
                WHERE analysis_id = %s
            """, (analysis_id,))
            
            row = cursor.fetchone()
            if row:
                results = json.loads(row.get("results_json", "")) if row.get("results_json", "") else None
                return {
                    "analysis_id": row.get("analysis_id", ""),
                    "file_name": row.get("file_name", ""),
                    "status": row.get("status", ""),
                    "file_size": row.get("file_size", ""),
                    "results": results,
                    "is_poisoned": bool(row.get("is_poisoned", "")) if row.get("is_poisoned", "") is not None else None,
                    "security_score": row.get("security_score", ""),
                    "total_entries": row.get("total_entries", ""),
                    "suspicious_entries": row.get("suspicious_entries", ""),
                    "message": row.get("message", ""),
                    "created_by": row.get("created_by", ""),
                    "created_at": row.get("created_at", ""),
                    "completed_at": row.get("completed_at", "")
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
            conn = self._get_connection()
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
                query += " AND created_by = %s"
                params.append(user_id)
            
            if status:
                query += " AND status = %s"
                params.append(status)
            
            query += " ORDER BY created_at DESC LIMIT %s OFFSET %s"
            params.extend([limit, offset])
            
            cursor.execute(query, params)
            
            results = []
            for row in cursor.fetchall():
                # Parse results JSON if present
                analysis_results = None
                if row.get("results_json", ""):  # results_json column
                    try:
                        analysis_results = json.loads(row.get("results_json", ""))
                    except:
                        pass
                
                results.append({
                    "analysis_id": row.get("analysis_id", ""),
                    "file_name": row.get("file_name", ""),
                    "status": row.get("status", ""),
                    "file_size": row.get("file_size", ""),
                    "is_poisoned": bool(row.get("is_poisoned", "")) if row.get("is_poisoned", "") is not None else None,
                    "security_score": row.get("security_score", ""),
                    "total_entries": row.get("total_entries", ""),
                    "suspicious_entries": row.get("suspicious_entries", ""),
                    "message": row.get("message", ""),
                    "created_by": row.get("created_by", ""),
                    "created_at": row.get("created_at", ""),
                    "completed_at": row.get("completed_at", ""),
                    "results": analysis_results,
                    "scan_name": row.get("scan_name")  # scan_name column
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
            conn = self._get_connection()
            cursor = conn.cursor()
            
            results_json = json.dumps(results) if results else None
            
            cursor.execute("""
                UPDATE dataset_analyses 
                SET status = %s, results_json = %s, is_poisoned = %s, security_score = %s,
                    total_entries = %s, suspicious_entries = %s, message = %s, completed_at = %s
                WHERE analysis_id = %s
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
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO dataset_inventory 
                (dataset_id, name, description, file_name, file_path, file_size, file_format,
                 row_count, column_count, created_by)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT dataset_id, name, description, file_name, file_path, file_size, file_format,
                       row_count, column_count, created_by, created_at, updated_at
                FROM dataset_inventory 
                WHERE dataset_id = %s
            """, (dataset_id,))
            
            row = cursor.fetchone()
            if row:
                return {
                    "dataset_id": row.get("dataset_id", ""),
                    "name": row.get("name", ""),
                    "description": row.get("description", ""),
                    "file_name": row.get("file_name", ""),
                    "file_path": row.get("file_path", ""),
                    "file_size": row.get("file_size", ""),
                    "file_format": row.get("file_format", ""),
                    "row_count": row.get("row_count", ""),
                    "column_count": row.get("column_count", ""),
                    "created_by": row.get("created_by", ""),
                    "created_at": row.get("created_at", ""),
                    "updated_at": row.get("updated_at", "")
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
            conn = self._get_connection()
            cursor = conn.cursor()
            
            query = """
                SELECT dataset_id, name, description, file_name, file_path, file_size, file_format,
                       row_count, column_count, created_by, created_at, updated_at
                FROM dataset_inventory 
                WHERE 1=1
            """
            params = []
            
            if created_by:
                query += " AND created_by = %s"
                params.append(created_by)
            
            query += " ORDER BY created_at DESC LIMIT %s OFFSET %s"
            params.extend([limit, offset])
            
            cursor.execute(query, params)
            
            results = []
            for row in cursor.fetchall():
                results.append({
                    "dataset_id": row.get("dataset_id", ""),
                    "name": row.get("name", ""),
                    "description": row.get("description", ""),
                    "file_name": row.get("file_name", ""),
                    "file_path": row.get("file_path", ""),
                    "file_size": row.get("file_size", ""),
                    "file_format": row.get("file_format", ""),
                    "row_count": row.get("row_count", ""),
                    "column_count": row.get("column_count", ""),
                    "created_by": row.get("created_by", ""),
                    "created_at": row.get("created_at", ""),
                    "updated_at": row.get("updated_at", "")
                })
            
            return results
            
        except Exception as e:
            self.console.print(f"[red]Error listing dataset inventory: {e}[/]")
            return []
    

    def delete_dataset_inventory(self, dataset_id: str) -> bool:
        """Delete dataset from inventory"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                DELETE FROM dataset_inventory WHERE dataset_id = %s
            """, (dataset_id,))
            
            conn.commit()
            return True
            
        except Exception as e:
            self.console.print(f"[red]Error deleting dataset from inventory: {e}[/]")
            return False
    
    # Model Inventory Methods

    def save_custom_agent_config(self, config: Dict[str, Any]) -> bool:
        """Save a user-provided custom agent config for Quick Start."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """REPLACE INTO custom_agent_configs
                   (id, name, description, endpoint, base_url, framework,
                    hosting_platform, headers_json, request_body_template,
                    response_json_path, init_endpoint, init_body_json,
                    init_headers_json, tools_json, agent_context,
                    protocol, created_by, updated_at)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)""",
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


    def get_custom_agent_config(self, config_id: str) -> Optional[Dict[str, Any]]:
        """Get a single custom agent config by ID."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM custom_agent_configs WHERE id = %s", (config_id,))
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


    def list_custom_agent_configs(self) -> List[Dict[str, Any]]:
        """List all custom agent configs."""
        try:
            conn = self._get_connection()
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


    def delete_custom_agent_config(self, config_id: str) -> bool:
        """Delete a custom agent config."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM custom_agent_configs WHERE id = %s", (config_id,))
            conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
            self.console.print(f"[red]Error deleting custom agent config: {e}[/]")
            return False

    # ── MCP Monitor Events ───────────────────────────────────────────────

    def save_model_config(self, model_name: str, config: Dict[str, Any]) -> bool:
        """Save model configuration"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            config_json = json.dumps(config)
            
            cursor.execute("""
                REPLACE INTO model_configs 
                (model_name, config_json, updated_at)
                VALUES (%s, %s, CURRENT_TIMESTAMP)
            """, (model_name, config_json))
            
            conn.commit()
            return True
            
        except Exception as e:
            self.console.print(f"[red]Error saving model config: {e}[/]")
            return False
    

    def get_model_config(self, model_name: str) -> Optional[Dict[str, Any]]:
        """Get model configuration"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT config_json FROM model_configs WHERE model_name = %s
            """, (model_name,))
            
            row = cursor.fetchone()
            if row:
                return json.loads(row.get("config_json", ""))
            
        except Exception as e:
            self.console.print(f"[red]Error getting model config: {e}[/]")
        
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
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Check if already exists
            existing = self.check_mcp_inventory(server_config_hash)
            
            if existing:
                # Check if this is actually a different config (different hash)
                if existing["server_config_hash"] != server_config_hash:
                    # Config changed - update with new hash and mark change
                    cursor.execute("""
                        UPDATE mcp_inventory
                        SET server_name = %s,
                            server_config_hash = %s,
                            server_url = %s,
                            server_type = %s,
                            server_config_json = %s,
                            last_seen = CURRENT_TIMESTAMP,
                            last_scan_id = %s,
                            previous_hash = %s,
                            change_detected = 1,
                            scan_count = scan_count + 1
                        WHERE server_config_hash = %s
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
                        SET server_name = %s,
                            last_seen = CURRENT_TIMESTAMP,
                            last_scan_id = %s,
                            change_detected = 0,
                            scan_count = scan_count + 1
                        WHERE server_config_hash = %s
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
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
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
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT id, server_name, server_config_hash, server_url, server_type,
                       server_config_json, first_seen, last_seen, last_scan_id,
                       previous_hash, change_detected, scan_count
                FROM mcp_inventory
                WHERE server_config_hash = %s
            """, (server_config_hash,))
            
            row = cursor.fetchone()
            if row:
                return {
                    "id": row.get("id", ""),
                    "server_name": row.get("server_name", ""),
                    "server_config_hash": row.get("server_config_hash", ""),
                    "server_url": row.get("server_url", ""),
                    "server_type": row.get("server_type", ""),
                    "server_config_json": json.loads(row.get("server_config_json", "")) if row.get("server_config_json", "") else None,
                    "first_seen": row.get("first_seen", ""),
                    "last_seen": row.get("last_seen", ""),
                    "last_scan_id": row.get("last_scan_id", ""),
                    "previous_hash": row.get("previous_hash", ""),
                    "change_detected": bool(row.get("change_detected", "")),
                    "scan_count": row.get("scan_count", "")
                }
            
            return None
            
        except Exception as e:
            self.console.print(f"[red]Error checking MCP inventory: {e}[/]")
            return None
    

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
            conn = self._get_connection()
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
            
            query += " ORDER BY last_seen DESC LIMIT %s OFFSET %s"
            params.extend([limit, offset])
            
            cursor.execute(query, params)
            
            results = []
            for row in cursor.fetchall():
                results.append({
                    "id": row.get("id", ""),
                    "server_name": row.get("server_name", ""),
                    "server_config_hash": row.get("server_config_hash", ""),
                    "server_url": row.get("server_url", ""),
                    "server_type": row.get("server_type", ""),
                    "first_seen": row.get("first_seen", ""),
                    "last_seen": row.get("last_seen", ""),
                    "last_scan_id": row.get("last_scan_id", ""),
                    "previous_hash": row.get("previous_hash", ""),
                    "change_detected": bool(row.get("change_detected", "")),
                    "scan_count": row.get("scan_count", "")
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
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT id, server_name, server_config_hash, server_url, server_type,
                       server_config_json, first_seen, last_seen, last_scan_id,
                       previous_hash, change_detected, scan_count
                FROM mcp_inventory
                WHERE server_name = %s
                ORDER BY last_seen DESC
                LIMIT 1
            """, (server_name,))
            
            row = cursor.fetchone()
            if row:
                return {
                    "id": row.get("id", ""),
                    "server_name": row.get("server_name", ""),
                    "server_config_hash": row.get("server_config_hash", ""),
                    "server_url": row.get("server_url", ""),
                    "server_type": row.get("server_type", ""),
                    "server_config_json": json.loads(row.get("server_config_json", "")) if row.get("server_config_json", "") else None,
                    "first_seen": row.get("first_seen", ""),
                    "last_seen": row.get("last_seen", ""),
                    "last_scan_id": row.get("last_scan_id", ""),
                    "previous_hash": row.get("previous_hash", ""),
                    "change_detected": bool(row.get("change_detected", "")),
                    "scan_count": row.get("scan_count", "")
                }
            
            return None
            
        except Exception as e:
            self.console.print(f"[red]Error getting MCP inventory by name: {e}[/]")
            return None
    

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
            conn = self._get_connection()
            cursor = conn.cursor()
            
            headers_json = json.dumps(headers) if headers else None
            
            cursor.execute("""
                REPLACE INTO mcp_tools_inventory
                (id, tool_id, tool_name, description, server_url, server_type, 
                 headers_json, tenant_id, source_user_id, created_by)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT id, tool_id, tool_name, description, server_url, server_type,
                       headers_json, tenant_id, source_user_id, created_by, created_at
                FROM mcp_tools_inventory
                WHERE id = %s OR tool_id = %s
            """, (tool_id, tool_id))
            
            row = cursor.fetchone()
            if row:
                headers = {}
                if row.get("headers_json", ""):
                    try:
                        headers = json.loads(row.get("headers_json", ""))
                    except:
                        pass
                
                return {
                    "id": row.get("id", ""),
                    "tool_id": row.get("tool_id", ""),
                    "tool_name": row.get("tool_name", ""),
                    "description": row.get("description", "") or "",
                    "server_url": row.get("server_url", ""),
                    "server_type": row.get("server_type", "") or "http",
                    "headers": headers,
                    "tenant_id": row.get("tenant_id", "") or "",
                    "source_user_id": row.get("source_user_id", "") or "",
                    "created_by": row.get("created_by", "") or "system",
                    "created_at": row.get("created_at", "") or ""
                }
            
            return None
            
        except Exception as e:
            self.console.print(f"[red]Error getting MCP tool: {e}[/]")
            return None
    

    def delete_mcp_tool(self, tool_id: str) -> bool:
        """Delete MCP tool from inventory"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                DELETE FROM mcp_tools_inventory WHERE id = %s OR tool_id = %s
            """, (tool_id, tool_id))
            
            conn.commit()
            return cursor.rowcount > 0
            
        except Exception as e:
            self.console.print(f"[red]Error deleting MCP tool: {e}[/]")
            return False
    
    # ========== Role Management Methods ==========
    

    def get_agents_inventory(
        self,
        repo_url: str = None,
        framework: str = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """Get agents from inventory with optional filtering"""
        try:
            conn = self._get_connection()
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
                query += " AND repo_url = %s"
                params.append(repo_url)
            
            if framework:
                query += " AND framework = %s"
                params.append(framework)
            
            query += " ORDER BY discovered_at DESC LIMIT %s OFFSET %s"
            params.extend([limit, offset])
            
            cursor.execute(query, params)
            
            agents = []
            for row in cursor.fetchall():
                agents.append({
                    "id": row.get("id", ""),
                    "discovery_id": row.get("discovery_id", ""),
                    "repo_url": row.get("repo_url", ""),
                    "repo_name": row.get("repo_name", ""),
                    "branch": row.get("branch", ""),
                    "name": row.get("agent_name", ""),
                    "file_path": row.get("file_path", ""),
                    "github_url": row.get("github_url", ""),
                    "framework": row.get("framework", ""),
                    "description": row.get("description", ""),
                    "capabilities": json.loads(row.get("capabilities_json", "")) if row.get("capabilities_json", "") else [],
                    "tools_used": json.loads(row.get("tools_used_json", "")) if row.get("tools_used_json", "") else [],
                    "llm_provider": row.get("llm_provider", ""),
                    "security_concerns": json.loads(row.get("security_concerns_json", "")) if row.get("security_concerns_json", "") else [],
                    "code_snippet": row.get("code_snippet", ""),
                    "discovered_by": row.get("discovered_by", ""),
                    "discovered_at": row.get("discovered_at", ""),
                    "last_updated": row.get("last_updated", "")
                })
            
            return agents
            
        except Exception as e:
            self.console.print(f"[red]Error getting agents inventory: {e}[/]")
            return []
    

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
            conn = self._get_connection()
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
                    WHERE repo_url = %s AND file_path = %s AND agent_name = %s
                """, (repo_url, file_path, agent_name))
                
                existing = cursor.fetchone()
                
                if existing:
                    # Update existing agent
                    cursor.execute("""
                        UPDATE agents_inventory 
                        SET framework = %s,
                            description = %s,
                            capabilities_json = %s,
                            tools_used_json = %s,
                            llm_provider = %s,
                            security_concerns_json = %s,
                            code_snippet = %s,
                            github_url = %s,
                            branch = %s,
                            last_updated = CURRENT_TIMESTAMP,
                            discovery_id = %s
                        WHERE id = %s
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
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
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
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO mcp_active_scan_results 
                (scan_id, tool_name, attack_type, payload, response, vulnerability_found,
                 vulnerability_type, severity, details, recommendation)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                SELECT tool_name, attack_type, payload, response, vulnerability_found,
                       vulnerability_type, severity, details, recommendation, created_at
                FROM mcp_active_scan_results
                WHERE scan_id = %s
                ORDER BY created_at DESC
            """, (scan_id,))
            
            results = []
            for row in cursor.fetchall():
                results.append({
                    "tool_name": row.get("tool_name", ""),
                    "attack_type": row.get("attack_type", ""),
                    "payload": row.get("payload", ""),
                    "response": row.get("response", ""),
                    "vulnerability_found": bool(row.get("vulnerability_found", "")),
                    "vulnerability_type": row.get("vulnerability_type", ""),
                    "severity": row.get("severity", ""),
                    "details": row.get("details", ""),
                    "recommendation": row.get("recommendation", ""),
                    "created_at": row.get("created_at", "")
                })
            return results
        except Exception as e:
            self.console.print(f"[red]Error getting active scan results: {e}[/]")
            return []
    

    def save_active_scan_batch(self, scan_id: str, findings: List[Dict[str, Any]]) -> bool:
        """Save multiple active scan findings at once"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            for finding in findings:
                cursor.execute("""
                    INSERT INTO mcp_active_scan_results 
                    (scan_id, tool_name, attack_type, payload, response, vulnerability_found,
                     vulnerability_type, severity, details, recommendation)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Check if entity exists
            cursor.execute("""
                SELECT description_hash, description 
                FROM mcp_entities 
                WHERE server_name = %s AND entity_name = %s AND entity_type = %s
            """, (server_name, entity_name, entity_type))
            
            row = cursor.fetchone()
            
            if row:
                # Entity exists - check if changed
                old_hash, old_description = row
                changed = old_hash != description_hash
                
                # Update last_seen and scan_id
                cursor.execute("""
                    UPDATE mcp_entities 
                    SET description_hash = %s, description = %s, last_seen = CURRENT_TIMESTAMP, scan_id = %s
                    WHERE server_name = %s AND entity_name = %s AND entity_type = %s
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
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (server_name, entity_name, entity_type, description_hash, description, scan_id))
                
                conn.commit()
                
                return {
                    "changed": False,
                    "previous_description": None
                }
                
        except Exception as e:
            self.console.print(f"[red]Error tracking MCP entity: {e}[/]")
            return {"changed": False, "previous_description": None}
    

    def get_mcp_security_findings(self, scan_id: str) -> List[Dict[str, Any]]:
        """Get all security findings for a scan"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT server_name, entity_name, entity_type, detector_type, severity, finding_details, created_at
                FROM mcp_security_findings
                WHERE scan_id = %s
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
                    details = json.loads(row.get("finding_details", "")) if row.get("finding_details", "") else {}
                except:
                    details = {}
                
                findings.append({
                    "server_name": row.get("server_name", ""),
                    "entity_name": row.get("entity_name", ""),
                    "entity_type": row.get("entity_type", ""),
                    "detector_type": row.get("detector_type", ""),
                    "severity": row.get("severity", ""),
                    "details": details,
                    "created_at": row.get("created_at", "")
                })
            
            return findings
            
        except Exception as e:
            self.console.print(f"[red]Error getting security findings: {e}[/]")
            return []
    
    # Dataset Analysis Methods

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
            conn = self._get_connection()
            cursor = conn.cursor()
            
            details_json = json.dumps(finding_details)
            
            cursor.execute("""
                INSERT INTO mcp_security_findings 
                (scan_id, server_name, entity_name, entity_type, detector_type, severity, finding_details)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
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

    def save_mcp_monitor_event(self, event: Dict[str, Any]) -> bool:
        """Persist a single monitoring event."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """INSERT INTO mcp_monitor_events
                   (ts, event_type, tool, risk, allowed, summary, details_json, session_id)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
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
            cursor.close()
            conn.close()
            return True
        except Exception as e:
            self.console.print(f"[red]Error saving MCP monitor event: {e}[/]")
            return False


    def list_mcp_monitor_events(
        self, limit: int = 100, risk: Optional[str] = None, event_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return the most recent monitor events, newest first."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            clauses = []
            params: list = []
            if risk:
                clauses.append("risk = %s")
                params.append(risk)
            if event_type:
                clauses.append("event_type = %s")
                params.append(event_type)
            where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
            cursor.execute(
                f"SELECT * FROM mcp_monitor_events{where} ORDER BY id DESC LIMIT %s",
                params + [limit],
            )
            rows = cursor.fetchall()
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
            cursor.close()
            conn.close()
            return results
        except Exception as e:
            self.console.print(f"[red]Error listing MCP monitor events: {e}[/]")
            return []


    def clear_mcp_monitor_events(self) -> bool:
        """Clear all monitor events."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM mcp_monitor_events")
            conn.commit()
            cursor.close()
            conn.close()
            return True
        except Exception as e:
            self.console.print(f"[red]Error clearing MCP monitor events: {e}[/]")
            return False

    # MCP Active Scan Results Methods (for client simulation / Triksha Agent)

    def get_mcp_monitor_stats(self) -> Dict[str, Any]:
        """Return aggregate statistics for the monitor dashboard."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as cnt FROM mcp_monitor_events")
            total = cursor.fetchone()["cnt"]
            cursor.execute("SELECT COUNT(*) as cnt FROM mcp_monitor_events WHERE allowed = 0")
            blocked = cursor.fetchone()["cnt"]
            by_risk = {}
            cursor.execute("SELECT risk, COUNT(*) as cnt FROM mcp_monitor_events GROUP BY risk")
            for row in cursor.fetchall():
                by_risk[row["risk"]] = row["cnt"]
            by_type = {}
            cursor.execute("SELECT event_type, COUNT(*) as cnt FROM mcp_monitor_events GROUP BY event_type")
            for row in cursor.fetchall():
                by_type[row["event_type"]] = row["cnt"]
            cursor.close()
            conn.close()
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
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                REPLACE INTO manual_target_models 
                (id, name, model_type, config_json, description, use_case_json, is_default, created_by, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
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
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT id, name, model_type, config_json, description, 
                       use_case_json, is_default, created_by, created_at
                FROM manual_target_models
                WHERE id = %s
            """, (model_id,))
            
            row = cursor.fetchone()
            if row:
                return {
                    "id": row.get("id", ""),
                    "name": row.get("name", ""),
                    "model_type": row.get("model_type", ""),
                    "config": json.loads(row.get("config_json", "")) if row.get("config_json", "") else {},
                    "description": row.get("description", ""),
                    "use_case": json.loads(row.get("use_case_json", "")) if row.get("use_case_json", "") else {},
                    "is_default": bool(row.get("is_default", "")),
                    "created_by": row.get("created_by", ""),
                    "created_at": row.get("created_at", "")
                }
            return None
            
        except Exception as e:
            self.console.print(f"[red]Error getting manual target model: {e}[/]")
            return None
    

    def list_manual_target_models(self) -> List[Dict[str, Any]]:
        """List all manual target models"""
        try:
            conn = self._get_connection()
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
                    "id": row.get("id", ""),
                    "name": row.get("name", ""),
                    "model_type": row.get("model_type", ""),
                    "config": json.loads(row.get("config_json", "")) if row.get("config_json", "") else {},
                    "description": row.get("description", ""),
                    "use_case": json.loads(row.get("use_case_json", "")) if row.get("use_case_json", "") else {},
                    "is_default": bool(row.get("is_default", "")),
                    "created_by": row.get("created_by", ""),
                    "created_at": row.get("created_at", "")
                })
            
            return models
            
        except Exception as e:
            self.console.print(f"[red]Error listing manual target models: {e}[/]")
            return []
    

    def delete_manual_target_model(self, model_id: str) -> bool:
        """Delete a manual target model"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                DELETE FROM manual_target_models WHERE id = %s
            """, (model_id,))
            
            conn.commit()
            return cursor.rowcount > 0
            
        except Exception as e:
            self.console.print(f"[red]Error deleting manual target model: {e}[/]")
            return False
    

    def update_manual_target_model_use_case(self, model_id: str, use_case: Dict[str, Any]) -> bool:
        """Update the use case configuration for a manual target model"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                UPDATE manual_target_models 
                SET use_case_json = %s, updated_at = CURRENT_TIMESTAMP
                WHERE id = %s
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

    def list_roles(self) -> List[Dict[str, Any]]:
        """List all roles"""
        try:
            conn = self._get_connection()
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
                    "role_id": row.get("role_id", ""),
                    "role_name": row.get("role_name", ""),
                    "display_name": row.get("display_name", ""),
                    "description": row.get("description", ""),
                    "permissions": json.loads(row.get("permissions_json", "")),
                    "is_system_role": bool(row.get("is_system_role", "")),
                    "created_by": row.get("created_by", ""),
                    "created_at": row.get("created_at", ""),
                    "updated_at": row.get("updated_at", "")
                })
            
            return roles
        except Exception as e:
            self.console.print(f"[red]Error listing roles: {e}[/]")
            return []
    

    def create_role(self, role_name: str, display_name: str, description: str, 
                   permissions: List[str], created_by: str) -> Optional[int]:
        """Create a new role"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO roles (role_name, display_name, description, permissions_json, is_system_role, created_by)
                VALUES (%s, %s, %s, %s, 0, %s)
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
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Check if it's a system role
            cursor.execute("SELECT is_system_role FROM roles WHERE role_id = %s", (role_id,))
            row = cursor.fetchone()
            if not row:
                return False
            if row.get("is_system_role", ""):  # is_system_role
                self.console.print(f"[yellow]Cannot update system role[/]")
                return False
            
            cursor.execute("""
                UPDATE roles 
                SET display_name = %s, description = %s, permissions_json = %s, 
                    updated_at = CURRENT_TIMESTAMP
                WHERE role_id = %s
            """, (display_name, description, json.dumps(permissions), role_id))
            
            conn.commit()
            return True
        except Exception as e:
            self.console.print(f"[red]Error updating role: {e}[/]")
            return False
    

    def delete_role(self, role_id: int) -> bool:
        """Delete a role (cannot delete system roles)"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Check if it's a system role
            cursor.execute("SELECT is_system_role FROM roles WHERE role_id = %s", (role_id,))
            row = cursor.fetchone()
            if not row:
                return False
            if row.get("is_system_role", ""):  # is_system_role
                self.console.print(f"[yellow]Cannot delete system role[/]")
                return False
            
            # Delete role and its assignments
            cursor.execute("DELETE FROM user_role_assignments WHERE role_id = %s", (role_id,))
            cursor.execute("DELETE FROM roles WHERE role_id = %s", (role_id,))
            
            conn.commit()
            return True
        except Exception as e:
            self.console.print(f"[red]Error deleting role: {e}[/]")
            return False
    

    def assign_role_to_user(self, user_id: str, role_id: int, assigned_by: str) -> bool:
        """Assign a role to a user"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT IGNORE INTO user_role_assignments (user_id, role_id, assigned_by)
                VALUES (%s, %s, %s)
            """, (user_id, role_id, assigned_by))
            
            conn.commit()
            return True
        except Exception as e:
            self.console.print(f"[red]Error assigning role to user: {e}[/]")
            return False
    

    def remove_role_from_user(self, user_id: str, role_id: int) -> bool:
        """Remove a role from a user"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                DELETE FROM user_role_assignments 
                WHERE user_id = %s AND role_id = %s
            """, (user_id, role_id))
            
            conn.commit()
            return True
        except Exception as e:
            self.console.print(f"[red]Error removing role from user: {e}[/]")
            return False
    

    def get_user_roles(self, user_id: str) -> List[Dict[str, Any]]:
        """Get all roles assigned to a user"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                SELECT r.role_id, r.role_name, r.display_name, r.description, 
                       r.permissions_json, r.is_system_role, ura.assigned_at
                FROM roles r
                INNER JOIN user_role_assignments ura ON r.role_id = ura.role_id
                WHERE ura.user_id = %s
                ORDER BY r.is_system_role DESC, r.display_name ASC
            """, (user_id,))
            
            roles = []
            for row in cursor.fetchall():
                roles.append({
                    "role_id": row.get("role_id", ""),
                    "role_name": row.get("role_name", ""),
                    "display_name": row.get("display_name", ""),
                    "description": row.get("description", ""),
                    "permissions": json.loads(row.get("permissions_json", "")),
                    "is_system_role": bool(row.get("is_system_role", "")),
                    "assigned_at": row.get("assigned_at", "")
                })
            
            return roles
        except Exception as e:
            self.console.print(f"[red]Error getting user roles: {e}[/]")
            return []
    

    def get_all_user_assignments(self) -> List[Dict[str, Any]]:
        """Get all user-role assignments"""
        try:
            conn = self._get_connection()
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
                    "assignment_id": row.get("assignment_id", ""),
                    "user_id": row.get("user_id", ""),
                    "role_id": row.get("role_id", ""),
                    "role_name": row.get("role_name", ""),
                    "display_name": row.get("display_name", ""),
                    "assigned_by": row.get("assigned_by", ""),
                    "assigned_at": row.get("assigned_at", "")
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
    

    def cleanup_old_data(self, days: int = 30) -> bool:
        """Clean up old data older than specified days"""
        try:
            conn = self._get_connection()
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
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Convert results and metadata to JSON
            results_json = json.dumps(results)
            metadata_json = json.dumps(metadata or {})
            
            # Insert or update
            cursor.execute("""
                REPLACE INTO benchmark_results 
                (scan_id, scan_name, status, results_json, metadata_json, created_by, reference_id, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
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
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                UPDATE benchmark_results 
                SET status = %s, updated_at = CURRENT_TIMESTAMP
                WHERE scan_id = %s
            """, (status, scan_id))
            
            conn.commit()
            
            # Invalidate cache for this scan since we just updated it
            self.invalidate_cache(scan_id)
            
            print(f"[DB] Updated scan {scan_id} status to {status}")
            return cursor.rowcount > 0
            
        except Exception as e:
            self.console.print(f"[red]Error updating benchmark status: {e}[/]")
            return False
    

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
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT scan_id, scan_name, status, results_json, metadata_json, 
                       created_by, reference_id, created_at, updated_at
                FROM benchmark_results 
                WHERE scan_id = %s
            """, (scan_id,))
            
            row = cursor.fetchone()
            if row:
                result = {
                    "scan_id": row.get("scan_id", ""),
                    "scan_name": row.get("scan_name", ""),
                    "status": row.get("status", ""),
                    "results": json.loads(row.get("results_json", "")) if row.get("results_json", "") else {},
                    "metadata": json.loads(row.get("metadata_json", "")) if row.get("metadata_json", "") else {},
                    "created_by": row.get("created_by", ""),
                    "reference_id": row.get("reference_id", ""),
                    "created_at": row.get("created_at", ""),
                    "updated_at": row.get("updated_at", "")
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
    

    def delete_benchmark_result(self, scan_id: str) -> bool:
        """Delete a contextual scan (benchmark result) from the database.
        
        Args:
            scan_id: The ID of the scan to delete
            
        Returns:
            True if deletion was successful, False otherwise
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Delete from benchmark_results table
            cursor.execute("DELETE FROM benchmark_results WHERE scan_id = %s", (scan_id,))
            
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
            conn = self._get_connection()
            cursor = conn.cursor()
            for row in rows:
                try:
                    cursor.execute("""
                        INSERT IGNORE INTO benchmark_data
                        (benchmark_id, prompt, response, bypass_status, model, attack_category, scan_id, prompt_hash)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
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
                except Exception:
                    pass
            conn.commit()
            cursor.close()
            conn.close()
        except Exception as e:
            self.console.print(f"[red]Error inserting benchmark rows: {e}[/]")
        return inserted

    def get_benchmark_data_stats(self, benchmark_id: str) -> Dict[str, Any]:
        """Returns per-category counts for a benchmark from the benchmark_data table."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                SELECT attack_category,
                       COUNT(*) as total,
                       SUM(CASE WHEN bypass_status = 'yes' THEN 1 ELSE 0 END) as bypassed,
                       SUM(CASE WHEN bypass_status = 'no' THEN 1 ELSE 0 END) as blocked,
                       SUM(CASE WHEN bypass_status = 'error' THEN 1 ELSE 0 END) as errors
                FROM benchmark_data
                WHERE benchmark_id = %s
                GROUP BY attack_category
            """, (benchmark_id,))
            categories = {}
            for row in cursor.fetchall():
                categories[row["attack_category"]] = {
                    "total": row["total"], "bypassed": row["bypassed"],
                    "blocked": row["blocked"], "errors": row["errors"],
                }
            cursor.close()
            conn.close()
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
            conn = self._get_connection()
            cursor = conn.cursor()
            query = "SELECT prompt, response, bypass_status, model, attack_category FROM benchmark_data WHERE benchmark_id = %s ORDER BY id"
            params: list = [benchmark_id]
            if limit:
                query += " LIMIT %s OFFSET %s"
                params.extend([limit, offset])
            cursor.execute(query, params)
            result = [
                {"Prompt": r["prompt"], "Response": r["response"], "Bypass Status": r["bypass_status"],
                 "Model": r["model"], "Attack Category": r["attack_category"]}
                for r in cursor.fetchall()
            ]
            cursor.close()
            conn.close()
            return result
        except Exception as e:
            self.console.print(f"[red]Error getting benchmark data rows: {e}[/]")
            return []

    def get_benchmark_row_count(self, benchmark_id: str) -> int:
        """Quick count for list endpoint."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM benchmark_data WHERE benchmark_id = %s", (benchmark_id,))
            count = cursor.fetchone()[0]
            cursor.close()
            conn.close()
            return count
        except Exception:
            return 0

    def has_benchmark_data(self, benchmark_id: str) -> bool:
        """Check if seed data exists for a benchmark."""
        return self.get_benchmark_row_count(benchmark_id) > 0

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

    # ── PRD Review Persistence ──────────────────────────────────────────────

    def save_prd_review(self, record: Dict[str, Any]) -> bool:
        """Insert or replace a PRD review record."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO prd_reviews
                    (review_id, document_title, reference_id, author, status, progress,
                     created_by, created_at, reference_link)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    document_title = VALUES(document_title),
                    reference_id   = VALUES(reference_id),
                    status         = IF(status IN ('completed', 'failed'), status, VALUES(status)),
                    progress       = IF(status IN ('completed', 'failed'), progress, VALUES(progress))
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
            cursor.close()
            conn.close()
            return True
        except Exception as e:
            self.console.print(f"[red]Error saving PRD review: {e}[/]")
            return False

    def update_prd_review(self, review_id: str, update: Dict[str, Any]) -> bool:
        """Update status/progress/result fields for a PRD review.

        Split into two writes so a large content payload never prevents the
        status from being persisted (large result_json can exceed
        max_allowed_packet and silently fail when bundled with status).
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            # ── Step 1: always commit the small critical fields first ──────────
            cursor.execute("""
                UPDATE prd_reviews
                SET status       = %s,
                    progress     = %s,
                    completed_at = %s,
                    error        = %s
                WHERE review_id = %s
            """, (
                update.get("status"),
                update.get("progress", 100),
                update.get("completed_at"),
                update.get("error"),
                review_id,
            ))
            conn.commit()

            # ── Step 2: write large content fields one-at-a-time ─────────────
            # Each field gets its own UPDATE so no single packet exceeds
            # max_allowed_packet regardless of content size.
            # Save download-critical fields first so a packet-too-large failure
            # on result_json never leaves surfaces/sections unwritten.
            sections_val = update.get("_sections_md")
            if isinstance(sections_val, list):
                sections_val = safe_json_dumps(sections_val)
            content_fields = [
                ("surfaces_json", safe_json_dumps(update["_surfaces"]) if update.get("_surfaces") else None),
                ("sections_md",   sections_val),
                ("summary_md",    update.get("_summary_md")),
                ("result_json",   safe_json_dumps(update["result"]) if update.get("result") else None),
            ]
            # Try to raise session packet limit first (best-effort; ignore if denied)
            try:
                cursor.execute("SET SESSION max_allowed_packet = 67108864")
            except Exception:
                pass

            for col, val in content_fields:
                if val is None:
                    continue
                try:
                    cursor.execute(
                        f"UPDATE prd_reviews SET {col} = %s WHERE review_id = %s",
                        (val, review_id),
                    )
                    conn.commit()
                    self.console.print(f"[green]PRD review field '{col}' saved for {review_id} ({len(val)} bytes)[/]")
                except Exception as field_err:
                    self.console.print(
                        f"[red]PRD review field '{col}' write FAILED for {review_id}: {field_err}[/]"
                    )
                    try:
                        conn.rollback()
                    except Exception:
                        pass

            cursor.close()
            conn.close()
            return True
        except Exception as e:
            self.console.print(f"[red]Error updating PRD review status for {review_id}: {e}[/]")
            return False

    def list_prd_reviews(self, created_by: str = None, limit: int = 200) -> List[Dict[str, Any]]:
        """List PRD reviews, newest first. Optionally filter by created_by."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            if created_by:
                cursor.execute("""
                    SELECT review_id, document_title, reference_id, author, status,
                           progress, created_by, created_at, completed_at, error, reference_link
                    FROM prd_reviews WHERE created_by = %s
                    ORDER BY created_at DESC LIMIT %s
                """, (created_by, limit))
            else:
                cursor.execute("""
                    SELECT review_id, document_title, reference_id, author, status,
                           progress, created_by, created_at, completed_at, error, reference_link
                    FROM prd_reviews ORDER BY created_at DESC LIMIT %s
                """, (limit,))
            rows = cursor.fetchall()
            cursor.close()
            conn.close()
            return [dict(r) for r in rows]
        except Exception as e:
            self.console.print(f"[red]Error listing PRD reviews: {e}[/]")
            return []

    def get_prd_review(self, review_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a single PRD review including result/surfaces for download."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM prd_reviews WHERE review_id = %s", (review_id,))
            row = cursor.fetchone()
            cursor.close()
            conn.close()
            if not row:
                return None
            r = dict(row)
            if r.get("result_json"):
                try:
                    r["result"] = json.loads(r.pop("result_json"))
                except Exception:
                    r.pop("result_json", None)
            if r.get("surfaces_json"):
                try:
                    r["_surfaces"] = json.loads(r.pop("surfaces_json"))
                except Exception:
                    r.pop("surfaces_json", None)
            raw_sections = r.pop("sections_md", None)
            if raw_sections:
                try:
                    r["_sections_md"] = json.loads(raw_sections)
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
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM prd_reviews WHERE review_id = %s", (review_id,))
            conn.commit()
            cursor.close()
            conn.close()
            return True
        except Exception as e:
            self.console.print(f"[red]Error deleting PRD review: {e}[/]")
            return False

    # ── Harden Jobs ───────────────────────────────────────────────────────────

    def save_harden_job(self, record: Dict[str, Any]) -> bool:
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO harden_jobs
                (job_id, prompt_name, system_prompt, context, reference_id, status, progress,
                 created_by, created_at, completed_at, security_addendum, error)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    prompt_name=VALUES(prompt_name),
                    status=VALUES(status), progress=VALUES(progress),
                    completed_at=VALUES(completed_at), security_addendum=VALUES(security_addendum),
                    error=VALUES(error)
            """, (
                record.get("job_id"), record.get("prompt_name"),
                record.get("system_prompt"), record.get("context"),
                record.get("reference_id"), record.get("status", "queued"),
                record.get("progress", 0), record.get("created_by", "anonymous"),
                record.get("created_at"), record.get("completed_at"),
                record.get("security_addendum"), record.get("error"),
            ))
            conn.commit()
            cursor.close()
            conn.close()
            return True
        except Exception as e:
            self.console.print(f"[red]Error saving harden job: {e}[/]")
            return False

    def update_harden_job(self, job_id: str, update: Dict[str, Any]) -> bool:
        allowed = {"status", "progress", "completed_at", "security_addendum", "error"}
        fields = {k: v for k, v in update.items() if k in allowed}
        if not fields:
            return False
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            set_clause = ", ".join(f"{k} = %s" for k in fields)
            cursor.execute(
                f"UPDATE harden_jobs SET {set_clause} WHERE job_id = %s",
                (*fields.values(), job_id),
            )
            conn.commit()
            cursor.close()
            conn.close()
            return True
        except Exception as e:
            self.console.print(f"[red]Error updating harden job: {e}[/]")
            return False

    def get_harden_job_by_reference_id(self, reference_id: str) -> Optional[Dict[str, Any]]:
        """Return the most-recent harden_jobs row for a reference id, or None."""
        if not reference_id:
            return None
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM harden_jobs WHERE reference_id = %s "
                "ORDER BY created_at DESC LIMIT 1",
                (reference_id,),
            )
            row = cursor.fetchone()
            cursor.close()
            conn.close()
            return row
        except Exception as e:
            self.console.print(f"[red]Error reading harden_jobs by reference_id: {e}[/]")
            return None

    def list_harden_jobs(self, created_by: str = None, limit: int = 200) -> List[Dict[str, Any]]:
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            if created_by:
                cursor.execute(
                    "SELECT * FROM harden_jobs WHERE created_by = %s ORDER BY created_at DESC LIMIT %s",
                    (created_by, limit),
                )
            else:
                cursor.execute(
                    "SELECT * FROM harden_jobs ORDER BY created_at DESC LIMIT %s", (limit,)
                )
            rows = cursor.fetchall()
            cursor.close()
            conn.close()
            return rows or []
        except Exception as e:
            self.console.print(f"[red]Error listing harden jobs: {e}[/]")
            return []

    def get_harden_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM harden_jobs WHERE job_id = %s", (job_id,))
            row = cursor.fetchone()
            cursor.close()
            conn.close()
            return row
        except Exception as e:
            self.console.print(f"[red]Error fetching harden job: {e}[/]")
            return None

    # ── Skill Harden Jobs ─────────────────────────────────────────────────────

    def save_skill_harden_job(self, record: Dict[str, Any]) -> bool:
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO skill_harden_jobs
                (job_id, repo_url, skill_name, branch, status, progress,
                 security_guidelines, full_content_preview, pr_url, pr_number,
                 created_by, created_at, completed_at, error, skill_content)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    repo_url = VALUES(repo_url), skill_name = VALUES(skill_name),
                    branch = VALUES(branch), status = VALUES(status),
                    progress = VALUES(progress)
            """, (
                record.get("job_id"), record.get("repo_url"), record.get("skill_name"),
                record.get("branch"), record.get("status", "queued"), record.get("progress", 0),
                record.get("security_guidelines"), record.get("full_content_preview"),
                record.get("pr_url"), record.get("pr_number"),
                record.get("created_by", "anonymous"), record.get("created_at"),
                record.get("completed_at"), record.get("error"), record.get("skill_content"),
            ))
            conn.commit()
            cursor.close()
            conn.close()
            return True
        except Exception as e:
            self.console.print(f"[red]Error saving skill harden job: {e}[/]")
            return False

    def update_skill_harden_job(self, job_id: str, update: Dict[str, Any]) -> bool:
        allowed = {"status", "progress", "completed_at", "security_guidelines", "full_content_preview", "pr_url", "pr_number", "error", "skill_content"}
        fields = {k: v for k, v in update.items() if k in allowed}
        if not fields:
            return False
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            set_clause = ", ".join(f"{k} = %s" for k in fields)
            cursor.execute(
                f"UPDATE skill_harden_jobs SET {set_clause} WHERE job_id = %s",
                (*fields.values(), job_id),
            )
            conn.commit()
            cursor.close()
            conn.close()
            return True
        except Exception as e:
            self.console.print(f"[red]Error updating skill harden job: {e}[/]")
            return False

    def list_skill_harden_jobs(self, created_by: str = None, limit: int = 200) -> List[Dict[str, Any]]:
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            if created_by:
                cursor.execute(
                    "SELECT * FROM skill_harden_jobs WHERE created_by = %s ORDER BY created_at DESC LIMIT %s",
                    (created_by, limit),
                )
            else:
                cursor.execute(
                    "SELECT * FROM skill_harden_jobs ORDER BY created_at DESC LIMIT %s", (limit,)
                )
            rows = cursor.fetchall()
            cursor.close()
            conn.close()
            return rows
        except Exception as e:
            self.console.print(f"[red]Error listing skill harden jobs: {e}[/]")
            return []

    def get_skill_harden_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM skill_harden_jobs WHERE job_id = %s", (job_id,))
            row = cursor.fetchone()
            cursor.close()
            conn.close()
            return row
        except Exception as e:
            self.console.print(f"[red]Error fetching skill harden job: {e}[/]")
            return None

    def delete_skill_harden_job(self, job_id: str) -> bool:
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM skill_harden_jobs WHERE job_id = %s", (job_id,))
            conn.commit()
            cursor.close()
            conn.close()
            return True
        except Exception as e:
            self.console.print(f"[red]Error deleting skill harden job: {e}[/]")
            return False

    def recover_stuck_skill_harden_jobs(self) -> int:
        try:
            conn = self._get_connection()
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
            cursor.close()
            conn.close()
            return recovered_count
        except Exception as e:
            self.console.print(f"[red]Error recovering stuck skill harden jobs: {e}[/]")
            return 0

    # ── JIRA Auto-Hardener Audit Log ──────────────────────────────────────────

    def has_jira_auto_harden_log(self, ticket_key: str, marker_label: Optional[str] = None) -> bool:
        """Return True if we've previously posted a comment for *this label version*."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            if marker_label:
                cursor.execute(
                    "SELECT 1 FROM jira_auto_harden_log WHERE ticket_key = %s AND marker_label = %s LIMIT 1",
                    (ticket_key, marker_label),
                )
            else:
                cursor.execute(
                    "SELECT 1 FROM jira_auto_harden_log WHERE ticket_key = %s LIMIT 1",
                    (ticket_key,),
                )
            row = cursor.fetchone()
            cursor.close()
            conn.close()
            return row is not None
        except Exception as e:
            self.console.print(f"[red]Error reading jira_auto_harden_log: {e}[/]")
            # On read error, prefer NOT to comment — safer to occasionally miss
            # a ticket than spam the same one repeatedly.
            return True

    def insert_jira_auto_harden_log(
        self,
        ticket_key: str,
        commented_at: str,
        marker_label: str = "",
        prompt_hash: str = "",
        prompt_preview: str = "",
    ) -> bool:
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO jira_auto_harden_log
                (ticket_key, commented_at, marker_label, prompt_hash, prompt_preview)
                VALUES (%s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    commented_at = VALUES(commented_at),
                    marker_label = VALUES(marker_label),
                    prompt_hash = VALUES(prompt_hash),
                    prompt_preview = VALUES(prompt_preview)
                """,
                (ticket_key, commented_at, marker_label, prompt_hash, prompt_preview[:500]),
            )
            conn.commit()
            cursor.close()
            conn.close()
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

        Pass marker_label='needs_info_skip' to get tickets whose descriptions
        the auto-hardener couldn't parse.
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            if marker_label:
                cursor.execute(
                    "SELECT ticket_key, commented_at, marker_label, prompt_hash, prompt_preview "
                    "FROM jira_auto_harden_log WHERE marker_label = %s "
                    "ORDER BY commented_at DESC LIMIT %s",
                    (marker_label, limit),
                )
            else:
                cursor.execute(
                    "SELECT ticket_key, commented_at, marker_label, prompt_hash, prompt_preview "
                    "FROM jira_auto_harden_log "
                    "ORDER BY commented_at DESC LIMIT %s",
                    (limit,),
                )
            rows = cursor.fetchall() or []
            cursor.close()
            conn.close()
            return list(rows)
        except Exception as e:
            self.console.print(f"[red]Error listing jira_auto_harden_log: {e}[/]")
            return []



    def insert_sandbox_log(self, entry):
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """INSERT INTO sandbox_logs
                   (ts, queried_by, query, agent_name, department,
                    inbound_decision, outbound_decision, llm_ok, final_response, steps_json)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
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
            cursor.close()
            conn.close()
            return True
        except Exception as e:
            self.console.print(f"[red]Error inserting sandbox_log: {e}[/]")
            return False

    def get_sandbox_logs(self, limit=200, offset=0):
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM sandbox_logs ORDER BY id DESC LIMIT %s OFFSET %s",
                (limit, offset),
            )
            rows = cursor.fetchall()
            cursor.close()
            conn.close()
            result = []
            for r in rows:
                try:
                    r["steps"] = json.loads(r.pop("steps_json") or "[]")
                except Exception:
                    r["steps"] = []
                result.append(r)
            return result
        except Exception as e:
            self.console.print(f"[red]Error reading sandbox_logs: {e}[/]")
            return []

    def clear_sandbox_logs(self) -> bool:
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM sandbox_logs")
            conn.commit()
            cursor.close()
            conn.close()
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
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """INSERT INTO mcp_security_reviews
                   (repo_full_name, repo_url, status, triggered_by)
                   VALUES (%s, %s, 'pending', %s)""",
                (repo_full_name, repo_url or "", triggered_by),
            )
            new_id = cursor.lastrowid
            conn.commit()
            cursor.close()
            conn.close()
            return new_id
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
            conn = self._get_connection()
            cursor = conn.cursor()
            set_clause = ", ".join(f"{col} = %s" for col in filtered)
            values = list(filtered.values()) + [review_id]
            cursor.execute(
                f"UPDATE mcp_security_reviews SET {set_clause} WHERE id = %s",
                values,
            )
            conn.commit()
            cursor.close()
            conn.close()
            return True
        except Exception as e:
            self.console.print(f"[red]Error updating MCP security review {review_id}: {e}[/]")
            return False

    def get_mcp_security_review(self, repo_full_name: str) -> Optional[Dict[str, Any]]:
        """Get the latest review for a repo."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """SELECT * FROM mcp_security_reviews
                   WHERE repo_full_name = %s
                   ORDER BY created_at DESC LIMIT 1""",
                (repo_full_name,),
            )
            row = cursor.fetchone()
            cursor.close()
            conn.close()
            return dict(row) if row else None
        except Exception as e:
            self.console.print(f"[red]Error fetching MCP security review for {repo_full_name}: {e}[/]")
            return None

    def list_mcp_security_reviews(self, limit: int = 200) -> List[Dict[str, Any]]:
        """List all reviews, latest first."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM mcp_security_reviews ORDER BY created_at DESC LIMIT %s",
                (limit,),
            )
            rows = cursor.fetchall()
            cursor.close()
            conn.close()
            return [dict(r) for r in rows]
        except Exception as e:
            self.console.print(f"[red]Error listing MCP security reviews: {e}[/]")
            return []

    def get_mcp_security_reviews_bulk(self, repo_names: List[str]) -> Dict[str, Dict[str, Any]]:
        """Return {repo_full_name: review} for a list of repos (latest per repo)."""
        if not repo_names:
            return {}
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            placeholders = ", ".join(["%s"] * len(repo_names))
            # Use a subquery to pick the latest row per repo
            cursor.execute(
                f"""SELECT m.*
                    FROM mcp_security_reviews m
                    INNER JOIN (
                        SELECT repo_full_name, MAX(id) AS max_id
                        FROM mcp_security_reviews
                        WHERE repo_full_name IN ({placeholders})
                        GROUP BY repo_full_name
                    ) latest ON m.id = latest.max_id""",
                repo_names,
            )
            rows = cursor.fetchall()
            cursor.close()
            conn.close()
            return {r["repo_full_name"]: dict(r) for r in rows}
        except Exception as e:
            self.console.print(f"[red]Error bulk-fetching MCP security reviews: {e}[/]")
            return {}
