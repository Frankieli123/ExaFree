"""
Storage abstraction supporting SQLite and PostgreSQL backends.

Priority:
1) DATABASE_URL -> PostgreSQL
2) SQLITE_PATH  -> SQLite (defaults to data.db when DATABASE_URL is empty)
3) No file fallback
"""

import asyncio
import json
import logging
import os
import re
import sqlite3
import threading
import time
from typing import Optional
from uuid import uuid4

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

_db_pool = None
_db_pool_lock = None
_db_loop = None
_db_thread = None
_db_loop_lock = threading.Lock()

_sqlite_conn = None
_sqlite_lock = threading.Lock()


def _get_database_url() -> str:
    return os.environ.get("DATABASE_URL", "").strip()

def _default_sqlite_path() -> str:
    return os.path.join("data", "data.db")

def _get_sqlite_path() -> str:
    env_path = os.environ.get("SQLITE_PATH", "").strip()
    if env_path:
        return env_path
    return _default_sqlite_path()

def _get_backend() -> str:
    if _get_database_url():
        return "postgres"
    if _get_sqlite_path():
        return "sqlite"
    return ""

def is_database_enabled() -> bool:
    """Return True when a database backend is configured."""
    return bool(_get_backend())


def get_database_backend() -> str:
    """Return active backend: postgres/sqlite/empty."""
    return _get_backend()


def get_sqlite_db_path() -> Optional[str]:
    """Return sqlite path when sqlite backend is active."""
    if _get_backend() != "sqlite":
        return None
    return _get_sqlite_path()


def export_sqlite_db_bytes() -> Optional[bytes]:
    """Export sqlite database file as bytes."""
    if _get_backend() != "sqlite":
        return None
    conn = _get_sqlite_conn()
    db_path = _get_sqlite_path()
    with _sqlite_lock:
        try:
            conn.commit()
        except Exception:
            pass
        with open(db_path, "rb") as f:
            return f.read()


def import_sqlite_db_bytes(db_bytes: bytes) -> tuple[bool, str]:
    """Import sqlite database bytes and overwrite existing file."""
    if _get_backend() != "sqlite":
        return False, "database backend is not sqlite"
    payload = db_bytes or b""
    if len(payload) < 16 or not payload.startswith(b"SQLite format 3\x00"):
        return False, "invalid sqlite database file"

    db_path = _get_sqlite_path()
    db_dir = os.path.dirname(db_path) or "."
    os.makedirs(db_dir, exist_ok=True)
    temp_path = f"{db_path}.upload.tmp"

    # Validate uploaded sqlite file before replacing current DB.
    try:
        with open(temp_path, "wb") as f:
            f.write(payload)
        verify_conn = sqlite3.connect(temp_path)
        try:
            verify_conn.execute("PRAGMA schema_version").fetchone()
        finally:
            verify_conn.close()
    except Exception as e:
        try:
            os.remove(temp_path)
        except Exception:
            pass
        return False, f"invalid sqlite file: {e}"

    global _sqlite_conn
    try:
        with _sqlite_lock:
            if _sqlite_conn is not None:
                try:
                    _sqlite_conn.close()
                except Exception:
                    pass
                _sqlite_conn = None
            os.replace(temp_path, db_path)
    except Exception as e:
        try:
            os.remove(temp_path)
        except Exception:
            pass
        return False, f"replace sqlite file failed: {e}"

    try:
        _get_sqlite_conn()
    except Exception as e:
        return False, f"reopen sqlite failed: {e}"
    return True, "ok"


def _data_file_path(name: str) -> str:
    return os.path.join("data", name)


def _ensure_backend_initialized() -> None:
    backend = _get_backend()
    if backend == "postgres":
        _run_in_db_loop(_get_pool())
        return
    if backend == "sqlite":
        _get_sqlite_conn()
        return


async def has_accounts() -> Optional[bool]:
    backend = _get_backend()
    if backend == "postgres":
        async with _pg_acquire() as conn:
            row = await conn.fetchrow("SELECT 1 FROM accounts LIMIT 1")
        return bool(row)
    if backend == "sqlite":
        conn = _get_sqlite_conn()
        with _sqlite_lock:
            row = conn.execute("SELECT 1 FROM accounts LIMIT 1").fetchone()
        return bool(row)
    return None


def has_accounts_sync() -> Optional[bool]:
    return _run_in_db_loop(has_accounts())


async def has_settings() -> Optional[bool]:
    backend = _get_backend()
    if backend == "postgres":
        async with _pg_acquire() as conn:
            row = await conn.fetchrow(
                "SELECT 1 FROM kv_settings WHERE key = $1",
                "settings",
            )
        return bool(row)
    if backend == "sqlite":
        conn = _get_sqlite_conn()
        with _sqlite_lock:
            row = conn.execute(
                "SELECT 1 FROM kv_settings WHERE key = ?",
                ("settings",),
            ).fetchone()
        return bool(row)
    return None


def has_settings_sync() -> Optional[bool]:
    return _run_in_db_loop(has_settings())


async def has_stats() -> Optional[bool]:
    backend = _get_backend()
    if backend == "postgres":
        async with _pg_acquire() as conn:
            row = await conn.fetchrow(
                "SELECT 1 FROM kv_stats WHERE key = $1",
                "stats",
            )
        return bool(row)
    if backend == "sqlite":
        conn = _get_sqlite_conn()
        with _sqlite_lock:
            row = conn.execute(
                "SELECT 1 FROM kv_stats WHERE key = ?",
                ("stats",),
            ).fetchone()
        return bool(row)
    return None


def has_stats_sync() -> Optional[bool]:
    return _run_in_db_loop(has_stats())


def _ensure_db_loop() -> asyncio.AbstractEventLoop:
    global _db_loop, _db_thread
    if _db_loop and _db_thread and _db_thread.is_alive():
        return _db_loop
    with _db_loop_lock:
        if _db_loop and _db_thread and _db_thread.is_alive():
            return _db_loop
        loop = asyncio.new_event_loop()

        def _runner() -> None:
            asyncio.set_event_loop(loop)
            loop.run_forever()

        thread = threading.Thread(target=_runner, name="storage-db-loop", daemon=True)
        thread.start()
        _db_loop = loop
        _db_thread = thread
        return _db_loop


def _run_in_db_loop(coro):
    loop = _ensure_db_loop()
    future = asyncio.run_coroutine_threadsafe(coro, loop)
    return future.result()

def _get_sqlite_conn():
    """Get (or create) the SQLite connection."""
    global _sqlite_conn
    if _sqlite_conn is not None:
        return _sqlite_conn
    with _sqlite_lock:
        if _sqlite_conn is not None:
            return _sqlite_conn
        sqlite_path = _get_sqlite_path()
        if not sqlite_path:
            raise ValueError("SQLITE_PATH is not set")
        os.makedirs(os.path.dirname(sqlite_path) or ".", exist_ok=True)
        conn = sqlite3.connect(sqlite_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        _init_sqlite_tables(conn)
        _sqlite_conn = conn
        logger.info(f"[STORAGE] SQLite initialized at {sqlite_path}")
        return _sqlite_conn


async def _get_pool():
    """Get (or create) the asyncpg connection pool."""
    global _db_pool, _db_pool_lock
    if _db_pool is not None:
        return _db_pool
    if _db_pool_lock is None:
        _db_pool_lock = asyncio.Lock()
    async with _db_pool_lock:
        if _db_pool is not None:
            return _db_pool
        db_url = _get_database_url()
        if not db_url:
            raise ValueError("DATABASE_URL is not set")
        try:
            import asyncpg
            _db_pool = await asyncpg.create_pool(
                db_url,
                min_size=0,
                max_size=10,
                command_timeout=30,
            )
            await _init_tables(_db_pool)
            logger.info("[STORAGE] PostgreSQL pool initialized")
        except ImportError:
            logger.error("[STORAGE] asyncpg is required for database storage")
            raise
        except Exception as e:
            logger.error(f"[STORAGE] Database connection failed: {e}")
            raise
    return _db_pool


async def _reset_pool():
    """Close and recreate the connection pool (called on stale connection errors)."""
    global _db_pool
    if _db_pool is not None:
        try:
            await _db_pool.close()
        except Exception:
            pass
        _db_pool = None
    return await _get_pool()


from contextlib import asynccontextmanager

@asynccontextmanager
async def _pg_acquire():
    """Acquire a connection with automatic retry on stale connection errors."""
    import asyncpg
    pool = await _get_pool()
    try:
        async with pool.acquire() as conn:
            yield conn
    except (asyncpg.ConnectionDoesNotExistError,
            asyncpg.InterfaceError,
            OSError) as e:
        logger.warning(f"[STORAGE] Connection lost, resetting pool: {e}")
        await _reset_pool()
        raise


async def _init_tables(pool) -> None:
    """Initialize PostgreSQL tables."""
    async with pool.acquire() as conn:
        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS accounts (
                account_id TEXT PRIMARY KEY,
                position INTEGER NOT NULL,
                data JSONB NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        await conn.execute(
            """
            CREATE INDEX IF NOT EXISTS accounts_position_idx
            ON accounts(position)
            """
        )
        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS kv_settings (
                key TEXT PRIMARY KEY,
                value JSONB NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS kv_stats (
                key TEXT PRIMARY KEY,
                value JSONB NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS task_history (
                id TEXT PRIMARY KEY,
                data JSONB NOT NULL,
                created_at DOUBLE PRECISION NOT NULL
            )
            """
        )
        await conn.execute(
            """
            CREATE INDEX IF NOT EXISTS task_history_created_at_idx
            ON task_history(created_at DESC)
            """
        )
        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS proxy_control (
                id INTEGER PRIMARY KEY,
                data JSONB NOT NULL
            )
            """
        )
        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS request_logs (
                id BIGSERIAL PRIMARY KEY,
                timestamp BIGINT NOT NULL,
                model TEXT NOT NULL,
                ttfb_ms INTEGER,
                total_ms INTEGER,
                status TEXT NOT NULL,
                status_code INTEGER,
                user_id TEXT,
                user_name TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        await conn.execute("ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS user_id TEXT")
        await conn.execute("ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS user_name TEXT")
        await conn.execute(
            """
            CREATE INDEX IF NOT EXISTS request_logs_timestamp_idx
            ON request_logs(timestamp)
            """
        )
        await conn.execute(
            """
            CREATE INDEX IF NOT EXISTS request_logs_model_idx
            ON request_logs(model)
            """
        )
        await conn.execute(
            """
            CREATE INDEX IF NOT EXISTS request_logs_status_idx
            ON request_logs(status)
            """
        )
        await conn.execute(
            """
            CREATE INDEX IF NOT EXISTS request_logs_user_id_idx
            ON request_logs(user_id)
            """
        )
        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS api_users (
                user_id TEXT PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                is_active BOOLEAN NOT NULL DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        await conn.execute(
            """
            CREATE INDEX IF NOT EXISTS api_users_username_idx
            ON api_users(username)
            """
        )
        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS api_keys (
                key_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES api_users(user_id) ON DELETE CASCADE,
                key_hash TEXT NOT NULL UNIQUE,
                key_prefix TEXT NOT NULL,
                name TEXT NOT NULL DEFAULT 'default',
                is_active BOOLEAN NOT NULL DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_used_at TIMESTAMP
            )
            """
        )
        await conn.execute(
            """
            CREATE INDEX IF NOT EXISTS api_keys_user_id_idx
            ON api_keys(user_id)
            """
        )
        await conn.execute(
            """
            CREATE INDEX IF NOT EXISTS api_keys_key_hash_idx
            ON api_keys(key_hash)
            """
        )
        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS redeem_codes (
                code_id TEXT PRIMARY KEY,
                code TEXT NOT NULL UNIQUE,
                is_used BOOLEAN NOT NULL DEFAULT FALSE,
                used_by_user_id TEXT REFERENCES api_users(user_id) ON DELETE SET NULL,
                used_at TIMESTAMP,
                created_by TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        await conn.execute(
            """
            CREATE INDEX IF NOT EXISTS redeem_codes_is_used_idx
            ON redeem_codes(is_used)
            """
        )
        await conn.execute(
            """
            CREATE INDEX IF NOT EXISTS redeem_codes_created_at_idx
            ON redeem_codes(created_at DESC)
            """
        )
        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS oauth_identities (
                identity_id TEXT PRIMARY KEY,
                provider TEXT NOT NULL,
                provider_user_id TEXT NOT NULL,
                user_id TEXT NOT NULL REFERENCES api_users(user_id) ON DELETE CASCADE,
                profile JSONB,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(provider, provider_user_id),
                UNIQUE(provider, user_id)
            )
            """
        )
        await conn.execute(
            """
            CREATE INDEX IF NOT EXISTS oauth_identities_user_idx
            ON oauth_identities(user_id)
            """
        )
        await conn.execute(
            """
            CREATE INDEX IF NOT EXISTS oauth_identities_provider_idx
            ON oauth_identities(provider, provider_user_id)
            """
        )
        logger.info("[STORAGE] Database tables initialized")

def _init_sqlite_tables(conn: sqlite3.Connection) -> None:
    """Initialize SQLite tables."""
    with conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS accounts (
                account_id TEXT PRIMARY KEY,
                position INTEGER NOT NULL,
                data TEXT NOT NULL,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS accounts_position_idx
            ON accounts(position)
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS kv_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS kv_stats (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS task_history (
                id TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                created_at REAL NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS task_history_created_at_idx
            ON task_history(created_at)
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS proxy_control (
                id INTEGER PRIMARY KEY,
                data TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS request_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                model TEXT NOT NULL,
                ttfb_ms INTEGER,
                total_ms INTEGER,
                status TEXT NOT NULL,
                status_code INTEGER,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        _ensure_sqlite_column(conn, "request_logs", "user_id", "TEXT")
        _ensure_sqlite_column(conn, "request_logs", "user_name", "TEXT")
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS request_logs_timestamp_idx
            ON request_logs(timestamp)
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS request_logs_model_idx
            ON request_logs(model)
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS request_logs_status_idx
            ON request_logs(status)
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS request_logs_user_id_idx
            ON request_logs(user_id)
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS api_users (
                user_id TEXT PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS api_users_username_idx
            ON api_users(username)
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS api_keys (
                key_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                key_hash TEXT NOT NULL UNIQUE,
                key_prefix TEXT NOT NULL,
                name TEXT NOT NULL DEFAULT 'default',
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                last_used_at TEXT,
                FOREIGN KEY(user_id) REFERENCES api_users(user_id) ON DELETE CASCADE
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS api_keys_user_id_idx
            ON api_keys(user_id)
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS api_keys_key_hash_idx
            ON api_keys(key_hash)
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS redeem_codes (
                code_id TEXT PRIMARY KEY,
                code TEXT NOT NULL UNIQUE,
                is_used INTEGER NOT NULL DEFAULT 0,
                used_by_user_id TEXT,
                used_at TEXT,
                created_by TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(used_by_user_id) REFERENCES api_users(user_id) ON DELETE SET NULL
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS redeem_codes_is_used_idx
            ON redeem_codes(is_used)
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS redeem_codes_created_at_idx
            ON redeem_codes(created_at)
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS oauth_identities (
                identity_id TEXT PRIMARY KEY,
                provider TEXT NOT NULL,
                provider_user_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                profile TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(provider, provider_user_id),
                UNIQUE(provider, user_id),
                FOREIGN KEY(user_id) REFERENCES api_users(user_id) ON DELETE CASCADE
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS oauth_identities_user_idx
            ON oauth_identities(user_id)
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS oauth_identities_provider_idx
            ON oauth_identities(provider, provider_user_id)
            """
        )


def _sqlite_column_exists(conn: sqlite3.Connection, table_name: str, column_name: str) -> bool:
    rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    for row in rows:
        if row["name"] == column_name:
            return True
    return False


def _ensure_sqlite_column(conn: sqlite3.Connection, table_name: str, column_name: str, column_type: str) -> None:
    if _sqlite_column_exists(conn, table_name, column_name):
        return
    conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}")


# ==================== Accounts storage ====================

def _normalize_accounts(accounts: list) -> list:
    normalized = []
    for index, acc in enumerate(accounts, 1):
        if not isinstance(acc, dict):
            continue
        account_id = acc.get("id") or f"account_{index}"
        next_acc = dict(acc)
        next_acc.setdefault("id", account_id)
        normalized.append(next_acc)
    return normalized

def _parse_account_value(value) -> Optional[dict]:
    if value is None:
        return None
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except Exception:
            return None
    if isinstance(value, dict):
        return value
    return None

async def _load_accounts_from_table() -> Optional[list]:
    backend = _get_backend()
    if backend == "postgres":
        async with _pg_acquire() as conn:
            rows = await conn.fetch(
                "SELECT data FROM accounts ORDER BY position ASC"
            )
        if not rows:
            return []
        accounts = []
        for row in rows:
            value = _parse_account_value(row["data"])
            if value is not None:
                accounts.append(value)
        return accounts
    if backend == "sqlite":
        conn = _get_sqlite_conn()
        with _sqlite_lock:
            rows = conn.execute(
                "SELECT data FROM accounts ORDER BY position ASC"
            ).fetchall()
        if not rows:
            return []
        accounts = []
        for row in rows:
            value = _parse_account_value(row["data"])
            if value is not None:
                accounts.append(value)
        return accounts
    return None

async def _save_accounts_to_table(accounts: list) -> bool:
    backend = _get_backend()
    if backend == "postgres":
        normalized = _normalize_accounts(accounts)
        async with _pg_acquire() as conn:
            async with conn.transaction():
                await conn.execute("DELETE FROM accounts")
                for index, acc in enumerate(normalized, 1):
                    await conn.execute(
                        """
                        INSERT INTO accounts (account_id, position, data, updated_at)
                        VALUES ($1, $2, $3, CURRENT_TIMESTAMP)
                        """,
                        acc["id"],
                        index,
                        json.dumps(acc, ensure_ascii=False),
                    )
        logger.info(f"[STORAGE] Saved {len(normalized)} accounts to database")
        return True
    if backend == "sqlite":
        conn = _get_sqlite_conn()
        normalized = _normalize_accounts(accounts)
        with _sqlite_lock, conn:
            conn.execute("DELETE FROM accounts")
            for index, acc in enumerate(normalized, 1):
                conn.execute(
                    """
                    INSERT INTO accounts (account_id, position, data, updated_at)
                    VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                    """,
                    (acc["id"], index, json.dumps(acc, ensure_ascii=False)),
                )
        logger.info(f"[STORAGE] Saved {len(normalized)} accounts to database")
        return True
    return False

async def load_accounts() -> Optional[list]:
    """
    从数据库加载账户配置（如果启用）

    注意：不再自动从 kv_store 迁移
    如需迁移，请手动运行：python scripts/migrate_to_database.py

    返回 None 表示降级到文件存储
    """
    if not is_database_enabled():
        return None
    try:
        data = await _load_accounts_from_table()
        if data is None:
            return None

        if data:
            logger.info(f"[STORAGE] 从数据库加载 {len(data)} 个账户")
        else:
            logger.info("[STORAGE] 数据库中未找到账户")

        return data
    except Exception as e:
        logger.error(f"[STORAGE] 数据库读取失败: {e}")
    return None


async def get_accounts_updated_at() -> Optional[float]:
    """
    Get the accounts updated_at timestamp (epoch seconds).
    Return None if database is not enabled or failed.
    """
    if not is_database_enabled():
        return None
    backend = _get_backend()
    try:
        if backend == "postgres":
            async with _pg_acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT EXTRACT(EPOCH FROM MAX(updated_at)) AS ts FROM accounts"
                )
                if not row or row["ts"] is None:
                    return None
                return float(row["ts"])
        if backend == "sqlite":
            conn = _get_sqlite_conn()
            with _sqlite_lock:
                row = conn.execute(
                    "SELECT STRFTIME('%s', MAX(updated_at)) AS ts FROM accounts"
                ).fetchone()
            if not row or row["ts"] is None:
                return None
            return float(row["ts"])
    except Exception as e:
        logger.error(f"[STORAGE] Database accounts updated_at failed: {e}")
    return None


def get_accounts_updated_at_sync() -> Optional[float]:
    """Sync wrapper for get_accounts_updated_at."""
    return _run_in_db_loop(get_accounts_updated_at())


async def save_accounts(accounts: list) -> bool:
    """Save account configuration to database when enabled."""
    if not is_database_enabled():
        return False
    try:
        return await _save_accounts_to_table(accounts)
    except Exception as e:
        logger.error(f"[STORAGE] Database write failed: {e}")
    return False


def load_accounts_sync() -> Optional[list]:
    """Sync wrapper for load_accounts (safe in sync/async call sites)."""
    return _run_in_db_loop(load_accounts())


def save_accounts_sync(accounts: list) -> bool:
    """Sync wrapper for save_accounts (safe in sync/async call sites)."""
    return _run_in_db_loop(save_accounts(accounts))

async def _get_account_data(account_id: str) -> Optional[dict]:
    backend = _get_backend()
    if backend == "postgres":
        async with _pg_acquire() as conn:
            row = await conn.fetchrow(
                "SELECT data FROM accounts WHERE account_id = $1",
                account_id,
            )
        if not row:
            return None
        return _parse_account_value(row["data"])
    if backend == "sqlite":
        conn = _get_sqlite_conn()
        with _sqlite_lock:
            row = conn.execute(
                "SELECT data FROM accounts WHERE account_id = ?",
                (account_id,),
            ).fetchone()
        if not row:
            return None
        return _parse_account_value(row["data"])
    return None

async def _update_account_data(account_id: str, data: dict) -> bool:
    backend = _get_backend()
    payload = json.dumps(data, ensure_ascii=False)
    if backend == "postgres":
        async with _pg_acquire() as conn:
            result = await conn.execute(
                """
                UPDATE accounts
                SET data = $2, updated_at = CURRENT_TIMESTAMP
                WHERE account_id = $1
                """,
                account_id,
                payload,
            )
        return result.startswith("UPDATE") and not result.endswith("0")
    if backend == "sqlite":
        conn = _get_sqlite_conn()
        with _sqlite_lock, conn:
            cur = conn.execute(
                """
                UPDATE accounts
                SET data = ?, updated_at = CURRENT_TIMESTAMP
                WHERE account_id = ?
                """,
                (payload, account_id),
            )
        return cur.rowcount > 0
    return False

async def update_account_disabled(account_id: str, disabled: bool) -> bool:
    data = await _get_account_data(account_id)
    if data is None:
        return False
    data["disabled"] = disabled
    return await _update_account_data(account_id, data)

def _apply_cooldown_data(data: dict, cooldown_data: dict) -> None:
    """应用冷却数据到账户数据（消除重复代码）"""
    data["quota_cooldowns"] = cooldown_data.get("quota_cooldowns", {})
    data["conversation_count"] = cooldown_data.get("conversation_count", 0)
    data["failure_count"] = cooldown_data.get("failure_count", 0)
    data["daily_usage"] = cooldown_data.get("daily_usage", {"text": 0, "images": 0, "videos": 0})
    data["daily_usage_date"] = cooldown_data.get("daily_usage_date", "")

async def update_account_cooldown(account_id: str, cooldown_data: dict) -> bool:
    """更新单个账户的冷却状态和统计数据"""
    data = await _get_account_data(account_id)
    if data is None:
        return False
    _apply_cooldown_data(data, cooldown_data)
    return await _update_account_data(account_id, data)

async def bulk_update_accounts_cooldown(updates: list[tuple[str, dict]]) -> tuple[int, list[str]]:
    """批量更新账户冷却状态"""
    if not updates:
        return 0, []

    account_ids = [account_id for account_id, _ in updates]
    cooldown_map = {account_id: cooldown_data for account_id, cooldown_data in updates}

    backend = _get_backend()
    existing: dict[str, dict] = {}
    updated = 0

    if backend == "postgres":
        async with _pg_acquire() as conn:
            # SELECT + UPDATE in one connection to avoid contention
            rows = await conn.fetch(
                "SELECT account_id, data FROM accounts WHERE account_id = ANY($1)",
                account_ids,
            )
            for row in rows:
                data = _parse_account_value(row["data"])
                if data is not None:
                    existing[row["account_id"]] = data

            missing = [aid for aid in account_ids if aid not in existing]
            if existing:
                async with conn.transaction():
                    for account_id, data in existing.items():
                        cooldown_data = cooldown_map[account_id]
                        _apply_cooldown_data(data, cooldown_data)
                        payload = json.dumps(data, ensure_ascii=False)
                        result = await conn.execute(
                            """
                            UPDATE accounts
                            SET data = $2, updated_at = CURRENT_TIMESTAMP
                            WHERE account_id = $1
                            """,
                            account_id,
                            payload,
                        )
                        if result.startswith("UPDATE") and not result.endswith("0"):
                            updated += 1
        return updated, missing if existing else account_ids

    elif backend == "sqlite":
        conn = _get_sqlite_conn()
        placeholders = ",".join(["?"] * len(account_ids))
        with _sqlite_lock:
            rows = conn.execute(
                f"SELECT account_id, data FROM accounts WHERE account_id IN ({placeholders})",
                tuple(account_ids),
            ).fetchall()
        for row in rows:
            data = _parse_account_value(row["data"])
            if data is not None:
                existing[row["account_id"]] = data

        missing = [aid for aid in account_ids if aid not in existing]
        if not existing:
            return 0, missing

        with _sqlite_lock, conn:
            for account_id, data in existing.items():
                cooldown_data = cooldown_map[account_id]
                _apply_cooldown_data(data, cooldown_data)
                payload = json.dumps(data, ensure_ascii=False)
                cur = conn.execute(
                    """
                    UPDATE accounts
                    SET data = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE account_id = ?
                    """,
                    (payload, account_id),
                )
                if cur.rowcount > 0:
                    updated += 1
        return updated, missing

    return 0, account_ids

async def bulk_update_accounts_disabled(account_ids: list[str], disabled: bool) -> tuple[int, list[str]]:
    if not account_ids:
        return 0, []
    backend = _get_backend()
    existing: dict[str, dict] = {}
    if backend == "postgres":
        async with _pg_acquire() as conn:
            rows = await conn.fetch(
                "SELECT account_id, data FROM accounts WHERE account_id = ANY($1)",
                account_ids,
            )
        for row in rows:
            data = _parse_account_value(row["data"])
            if data is not None:
                existing[row["account_id"]] = data
    elif backend == "sqlite":
        conn = _get_sqlite_conn()
        placeholders = ",".join(["?"] * len(account_ids))
        with _sqlite_lock:
            rows = conn.execute(
                f"SELECT account_id, data FROM accounts WHERE account_id IN ({placeholders})",
                tuple(account_ids),
            ).fetchall()
        for row in rows:
            data = _parse_account_value(row["data"])
            if data is not None:
                existing[row["account_id"]] = data
    else:
        return 0, account_ids

    missing = [account_id for account_id in account_ids if account_id not in existing]
    if not existing:
        return 0, missing

    updated = 0
    backend = _get_backend()
    if backend == "postgres":
        async with _pg_acquire() as conn:
            async with conn.transaction():
                for account_id, data in existing.items():
                    data["disabled"] = disabled
                    payload = json.dumps(data, ensure_ascii=False)
                    result = await conn.execute(
                        """
                        UPDATE accounts
                        SET data = $2, updated_at = CURRENT_TIMESTAMP
                        WHERE account_id = $1
                        """,
                        account_id,
                        payload,
                    )
                    if result.startswith("UPDATE") and not result.endswith("0"):
                        updated += 1
    elif backend == "sqlite":
        conn = _get_sqlite_conn()
        with _sqlite_lock, conn:
            for account_id, data in existing.items():
                data["disabled"] = disabled
                payload = json.dumps(data, ensure_ascii=False)
                cur = conn.execute(
                    """
                    UPDATE accounts
                    SET data = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE account_id = ?
                    """,
                    (payload, account_id),
                )
                if cur.rowcount > 0:
                    updated += 1
    return updated, missing

async def _renumber_account_positions() -> None:
    backend = _get_backend()
    if backend == "postgres":
        async with _pg_acquire() as conn:
            await conn.execute(
                """
                WITH ordered AS (
                    SELECT account_id, ROW_NUMBER() OVER (ORDER BY position ASC) AS new_pos
                    FROM accounts
                )
                UPDATE accounts AS a
                SET position = ordered.new_pos,
                    updated_at = CURRENT_TIMESTAMP
                FROM ordered
                WHERE a.account_id = ordered.account_id
                """
            )
        return
    if backend == "sqlite":
        conn = _get_sqlite_conn()
        with _sqlite_lock, conn:
            rows = conn.execute(
                "SELECT account_id FROM accounts ORDER BY position ASC"
            ).fetchall()
            for index, row in enumerate(rows, 1):
                conn.execute(
                    "UPDATE accounts SET position = ?, updated_at = CURRENT_TIMESTAMP WHERE account_id = ?",
                    (index, row["account_id"]),
                )

async def delete_accounts(account_ids: list[str]) -> int:
    if not account_ids:
        return 0
    backend = _get_backend()
    deleted = 0
    if backend == "postgres":
        async with _pg_acquire() as conn:
            result = await conn.execute(
                "DELETE FROM accounts WHERE account_id = ANY($1)",
                account_ids,
            )
        try:
            deleted = int(result.split()[-1])
        except Exception:
            deleted = 0
    elif backend == "sqlite":
        conn = _get_sqlite_conn()
        placeholders = ",".join(["?"] * len(account_ids))
        with _sqlite_lock, conn:
            cur = conn.execute(
                f"DELETE FROM accounts WHERE account_id IN ({placeholders})",
                tuple(account_ids),
            )
            deleted = cur.rowcount or 0
    else:
        return 0

    if deleted > 0:
        await _renumber_account_positions()
    return deleted

def update_account_disabled_sync(account_id: str, disabled: bool) -> bool:
    return _run_in_db_loop(update_account_disabled(account_id, disabled))

def update_account_cooldown_sync(account_id: str, cooldown_data: dict) -> bool:
    return _run_in_db_loop(update_account_cooldown(account_id, cooldown_data))

def bulk_update_accounts_cooldown_sync(updates: list[tuple[str, dict]]) -> tuple[int, list[str]]:
    return _run_in_db_loop(bulk_update_accounts_cooldown(updates))

def bulk_update_accounts_disabled_sync(account_ids: list[str], disabled: bool) -> tuple[int, list[str]]:
    return _run_in_db_loop(bulk_update_accounts_disabled(account_ids, disabled))

def delete_accounts_sync(account_ids: list[str]) -> int:
    return _run_in_db_loop(delete_accounts(account_ids))


# ==================== Settings storage ====================

async def _load_kv(table_name: str, key: str) -> Optional[dict]:
    """加载键值数据"""
    backend = _get_backend()
    if backend == "postgres":
        async with _pg_acquire() as conn:
            row = await conn.fetchrow(
                f"SELECT value FROM {table_name} WHERE key = $1",
                key,
            )
        if not row:
            return None
        value = row["value"]
        if isinstance(value, str):
            return json.loads(value)
        return value

    if backend == "sqlite":
        conn = _get_sqlite_conn()
        with _sqlite_lock:
            row = conn.execute(
                f"SELECT value FROM {table_name} WHERE key = ?",
                (key,),
            ).fetchone()
        if not row:
            return None
        value = row["value"]
        if isinstance(value, str):
            return json.loads(value)
        return value
    return None


async def _save_kv(table_name: str, key: str, value: dict) -> bool:
    backend = _get_backend()
    payload = json.dumps(value, ensure_ascii=False)
    if backend == "postgres":
        async with _pg_acquire() as conn:
            await conn.execute(
                f"""
                INSERT INTO {table_name} (key, value, updated_at)
                VALUES ($1, $2, CURRENT_TIMESTAMP)
                ON CONFLICT (key) DO UPDATE SET
                    value = EXCLUDED.value,
                    updated_at = CURRENT_TIMESTAMP
                """,
                key,
                payload,
            )
        return True
    if backend == "sqlite":
        conn = _get_sqlite_conn()
        with _sqlite_lock, conn:
            conn.execute(
                f"""
                INSERT INTO {table_name} (key, value, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(key) DO UPDATE SET
                    value = excluded.value,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (key, payload),
            )
        return True
    return False

async def load_settings() -> Optional[dict]:
    if not is_database_enabled():
        return None
    try:
        return await _load_kv("kv_settings", "settings")
    except Exception as e:
        logger.error(f"[STORAGE] Settings read failed: {e}")
    return None


async def save_settings(settings: dict) -> bool:
    if not is_database_enabled():
        return False
    try:
        saved = await _save_kv("kv_settings", "settings", settings)
        if saved:
            logger.info("[STORAGE] Settings saved to database")
        return saved
    except Exception as e:
        logger.error(f"[STORAGE] Settings write failed: {e}")
    return False


# ==================== Stats storage ====================

async def load_stats() -> Optional[dict]:
    if not is_database_enabled():
        return None
    try:
        return await _load_kv("kv_stats", "stats")
    except Exception as e:
        logger.error(f"[STORAGE] Stats read failed: {e}")
    return None


async def save_stats(stats: dict) -> bool:
    if not is_database_enabled():
        return False
    try:
        return await _save_kv("kv_stats", "stats", stats)
    except Exception as e:
        logger.error(f"[STORAGE] Stats write failed: {e}")
    return False


def load_settings_sync() -> Optional[dict]:
    return _run_in_db_loop(load_settings())


def save_settings_sync(settings: dict) -> bool:
    return _run_in_db_loop(save_settings(settings))


# ==================== Nodes storage ====================

async def load_nodes() -> Optional[list]:
    if not is_database_enabled():
        return None
    try:
        data = await _load_kv("kv_settings", "nodes")
        if data is None:
            return []
        if isinstance(data, list):
            return data
        return []
    except Exception as e:
        logger.error(f"[STORAGE] Nodes read failed: {e}")
    return None


async def save_nodes(nodes: list) -> bool:
    if not is_database_enabled():
        return False
    try:
        saved = await _save_kv("kv_settings", "nodes", nodes)
        if saved:
            logger.info(f"[STORAGE] Saved {len(nodes)} nodes to database")
        return saved
    except Exception as e:
        logger.error(f"[STORAGE] Nodes write failed: {e}")
    return False


def load_nodes_sync() -> Optional[list]:
    return _run_in_db_loop(load_nodes())


def save_nodes_sync(nodes: list) -> bool:
    return _run_in_db_loop(save_nodes(nodes))


def load_stats_sync() -> Optional[dict]:
    return _run_in_db_loop(load_stats())


def save_stats_sync(stats: dict) -> bool:
    return _run_in_db_loop(save_stats(stats))


# ==================== Task history storage ====================

async def save_task_history_entry(entry: dict) -> bool:
    if not is_database_enabled():
        return False
    entry_id = entry.get("id")
    if not entry_id:
        return False
    created_at = float(entry.get("created_at", time.time()))
    payload = json.dumps(entry, ensure_ascii=False)
    backend = _get_backend()
    try:
        if backend == "postgres":
            async with _pg_acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO task_history (id, data, created_at)
                    VALUES ($1, $2, $3)
                    ON CONFLICT (id) DO UPDATE SET
                        data = EXCLUDED.data,
                        created_at = EXCLUDED.created_at
                    """,
                    entry_id,
                    payload,
                    created_at,
                )
                await conn.execute(
                    """
                    DELETE FROM task_history
                    WHERE id IN (
                        SELECT id FROM task_history
                        ORDER BY created_at DESC
                        OFFSET 100
                    )
                    """
                )
            return True
        if backend == "sqlite":
            conn = _get_sqlite_conn()
            with _sqlite_lock, conn:
                conn.execute(
                    """
                    INSERT INTO task_history (id, data, created_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        data = excluded.data,
                        created_at = excluded.created_at
                    """,
                    (entry_id, payload, created_at),
                )
                conn.execute(
                    """
                    DELETE FROM task_history
                    WHERE id IN (
                        SELECT id FROM task_history
                        ORDER BY created_at DESC
                        LIMIT -1 OFFSET 100
                    )
                    """
                )
            return True
    except Exception as e:
        logger.error(f"[STORAGE] Task history write failed: {e}")
    return False


async def load_task_history(limit: int = 100) -> Optional[list]:
    if not is_database_enabled():
        return None
    backend = _get_backend()
    try:
        if backend == "postgres":
            async with _pg_acquire() as conn:
                rows = await conn.fetch(
                    """
                    SELECT data FROM task_history
                    ORDER BY created_at DESC
                    LIMIT $1
                    """,
                    limit,
                )
            return [_parse_account_value(row["data"]) for row in rows if row and row["data"] is not None]
        if backend == "sqlite":
            conn = _get_sqlite_conn()
            with _sqlite_lock:
                rows = conn.execute(
                    """
                    SELECT data FROM task_history
                    ORDER BY created_at DESC
                    LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
            results = []
            for row in rows:
                value = _parse_account_value(row["data"])
                if value is not None:
                    results.append(value)
            return results
    except Exception as e:
        logger.error(f"[STORAGE] Task history read failed: {e}")
    return None


async def clear_task_history() -> int:
    if not is_database_enabled():
        return 0
    backend = _get_backend()
    try:
        if backend == "postgres":
            async with _pg_acquire() as conn:
                result = await conn.execute("DELETE FROM task_history")
            if result.startswith("DELETE"):
                parts = result.split()
                return int(parts[-1]) if parts else 0
            return 0
        if backend == "sqlite":
            conn = _get_sqlite_conn()
            with _sqlite_lock, conn:
                cur = conn.execute("DELETE FROM task_history")
                return cur.rowcount or 0
    except Exception as e:
        logger.error(f"[STORAGE] Task history clear failed: {e}")
    return 0


def save_task_history_entry_sync(entry: dict) -> bool:
    return _run_in_db_loop(save_task_history_entry(entry))


def load_task_history_sync(limit: int = 100) -> Optional[list]:
    return _run_in_db_loop(load_task_history(limit))


def clear_task_history_sync() -> int:
    return _run_in_db_loop(clear_task_history())


# ==================== API users & keys ====================

def _normalize_api_user_row(row) -> dict:
    return {
        "user_id": row["user_id"],
        "username": row["username"],
        "password_hash": row["password_hash"],
        "role": row["role"],
        "is_active": bool(row["is_active"]),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def _normalize_api_key_row(row) -> dict:
    return {
        "key_id": row["key_id"],
        "user_id": row["user_id"],
        "key_prefix": row["key_prefix"],
        "name": row["name"],
        "is_active": bool(row["is_active"]),
        "created_at": row["created_at"],
        "last_used_at": row["last_used_at"],
    }


_REDEEM_CODE_PATTERN = re.compile(r"^[A-Z0-9][A-Z0-9_-]{5,63}$")


def normalize_redeem_code(code: str) -> str:
    return str(code or "").strip().upper()


def is_valid_redeem_code(code: str) -> bool:
    return bool(_REDEEM_CODE_PATTERN.fullmatch(normalize_redeem_code(code)))


def _normalize_redeem_code_row(row) -> dict:
    return {
        "code_id": row["code_id"],
        "code": row["code"],
        "is_used": bool(row["is_used"]),
        "used_by_user_id": row["used_by_user_id"],
        "used_at": row["used_at"],
        "created_by": row["created_by"],
        "created_at": row["created_at"],
    }


def _normalize_oauth_identity_row(row) -> dict:
    profile_raw = row["profile"]
    profile = None
    if isinstance(profile_raw, str):
        try:
            profile = json.loads(profile_raw)
        except Exception:
            profile = None
    elif isinstance(profile_raw, dict):
        profile = profile_raw
    return {
        "identity_id": row["identity_id"],
        "provider": row["provider"],
        "provider_user_id": row["provider_user_id"],
        "user_id": row["user_id"],
        "profile": profile,
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


async def get_api_user_by_username(username: str) -> Optional[dict]:
    if not is_database_enabled():
        return None
    uname = (username or "").strip().lower()
    if not uname:
        return None
    backend = _get_backend()
    try:
        if backend == "postgres":
            async with _pg_acquire() as conn:
                row = await conn.fetchrow(
                    """
                    SELECT user_id, username, password_hash, role, is_active, created_at, updated_at
                    FROM api_users
                    WHERE username = $1
                    """,
                    uname,
                )
            return _normalize_api_user_row(row) if row else None
        if backend == "sqlite":
            conn = _get_sqlite_conn()
            with _sqlite_lock:
                row = conn.execute(
                    """
                    SELECT user_id, username, password_hash, role, is_active, created_at, updated_at
                    FROM api_users
                    WHERE username = ?
                    """,
                    (uname,),
                ).fetchone()
            return _normalize_api_user_row(row) if row else None
    except Exception as e:
        logger.error(f"[STORAGE] get_api_user_by_username failed: {e}")
    return None


async def ensure_admin_api_user(username: str = "admin", password_hash: str = "") -> Optional[dict]:
    if not is_database_enabled():
        return None
    uname = (username or "admin").strip().lower() or "admin"
    existing = await get_api_user_by_username(uname)
    if existing:
        backend = _get_backend()
        update_password = bool(password_hash and (existing.get("password_hash") in ("", "!", None)))
        try:
            if backend == "postgres":
                async with _pg_acquire() as conn:
                    if update_password:
                        await conn.execute(
                            """
                            UPDATE api_users
                            SET role = 'admin', is_active = TRUE, password_hash = $2, updated_at = CURRENT_TIMESTAMP
                            WHERE user_id = $1
                            """,
                            existing["user_id"],
                            password_hash,
                        )
                    else:
                        await conn.execute(
                            """
                            UPDATE api_users
                            SET role = 'admin', is_active = TRUE, updated_at = CURRENT_TIMESTAMP
                            WHERE user_id = $1
                            """,
                            existing["user_id"],
                        )
            elif backend == "sqlite":
                conn = _get_sqlite_conn()
                with _sqlite_lock, conn:
                    if update_password:
                        conn.execute(
                            """
                            UPDATE api_users
                            SET role = 'admin', is_active = 1, password_hash = ?, updated_at = CURRENT_TIMESTAMP
                            WHERE user_id = ?
                            """,
                            (password_hash, existing["user_id"]),
                        )
                    else:
                        conn.execute(
                            """
                            UPDATE api_users
                            SET role = 'admin', is_active = 1, updated_at = CURRENT_TIMESTAMP
                            WHERE user_id = ?
                            """,
                            (existing["user_id"],),
                        )
            return await get_api_user_by_username(uname)
        except Exception as e:
            logger.error(f"[STORAGE] ensure_admin_api_user update failed: {e}")
            return None

    user_id = str(uuid4())
    initial_hash = (password_hash or "").strip() or "!"
    backend = _get_backend()
    try:
        if backend == "postgres":
            async with _pg_acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO api_users (user_id, username, password_hash, role, is_active, created_at, updated_at)
                    VALUES ($1, $2, $3, 'admin', TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                    """,
                    user_id,
                    uname,
                    initial_hash,
                )
        elif backend == "sqlite":
            conn = _get_sqlite_conn()
            with _sqlite_lock, conn:
                conn.execute(
                    """
                    INSERT INTO api_users (user_id, username, password_hash, role, is_active, created_at, updated_at)
                    VALUES (?, ?, ?, 'admin', 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                    """,
                    (user_id, uname, initial_hash),
                )
        logger.info(f"[AUTH] ensured admin api user: {uname}")
        return await get_api_user_by_username(uname)
    except Exception as e:
        logger.error(f"[STORAGE] ensure_admin_api_user insert failed: {e}")
    return None


async def create_api_user(username: str, password_hash: str, role: str = "user") -> Optional[dict]:
    if not is_database_enabled():
        return None
    uname = (username or "").strip().lower()
    pwd_hash = (password_hash or "").strip()
    user_role = (role or "user").strip().lower() or "user"
    if not uname or not pwd_hash:
        return None
    user_id = str(uuid4())
    backend = _get_backend()
    try:
        if backend == "postgres":
            async with _pg_acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO api_users (user_id, username, password_hash, role, is_active, created_at, updated_at)
                    VALUES ($1, $2, $3, $4, TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                    """,
                    user_id,
                    uname,
                    pwd_hash,
                    user_role,
                )
        elif backend == "sqlite":
            conn = _get_sqlite_conn()
            with _sqlite_lock, conn:
                conn.execute(
                    """
                    INSERT INTO api_users (user_id, username, password_hash, role, is_active, created_at, updated_at)
                    VALUES (?, ?, ?, ?, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                    """,
                    (user_id, uname, pwd_hash, user_role),
                )
        return await get_api_user_by_username(uname)
    except Exception as e:
        logger.warning(f"[STORAGE] create_api_user failed for {uname}: {e}")
        # most likely duplicate username
        return None


async def create_api_key(user_id: str, key_hash: str, key_prefix: str, name: str = "default") -> Optional[dict]:
    if not is_database_enabled():
        return None
    uid = (user_id or "").strip()
    khash = (key_hash or "").strip()
    prefix = (key_prefix or "").strip()
    key_name = (name or "default").strip() or "default"
    if not uid or not khash or not prefix:
        return None
    key_id = str(uuid4())
    backend = _get_backend()
    try:
        if backend == "postgres":
            async with _pg_acquire() as conn:
                row = await conn.fetchrow(
                    """
                    INSERT INTO api_keys (key_id, user_id, key_hash, key_prefix, name, is_active, created_at)
                    VALUES ($1, $2, $3, $4, $5, TRUE, CURRENT_TIMESTAMP)
                    RETURNING key_id, user_id, key_prefix, name, is_active, created_at, last_used_at
                    """,
                    key_id,
                    uid,
                    khash,
                    prefix,
                    key_name,
                )
            return _normalize_api_key_row(row) if row else None
        if backend == "sqlite":
            conn = _get_sqlite_conn()
            with _sqlite_lock, conn:
                conn.execute(
                    """
                    INSERT INTO api_keys (key_id, user_id, key_hash, key_prefix, name, is_active, created_at)
                    VALUES (?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP)
                    """,
                    (key_id, uid, khash, prefix, key_name),
                )
                row = conn.execute(
                    """
                    SELECT key_id, user_id, key_prefix, name, is_active, created_at, last_used_at
                    FROM api_keys
                    WHERE key_id = ?
                    """,
                    (key_id,),
                ).fetchone()
            return _normalize_api_key_row(row) if row else None
    except Exception as e:
        logger.error(f"[STORAGE] create_api_key failed: {e}")
    return None


async def list_user_api_keys(user_id: str, include_inactive: bool = False) -> list[dict]:
    uid = (user_id or "").strip()
    if not is_database_enabled() or not uid:
        return []
    backend = _get_backend()
    rows = []
    try:
        if backend == "postgres":
            query = """
                SELECT key_id, user_id, key_prefix, name, is_active, created_at, last_used_at
                FROM api_keys
                WHERE user_id = $1
            """
            if not include_inactive:
                query += " AND is_active = TRUE"
            query += " ORDER BY created_at DESC"
            async with _pg_acquire() as conn:
                rows = await conn.fetch(query, uid)
        elif backend == "sqlite":
            query = """
                SELECT key_id, user_id, key_prefix, name, is_active, created_at, last_used_at
                FROM api_keys
                WHERE user_id = ?
            """
            if not include_inactive:
                query += " AND is_active = 1"
            query += " ORDER BY datetime(created_at) DESC"
            conn = _get_sqlite_conn()
            with _sqlite_lock:
                rows = conn.execute(query, (uid,)).fetchall()
    except Exception as e:
        logger.error(f"[STORAGE] list_user_api_keys failed: {e}")
        return []
    return [_normalize_api_key_row(row) for row in rows]


async def deactivate_api_key(key_id: str, user_id: Optional[str] = None) -> bool:
    kid = (key_id or "").strip()
    uid = (user_id or "").strip()
    if not is_database_enabled() or not kid:
        return False
    backend = _get_backend()
    try:
        if backend == "postgres":
            if uid:
                sql = "UPDATE api_keys SET is_active = FALSE WHERE key_id = $1 AND user_id = $2"
                args = (kid, uid)
            else:
                sql = "UPDATE api_keys SET is_active = FALSE WHERE key_id = $1"
                args = (kid,)
            async with _pg_acquire() as conn:
                result = await conn.execute(sql, *args)
            return result.startswith("UPDATE") and not result.endswith("0")
        if backend == "sqlite":
            conn = _get_sqlite_conn()
            with _sqlite_lock, conn:
                if uid:
                    cur = conn.execute(
                        "UPDATE api_keys SET is_active = 0 WHERE key_id = ? AND user_id = ?",
                        (kid, uid),
                    )
                else:
                    cur = conn.execute(
                        "UPDATE api_keys SET is_active = 0 WHERE key_id = ?",
                        (kid,),
                    )
            return (cur.rowcount or 0) > 0
    except Exception as e:
        logger.error(f"[STORAGE] deactivate_api_key failed: {e}")
    return False


async def authenticate_api_key(key_hash: str) -> Optional[dict]:
    khash = (key_hash or "").strip()
    if not is_database_enabled() or not khash:
        return None
    backend = _get_backend()
    try:
        if backend == "postgres":
            async with _pg_acquire() as conn:
                row = await conn.fetchrow(
                    """
                    SELECT
                        u.user_id, u.username, u.role, u.is_active AS user_is_active,
                        k.key_id, k.is_active AS key_is_active
                    FROM api_keys k
                    JOIN api_users u ON u.user_id = k.user_id
                    WHERE k.key_hash = $1
                    """,
                    khash,
                )
                if not row:
                    return None
                if not row["user_is_active"] or not row["key_is_active"]:
                    return None
                await conn.execute(
                    "UPDATE api_keys SET last_used_at = CURRENT_TIMESTAMP WHERE key_id = $1",
                    row["key_id"],
                )
                return {
                    "user_id": row["user_id"],
                    "username": row["username"],
                    "role": row["role"],
                    "key_id": row["key_id"],
                }
        if backend == "sqlite":
            conn = _get_sqlite_conn()
            with _sqlite_lock, conn:
                row = conn.execute(
                    """
                    SELECT
                        u.user_id, u.username, u.role, u.is_active AS user_is_active,
                        k.key_id, k.is_active AS key_is_active
                    FROM api_keys k
                    JOIN api_users u ON u.user_id = k.user_id
                    WHERE k.key_hash = ?
                    """,
                    (khash,),
                ).fetchone()
                if not row:
                    return None
                if not bool(row["user_is_active"]) or not bool(row["key_is_active"]):
                    return None
                conn.execute(
                    "UPDATE api_keys SET last_used_at = CURRENT_TIMESTAMP WHERE key_id = ?",
                    (row["key_id"],),
                )
            return {
                "user_id": row["user_id"],
                "username": row["username"],
                "role": row["role"],
                "key_id": row["key_id"],
            }
    except Exception as e:
        logger.error(f"[STORAGE] authenticate_api_key failed: {e}")
    return None


async def list_api_users(limit: int = 200) -> list[dict]:
    if not is_database_enabled():
        return []
    max_limit = max(1, min(int(limit), 1000))
    backend = _get_backend()
    rows = []
    try:
        if backend == "postgres":
            async with _pg_acquire() as conn:
                rows = await conn.fetch(
                    """
                    SELECT
                        u.user_id, u.username, u.role, u.is_active, u.created_at, u.updated_at,
                        COUNT(k.key_id) FILTER (WHERE k.is_active = TRUE) AS active_key_count,
                        COUNT(k.key_id) AS total_key_count
                    FROM api_users u
                    LEFT JOIN api_keys k ON k.user_id = u.user_id
                    GROUP BY u.user_id, u.username, u.role, u.is_active, u.created_at, u.updated_at
                    ORDER BY u.created_at DESC
                    LIMIT $1
                    """,
                    max_limit,
                )
            result = []
            for row in rows:
                result.append(
                    {
                        "user_id": row["user_id"],
                        "username": row["username"],
                        "role": row["role"],
                        "is_active": bool(row["is_active"]),
                        "created_at": row["created_at"],
                        "updated_at": row["updated_at"],
                        "active_key_count": int(row["active_key_count"] or 0),
                        "total_key_count": int(row["total_key_count"] or 0),
                    }
                )
            return result
        if backend == "sqlite":
            conn = _get_sqlite_conn()
            with _sqlite_lock:
                rows = conn.execute(
                    """
                    SELECT
                        u.user_id, u.username, u.role, u.is_active, u.created_at, u.updated_at,
                        SUM(CASE WHEN k.is_active = 1 THEN 1 ELSE 0 END) AS active_key_count,
                        COUNT(k.key_id) AS total_key_count
                    FROM api_users u
                    LEFT JOIN api_keys k ON k.user_id = u.user_id
                    GROUP BY u.user_id, u.username, u.role, u.is_active, u.created_at, u.updated_at
                    ORDER BY datetime(u.created_at) DESC
                    LIMIT ?
                    """,
                    (max_limit,),
                ).fetchall()
            result = []
            for row in rows:
                result.append(
                    {
                        "user_id": row["user_id"],
                        "username": row["username"],
                        "role": row["role"],
                        "is_active": bool(row["is_active"]),
                        "created_at": row["created_at"],
                        "updated_at": row["updated_at"],
                        "active_key_count": int(row["active_key_count"] or 0),
                        "total_key_count": int(row["total_key_count"] or 0),
                    }
                )
            return result
    except Exception as e:
        logger.error(f"[STORAGE] list_api_users failed: {e}")
    return []


async def set_api_user_active(user_id: str, is_active: bool) -> bool:
    uid = (user_id or "").strip()
    if not is_database_enabled() or not uid:
        return False
    backend = _get_backend()
    try:
        if backend == "postgres":
            async with _pg_acquire() as conn:
                result = await conn.execute(
                    """
                    UPDATE api_users
                    SET is_active = $2, updated_at = CURRENT_TIMESTAMP
                    WHERE user_id = $1
                    """,
                    uid,
                    bool(is_active),
                )
            return result.startswith("UPDATE") and not result.endswith("0")
        if backend == "sqlite":
            conn = _get_sqlite_conn()
            with _sqlite_lock, conn:
                cur = conn.execute(
                    """
                    UPDATE api_users
                    SET is_active = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE user_id = ?
                    """,
                    (1 if is_active else 0, uid),
                )
            return (cur.rowcount or 0) > 0
    except Exception as e:
        logger.error(f"[STORAGE] set_api_user_active failed: {e}")
    return False


async def get_api_user_by_id(user_id: str) -> Optional[dict]:
    uid = (user_id or "").strip()
    if not is_database_enabled() or not uid:
        return None
    backend = _get_backend()
    try:
        if backend == "postgres":
            async with _pg_acquire() as conn:
                row = await conn.fetchrow(
                    """
                    SELECT user_id, username, password_hash, role, is_active, created_at, updated_at
                    FROM api_users
                    WHERE user_id = $1
                    """,
                    uid,
                )
            return _normalize_api_user_row(row) if row else None
        if backend == "sqlite":
            conn = _get_sqlite_conn()
            with _sqlite_lock:
                row = conn.execute(
                    """
                    SELECT user_id, username, password_hash, role, is_active, created_at, updated_at
                    FROM api_users
                    WHERE user_id = ?
                    """,
                    (uid,),
                ).fetchone()
            return _normalize_api_user_row(row) if row else None
    except Exception as e:
        logger.error(f"[STORAGE] get_api_user_by_id failed: {e}")
    return None


async def update_api_user_role(user_id: str, role: str) -> bool:
    uid = (user_id or "").strip()
    target_role = (role or "").strip().lower()
    if not is_database_enabled() or not uid or not target_role:
        return False
    backend = _get_backend()
    try:
        if backend == "postgres":
            async with _pg_acquire() as conn:
                result = await conn.execute(
                    """
                    UPDATE api_users
                    SET role = $2, updated_at = CURRENT_TIMESTAMP
                    WHERE user_id = $1
                    """,
                    uid,
                    target_role,
                )
            return result.startswith("UPDATE") and not result.endswith("0")
        if backend == "sqlite":
            conn = _get_sqlite_conn()
            with _sqlite_lock, conn:
                cur = conn.execute(
                    """
                    UPDATE api_users
                    SET role = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE user_id = ?
                    """,
                    (target_role, uid),
                )
            return (cur.rowcount or 0) > 0
    except Exception as e:
        logger.error(f"[STORAGE] update_api_user_role failed: {e}")
    return False


async def update_api_user_password(user_id: str, password_hash: str) -> bool:
    uid = (user_id or "").strip()
    pwd_hash = (password_hash or "").strip()
    if not is_database_enabled() or not uid or not pwd_hash:
        return False
    backend = _get_backend()
    try:
        if backend == "postgres":
            async with _pg_acquire() as conn:
                result = await conn.execute(
                    """
                    UPDATE api_users
                    SET password_hash = $2, updated_at = CURRENT_TIMESTAMP
                    WHERE user_id = $1
                    """,
                    uid,
                    pwd_hash,
                )
            return result.startswith("UPDATE") and not result.endswith("0")
        if backend == "sqlite":
            conn = _get_sqlite_conn()
            with _sqlite_lock, conn:
                cur = conn.execute(
                    """
                    UPDATE api_users
                    SET password_hash = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE user_id = ?
                    """,
                    (pwd_hash, uid),
                )
            return (cur.rowcount or 0) > 0
    except Exception as e:
        logger.error(f"[STORAGE] update_api_user_password failed: {e}")
    return False


async def delete_api_user(user_id: str) -> bool:
    uid = (user_id or "").strip()
    if not is_database_enabled() or not uid:
        return False
    backend = _get_backend()
    try:
        if backend == "postgres":
            async with _pg_acquire() as conn:
                result = await conn.execute("DELETE FROM api_users WHERE user_id = $1", uid)
            return result.startswith("DELETE") and not result.endswith("0")
        if backend == "sqlite":
            conn = _get_sqlite_conn()
            with _sqlite_lock, conn:
                cur = conn.execute("DELETE FROM api_users WHERE user_id = ?", (uid,))
            return (cur.rowcount or 0) > 0
    except Exception as e:
        logger.error(f"[STORAGE] delete_api_user failed: {e}")
    return False


async def get_oauth_identity(provider: str, provider_user_id: str) -> Optional[dict]:
    if not is_database_enabled():
        return None
    p = (provider or "").strip().lower()
    subject = (provider_user_id or "").strip()
    if not p or not subject:
        return None
    backend = _get_backend()
    try:
        if backend == "postgres":
            async with _pg_acquire() as conn:
                row = await conn.fetchrow(
                    """
                    SELECT identity_id, provider, provider_user_id, user_id, profile, created_at, updated_at
                    FROM oauth_identities
                    WHERE provider = $1 AND provider_user_id = $2
                    """,
                    p,
                    subject,
                )
            return _normalize_oauth_identity_row(row) if row else None
        if backend == "sqlite":
            conn = _get_sqlite_conn()
            with _sqlite_lock:
                row = conn.execute(
                    """
                    SELECT identity_id, provider, provider_user_id, user_id, profile, created_at, updated_at
                    FROM oauth_identities
                    WHERE provider = ? AND provider_user_id = ?
                    """,
                    (p, subject),
                ).fetchone()
            return _normalize_oauth_identity_row(row) if row else None
    except Exception as e:
        logger.error(f"[STORAGE] get_oauth_identity failed: {e}")
    return None


async def get_api_user_by_oauth(provider: str, provider_user_id: str) -> Optional[dict]:
    if not is_database_enabled():
        return None
    p = (provider or "").strip().lower()
    subject = (provider_user_id or "").strip()
    if not p or not subject:
        return None
    backend = _get_backend()
    try:
        if backend == "postgres":
            async with _pg_acquire() as conn:
                row = await conn.fetchrow(
                    """
                    SELECT u.user_id, u.username, u.password_hash, u.role, u.is_active, u.created_at, u.updated_at
                    FROM oauth_identities o
                    JOIN api_users u ON u.user_id = o.user_id
                    WHERE o.provider = $1 AND o.provider_user_id = $2
                    """,
                    p,
                    subject,
                )
            return _normalize_api_user_row(row) if row else None
        if backend == "sqlite":
            conn = _get_sqlite_conn()
            with _sqlite_lock:
                row = conn.execute(
                    """
                    SELECT u.user_id, u.username, u.password_hash, u.role, u.is_active, u.created_at, u.updated_at
                    FROM oauth_identities o
                    JOIN api_users u ON u.user_id = o.user_id
                    WHERE o.provider = ? AND o.provider_user_id = ?
                    """,
                    (p, subject),
                ).fetchone()
            return _normalize_api_user_row(row) if row else None
    except Exception as e:
        logger.error(f"[STORAGE] get_api_user_by_oauth failed: {e}")
    return None


async def save_oauth_identity(
    user_id: str,
    provider: str,
    provider_user_id: str,
    profile: Optional[dict] = None,
) -> Optional[dict]:
    if not is_database_enabled():
        return None
    uid = (user_id or "").strip()
    p = (provider or "").strip().lower()
    subject = (provider_user_id or "").strip()
    if not uid or not p or not subject:
        return None

    existing = await get_oauth_identity(p, subject)
    if existing:
        if existing.get("user_id") != uid:
            logger.warning(
                "[STORAGE] oauth subject already bound to another user: provider=%s subject=%s",
                p,
                subject,
            )
            return None
        backend = _get_backend()
        payload = json.dumps(profile or {}, ensure_ascii=False)
        try:
            if backend == "postgres":
                async with _pg_acquire() as conn:
                    row = await conn.fetchrow(
                        """
                        UPDATE oauth_identities
                        SET profile = $3::jsonb, updated_at = CURRENT_TIMESTAMP
                        WHERE provider = $1 AND provider_user_id = $2
                        RETURNING identity_id, provider, provider_user_id, user_id, profile, created_at, updated_at
                        """,
                        p,
                        subject,
                        payload,
                    )
                return _normalize_oauth_identity_row(row) if row else existing
            if backend == "sqlite":
                conn = _get_sqlite_conn()
                with _sqlite_lock, conn:
                    conn.execute(
                        """
                        UPDATE oauth_identities
                        SET profile = ?, updated_at = CURRENT_TIMESTAMP
                        WHERE provider = ? AND provider_user_id = ?
                        """,
                        (payload, p, subject),
                    )
                    row = conn.execute(
                        """
                        SELECT identity_id, provider, provider_user_id, user_id, profile, created_at, updated_at
                        FROM oauth_identities
                        WHERE provider = ? AND provider_user_id = ?
                        """,
                        (p, subject),
                    ).fetchone()
                return _normalize_oauth_identity_row(row) if row else existing
        except Exception as e:
            logger.error(f"[STORAGE] save_oauth_identity update failed: {e}")
            return existing

    backend = _get_backend()
    payload = json.dumps(profile or {}, ensure_ascii=False)
    identity_id = str(uuid4())
    try:
        if backend == "postgres":
            async with _pg_acquire() as conn:
                row = await conn.fetchrow(
                    """
                    INSERT INTO oauth_identities (
                        identity_id, provider, provider_user_id, user_id, profile, created_at, updated_at
                    )
                    VALUES ($1, $2, $3, $4, $5::jsonb, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                    RETURNING identity_id, provider, provider_user_id, user_id, profile, created_at, updated_at
                    """,
                    identity_id,
                    p,
                    subject,
                    uid,
                    payload,
                )
            return _normalize_oauth_identity_row(row) if row else None
        if backend == "sqlite":
            conn = _get_sqlite_conn()
            with _sqlite_lock, conn:
                conn.execute(
                    """
                    INSERT INTO oauth_identities (
                        identity_id, provider, provider_user_id, user_id, profile, created_at, updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                    """,
                    (identity_id, p, subject, uid, payload),
                )
                row = conn.execute(
                    """
                    SELECT identity_id, provider, provider_user_id, user_id, profile, created_at, updated_at
                    FROM oauth_identities
                    WHERE identity_id = ?
                    """,
                    (identity_id,),
                ).fetchone()
            return _normalize_oauth_identity_row(row) if row else None
    except Exception as e:
        logger.error(f"[STORAGE] save_oauth_identity insert failed: {e}")
    return None


def _start_of_local_day_timestamp() -> int:
    now = time.time()
    local = time.localtime(now)
    day_start = time.mktime(
        (
            local.tm_year,
            local.tm_mon,
            local.tm_mday,
            0,
            0,
            0,
            local.tm_wday,
            local.tm_yday,
            local.tm_isdst,
        )
    )
    return int(day_start)


async def get_user_request_counts(user_id: str, *, day_start_ts: int, window_start_ts: int) -> dict:
    uid = (user_id or "").strip()
    if not is_database_enabled() or not uid:
        return {"day_count": 0, "window_count": 0, "total_count": 0, "last_call_ts": None}
    backend = _get_backend()
    try:
        if backend == "postgres":
            async with _pg_acquire() as conn:
                row = await conn.fetchrow(
                    """
                    SELECT
                        COUNT(*) FILTER (WHERE timestamp >= $2) AS day_count,
                        COUNT(*) FILTER (WHERE timestamp >= $3) AS window_count,
                        COUNT(*) AS total_count,
                        MAX(timestamp) AS last_call_ts
                    FROM request_logs
                    WHERE user_id = $1
                    """,
                    uid,
                    int(day_start_ts),
                    int(window_start_ts),
                )
            return {
                "day_count": int(row["day_count"] or 0),
                "window_count": int(row["window_count"] or 0),
                "total_count": int(row["total_count"] or 0),
                "last_call_ts": int(row["last_call_ts"]) if row["last_call_ts"] is not None else None,
            }
        if backend == "sqlite":
            conn = _get_sqlite_conn()
            with _sqlite_lock:
                row = conn.execute(
                    """
                    SELECT
                        SUM(CASE WHEN timestamp >= ? THEN 1 ELSE 0 END) AS day_count,
                        SUM(CASE WHEN timestamp >= ? THEN 1 ELSE 0 END) AS window_count,
                        COUNT(*) AS total_count,
                        MAX(timestamp) AS last_call_ts
                    FROM request_logs
                    WHERE user_id = ?
                    """,
                    (int(day_start_ts), int(window_start_ts), uid),
                ).fetchone()
            return {
                "day_count": int(row["day_count"] or 0),
                "window_count": int(row["window_count"] or 0),
                "total_count": int(row["total_count"] or 0),
                "last_call_ts": int(row["last_call_ts"]) if row["last_call_ts"] is not None else None,
            }
    except Exception as e:
        logger.error(f"[STORAGE] get_user_request_counts failed: {e}")
    return {"day_count": 0, "window_count": 0, "total_count": 0, "last_call_ts": None}


async def list_api_users_with_usage(limit: int = 200) -> list[dict]:
    users = await list_api_users(limit=limit)
    if not users:
        return []
    day_start = _start_of_local_day_timestamp()
    now_ts = int(time.time())
    result = []
    for user in users:
        counts = await get_user_request_counts(
            user["user_id"],
            day_start_ts=day_start,
            window_start_ts=now_ts - 60,
        )
        item = dict(user)
        item["today_call_count"] = counts["day_count"]
        item["total_call_count"] = counts["total_count"]
        item["last_call_ts"] = counts["last_call_ts"]
        result.append(item)
    return result


async def load_user_auth_policy() -> Optional[dict]:
    if not is_database_enabled():
        return None
    try:
        return await _load_kv("kv_settings", "user_auth_policy")
    except Exception as e:
        logger.error(f"[STORAGE] load_user_auth_policy failed: {e}")
    return None


async def save_user_auth_policy(policy: dict) -> bool:
    if not is_database_enabled():
        return False
    try:
        return await _save_kv("kv_settings", "user_auth_policy", policy)
    except Exception as e:
        logger.error(f"[STORAGE] save_user_auth_policy failed: {e}")
    return False


# ==================== Redeem codes ====================

async def list_redeem_codes(limit: int = 1000, include_used: bool = True) -> list[dict]:
    if not is_database_enabled():
        return []
    max_limit = max(1, min(int(limit), 5000))
    backend = _get_backend()
    rows = []
    try:
        if backend == "postgres":
            query = """
                SELECT code_id, code, is_used, used_by_user_id, used_at, created_by, created_at
                FROM redeem_codes
            """
            args = []
            if not include_used:
                query += " WHERE is_used = FALSE"
            query += " ORDER BY created_at DESC LIMIT $1"
            args.append(max_limit)
            async with _pg_acquire() as conn:
                rows = await conn.fetch(query, *args)
        elif backend == "sqlite":
            query = """
                SELECT code_id, code, is_used, used_by_user_id, used_at, created_by, created_at
                FROM redeem_codes
            """
            params = []
            if not include_used:
                query += " WHERE is_used = 0"
            query += " ORDER BY datetime(created_at) DESC LIMIT ?"
            params.append(max_limit)
            conn = _get_sqlite_conn()
            with _sqlite_lock:
                rows = conn.execute(query, tuple(params)).fetchall()
    except Exception as e:
        logger.error(f"[STORAGE] list_redeem_codes failed: {e}")
        return []
    return [_normalize_redeem_code_row(row) for row in rows]


async def create_redeem_codes(codes: list[str], created_by: Optional[str] = None) -> dict:
    if not is_database_enabled():
        return {"created": [], "duplicates": [], "invalid": []}

    normalized_codes = []
    invalid = []
    seen = set()
    for raw in codes or []:
        code = normalize_redeem_code(raw)
        if not is_valid_redeem_code(code):
            invalid.append(str(raw or ""))
            continue
        if code in seen:
            continue
        seen.add(code)
        normalized_codes.append(code)

    created = []
    duplicates = []
    creator = str(created_by or "").strip() or None
    backend = _get_backend()

    try:
        if backend == "postgres":
            async with _pg_acquire() as conn:
                async with conn.transaction():
                    for code in normalized_codes:
                        code_id = str(uuid4())
                        row = await conn.fetchrow(
                            """
                            INSERT INTO redeem_codes (code_id, code, is_used, created_by, created_at)
                            VALUES ($1, $2, FALSE, $3, CURRENT_TIMESTAMP)
                            ON CONFLICT (code) DO NOTHING
                            RETURNING code_id, code, is_used, used_by_user_id, used_at, created_by, created_at
                            """,
                            code_id,
                            code,
                            creator,
                        )
                        if row:
                            created.append(_normalize_redeem_code_row(row))
                        else:
                            duplicates.append(code)
        elif backend == "sqlite":
            conn = _get_sqlite_conn()
            with _sqlite_lock, conn:
                for code in normalized_codes:
                    code_id = str(uuid4())
                    cur = conn.execute(
                        """
                        INSERT OR IGNORE INTO redeem_codes (code_id, code, is_used, created_by, created_at)
                        VALUES (?, ?, 0, ?, CURRENT_TIMESTAMP)
                        """,
                        (code_id, code, creator),
                    )
                    if (cur.rowcount or 0) > 0:
                        row = conn.execute(
                            """
                            SELECT code_id, code, is_used, used_by_user_id, used_at, created_by, created_at
                            FROM redeem_codes
                            WHERE code = ?
                            """,
                            (code,),
                        ).fetchone()
                        if row:
                            created.append(_normalize_redeem_code_row(row))
                    else:
                        duplicates.append(code)
    except Exception as e:
        logger.error(f"[STORAGE] create_redeem_codes failed: {e}")
        return {"created": created, "duplicates": duplicates, "invalid": invalid, "error": str(e)}

    return {"created": created, "duplicates": duplicates, "invalid": invalid}


async def delete_redeem_code(code_id: str) -> bool:
    if not is_database_enabled():
        return False
    cid = (code_id or "").strip()
    if not cid:
        return False
    backend = _get_backend()
    try:
        if backend == "postgres":
            async with _pg_acquire() as conn:
                result = await conn.execute("DELETE FROM redeem_codes WHERE code_id = $1", cid)
            return result.startswith("DELETE") and not result.endswith("0")
        if backend == "sqlite":
            conn = _get_sqlite_conn()
            with _sqlite_lock, conn:
                cur = conn.execute("DELETE FROM redeem_codes WHERE code_id = ?", (cid,))
            return (cur.rowcount or 0) > 0
    except Exception as e:
        logger.error(f"[STORAGE] delete_redeem_code failed: {e}")
    return False


async def consume_redeem_code_for_user(code: str, user_id: str) -> dict:
    """Atomically consume a redeem code and upgrade user to premium."""
    if not is_database_enabled():
        return {"ok": False, "reason": "storage_unavailable"}
    normalized_code = normalize_redeem_code(code)
    uid = (user_id or "").strip()
    if not uid or not is_valid_redeem_code(normalized_code):
        return {"ok": False, "reason": "invalid_code"}

    backend = _get_backend()
    try:
        if backend == "postgres":
            async with _pg_acquire() as conn:
                async with conn.transaction():
                    user = await conn.fetchrow(
                        """
                        SELECT user_id, role, is_active
                        FROM api_users
                        WHERE user_id = $1
                        FOR UPDATE
                        """,
                        uid,
                    )
                    if not user or not bool(user["is_active"]):
                        return {"ok": False, "reason": "user_not_found"}
                    role = str(user["role"] or "").strip().lower()
                    if role == "admin":
                        return {"ok": False, "reason": "admin_forbidden"}
                    if role == "premium":
                        return {"ok": False, "reason": "already_premium"}

                    code_row = await conn.fetchrow(
                        """
                        SELECT code_id, code, is_used
                        FROM redeem_codes
                        WHERE code = $1
                        FOR UPDATE
                        """,
                        normalized_code,
                    )
                    if not code_row:
                        return {"ok": False, "reason": "invalid_code"}
                    if bool(code_row["is_used"]):
                        return {"ok": False, "reason": "already_used"}

                    result = await conn.execute(
                        """
                        UPDATE api_users
                        SET role = 'premium', updated_at = CURRENT_TIMESTAMP
                        WHERE user_id = $1
                        """,
                        uid,
                    )
                    if result.endswith("0"):
                        return {"ok": False, "reason": "upgrade_failed"}

                    used_result = await conn.execute(
                        """
                        UPDATE redeem_codes
                        SET is_used = TRUE,
                            used_by_user_id = $2,
                            used_at = CURRENT_TIMESTAMP
                        WHERE code_id = $1 AND is_used = FALSE
                        """,
                        code_row["code_id"],
                        uid,
                    )
                    if used_result.endswith("0"):
                        return {"ok": False, "reason": "already_used"}

                    return {"ok": True, "reason": "success", "code": normalized_code}

        if backend == "sqlite":
            conn = _get_sqlite_conn()
            with _sqlite_lock, conn:
                user = conn.execute(
                    """
                    SELECT user_id, role, is_active
                    FROM api_users
                    WHERE user_id = ?
                    """,
                    (uid,),
                ).fetchone()
                if not user or not bool(user["is_active"]):
                    return {"ok": False, "reason": "user_not_found"}
                role = str(user["role"] or "").strip().lower()
                if role == "admin":
                    return {"ok": False, "reason": "admin_forbidden"}
                if role == "premium":
                    return {"ok": False, "reason": "already_premium"}

                code_row = conn.execute(
                    """
                    SELECT code_id, code, is_used
                    FROM redeem_codes
                    WHERE code = ?
                    """,
                    (normalized_code,),
                ).fetchone()
                if not code_row:
                    return {"ok": False, "reason": "invalid_code"}
                if bool(code_row["is_used"]):
                    return {"ok": False, "reason": "already_used"}

                user_cur = conn.execute(
                    """
                    UPDATE api_users
                    SET role = 'premium', updated_at = CURRENT_TIMESTAMP
                    WHERE user_id = ?
                    """,
                    (uid,),
                )
                if (user_cur.rowcount or 0) <= 0:
                    return {"ok": False, "reason": "upgrade_failed"}

                code_cur = conn.execute(
                    """
                    UPDATE redeem_codes
                    SET is_used = 1,
                        used_by_user_id = ?,
                        used_at = CURRENT_TIMESTAMP
                    WHERE code_id = ? AND is_used = 0
                    """,
                    (uid, code_row["code_id"]),
                )
                if (code_cur.rowcount or 0) <= 0:
                    return {"ok": False, "reason": "already_used"}

                return {"ok": True, "reason": "success", "code": normalized_code}
    except Exception as e:
        logger.error(f"[STORAGE] consume_redeem_code_for_user failed: {e}")
        return {"ok": False, "reason": "storage_error"}

    return {"ok": False, "reason": "storage_unavailable"}


# ---------- 代理控制配置 ----------

async def save_proxy_control(data: dict) -> bool:
    """保存代理控制配置"""
    if not is_database_enabled():
        return False
    backend = _get_backend()
    try:
        json_data = json.dumps(data)
        if backend == "postgres":
            async with _pg_acquire() as conn:
                await conn.execute(
                    "INSERT INTO proxy_control (id, data) VALUES (1, $1) ON CONFLICT (id) DO UPDATE SET data = $1",
                    json_data
                )
            return True
        if backend == "sqlite":
            conn = _get_sqlite_conn()
            with _sqlite_lock, conn:
                conn.execute("INSERT OR REPLACE INTO proxy_control (id, data) VALUES (1, ?)", (json_data,))
            return True
    except Exception as e:
        logger.error(f"[STORAGE] Save proxy control failed: {e}")
    return False


async def load_proxy_control() -> Optional[dict]:
    """加载代理控制配置"""
    if not is_database_enabled():
        return None
    backend = _get_backend()
    try:
        if backend == "postgres":
            async with _pg_acquire() as conn:
                row = await conn.fetchrow("SELECT data FROM proxy_control WHERE id = 1")
            return json.loads(row["data"]) if row else None
        if backend == "sqlite":
            conn = _get_sqlite_conn()
            with _sqlite_lock:
                cur = conn.execute("SELECT data FROM proxy_control WHERE id = 1")
                row = cur.fetchone()
            return json.loads(row[0]) if row else None
    except Exception as e:
        logger.error(f"[STORAGE] Load proxy control failed: {e}")
    return None


def save_proxy_control_sync(data: dict) -> bool:
    return _run_in_db_loop(save_proxy_control(data))


def load_proxy_control_sync() -> Optional[dict]:
    return _run_in_db_loop(load_proxy_control())
