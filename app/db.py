"""SQLite 持久层。

两类持久数据：
* state：已确认规则（当前白名单），整套服务重启后据此先恢复再开放网页；
* changes：每次“应用”产生的变更单，含应用前快照与完整生命周期状态。
Web 进程与独立看护进程各自打开连接，通过 WAL + BEGIN IMMEDIATE 串行化写入。
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
from contextlib import contextmanager
from typing import Any, Iterator

from config import DB_PATH

# 变更单状态机
PENDING = "pending"      # 已应用、等待确认
CONFIRMED = "confirmed"  # 已在窗口内确认
EXPIRED = "expired"      # 超时未确认，看护进程已回退
FAILED = "failed"        # 应用失败（规则未生效，旧规则保留）

# 诊断会话状态机
DIAG_RUNNING = "running"        # 正在采集（同期唯一）
DIAG_FINALIZING = "finalizing"  # 采集结束，正在回收监听进程/规则
DIAG_DONE = "done"              # 正常结束，结果已生成
DIAG_ERROR = "error"            # 采集故障/启动失败/服务重启遗留，结果不可信

STATE_CONFIRMED_PORTS = "confirmed_ports"


def _connect() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=10000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@contextmanager
def get_conn() -> Iterator[sqlite3.Connection]:
    conn = _connect()
    try:
        yield conn
    finally:
        conn.close()


def init_db() -> None:
    with get_conn() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS state (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS changes (
                id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                requested_ports    TEXT NOT NULL,  -- JSON 数组：本次请求的白名单
                previous_ports     TEXT NOT NULL,  -- JSON 数组：应用前已确认快照
                status             TEXT NOT NULL,
                created_at         REAL NOT NULL,  -- 应用生效时刻（epoch 秒）
                expires_at         REAL NOT NULL,  -- 确认截止时刻
                confirmed_at       REAL,
                finalized_at       REAL,
                detail             TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_changes_status ON changes(status);
            -- 跨进程硬约束：任意时刻最多一张待确认(pending)变更单。
            -- 进程内锁之外的第二道防线：并发应用时后到者直接被数据库拒绝。
            CREATE TRIGGER IF NOT EXISTS trg_changes_one_pending
            BEFORE INSERT ON changes
            WHEN NEW.status = 'pending'
                 AND EXISTS (SELECT 1 FROM changes WHERE status = 'pending')
            BEGIN
                SELECT RAISE(ABORT, 'already has a pending change');
            END;

            -- 短时诊断会话：同期只允许一份（running/finalizing 视为占用中）
            CREATE TABLE IF NOT EXISTS diag_sessions (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                source_ip       TEXT NOT NULL,           -- 用户输入的源 IPv4
                status          TEXT NOT NULL,
                started_at      REAL NOT NULL,           -- 采集开始 epoch 秒
                ends_at         REAL NOT NULL,           -- 计划结束 epoch 秒
                finalized_at    REAL,
                packets_captured INTEGER NOT NULL DEFAULT 0,  -- 已纳入关联的包数
                packets_dropped_cap INTEGER NOT NULL DEFAULT 0, -- 超 100 包上限而未纳入的包数
                events_seen     INTEGER NOT NULL DEFAULT 0,
                result_json     TEXT,                    -- 最终结果（包级判定明细）
                error_detail    TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_diag_status ON diag_sessions(status);
            -- 数据库级硬约束：任意时刻最多一个占用中的诊断会话
            CREATE UNIQUE INDEX IF NOT EXISTS idx_diag_one_active
            ON diag_sessions(1)
            WHERE status IN ('running', 'finalizing');

            -- 规则版本时间线：每次规则集写入（应用/确认/回退/诊断启停）一行。
            -- 迟到事件按“包实际被判定的时刻”落到对应版本，关联当时的白名单，
            -- 而不是套用查看结果时的当前策略。
            CREATE TABLE IF NOT EXISTS rule_versions (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                applied_at      REAL NOT NULL,           -- 写入完成时刻（墙钟 epoch）
                whitelist_json  TEXT NOT NULL,           -- 该版本白名单端口
                reason          TEXT NOT NULL,
                diag_session_id INTEGER                  -- 诊断期间的写入关联到会话
            );
            CREATE INDEX IF NOT EXISTS idx_rule_versions_time
            ON rule_versions(applied_at);
            """
        )
        conn.commit()


def get_confirmed_ports() -> list[int] | None:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT value FROM state WHERE key = ?", (STATE_CONFIRMED_PORTS,)
        ).fetchone()
    if row is None:
        return None
    return json.loads(row["value"])


def set_confirmed_ports(ports: list[int]) -> None:
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO state(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (STATE_CONFIRMED_PORTS, json.dumps(sorted(set(ports)))),
        )
        conn.commit()


def get_pending_change() -> dict[str, Any] | None:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM changes WHERE status = ? ORDER BY id DESC LIMIT 1",
            (PENDING,),
        ).fetchone()
    return dict(row) if row else None


def insert_change(
    requested_ports: list[int],
    previous_ports: list[int],
    created_at: float,
    expires_at: float,
    status: str,
    detail: str | None = None,
) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO changes(requested_ports, previous_ports, status, "
            "created_at, expires_at, detail) VALUES (?, ?, ?, ?, ?, ?)",
            (
                json.dumps(sorted(set(requested_ports))),
                json.dumps(sorted(set(previous_ports))),
                status,
                created_at,
                expires_at,
                detail,
            ),
        )
        conn.commit()
        return int(cur.lastrowid)


def get_change(change_id: int) -> dict[str, Any] | None:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM changes WHERE id = ?", (change_id,)
        ).fetchone()
    return dict(row) if row else None


def mark_change_status(
    change_id: int, status: str, when: float | None = None, detail: str | None = None
) -> None:
    with get_conn() as conn:
        conn.execute(
            "UPDATE changes SET status = ?, finalized_at = ?, "
            "detail = COALESCE(?, detail) WHERE id = ?",
            (status, when if when is not None else time.time(), detail, change_id),
        )
        conn.commit()


def mark_expired_if_pending(change_id: int, when: float, detail: str) -> bool:
    """仅当单子仍为 pending 时标记 expired（与确认路径竞争时的安全收口）。

    返回 True 表示本调用赢得了状态机；False 表示单子已被确认，回退方
    必须放弃覆盖，并把 nft 规则恢复为已确认基线。
    """
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT status FROM changes WHERE id = ?", (change_id,)
        ).fetchone()
        if row is None or row["status"] != PENDING:
            conn.rollback()
            return False
        conn.execute(
            "UPDATE changes SET status = ?, finalized_at = ?, detail = ? WHERE id = ?",
            (EXPIRED, when, detail, change_id),
        )
        conn.commit()
        return True


def confirm_change(change_id: int, when: float) -> bool:
    """仅当变更单仍为 pending 时确认成功（行锁内完成，避免与看护进程竞争）。"""
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT status FROM changes WHERE id = ?", (change_id,)
        ).fetchone()
        if row is None or row["status"] != PENDING:
            conn.rollback()
            return False
        conn.execute(
            "UPDATE changes SET status = ?, confirmed_at = ?, finalized_at = ? "
            "WHERE id = ?",
            (CONFIRMED, when, when, change_id),
        )
        conn.commit()
        return True


def list_recent_changes(limit: int = 10) -> list[dict[str, Any]]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM changes ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def expire_all_pending(reason: str, when: float) -> list[int]:
    """启动恢复时使用：把所有遗留 pending 单标记为 expired，返回其 id 列表。"""
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        rows = conn.execute(
            "SELECT id FROM changes WHERE status = ?", (PENDING,)
        ).fetchall()
        ids = [r["id"] for r in rows]
        if ids:
            conn.execute(
                "UPDATE changes SET status = ?, finalized_at = ?, detail = ? "
                "WHERE status = ?",
                (EXPIRED, when, reason, PENDING),
            )
        conn.commit()
    return ids


# ---------------------------------------------------------------------------
# 短时诊断（diag_sessions）与规则版本时间线（rule_versions）
# ---------------------------------------------------------------------------

def insert_diag_session(source_ip: str, started_at: float, ends_at: float) -> int:
    """创建诊断会话；已有占用中的会话时由唯一索引拒绝（IntegrityError）。"""
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO diag_sessions(source_ip, status, started_at, ends_at) "
            "VALUES (?, ?, ?, ?)",
            (source_ip, DIAG_RUNNING, started_at, ends_at),
        )
        conn.commit()
        return int(cur.lastrowid)


def get_active_diag_session() -> dict[str, Any] | None:
    """返回当前占用中的诊断会话（running/finalizing），没有则 None。"""
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM diag_sessions "
            "WHERE status IN (?, ?) ORDER BY id DESC LIMIT 1",
            (DIAG_RUNNING, DIAG_FINALIZING),
        ).fetchone()
    return dict(row) if row else None


def get_diag_session(session_id: int) -> dict[str, Any] | None:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM diag_sessions WHERE id = ?", (session_id,)
        ).fetchone()
    return dict(row) if row else None


def get_last_diag_session() -> dict[str, Any] | None:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM diag_sessions ORDER BY id DESC LIMIT 1"
        ).fetchone()
    return dict(row) if row else None


def mark_diag_status(
    session_id: int,
    status: str,
    when: float | None = None,
    error_detail: str | None = None,
) -> None:
    with get_conn() as conn:
        conn.execute(
            "UPDATE diag_sessions SET status = ?, finalized_at = ?, "
            "error_detail = COALESCE(?, error_detail) WHERE id = ?",
            (status, when if when is not None else time.time(), error_detail, session_id),
        )
        conn.commit()


def finalize_diag_session(
    session_id: int,
    status: str,
    when: float,
    packets_captured: int,
    packets_dropped_cap: int,
    events_seen: int,
    result_json: str,
    error_detail: str | None,
) -> None:
    """诊断收口：写最终状态与结果（结果 JSON 一并落盘，跨进程/重启可查）。"""
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "UPDATE diag_sessions SET status = ?, finalized_at = ?, "
            "packets_captured = ?, packets_dropped_cap = ?, events_seen = ?, "
            "result_json = ?, error_detail = COALESCE(?, error_detail) WHERE id = ?",
            (
                status, when, packets_captured, packets_dropped_cap,
                events_seen, result_json, error_detail, session_id,
            ),
        )
        conn.commit()


def fail_active_diag_sessions(reason: str, when: float) -> list[int]:
    """启动恢复/异常清理：把所有占用中的会话判为采集故障（结果不可信）。"""
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        rows = conn.execute(
            "SELECT id FROM diag_sessions WHERE status IN (?, ?)",
            (DIAG_RUNNING, DIAG_FINALIZING),
        ).fetchall()
        ids = [r["id"] for r in rows]
        if ids:
            conn.execute(
                "UPDATE diag_sessions SET status = ?, finalized_at = ?, "
                "error_detail = ? WHERE status IN (?, ?)",
                (DIAG_ERROR, when, reason, DIAG_RUNNING, DIAG_FINALIZING),
            )
        conn.commit()
    return ids


def insert_rule_version(
    applied_at: float,
    whitelist: list[int],
    reason: str,
    diag_session_id: int | None = None,
) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO rule_versions(applied_at, whitelist_json, reason, diag_session_id) "
            "VALUES (?, ?, ?, ?)",
            (applied_at, json.dumps(sorted(set(whitelist))), reason, diag_session_id),
        )
        conn.commit()
        return int(cur.lastrowid)


def list_rule_versions_since(since_epoch: float) -> list[dict[str, Any]]:
    """返回某时刻之后的规则版本（按时间升序），用于迟到事件关联当时白名单。"""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM rule_versions WHERE applied_at >= ? ORDER BY applied_at ASC, id ASC",
            (since_epoch,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_rule_version_at(at_epoch: float) -> dict[str, Any] | None:
    """返回指定时刻生效的规则版本（applied_at <= at_epoch 的最新一行）。"""
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM rule_versions WHERE applied_at <= ? "
            "ORDER BY applied_at DESC, id DESC LIMIT 1",
            (at_epoch,),
        ).fetchone()
    return dict(row) if row else None
