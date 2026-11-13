"""规则集写入协调层：所有 nft 规则重写的唯一入口。

协调目标（对应需求）：
* 诊断的启动/结束/异常清理与业务规则写入（应用/确认/看护回退）共用一把
  进程内锁并串行化，任何一次重写都会把“当前白名单 + 当前 trace 规则”
  放进同一个原子事务，因此：
  - 诊断期间应用/确认/自动回退照常发生，trace 规则不会丢失；
  - 诊断启停不会覆盖期间产生的新白名单；
  - 不触碰确认窗口的 30 秒期限（时间判定仍完全由防火墙状态机负责）。
* 每次写入都在 ``rule_versions`` 留一条带墙钟时间的版本记录，迟到的
  trace 事件按包实际被判定的时刻关联当时白名单，而不是套用当前策略。
* 跨进程（Web 与独立看护进程）通过 SQLite 中的诊断会话状态协调：
  看护进程写规则前读取“占用中的诊断会话”，把相同 trace 条件带上。
"""
from __future__ import annotations

import threading
import time
from typing import Any

import db
import nft

# 进程内串行化所有规则集写入（诊断启停 + 应用/确认/回退）。
# 跨进程的一致性由 SQLite 会话状态 + 原子 nft 事务共同保证。
_RULESET_LOCK = threading.RLock()


def current_trace_source() -> str | None:
    """读取当前应保留 trace 规则的诊断会话源 IPv4；无则 None。

    注意：``finalizing`` 状态仍占用单飞名额（阻止新会话插入），但收尾
    重写的目的就是移除 trace，因此只有 ``running`` 会话才返回 trace 源。
    """
    active = db.get_active_diag_session()
    if active and active["status"] == db.DIAG_RUNNING:
        return active["source_ip"]
    return None


def current_effective_ports() -> list[int]:
    """当前真正下发到 nft 的白名单端口。

    有待确认变更时，生效中的是该变更请求的端口（回退前一直如此）；
    否则是已确认基线。
    """
    pending = db.get_pending_change()
    if pending is not None:
        import json as _json
        return sorted(_json.loads(pending["requested_ports"]))
    return sorted(db.get_confirmed_ports() or [])


def write_ruleset(
    ports: list[int],
    reason: str,
    diag_session_id: int | None = None,
) -> None:
    """原子写入规则集并记录版本（所有 nft 重写的唯一入口）。

    自动带上当前诊断会话的 trace 规则（若存在），保证诊断与业务写入
    在同一事务内共存、互不覆盖。nft 失败时内核保留旧规则，版本表也
    不会留下“已生效”的假记录。
    """
    ports = sorted({int(p) for p in ports})
    with _RULESET_LOCK:
        trace_source = current_trace_source()
        nft.apply_ruleset(ports, trace_source_v4=trace_source)
        # 仅在 nft 成功后记录版本，保证时间线与内核实际状态一致
        db.insert_rule_version(
            applied_at=time.time(),
            whitelist=ports,
            reason=reason,
            diag_session_id=diag_session_id,
        )


def write_ruleset_with_trace(
    ports: list[int],
    trace_source_v4: str,
    reason: str,
    diag_session_id: int | None = None,
) -> None:
    """显式带 trace 规则写入（诊断启动用）。"""
    ports = sorted({int(p) for p in ports})
    with _RULESET_LOCK:
        nft.apply_ruleset(ports, trace_source_v4=trace_source_v4)
        db.insert_rule_version(
            applied_at=time.time(),
            whitelist=ports,
            reason=reason,
            diag_session_id=diag_session_id,
        )


def whitelist_at(at_epoch: float) -> list[int] | None:
    """返回某时刻生效的白名单（用于迟到事件关联实际判定时的策略）。"""
    import json as _json
    version = db.get_rule_version_at(at_epoch)
    if version is None:
        return None
    return sorted(_json.loads(version["whitelist_json"]))


def versions_since(since_epoch: float) -> list[dict[str, Any]]:
    return db.list_rule_versions_since(since_epoch)
