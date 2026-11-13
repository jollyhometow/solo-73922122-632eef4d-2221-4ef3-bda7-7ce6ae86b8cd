"""短时入站诊断：用 nftables trace 观察真实非回环入站 IPv4 TCP 包的最终裁决。

关键设计（逐条对应需求）：

1. 同期只运行一份
   * 进程内 ``_DIAG_LOCK`` 单飞 + SQLite 部分唯一索引
     (``running``/``finalizing`` 唯一) 双重保证；重复启动直接 409。

2. 只观察真实非回环入站 IPv4 TCP，不改变裁决
   * trace 规则为 ``iif != lo ip saddr <源IPv4> meta l4proto tcp
     meta nftrace set 1``，无 verdict，包继续走原白名单规则；
   * 每次诊断启动一个**全新**的 ``nft -j monitor trace`` 进程，结束时
     terminate/wait（必要时 SIGKILL）整组回收；旧进程的事件从机制上
     不可能进入下次诊断。

3. 按包关联交错事件，最多 100 包
   * 以 trace id 为主键（5 元组兜底）把 packet/rule/verdict 事件汇聚到
     同一个包；事件按到达顺序保留全局序号，可还原多包交错；
   * 超过上限的包只计数不入库。

4. 缺少最终判定 / 采集故障须注明无法判定
   * 没有终端 verdict(accept/drop) 的包 ``decidable=false``，结果注明
     “缺少最终判定事件，无法判定”；
   * 监听进程异常退出则整单标记 error，已有终端判定的包仍展示判定，
     其余包注明受故障影响无法判定。

5. 迟到事件关联“实际判定时”的白名单
   * 每次规则集写入在 ``rule_versions`` 留带墙钟时间的版本；包的 verdict
     事件按其接收时刻落到对应版本，取当时白名单展示，绝不套用当前策略。

6. 与规则写入协调
   * 所有 nft 重写统一走 :mod:`ruleset`，trace 规则与白名单在同一原子
     事务内共存；诊断期间应用/确认/30 秒自动回退照常，不覆盖新白名单、
     不改变期限；结束时用“当前生效白名单 + 无 trace”重写回收。
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import queue
import signal
import subprocess
import threading
import time
from datetime import datetime
from typing import Any

import db
import nft
import ruleset
from config import DIAG_DURATION_SECONDS, DIAG_MAX_PACKETS, DIAG_STATE_DIR
from config import NFT_CHAIN_NAME, NFT_TABLE_NAME

log = logging.getLogger("diag")

# 终端裁决（continue 不是最终结果）
_TERMINAL_VERDICTS = {"accept", "drop"}
# 本专用表的 input 链名（policy 事件按链名兜底归属）
_INPUT_CHAIN = NFT_CHAIN_NAME
# 收尾时给在途事件的宽限时间（秒）
_FINAL_GRACE_SECONDS = 0.8
# 等待监听进程退出的时间（秒）
_MONITOR_EXIT_TIMEOUT = 3.0

_DIAG_LOCK = threading.RLock()


class DiagError(RuntimeError):
    """诊断启动/采集业务错误。"""


def _now() -> float:
    return time.time()


def _parse_kernel_ts(raw: str | None) -> str | None:
    """内核时间戳原样保留展示；解析失败不影响主流程。"""
    if not raw:
        return None
    try:
        datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return raw
    except (ValueError, AttributeError):
        return raw


def validate_source_ip(value: str) -> str:
    """校验用户输入的源 IPv4（拒绝主机名、IPv6、网段、非法地址）。"""
    if not isinstance(value, str) or not value.strip():
        raise DiagError("请输入源 IPv4 地址")
    value = value.strip()
    try:
        ip = ipaddress.ip_address(value)
    except ValueError as exc:
        raise DiagError(f"非法 IP 地址: {value}") from exc
    if ip.version != 4:
        raise DiagError("仅支持源 IPv4 地址")
    if ip.is_loopback:
        raise DiagError("回环地址不属于真实非回环入站流量，请输入实际源 IPv4")
    if ip.is_multicast or ip.is_unspecified or str(ip) == "255.255.255.255":
        raise DiagError("组播/全零/广播地址不能作为诊断源")
    return str(ip)


def _pid_file() -> str:
    os.makedirs(DIAG_STATE_DIR, exist_ok=True)
    return os.path.join(DIAG_STATE_DIR, "monitor.pid")


def kill_stale_monitor() -> None:
    """启动恢复/异常清理：按 PID 文件回收可能残留的监听进程（整进程组）。"""
    path = _pid_file()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            pid = int(fh.read().strip())
    except (FileNotFoundError, ValueError):
        return
    try:
        pgid = os.getpgid(pid)
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    except Exception as exc:  # 权限等异常不应阻断启动
        log.warning("回收残留监听进程失败: %s", exc)
    finally:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass


class _PacketAccumulator:
    """单个诊断会话内的按包事件汇聚器（仅采集线程写，收尾时读）。"""

    def __init__(self, source_ip: str, max_packets: int) -> None:
        self.source_ip = source_ip
        self.max_packets = max_packets
        self.packets: dict[str, dict[str, Any]] = {}
        self.order: list[str] = []          # trace id 的首次出现顺序
        self.events_seen = 0
        self.parse_errors = 0
        self.overflow_packets = 0
        self.orphan_events = 0
        self._global_seq = 0

    def _next_seq(self) -> int:
        self._global_seq += 1
        return self._global_seq

    def _get_or_create(self, trace_id: str | None) -> dict[str, Any] | None:
        if not trace_id:
            self.orphan_events += 1
            return None
        pkt = self.packets.get(trace_id)
        if pkt is None:
            if len(self.order) >= self.max_packets:
                # 超出 100 包上限：不再新建包记录，仅累计计数
                self.overflow_packets += 1
                return None
            pkt = {
                "trace_id": trace_id,
                "src_ip": None,
                "dst_ip": None,
                "sport": None,
                "dport": None,
                "iface": None,
                "first_seen": None,
                "kernel_timestamp": None,
                "verdict": None,
                "verdict_at": None,
                "verdict_rule_handle": None,
                "events": [],
            }
            self.packets[trace_id] = pkt
            self.order.append(trace_id)
        return pkt

    def handle_event(self, obj: dict[str, Any], receipt_at: float) -> None:
        """处理一行 nft JSON 输出。"""
        self.events_seen += 1
        etype = obj.get("type")
        data = obj.get("data") or {}
        if etype == "packet":
            self._handle_packet(data, receipt_at)
        elif etype == "trace":
            self._handle_trace(data, receipt_at)
        # 其他类型（table/chain/rule 通告等）忽略

    def _handle_packet(self, data: dict[str, Any], receipt_at: float) -> None:
        # 真实 `nft -j monitor trace` 的包载荷在 data.skb 下；
        # 同时兼容扁平结构，避免不同 nft 版本差异。
        skb = data.get("skb") if isinstance(data.get("skb"), dict) else data
        ip = skb.get("ip") or {}
        tcp = skb.get("tcp") or {}
        iface = (data.get("interface") or {}).get("dev")
        src = ip.get("src")
        # 防御性过滤：只保留真实非回环入站 IPv4 TCP 且源匹配的包
        if not ip or not tcp or src != self.source_ip or iface == "lo":
            return
        trace_id = data.get("id")
        pkt = self._get_or_create(trace_id)
        if pkt is None:
            return
        if pkt["first_seen"] is None:
            pkt["first_seen"] = receipt_at
            pkt["kernel_timestamp"] = _parse_kernel_ts(data.get("timestamp"))
            pkt["src_ip"] = src
            pkt["dst_ip"] = ip.get("dst")
            pkt["sport"] = tcp.get("sport")
            pkt["dport"] = tcp.get("dport")
            pkt["iface"] = iface
        pkt["events"].append({
            "seq": self._next_seq(),
            "kind": "packet",
            "timestamp": _parse_kernel_ts(data.get("timestamp")),
            "receipt_at": receipt_at,
        })

    def _handle_trace(self, data: dict[str, Any], receipt_at: float) -> None:
        # 只接受本专用表产生的 trace 事件（绝不混入其他表）。
        # 真实 nft JSON 里 table/chain/handle 可能位于顶层 data，
        # 也可能嵌在 data.rule / data.verdict 内，这里统一兜底。
        rule = data.get("rule") or {}
        verdict_obj = data.get("verdict") or {}
        subtype = data.get("type", "rule")
        table = (
            data.get("table")
            or rule.get("table")
            or verdict_obj.get("table")
        )
        chain = (
            data.get("chain")
            or rule.get("chain")
            or verdict_obj.get("chain")
        )
        # policy 事件（命中链默认策略 drop/accept）可能不带 table，
        # 但一定带本链名；用链名兜底，避免漏掉最终裁决。
        if table is None and subtype == "policy" and chain == _INPUT_CHAIN:
            table = NFT_TABLE_NAME
        if table != NFT_TABLE_NAME:
            return
        trace_id = data.get("id")
        pkt = self._get_or_create(trace_id)
        if pkt is None:
            return
        # 终态裁决有两种形态：
        #  1) 规则带 verdict：data.verdict = {"type": "accept"|"drop", ...}
        #  2) 命中链策略：type="policy"，data.policy = "drop"|"accept"
        verdict = verdict_obj.get("type") if verdict_obj else None
        if not isinstance(verdict, str) and subtype == "policy":
            policy = data.get("policy")
            verdict = policy if isinstance(policy, str) else None
        if not isinstance(verdict, str):
            verdict = None
        handle = (
            data.get("handle")
            or rule.get("handle")
            or verdict_obj.get("handle")
        )
        event = {
            "seq": self._next_seq(),
            "kind": "trace",
            "subtype": subtype,
            "chain": chain,
            "handle": handle,
            "verdict": verdict,
            "rule_expr": _compact_rule_expr(rule.get("expr")),
            "timestamp": _parse_kernel_ts(data.get("timestamp")),
            "receipt_at": receipt_at,
        }
        pkt["events"].append(event)
        # 记录最后一个终端裁决（accept/drop）；continue 不覆盖
        if verdict in _TERMINAL_VERDICTS:
            pkt["verdict"] = verdict
            pkt["verdict_at"] = receipt_at
            pkt["verdict_rule_handle"] = handle

    def build_packets(self, monitor_failed: bool) -> list[dict[str, Any]]:
        """生成按首次出现顺序排列的包级结果。"""
        out: list[dict[str, Any]] = []
        for idx, trace_id in enumerate(self.order, start=1):
            pkt = self.packets[trace_id]
            notes: list[str] = []
            decidable = True
            if pkt["verdict"] is None:
                decidable = False
                notes.append("缺少最终判定事件（accept/drop），无法判定")
            if monitor_failed:
                notes.append("采集监听进程异常退出，本包结果可能不完整")
            whitelist_at_verdict = None
            if pkt["verdict_at"] is not None:
                whitelist_at_verdict = ruleset.whitelist_at(pkt["verdict_at"])
                if whitelist_at_verdict is None:
                    notes.append("未找到判定时刻的规则版本记录，无法还原当时白名单")
            if pkt["src_ip"] is None:
                decidable = False
                notes.append("缺少 packet 事件，无法还原五元组")
            out.append({
                "index": idx,
                "trace_id": trace_id,
                "src_ip": pkt["src_ip"],
                "dst_ip": pkt["dst_ip"],
                "sport": pkt["sport"],
                "dport": pkt["dport"],
                "iface": pkt["iface"],
                "first_seen": pkt["first_seen"],
                "kernel_timestamp": pkt["kernel_timestamp"],
                "verdict": pkt["verdict"],
                "verdict_label": _verdict_label(pkt["verdict"]),
                "verdict_at": pkt["verdict_at"],
                "verdict_rule_handle": pkt["verdict_rule_handle"],
                "whitelist_at_verdict": whitelist_at_verdict,
                "decidable": decidable,
                "note": "；".join(notes),
                "events": pkt["events"],
            })
        return out


def _compact_rule_expr(expr: Any) -> str | None:
    if not expr:
        return None
    try:
        text = json.dumps(expr, ensure_ascii=False, separators=(",", ":"))
    except (TypeError, ValueError):
        return None
    return text[:300]


def _verdict_label(verdict: str | None) -> str:
    if verdict == "accept":
        return "放行 accept"
    if verdict == "drop":
        return "丢弃 drop"
    return "无法判定"


class _Collector(threading.Thread):
    """采集线程：读事件、卡 10 秒窗口、收尾回收。"""

    def __init__(self, session_id: int, source_ip: str, proc: Any,
                 started_at: float, ends_at: float) -> None:
        super().__init__(name=f"diag-collector-{session_id}", daemon=True)
        self.session_id = session_id
        self.source_ip = source_ip
        self.proc = proc
        self.started_at = started_at
        self.ends_at = ends_at
        self.acc = _PacketAccumulator(source_ip, DIAG_MAX_PACKETS)
        self._q: queue.Queue[tuple[str, float] | None] = queue.Queue()
        self._monitor_failed = False
        self._monitor_stderr = ""

    def run(self) -> None:
        reader = threading.Thread(
            target=self._read_loop, name=f"diag-reader-{self.session_id}", daemon=True
        )
        reader.start()
        try:
            self._collect_window()
        except Exception as exc:  # 采集线程绝不能静默死掉
            log.exception("诊断 #%s 采集异常", self.session_id)
            self._monitor_failed = True
            self._finish(error_detail=f"采集异常: {exc}")
            return
        self._finish()

    # -- 事件读取 --------------------------------------------------------

    def _read_loop(self) -> None:
        assert self.proc.stdout is not None
        try:
            for line in self.proc.stdout:
                if not line.strip():
                    continue
                self._q.put((line, _now()))
        except Exception as exc:
            log.warning("诊断 #%s 读取 trace 输出失败: %s", self.session_id, exc)
            self._monitor_failed = True
        finally:
            self._q.put(None)  # EOF 哨兵

    def _drain_available(self) -> None:
        """非阻塞排空队列中已到达的事件（收尾宽限用）。"""
        while True:
            try:
                item = self._q.get_nowait()
            except queue.Empty:
                return
            if item is None:
                self._monitor_failed = True
                return
            self._consume(item)

    def _consume(self, item: tuple[str, float]) -> None:
        line, receipt_at = item
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            self.acc.parse_errors += 1
            log.warning("诊断 #%s 无法解析 trace 行: %s", self.session_id, line[:200])
            return
        if isinstance(obj, dict):
            self.acc.handle_event(obj, receipt_at)

    def _collect_window(self) -> None:
        while True:
            # 监听进程已退出：不必再等满 10 秒
            if self.proc.poll() is not None:
                self._monitor_failed = True
                log.error("诊断 #%s 监听进程提前退出 code=%s",
                          self.session_id, self.proc.returncode)
                break
            remaining = self.ends_at - _now()
            if remaining <= 0:
                break
            try:
                item = self._q.get(timeout=min(0.2, remaining))
            except queue.Empty:
                continue
            if item is None:
                self._monitor_failed = True
                break
            self._consume(item)

        # 宽限：回收前尽量纳入在途/迟到事件（仍按实际时刻关联白名单版本）
        grace_end = _now() + _FINAL_GRACE_SECONDS
        while _now() < grace_end and self.proc.poll() is None:
            try:
                item = self._q.get(timeout=0.1)
            except queue.Empty:
                continue
            if item is None:
                self._monitor_failed = True
                break
            self._consume(item)
        self._drain_available()

    # -- 收尾 ------------------------------------------------------------

    def _stop_monitor(self) -> None:
        if self.proc.poll() is None:
            try:
                os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
            except ProcessLookupError:
                pass
        try:
            self.proc.wait(timeout=_MONITOR_EXIT_TIMEOUT)
        except subprocess.TimeoutExpired:
            log.warning("诊断 #%s 监听进程未按时退出，SIGKILL 回收", self.session_id)
            try:
                os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
            except ProcessLookupError:
                pass
            self.proc.wait(timeout=2)
        if self.proc.stderr is not None:
            try:
                self._monitor_stderr = self.proc.stderr.read() or ""
            except Exception:
                self._monitor_stderr = ""
        try:
            os.unlink(_pid_file())
        except FileNotFoundError:
            pass

    def _finish(self, error_detail: str | None = None) -> None:
        # 先占位 finalizing：占用唯一索引，阻止收尾期间插入新会话
        db.mark_diag_status(self.session_id, db.DIAG_FINALIZING)
        self._stop_monitor()

        # 回收 trace 规则：用“当前生效白名单 + 无 trace”原子重写，
        # 不覆盖诊断期间可能发生的任何新白名单。
        restore_error: str | None = None
        try:
            ports = ruleset.current_effective_ports()
            ruleset.write_ruleset(ports, reason=f"diag #{self.session_id} trace removed")
        except Exception as exc:
            restore_error = f"trace 规则回收失败: {exc}"
            log.exception("诊断 #%s 回收 trace 规则失败", self.session_id)

        packets = self.acc.build_packets(self._monitor_failed)
        versions = [
            {
                "applied_at": v["applied_at"],
                "whitelist": json.loads(v["whitelist_json"]),
                "reason": v["reason"],
            }
            for v in ruleset.versions_since(self.started_at - 1.0)
        ]
        errors: list[str] = []
        if error_detail:
            errors.append(error_detail)
        if self._monitor_failed:
            errors.append(
                "nft trace 监听进程异常退出，采集不完整："
                "已有最终判定的包结论可信，缺少判定的包为无法判定"
            )
            if self._monitor_stderr.strip():
                errors.append(f"监听进程 stderr: {self._monitor_stderr.strip()[:300]}")
        if self.acc.parse_errors:
            errors.append(f"{self.acc.parse_errors} 行 trace 输出无法解析，已跳过")
        if restore_error:
            errors.append(restore_error)

        result = {
            "session_id": self.session_id,
            "source_ip": self.source_ip,
            "started_at": self.started_at,
            "ends_at": self.ends_at,
            "finalized_at": _now(),
            "duration_seconds": DIAG_DURATION_SECONDS,
            "max_packets": DIAG_MAX_PACKETS,
            "packets_captured": len(packets),
            "packets_dropped_cap": self.acc.overflow_packets,
            "events_seen": self.acc.events_seen,
            "orphan_events": self.acc.orphan_events,
            "whitelist_versions": versions,
            "monitor_failed": self._monitor_failed,
            "error_detail": "；".join(errors) if errors else None,
            "packets": packets,
        }
        status = db.DIAG_ERROR if (self._monitor_failed or restore_error or error_detail) \
            else db.DIAG_DONE
        db.finalize_diag_session(
            session_id=self.session_id,
            status=status,
            when=_now(),
            packets_captured=len(packets),
            packets_dropped_cap=self.acc.overflow_packets,
            events_seen=self.acc.events_seen,
            result_json=json.dumps(result, ensure_ascii=False),
            error_detail=result["error_detail"],
        )
        log.info("诊断 #%s 结束 status=%s 包数=%s 上限丢弃=%s",
                 self.session_id, status, len(packets), self.acc.overflow_packets)


def start_diagnosis(source_ip: str) -> dict[str, Any]:
    """启动一次 10 秒诊断；同期已有诊断时抛 DiagError。"""
    source_ip = validate_source_ip(source_ip)
    with _DIAG_LOCK:
        if db.get_active_diag_session() is not None:
            raise DiagError("已有诊断正在进行（同期只运行一份），请等待其结束后再试")

        started_at = _now()
        ends_at = started_at + DIAG_DURATION_SECONDS
        try:
            session_id = db.insert_diag_session(source_ip, started_at, ends_at)
        except Exception as exc:  # 唯一索引冲突等
            raise DiagError("已有诊断正在进行（数据库约束），请稍后再试") from exc

        # 先启动全新监听进程（在安装 trace 规则之前），保证本会话只看新事件
        try:
            proc = nft.spawn_trace_monitor()
        except Exception as exc:
            db.mark_diag_status(
                session_id, db.DIAG_ERROR,
                error_detail=f"trace 监听进程启动失败: {exc}",
            )
            raise DiagError(f"trace 监听进程启动失败: {exc}") from exc

        with open(_pid_file(), "w", encoding="utf-8") as fh:
            fh.write(str(proc.pid))

        # 同事务安装 trace 规则（保留当前白名单），不改变任何裁决语义
        try:
            ports = ruleset.current_effective_ports()
            ruleset.write_ruleset_with_trace(
                ports, source_ip,
                reason=f"diag #{session_id} trace installed",
                diag_session_id=session_id,
            )
        except Exception as exc:
            # 安装失败：回收监听进程，恢复无 trace 规则，会话判故障
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                proc.wait(timeout=_MONITOR_EXIT_TIMEOUT)
            except Exception:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass
            try:
                os.unlink(_pid_file())
            except FileNotFoundError:
                pass
            try:
                ruleset.write_ruleset(
                    ruleset.current_effective_ports(),
                    reason=f"diag #{session_id} install failed cleanup",
                )
            except Exception:
                log.exception("诊断 #%s 安装失败后的规则清理也失败", session_id)
            db.mark_diag_status(
                session_id, db.DIAG_ERROR,
                error_detail=f"trace 规则安装失败，已回收监听进程: {exc}",
            )
            raise DiagError(f"trace 规则安装失败: {exc}") from exc

        collector = _Collector(session_id, source_ip, proc, started_at, ends_at)
        collector.start()
        log.warning("诊断 #%s 已启动，源 %s，采集 %.0f 秒",
                    session_id, source_ip, DIAG_DURATION_SECONDS)
        return {
            "session_id": session_id,
            "source_ip": source_ip,
            "started_at": started_at,
            "ends_at": ends_at,
            "duration_seconds": DIAG_DURATION_SECONDS,
            "max_packets": DIAG_MAX_PACKETS,
            "status": db.DIAG_RUNNING,
        }


def get_session_view(session_id: int | None = None) -> dict[str, Any] | None:
    """返回诊断会话视图（含解析后的结果 JSON）。"""
    row = db.get_diag_session(session_id) if session_id is not None \
        else db.get_last_diag_session()
    if row is None:
        return None
    view = dict(row)
    view["result"] = json.loads(row["result_json"]) if row.get("result_json") else None
    return view


def active_session_view() -> dict[str, Any] | None:
    row = db.get_active_diag_session()
    if row is None:
        return None
    view = dict(row)
    view["result"] = None
    view["remaining_seconds"] = max(0.0, row["ends_at"] - _now())
    return view
