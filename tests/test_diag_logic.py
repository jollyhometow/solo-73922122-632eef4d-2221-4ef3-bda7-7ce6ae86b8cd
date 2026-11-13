"""诊断/规则协调核心逻辑单元测试（无需 nft/docker，全部用替身）。

运行：python -I tests/test_diag_logic.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time

# ---- 在导入业务模块前准备临时环境 --------------------------------------
_TMP = tempfile.mkdtemp(prefix="diag_test_")
os.environ["DB_PATH"] = os.path.join(_TMP, "mgmt.db")
os.environ["DIAG_STATE_DIR"] = os.path.join(_TMP, "diag")
os.environ["DIAG_DURATION_SECONDS"] = "0.8"
os.environ["DIAG_MAX_PACKETS"] = "100"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import db  # noqa: E402
import diagnostics  # noqa: E402
import ruleset  # noqa: E402

PASS = 0
FAIL = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name} {detail}")


def pkt_event(tid: str, src: str, dst: str, sport: int, dport: int,
              iface: str = "eth0", ts: str | None = None) -> dict:
    return {
        "type": "packet",
        "data": {
            "id": tid,
            "timestamp": ts or "2026-11-13T10:00:00.000Z",
            "interface": {"dev": iface},
            "skb": {
                "ip": {"version": 4, "src": src, "dst": dst, "protocol": "tcp"},
                "tcp": {"sport": sport, "dport": dport},
            },
        },
    }


def trace_event(tid: str, subtype: str, verdict: str | None = None,
                handle: int | None = None) -> dict:
    # 模拟真实 `nft -j monitor trace` 嵌套结构：
    # 规则信息在 data.rule，裁决在 data.verdict
    data: dict = {
        "id": tid,
        "type": subtype,
        "chain": "input_filter",
        "table": "port_mgmt",
        "timestamp": "2026-11-13T10:00:00.001Z",
    }
    if verdict:
        data["verdict"] = {"type": verdict, "chain": "input_filter",
                           "table": "port_mgmt", "handle": handle}
    if handle is not None:
        data["rule"] = {"family": "inet", "table": "port_mgmt",
                        "chain": "input_filter", "handle": handle,
                        "expr": [{"match": {"op": "=="}}]}
    return {"type": "trace", "data": data}


def policy_event(tid: str, policy: str) -> dict:
    # 真实 `nft -j monitor trace` 命中链默认策略时的形态：
    # type=policy，data.policy="drop"，通常不带 table、带 chain
    return {"type": "trace", "data": {
        "id": tid, "type": "policy", "chain": "input_filter",
        "policy": policy,
        "timestamp": "2026-11-13T10:00:00.002Z",
    }}


def test_accumulator_interleave_and_verdicts() -> None:
    print("\n[1] 按包关联交错事件 + 最终判定 + 无法判定")
    db.init_db()
    acc = diagnostics._PacketAccumulator("10.0.0.9", 100)
    base = time.time()
    # 规则版本时间线：base-1 白名单 [8080]，base+50 切换为 [8090]
    db.insert_rule_version(base - 1, [8080], "baseline")
    db.insert_rule_version(base + 50, [8090], "apply change")

    # 两个包交错：t1 在旧版本时刻被 accept，t2 在新版本时刻被 drop
    acc.handle_event(pkt_event("t1", "10.0.0.9", "172.18.0.2", 40001, 8080), base + 1)
    acc.handle_event(pkt_event("t2", "10.0.0.9", "172.18.0.2", 40002, 8080), base + 2)
    acc.handle_event(trace_event("t1", "rule", handle=5), base + 1)
    acc.handle_event(trace_event("t2", "rule", handle=6), base + 2)
    acc.handle_event(trace_event("t1", "rule", "accept", handle=5), base + 1)
    acc.handle_event(trace_event("t2", "rule", "drop", handle=9), base + 52)
    # t3 只有 packet，没有最终判定
    acc.handle_event(pkt_event("t3", "10.0.0.9", "172.18.0.2", 40003, 22), base + 3)
    # 回环/异源/非 TCP 载荷应被过滤
    acc.handle_event(pkt_event("tX", "10.0.0.9", "127.0.0.1", 1, 2, iface="lo"), base + 4)
    acc.handle_event(pkt_event("tY", "10.0.0.1", "172.18.0.2", 1, 2), base + 4)
    # 其他 nft 表的 trace 事件不得混入本专用表诊断
    other = trace_event("t9", "rule", "drop", handle=1)
    other["data"]["table"] = "some_other_table"
    other["data"]["verdict"]["table"] = "some_other_table"
    acc.handle_event(other, base + 4)
    # continue 不是终态，不得覆盖后续真正的 accept
    acc.handle_event(trace_event("t4c", "rule", handle=7), base + 5)
    cont = trace_event("t4c", "rule", "continue", handle=7)
    acc.handle_event(cont, base + 5)
    acc.handle_event(pkt_event("t4c", "10.0.0.9", "172.18.0.2", 40004, 8090), base + 5)
    acc.handle_event(trace_event("t4c", "rule", "accept", handle=8), base + 5)

    packets = acc.build_packets(False)
    by_id = {p["trace_id"]: p for p in packets}
    check("仅纳入 4 个匹配包（回环/异源/跨表被过滤）", len(packets) == 4, str(len(packets)))
    check("t9 跨表事件未建包", "t9" not in by_id)
    check("t4c continue 后以 accept 为准", by_id["t4c"]["verdict"] == "accept",
          str(by_id.get("t4c", {}).get("verdict")))
    check("t1 放行", by_id["t1"]["verdict"] == "accept")
    check("t2 丢弃", by_id["t2"]["verdict"] == "drop")
    check("t3 无法判定", by_id["t3"]["verdict"] is None and not by_id["t3"]["decidable"])
    check("t3 注明缺少最终判定", "缺少最终判定" in by_id["t3"]["note"])
    check("五元组完整", by_id["t1"]["sport"] == 40001 and by_id["t1"]["dport"] == 8080
          and by_id["t1"]["src_ip"] == "10.0.0.9" and by_id["t1"]["dst_ip"] == "172.18.0.2")
    # 迟到事件版本对齐：t1 判定时刻在版本切换前 => [8080]；t2 在切换后 => [8090]
    check("t1 关联判定时旧白名单 [8080]", by_id["t1"]["whitelist_at_verdict"] == [8080],
          str(by_id["t1"]["whitelist_at_verdict"]))
    check("t2 关联判定时新白名单 [8090]（不套用当前策略）",
          by_id["t2"]["whitelist_at_verdict"] == [8090],
          str(by_id["t2"]["whitelist_at_verdict"]))
    check("交错事件保留全局序号",
          [e["seq"] for e in by_id["t1"]["events"]] == sorted(e["seq"] for e in by_id["t1"]["events"]))


def test_policy_drop_event() -> None:
    print("\n[1b] 链默认策略 drop（policy 事件）必须识别为最终丢弃")
    acc = diagnostics._PacketAccumulator("10.0.0.9", 100)
    base = time.time()
    # 白名单外端口 22：没有规则 accept，最终命中链 policy drop
    acc.handle_event(pkt_event("d1", "10.0.0.9", "172.18.0.2", 40010, 22), base)
    acc.handle_event(trace_event("d1", "rule", handle=4), base)  # 经过某条非裁决规则
    acc.handle_event(policy_event("d1", "drop"), base)
    packets = acc.build_packets(False)
    p = next(x for x in packets if x["trace_id"] == "d1")
    check("policy drop 被识别为最终丢弃", p["verdict"] == "drop", str(p["verdict"]))
    check("该包可判定（非无法判定）", p["decidable"] is True)
    check("事件链保留 policy 子类型",
          any(e.get("subtype") == "policy" and e["verdict"] == "drop" for e in p["events"]))


def test_cap_100() -> None:
    print("\n[2] 最多 100 包，超出仅计数")
    acc = diagnostics._PacketAccumulator("10.0.0.9", 100)
    base = time.time()
    for i in range(130):
        acc.handle_event(pkt_event(f"p{i}", "10.0.0.9", "172.18.0.2", 50000 + i, 8080), base)
    packets = acc.build_packets(False)
    check("纳入恰好 100 包", len(packets) == 100, str(len(packets)))
    check("超出 30 包计入 overflow", acc.overflow_packets == 30, str(acc.overflow_packets))


def test_validate_ip() -> None:
    print("\n[3] 源 IPv4 校验")
    check("合法 IPv4", diagnostics.validate_source_ip("10.1.2.3") == "10.1.2.3")
    for bad in ["127.0.0.1", "::1", "10.0.0.0/24", "not-an-ip", "0.0.0.0", "224.0.0.1", ""]:
        try:
            diagnostics.validate_source_ip(bad)
            check(f"拒绝 {bad!r}", False)
        except diagnostics.DiagError:
            check(f"拒绝 {bad!r}", True)


def test_single_flight() -> None:
    print("\n[4] 同期只运行一份（单飞 + DB 约束）")
    now = time.time()
    db.insert_diag_session("10.0.0.9", now, now + 10)
    try:
        diagnostics.start_diagnosis("10.0.0.9")
        check("重复启动被拒绝", False)
    except diagnostics.DiagError:
        check("重复启动被拒绝", True)
    active = db.get_active_diag_session()
    check("仍只有一个占用会话", active is not None and active["source_ip"] == "10.0.0.9")


def test_ruleset_coordination() -> None:
    print("\n[5] 诊断期间规则写入携带 trace 且不覆盖白名单 + 版本留痕")
    calls: list[tuple] = []

    def fake_apply(ports, trace_source_v4=None):
        calls.append((sorted(ports), trace_source_v4))

    import nft  # 业务模块导入的适配层
    orig = nft.apply_ruleset
    nft.apply_ruleset = fake_apply
    try:
        active = db.get_active_diag_session()
        ruleset.write_ruleset([8090, 9000], reason="test apply",
                              diag_session_id=active["id"])
        ports, trace = calls[-1]
        check("写入白名单为新值（不被覆盖）", ports == [8090, 9000], str(ports))
        check("trace 规则随事务保留", trace == "10.0.0.9", str(trace))
        v = db.get_rule_version_at(time.time())
        check("规则版本已留痕", v is not None and json.loads(v["whitelist_json"]) == [8090, 9000])
        check("版本关联诊断会话", v["diag_session_id"] == active["id"])

        # 结束诊断：无 trace 重写当前白名单
        db.mark_diag_status(active["id"], db.DIAG_DONE)
        ruleset.write_ruleset([8090, 9000], reason="trace removed")
        ports2, trace2 = calls[-1]
        check("结束后重写不再带 trace", trace2 is None and ports2 == [8090, 9000])
    finally:
        nft.apply_ruleset = orig


class _FakeProc:
    def __init__(self, r_fd: int) -> None:
        self.pid = 999999
        self.stdout = os.fdopen(r_fd)
        self.stderr = None
        self.returncode = None
        self.waited = threading.Event()

    def poll(self):
        return None if not self.waited.is_set() else 0

    def wait(self, timeout=None):
        self.waited.set()
        self.returncode = 0
        return 0


def test_full_session_lifecycle() -> None:
    print("\n[6] 完整会话生命周期：启动->采集->自动回收->结果落盘->旧事件隔离")
    import nft
    calls: list[tuple] = []

    def fake_apply(ports, trace_source_v4=None):
        calls.append((sorted(ports), trace_source_v4))

    r, w = os.pipe()
    fake_proc = _FakeProc(r)

    def fake_spawn():
        return fake_proc

    orig_apply, orig_spawn = nft.apply_ruleset, nft.spawn_trace_monitor
    nft.apply_ruleset = fake_apply
    nft.spawn_trace_monitor = fake_spawn
    orig_killpg, orig_getpgid = os.killpg, os.getpgid
    os.killpg = lambda *a, **k: None  # type: ignore[assignment]
    os.getpgid = lambda pid: 999998  # type: ignore[assignment]
    try:
        db.set_confirmed_ports([8080, 8090])
        out = diagnostics.start_diagnosis("10.0.0.9")
        sid = out["session_id"]
        check("启动即安装 trace", calls and calls[-1][1] == "10.0.0.9", str(calls[-1:]))
        # 模拟监听进程收到真实形态的事件（skb 嵌套）
        for line in [
            json.dumps(pkt_event("z1", "10.0.0.9", "172.18.0.2", 41001, 8080)),
            json.dumps(trace_event("z1", "rule", "accept", handle=5)),
            json.dumps(pkt_event("z2", "10.0.0.9", "172.18.0.2", 41002, 22)),
            json.dumps(trace_event("z2", "rule", "drop", handle=9)),
            "{not valid json",
        ]:
            os.write(w, (line + "\n").encode())
        # 等待采集窗口结束并收口
        deadline = time.time() + 8
        while time.time() < deadline:
            row = db.get_diag_session(sid)
            if row["status"] in (db.DIAG_DONE, db.DIAG_ERROR):
                break
            time.sleep(0.1)
        os.close(w)
        row = db.get_diag_session(sid)
        check("会话正常收口为 done", row["status"] == db.DIAG_DONE, row["status"])
        check("监听进程已 wait 回收", fake_proc.waited.is_set())
        check("收尾重写已移除 trace", calls and calls[-1][1] is None, str(calls[-1:]))
        result = json.loads(row["result_json"])
        check("结果按包落盘（2 包）", result["packets_captured"] == 2,
              str(result["packets_captured"]))
        check("解析错误被计数但不致命", result["error_detail"] is None
              or "无法解析" in result["error_detail"])
        ids = {p["trace_id"]: p for p in result["packets"]}
        check("z1 放行 / z2 丢弃",
              ids["z1"]["verdict"] == "accept" and ids["z2"]["verdict"] == "drop")

        # 新会话：全新监听进程 + 旧事件不可能进入（新进程/新 accumulator）
        r2, w2 = os.pipe()
        fake2 = _FakeProc(r2)
        nft.spawn_trace_monitor = lambda: fake2
        out2 = diagnostics.start_diagnosis("10.0.0.9")
        check("第二次诊断是全新会话", out2["session_id"] != sid)
        time.sleep(0.2)
        view = diagnostics.get_session_view(out2["session_id"])
        check("新会话初始无任何旧包", view is not None and view["result"] is None)
        os.close(w2)
        deadline = time.time() + 8
        while time.time() < deadline:
            if db.get_diag_session(out2["session_id"])["status"] in (db.DIAG_DONE, db.DIAG_ERROR):
                break
            time.sleep(0.1)
        r2 = json.loads(db.get_diag_session(out2["session_id"])["result_json"])
        check("旧事件未进入下次诊断（0 包）", r2["packets_captured"] == 0,
              str(r2["packets_captured"]))
    finally:
        nft.apply_ruleset = orig_apply
        nft.spawn_trace_monitor = orig_spawn
        os.killpg = orig_killpg  # type: ignore[assignment]
        os.getpgid = orig_getpgid  # type: ignore[assignment]


def test_bootstrap_recovery() -> None:
    print("\n[7] 启动恢复：遗留诊断判故障 + 干净规则集")
    now = time.time()
    sid = db.insert_diag_session("10.0.0.8", now, now + 10)
    ids = db.fail_active_diag_sessions("服务重启：诊断未正常结束，结果作废", time.time())
    check("遗留会话被判故障", sid in ids and db.get_diag_session(sid)["status"] == db.DIAG_ERROR)
    check("无占用会话", db.get_active_diag_session() is None)
    # kill_stale_monitor 在 PID 文件缺失时应安静返回
    diagnostics.kill_stale_monitor()
    check("无 PID 文件时清理安全返回", True)


if __name__ == "__main__":
    test_accumulator_interleave_and_verdicts()
    test_policy_drop_event()
    test_cap_100()
    test_validate_ip()
    test_single_flight()
    test_ruleset_coordination()
    test_full_session_lifecycle()
    test_bootstrap_recovery()
    print(f"\n==== 结果：{PASS} 通过 / {FAIL} 失败 ====")
    sys.exit(1 if FAIL else 0)
