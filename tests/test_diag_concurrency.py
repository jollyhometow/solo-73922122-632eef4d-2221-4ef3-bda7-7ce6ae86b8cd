"""诊断与防火墙状态机并发协调的端到端逻辑测试。

覆盖需求：诊断期间仍可应用、确认，自动回退照常执行且不改变 30 秒期限；
trace 规则在每次规则重写中保留，新白名单不被覆盖；版本时间线完整。
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import time

_TMP = tempfile.mkdtemp(prefix="diag_concur_")
os.environ["DB_PATH"] = os.path.join(_TMP, "mgmt.db")
os.environ["DIAG_STATE_DIR"] = os.path.join(_TMP, "diag")
os.environ["DIAG_DURATION_SECONDS"] = "1.0"
os.environ["DIAG_MAX_PACKETS"] = "100"
os.environ["CONFIRM_WINDOW_SECONDS"] = "30"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import db  # noqa: E402
import diagnostics  # noqa: E402
import firewall  # noqa: E402
import nft  # noqa: E402
import ruleset  # noqa: E402

PASS = 0
FAIL = 0
def check(name, cond, detail=""):
    global PASS, FAIL
    if cond: PASS += 1; print("  PASS", name)
    else: FAIL += 1; print("  FAIL", name, detail)

calls = []
def fake_apply(ports, trace_source_v4=None):
    calls.append((sorted(ports), trace_source_v4))
nft.apply_ruleset = fake_apply

r, w = os.pipe()
class FakeProc:
    def __init__(self, fd):
        self.pid = 777001; self.stdout = os.fdopen(fd); self.stderr = None
        self.returncode = None
    def poll(self): return None
    def wait(self, timeout=None): self.returncode = 0; return 0
nft.spawn_trace_monitor = lambda: FakeProc(r)
os.killpg = lambda *a, **k: None
os.getpgid = lambda pid: 777000

db.init_db()
db.set_confirmed_ports([8080, 8090])
# 基线版本
ruleset.write_ruleset([8080, 8090], reason="baseline")

# 启动诊断
out = diagnostics.start_diagnosis("10.9.9.9")
sid = out["session_id"]
check("诊断启动带 trace", calls[-1] == ([8080, 8090], "10.9.9.9"), str(calls[-1]))

# 诊断期间应用新白名单（含一个新端口 9000，移除 8090）
res = firewall.apply_change([8080, 9000])
check("诊断期间允许应用变更", res.requested_ports == [8080, 9000])
check("应用重写保留 trace 且白名单为新值",
      calls[-1] == ([8080, 9000], "10.9.9.9"), str(calls[-1]))
check("确认窗口仍为 30 秒（期限不变）",
      abs((res.expires_at - res.now) - 30.0) < 0.01, str(res.expires_at - res.now))

# 版本时间线应记录这次写入，且与诊断会话关联
v = db.get_rule_version_at(time.time())
check("版本时间线记录新白名单", json.loads(v["whitelist_json"]) == [8080, 9000])
check("版本关联诊断会话 id", v["diag_session_id"] == sid)

# 诊断期间确认
confirm_out = firewall.confirm_change(res.change_id)
check("诊断期间确认成功", confirm_out["confirmed_ports"] == [8080, 9000])
check("确认重写仍带 trace", calls[-1][1] == "10.9.9.9", str(calls[-1]))
check("确认后已确认基线更新", db.get_confirmed_ports() == [8080, 9000])

# 再来一次 pending，然后让看护进程在诊断期间自动回退
res2 = firewall.apply_change([8080])
check("二次应用（待确认）", res2.requested_ports == [8080])
check("二次应用仍带 trace", calls[-1] == ([8080], "10.9.9.9"), str(calls[-1]))
# 手工把截止时间调到过去，模拟 30 秒到期
with db.get_conn() as conn:
    conn.execute("UPDATE changes SET expires_at = ? WHERE id = ?",
                 (time.time() - 1, res2.change_id))
    conn.commit()
rolled = firewall.rollback_expired()
check("看护进程照常回退（诊断期间）", rolled == [res2.change_id], str(rolled))
check("回退重写仍带 trace，且恢复为确认基线 [8080,9000]",
      calls[-1] == ([8080, 9000], "10.9.9.9"), str(calls[-1]))
chg = db.get_change(res2.change_id)
check("变更单标记 expired", chg["status"] == db.EXPIRED)

# 等诊断自动收口（保持管道写端开启，避免被误判为监听进程死亡）
deadline = time.time() + 8
while time.time() < deadline:
    if db.get_diag_session(sid)["status"] in (db.DIAG_DONE, db.DIAG_ERROR):
        break
    time.sleep(0.1)
os.close(w)
row = db.get_diag_session(sid)
check("诊断正常收口", row["status"] == db.DIAG_DONE, row["status"])
check("收口重写移除 trace 且保留最终白名单",
      calls[-1] == ([8080, 9000], None), str(calls[-1]))
# 收口后规则版本无诊断 trace
final_versions = db.list_rule_versions_since(0)
reasons = [x["reason"] for x in final_versions]
check("时间线含完整事件序列",
      "baseline" in reasons and
      any("trace installed" in x for x in reasons) and
      any("trace removed" in x for x in reasons), str(reasons))

# 收口后再应用，不应带任何 trace
firewall.apply_change([8080, 8090, 9000])
check("诊断结束后的写入不带 trace", calls[-1][1] is None, str(calls[-1]))

# 确认 30 秒窗口默认值未被诊断模块改动
from config import CONFIRM_WINDOW_SECONDS as CWS
check("确认窗口常量仍为 30", CWS == 30.0, str(CWS))

print(f"\n==== 并发协调测试：{PASS} 通过 / {FAIL} 失败 ====")
sys.exit(1 if FAIL else 0)
