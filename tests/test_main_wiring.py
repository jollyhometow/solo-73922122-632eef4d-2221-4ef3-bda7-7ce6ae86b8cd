"""用最小替身导入真实 main.py，验证路由与业务调用链（无 fastapi 环境）。

仅用于本机无 fastapi 时的接线校验，不替代容器内真实运行。
"""
from __future__ import annotations

import os
import sys
import tempfile
import types
import json

_TMP = tempfile.mkdtemp(prefix="main_stub_")
os.environ["DB_PATH"] = os.path.join(_TMP, "mgmt.db")
os.environ["DIAG_STATE_DIR"] = os.path.join(_TMP, "diag")
os.environ["DIAG_DURATION_SECONDS"] = "0.8"
os.environ["PROBER_URL"] = "http://prober-stub:9000"
APP_DIR = os.path.join(os.path.dirname(__file__), "..", "app")
sys.path.insert(0, os.path.abspath(APP_DIR))
STUB = os.path.join(_TMP, "stubs")
os.makedirs(STUB, exist_ok=True)

# ---- pydantic 替身：支持 BaseModel/Field/field_validator ----------------
pyd = types.ModuleType("pydantic")

class BaseModel:
    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)

    def __init_subclass__(cls, **kw):
        # 找到 model 字段（类注解）
        cls._fields = {}
        for klass in reversed(cls.__mro__):
            cls._fields.update(getattr(klass, "__annotations__", {}))
        # 包装 __init__ 做校验
        orig_init = cls.__dict__.get("__init__")

        def __init__(self, **data):
            for name in self._fields:
                setattr(self, name, data.get(name))
            for name, method in list(vars(cls).items()):
                if hasattr(method, "_is_validator"):
                    for fname in method._fields_names:
                        if hasattr(self, fname):
                            setattr(self, fname, method(getattr(self, fname)))
        cls.__init__ = __init__

def Field(default=None, **kw):
    return default

def field_validator(*names):
    def deco(fn):
        fn._is_validator = True
        fn._fields_names = names
        @classmethod
        def wrapper(cls, value):
            return fn(cls, value)
        return wrapper
    return deco

pyd.BaseModel = BaseModel
pyd.Field = Field
pyd.field_validator = field_validator
sys.modules["pydantic"] = pyd

# ---- fastapi 替身：记录路由 ---------------------------------------------
fa = types.ModuleType("fastapi")

class HTTPException(Exception):
    def __init__(self, status_code, detail):
        self.status_code = status_code
        self.detail = detail
        super().__init__(detail)

class FastAPI:
    def __init__(self, **kw):
        self.routes = {}
    def _reg(self, path, method, fn):
        self.routes[(method, path)] = fn
    def get(self, path, **kw):
        return lambda fn: (self._reg(path, "GET", fn), fn)[1]
    def post(self, path, **kw):
        return lambda fn: (self._reg(path, "POST", fn), fn)[1]
    def mount(self, *a, **kw):
        pass

fa.FastAPI = FastAPI
fa.HTTPException = HTTPException
sys.modules["fastapi"] = fa

fr = types.ModuleType("fastapi.responses")
class _Resp:
    def __init__(self, content=None, **kw):
        self.content = content
        self.kwargs = kw
class FileResponse(_Resp): pass
class JSONResponse(_Resp): pass
fr.FileResponse = FileResponse
fr.JSONResponse = JSONResponse
sys.modules["fastapi.responses"] = fr

fs = types.ModuleType("fastapi.staticfiles")
class StaticFiles:
    def __init__(self, *a, **kw): pass
fs.StaticFiles = StaticFiles
sys.modules["fastapi.staticfiles"] = fs

# 让 import fastapi.responses 能从包属性取到
fa.responses = fr
fa.staticfiles = fs

PASS = 0
FAIL = 0
def check(name, cond, detail=""):
    global PASS, FAIL
    if cond: PASS += 1; print("  PASS", name)
    else: FAIL += 1; print("  FAIL", name, detail)

import main  # 真实业务模块
import db, diagnostics

db.init_db()
db.set_confirmed_ports([8080, 8090])

registered = set(main.app.routes.keys())
expected = {
    ("GET", "/"), ("GET", "/api/config"), ("GET", "/api/status"),
    ("POST", "/api/apply"), ("POST", "/api/confirm"),
    ("GET", "/api/diag/config"), ("GET", "/api/diag/active"),
    ("GET", "/api/diag/session"), ("POST", "/api/diag/start"),
    ("POST", "/api/prober/info"), ("POST", "/api/prober/probe"),
}
missing = expected - registered
check("全部预期路由已注册", not missing, str(missing))

# 诊断配置接口（时长来自环境变量，本测试设为 0.8 加速；上限固定 100）
cfg = main.api_diag_config()
check("diag config 时长/100 包上限", cfg["max_packets"] == 100
      and cfg["duration_seconds"] == float(os.environ["DIAG_DURATION_SECONDS"]), str(cfg))
check("无活动诊断", main.api_diag_active()["active"] is None)

# 启动诊断（替身 nft，避免真实 nft 调用）
import nft, ruleset
calls = []
nft.apply_ruleset = lambda ports, trace_source_v4=None: calls.append((ports, trace_source_v4))
r, w = os.pipe()
class FakeProc:
    def __init__(self, fd):
        self.pid = 424242; self.stdout = os.fdopen(fd); self.stderr = None
        self.returncode = None
    def poll(self): return None
    def wait(self, timeout=None): self.returncode = 0; return 0
nft.spawn_trace_monitor = lambda: FakeProc(r)
os.killpg = lambda *a, **k: None
os.getpgid = lambda pid: 424241

req = main.DiagStartRequest(source_ip="10.20.30.40")
out = main.api_diag_start(req)
check("api 启动诊断成功", out["ok"] and out["session_id"] > 0, str(out))
check("启动安装了 trace 规则", calls and calls[-1][1] == "10.20.30.40", str(calls[-1:]))

# 同期再启动 -> 409
try:
    main.api_diag_start(main.DiagStartRequest(source_ip="10.20.30.40"))
    check("重复启动返回 409", False)
except main.HTTPException as e:
    check("重复启动返回 409", e.status_code == 409)

active = main.api_diag_active()["active"]
check("活动会话带倒计时", active and active["remaining_seconds"] > 0, str(active))

# 非法源 IP -> 409（DiagError 映射）
for bad in ["127.0.0.1", "not-ip", "::1"]:
    try:
        main.api_diag_start(main.DiagStartRequest(source_ip=bad))
        check(f"非法源 {bad} 被拒", False)
    except main.HTTPException as e:
        check(f"非法源 {bad} 被拒({e.status_code})", e.status_code == 409)

# 代理：发包端不可达 -> 502
try:
    main.api_prober_info()
    check("发包端不可达返回 502", False)
except main.HTTPException as e:
    check("发包端不可达返回 502", e.status_code == 502 and "发包端" in e.detail, str(e.detail))

# 代理成功路径：monkeypatch urlopen
import urllib.request
class FakeResp:
    def __init__(self, payload): self._b = json.dumps(payload).encode()
    def read(self): return self._b
    def __enter__(self): return self
    def __exit__(self, *a): return False
orig_urlopen = urllib.request.urlopen
urllib.request.urlopen = lambda req, timeout=None: FakeResp(
    {"service": "independent-tcp-sender", "source_ips": ["172.18.0.3"]})
info = main.api_prober_info()
check("代理 info 返回发包端数据", info["source_ips"] == ["172.18.0.3"], str(info))
probe = main.api_prober_probe({"ports": [8080]})
check("代理 probe 透传", probe["source_ips"] == ["172.18.0.3"])
urllib.request.urlopen = orig_urlopen

# 注入真实形态事件后再关闭写端（让采集正常收口而非进程异常）
def pkt(tid, dport):
    return json.dumps({"type": "packet", "data": {
        "id": tid, "interface": {"dev": "eth0"},
        "skb": {"ip": {"src": "10.20.30.40", "dst": "172.18.0.2"},
                "tcp": {"sport": 40000 + dport, "dport": dport}}}})
def tr(tid, verdict, handle):
    return json.dumps({"type": "trace", "data": {
        "id": tid, "type": "rule", "table": "port_mgmt",
        "verdict": {"type": verdict, "handle": handle, "table": "port_mgmt"},
        "rule": {"handle": handle, "table": "port_mgmt"}}})
for line in (pkt("w1", 8080), tr("w1", "accept", 5), pkt("w2", 22), tr("w2", "drop", 9)):
    os.write(w, (line + "\n").encode())

# 等待采集自动收口
import time
sid = out["session_id"]
deadline = time.time() + 8
while time.time() < deadline:
    if db.get_diag_session(sid)["status"] in (db.DIAG_DONE, db.DIAG_ERROR):
        break
    time.sleep(0.1)
os.close(w)

def body(resp):
    if isinstance(resp, fr.JSONResponse):
        c = resp.content
        return json.loads(c) if isinstance(c, (str, bytes, bytearray)) else c
    return resp

sess_resp = body(main.api_diag_session(sid))
check("会话接口可查结果", sess_resp["exists"] and sess_resp["session"]["status"] == db.DIAG_DONE,
      str(sess_resp.get("session", {}).get("status")))
missing_resp = body(main.api_diag_session(99999))
check("不存在会话返回 exists=False", missing_resp["exists"] is False)
check("收尾已移除 trace", calls and calls[-1][1] is None, str(calls[-1:]))
result = sess_resp["session"]["result"]
by = {p["trace_id"]: p for p in result["packets"]}
check("结果含放行/丢弃各一包",
      by["w1"]["verdict"] == "accept" and by["w2"]["verdict"] == "drop"
      and by["w1"]["src_ip"] == "10.20.30.40", str(result["packets"]))

# 应用变更在诊断结束后仍正常（接线）
ar = main.api_apply(main.ApplyRequest(ports=[8080, 8090, 9000]))
check("apply 接线正常", ar["ok"] and ar["requested_ports"] == [8080, 8090, 9000], str(ar))
st = body(main.api_status())
check("status 含 recent_changes 与 nft 规则字段",
      "recent_changes" in st and "active_nft_rules" in st, str(list(st.keys())))

print(f"\n==== 接线测试：{PASS} 通过 / {FAIL} 失败 ====")
sys.exit(1 if FAIL else 0)
