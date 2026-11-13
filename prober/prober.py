"""独立来源的本地发包端（与管理面完全独立的容器/代码/网络栈）。

用途：诊断开始后，由浏览器通过管理面后端代理触发本服务，向目标容器
发起**真实的非回环 IPv4 TCP 连接**（容器间跨网络命名空间，经 veth/网桥
入站），从而在 nftables trace 中产生可关联的真实包。

设计约束：
* 仅使用 Python 标准库，无第三方依赖、无 NET_ADMIN/NET_RAW 特权；
* 只主动向外发起 TCP 连接，不修改任何防火墙规则；
* 每个探测使用临时源端口（connect 由内核分配），多次探测形成多个包；
* 提供 CORS 头，便于浏览器直接或经代理调用。
"""
from __future__ import annotations

import json
import os
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

PROBER_PORT = int(os.getenv("PROBER_PORT", "9000"))
# 默认探测目标（管理面容器在 compose 网络上的主机名与端口）
DEFAULT_TARGET_HOST = os.getenv("TARGET_HOST", "port-mgmt")
DEFAULT_TARGET_PORTS = [
    int(p) for p in os.getenv("TARGET_PORTS", "8080,8090,9000").split(",") if p.strip()
]
# 每端口探测轮数：每轮一个新连接 = 一个新的入站 SYN 包
DEFAULT_ROUNDS = int(os.getenv("PROBE_ROUNDS", "2"))
CONNECT_TIMEOUT = float(os.getenv("CONNECT_TIMEOUT", "1.5"))


def _local_ips() -> list[str]:
    """枚举本机所有 IPv4（排除回环），供页面预填“源 IPv4”。"""
    ips: set[str] = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith("127."):
                ips.add(ip)
    except OSError:
        pass
    # UDP 连一下对端拿到本出口源地址（不真正发包），兜底获得网桥内 IP
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((DEFAULT_TARGET_HOST, 8080))
            ips.add(s.getsockname()[0])
    except OSError:
        pass
    return sorted(ips)


def _probe_once(host: str, port: int) -> dict:
    """发起一次真实 TCP 连接，返回带临时源端口的结果。"""
    started = time.time()
    # 每次新建 socket：内核分配新的临时源端口，产生独立的入站 SYN
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(CONNECT_TIMEOUT)
    result: dict = {"target_port": port, "source_port": None}
    try:
        sock.connect((host, port))
        result["outcome"] = "connected"  # 被白名单放行（TCP 握手完成）
    except TimeoutError:
        result["outcome"] = "timeout"    # 大概率被丢弃（无 SYN-ACK）
    except ConnectionRefusedError:
        result["outcome"] = "refused"    # 包到达但端口无服务（说明已放行）
    except OSError as exc:
        result["outcome"] = "error"
        result["error"] = str(exc)
    finally:
        try:
            result["source_port"] = sock.getsockname()[1]
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass
    result["elapsed_ms"] = round((time.time() - started) * 1000, 1)
    return result


def run_probe(host: str, ports: list[int], rounds: int) -> dict:
    attempts: list[dict] = []
    for rnd in range(1, rounds + 1):
        for port in ports:
            item = _probe_once(host, port)
            item["round"] = rnd
            attempts.append(item)
    return {
        "prober": "independent-tcp-sender",
        "source_ips": _local_ips(),
        "target_host": host,
        "attempts": attempts,
        "sent_at": time.time(),
    }


class Handler(BaseHTTPRequestHandler):
    def _send_json(self, payload: dict, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:  # CORS 预检
        self._send_json({"ok": True})

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path in ("/", "/info"):
            self._send_json({
                "service": "independent-tcp-sender",
                "source_ips": _local_ips(),
                "default_target_host": DEFAULT_TARGET_HOST,
                "default_target_ports": DEFAULT_TARGET_PORTS,
            })
            return
        if parsed.path == "/probe":
            qs = parse_qs(parsed.query)
            host = (qs.get("host") or [DEFAULT_TARGET_HOST])[0]
            ports = _parse_ports(qs.get("ports"), DEFAULT_TARGET_PORTS)
            rounds = _parse_rounds(qs.get("rounds"))
            try:
                self._send_json(run_probe(host, ports, rounds))
            except Exception as exc:  # 单点失败不应让进程退出
                self._send_json({"ok": False, "error": str(exc)}, status=500)
            return
        self._send_json({"ok": False, "error": "not found"}, status=404)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path != "/probe":
            self._send_json({"ok": False, "error": "not found"}, status=404)
            return
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            body = {}
        host = str(body.get("host") or DEFAULT_TARGET_HOST)
        ports = _parse_ports(
            [",".join(map(str, body["ports"]))] if isinstance(body.get("ports"), list)
            else body.get("ports"),
            DEFAULT_TARGET_PORTS,
        )
        rounds = _parse_rounds(body.get("rounds"))
        try:
            self._send_json(run_probe(host, ports, rounds))
        except Exception as exc:
            self._send_json({"ok": False, "error": str(exc)}, status=500)

    def log_message(self, fmt: str, *args) -> None:
        threading.current_thread().name = "prober-worker"
        print(f"[prober] {self.address_string()} {fmt % args}", flush=True)


def _parse_ports(value, default: list[int]) -> list[int]:
    if value is None:
        return list(default)
    if isinstance(value, (list, tuple)):
        text = ",".join(str(v) for v in value)
    else:
        text = str(value)
    ports: list[int] = []
    for part in text.replace(";", ",").replace(" ", ",").split(","):
        part = part.strip()
        if part.isdigit() and 1 <= int(part) <= 65535:
            ports.append(int(part))
    return sorted(set(ports)) or list(default)


def _parse_rounds(value) -> int:
    try:
        if value is None:
            return DEFAULT_ROUNDS
        rounds = int(value[0] if isinstance(value, list) else value)
        return max(1, min(rounds, 5))
    except (TypeError, ValueError):
        return DEFAULT_ROUNDS


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", PROBER_PORT), Handler)
    print(f"[prober] 独立发包端监听 0.0.0.0:{PROBER_PORT}，本机 IPv4: {_local_ips()}",
          flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
