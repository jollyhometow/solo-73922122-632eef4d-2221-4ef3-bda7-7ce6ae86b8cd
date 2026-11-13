"""集中配置：端口、超时、nftables 表名等均可通过环境变量覆盖。"""
from __future__ import annotations

import os

# 管理网页端口（初始白名单之一，演示时可把它移出白名单以模拟失联）
WEB_PORT = int(os.getenv("WEB_PORT", "8080"))
# 附带的 HTTP 回显服务端口（初始白名单之一）
ECHO_PORT = int(os.getenv("ECHO_PORT", "8090"))

# 确认窗口（秒）：规则生效后必须在该时长内确认，否则看护进程回退
CONFIRM_WINDOW_SECONDS = float(os.getenv("CONFIRM_WINDOW_SECONDS", "30"))
# 看护进程轮询周期
WATCHDOG_INTERVAL_SECONDS = float(os.getenv("WATCHDOG_INTERVAL_SECONDS", "0.5"))

# 容器内专用 nftables 表（只操作这张表，绝不触碰宿主或其他表/链）
NFT_TABLE_FAMILY = "inet"
NFT_TABLE_NAME = os.getenv("NFT_TABLE_NAME", "port_mgmt")
NFT_CHAIN_NAME = "input_filter"
NFT_CHAIN_PRIORITY = 0

DB_PATH = os.getenv("DB_PATH", "/data/mgmt.db")

# 初始放行端口：管理网页 + HTTP 回显服务
INITIAL_PORTS = sorted({WEB_PORT, ECHO_PORT})

MIN_PORT = 1
MAX_PORT = 65535

# ---- 短时入站诊断（nftables trace）相关配置 ----
# 单次诊断采集时长（秒）：到期自动回收监听进程并移除 trace 规则
DIAG_DURATION_SECONDS = float(os.getenv("DIAG_DURATION_SECONDS", "10"))
# 单次诊断最多关联展示的包数（超出仅计数，不进入结果）
DIAG_MAX_PACKETS = int(os.getenv("DIAG_MAX_PACKETS", "100"))
# 监听进程等运行期文件（PID 等）目录
DIAG_STATE_DIR = os.getenv("DIAG_STATE_DIR", "/data/diag")
# 独立发包端服务地址（容器网络内主机名 prober）；浏览器经后端代理访问
PROBER_URL = os.getenv("PROBER_URL", "http://prober:9000")
# 后端代理发包端请求的超时
PROBER_TIMEOUT_SECONDS = float(os.getenv("PROBER_TIMEOUT_SECONDS", "12"))
