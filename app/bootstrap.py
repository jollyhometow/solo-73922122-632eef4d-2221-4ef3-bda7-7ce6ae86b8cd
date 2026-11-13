"""整套服务启动恢复（entrypoint 在开放网页之前调用）。

恢复顺序：
1. 初始化数据库；
2. 把所有历史遗留的 pending 变更标记为 expired
   （未确认的变更在重启后一律不保留）；
3. 把所有遗留的诊断会话判为采集故障并回收可能残留的 trace 监听进程
   （监听进程已随旧容器消失，PID 文件清理仅为防御）；
4. 读取已确认规则并先在 nftables 恢复（无 trace 的干净规则集），
   之后才允许启动 Web。
首次启动（无已确认规则）时写入初始白名单（网页端口 + 回显端口）。
"""
from __future__ import annotations

import logging
import time

import db
import diagnostics
import ruleset
from config import INITIAL_PORTS

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [bootstrap] %(levelname)s %(message)s",
)
log = logging.getLogger("bootstrap")


def bootstrap() -> list[int]:
    db.init_db()

    when = time.time()
    stale = db.expire_all_pending("服务重启：未确认变更一律作废", when)
    for change_id in stale:
        log.info("遗留待确认变更单 #%s 已标记为 expired", change_id)

    # 遗留诊断一律判故障：监听进程已不存在，结果不可信；
    # 同时回收 PID 文件指向的残留进程（如有），并确保规则集不带 trace。
    stale_diag = db.fail_active_diag_sessions("服务重启：诊断未正常结束，结果作废", when)
    for session_id in stale_diag:
        log.info("遗留诊断会话 #%s 已标记为 error", session_id)
    diagnostics.kill_stale_monitor()

    ports = db.get_confirmed_ports()
    if ports is None:
        ports = sorted(INITIAL_PORTS)
        db.set_confirmed_ports(ports)
        log.info("首次启动，写入初始白名单 %s", ports)
    else:
        ports = sorted(ports)
        log.info("恢复已确认规则白名单 %s", ports)

    # 先恢复防火墙（无 trace 的干净原子规则集），再开放网页：
    # 失败则让容器启动失败，避免“裸奔”对外。
    ruleset.write_ruleset(ports, reason="bootstrap baseline restore")
    log.info("nftables 专用表规则已恢复，现在可以启动 Web")
    return ports


if __name__ == "__main__":
    bootstrap()
