#!/usr/bin/env bash
# 短时入站诊断端到端演示（在能访问已发布端口的机器上运行，容器宿主即可）
# 流程：读取独立发包端源 IP -> 启动 10 秒诊断 -> 触发真实探测 -> 等待并查看按包判定
# 用法: ./diag_demo.sh
set -u
WEB="${WEB:-http://127.0.0.1:8080}"
PROBER="${PROBER:-http://127.0.0.1:9000}"

hr() { printf '\n========== %s ==========\n' "$1"; }

command -v python3 >/dev/null || { echo "需要 python3 解析 JSON"; exit 1; }

hr "1. 读取独立发包端信息（独立容器、独立网络栈、无特权）"
INFO=$(curl -s "$PROBER/info")
echo "$INFO" | python3 -m json.tool
SRC=$(echo "$INFO" | python3 -c 'import sys,json;print(json.load(sys.stdin)["source_ips"][0])')
echo ">>> 使用源 IPv4: $SRC"

hr "2. 启动 10 秒 nftables trace 诊断（同期只允许一份）"
START=$(curl -s -X POST "$WEB/api/diag/start" \
  -H 'Content-Type: application/json' -d "{\"source_ip\":\"$SRC\"}")
echo "$START" | python3 -m json.tool
SID=$(echo "$START" | python3 -c 'import sys,json;print(json.load(sys.stdin)["session_id"])')

hr "3. 立即通过浏览器同源代理触发独立发包端发起真实 TCP 连接（两轮）"
curl -s -X POST "$WEB/api/prober/probe" \
  -H 'Content-Type: application/json' -d '{"rounds":2}' \
  | python3 -m json.tool

hr "4. 再次确认同期重复启动会被拒绝（409）"
curl -s -o /dev/null -w "HTTP %{http_code}\n" -X POST "$WEB/api/diag/start" \
  -H 'Content-Type: application/json' -d "{\"source_ip\":\"$SRC\"}"

hr "5. 等待采集窗口结束并自动回收监听进程（约 11 秒）…"
sleep 11

hr "6. 查看按包诊断结果（源/目标 IP、端口、最终放行或丢弃、判定时白名单）"
curl -s "$WEB/api/diag/session?session_id=$SID" | python3 -m json.tool

hr "7. 确认专用表已无残留 trace 规则（应看不到 nftrace）"
docker compose exec -T port-mgmt nft list table inet port_mgmt 2>/dev/null \
  | grep -q nftrace && echo "!! 仍存在 trace 规则（异常）" || echo "OK: trace 规则已回收"

echo
echo "浏览器打开 $WEB 滚到“短时入站诊断”可图形化重复以上流程。"
