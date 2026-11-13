# 入站端口白名单变更管理（FastAPI + SQLite + nftables）

面向远程运维场景：调整入站端口白名单时，如果误封了管理网页自身，系统会在确认窗口
（默认 30 秒）到期后由**独立于 Web 的看护进程**自动恢复旧规则，无需登录宿主操作。

同时内置**短时入站诊断**：运维排查“端口为何不通”时，输入源 IPv4 即可采集 10 秒
真实非回环入站 IPv4 TCP 包的 nftables trace，按包看到本专用表的最终放行/丢弃结果，
并可在浏览器一键触发独立发包端产生真实探测流量。

## 架构与边界

```
容器（独立网络命名空间，不使用 network_mode: host）
├── bootstrap.py    入口恢复：恢复已确认规则、作废遗留诊断、再开放网页
├── nft.py          nftables 适配：仅操作专用表 inet port_mgmt，原子批量提交，
│                   含诊断 trace 规则渲染与 trace 监听进程拉起
├── ruleset.py      规则集写入唯一协调入口：trace 与白名单同事务、版本时间线
├── diagnostics.py  短时诊断：nft monitor trace 采集、按包关联、判定/无法判定、回收
├── firewall.py     变更业务：应用 / 确认 / 超时回退（全部经 ruleset 协调层）
├── db.py           SQLite 持久层（WAL）：规则、变更单、诊断会话、规则版本时间线
├── watchdog.py     独立看护进程：超时未确认即回退，Web 退出后仍值守
├── main.py         FastAPI 管理网页（应用、确认、状态、诊断、发包端代理）
├── echo_server.py  附带的 HTTP 回显服务
└── /data/mgmt.db   命名卷持久化

独立容器（独立镜像/代码/网络栈，无 NET_ADMIN/NET_RAW）
└── prober/         独立来源本地发包端：只主动发起真实 TCP 连接，不碰防火墙
```

* **只修改容器内专用表** `inet port_mgmt`（链 `input_filter`，策略 `drop`），
  不触碰宿主网络命名空间或其他任何 nftables 表；Compose 仅授予 `NET_ADMIN`/`NET_RAW`。
* **过滤所有非回环入站流量**：回环接口显式放行；白名单 TCP 端口放行，
  其余入站（含白名单外 TCP 的**已有连接**）一律丢弃。非 TCP 的
  established/related（如 UDP DNS 应答）放行，保证容器基础网络可用。
* **原子生效**：每次变更通过一次 `nft -f -` 批量事务（destroy + create 同批）提交，
  内核要么整体生效、要么整体回滚——**应用失败时旧规则原样保留**。
* **先持久化后生效**：应用前先把“已确认规则快照 + pending 变更单”写入 SQLite，
  再调用 nft；因此 Web 在生效后任意时刻退出，看护进程都能据快照回退。

## 确认窗口状态机（关键安全语义）

1. 有待确认（pending）变更时，**拒绝任何新变更**（HTTP 409）。
2. 变更生效后 **30 秒内**在页面点“确认”：白名单固化为已确认规则并持久化。
3. 30 秒内未确认：独立看护进程自动把 nft 规则恢复为应用前快照，变更单标记 `expired`。
4. **过期单 / 旧变更单的确认一律拒绝**，不会影响当前规则。
5. Web 进程退出不影响回退（看护进程是独立 OS 进程，按数据库中的截止时间判定）。
6. 整套服务重启：遗留 pending 单全部作废，**先恢复已确认规则，再开放网页**。

## 快速启动

```bash
docker compose up --build
```

浏览器入口：

| 服务 | 地址 | 说明 |
|---|---|---|
| 管理网页 | http://localhost:8080/ | 应用 / 确认 / 状态查看 / 入站诊断 |
| HTTP 回显 | http://localhost:8090/ | 验证端口连通性，返回请求 JSON 回显 |
| 独立发包端 | http://localhost:9000/info | 独立容器的真实 TCP 发包端（诊断用） |

初始白名单为 `8080`（网页）+ `8090`（回显），首次启动时写入 SQLite 并下发 nft。

## 短时入站诊断（nftables trace）

排查“某源访问端口被拦”时，在网页底部“短时入站诊断”卡片操作，或直接调 API。

### 它观察什么、保证什么

* **真实非回环入站 IPv4 TCP**：trace 规则为
  `iif != lo ip saddr <源IPv4> meta l4proto tcp meta nftrace set 1`，
  位于链首但**无 verdict，只观察不裁决**，包继续走原白名单规则，放行/丢弃语义不变。
* **同期只运行一份**：进程内单飞锁 + SQLite 部分唯一索引（running/finalizing 唯一）双保险，
  重复启动返回 409。
* **每次诊断一个全新 `nft -j monitor trace` 进程**：只看进程启动后的新事件；
  结束时 terminate/wait（必要时 SIGKILL）整组回收，**旧事件不可能进入下次诊断**。
* **按包关联交错事件，最多 100 包**：以 trace id 汇聚 packet/rule/verdict/policy 事件，
  保留全局事件序号还原多包交错；超 100 包只计数不纳入。
* **最终放行/丢弃结果**：规则 `accept` 与链默认策略 `drop`（policy 事件）都识别为终态；
  **缺少终态判定或采集监听故障的包明确标注“无法判定”**，绝不臆测。
* **迟到事件关联“实际判定时”的白名单**：每次规则集写入都在 `rule_versions`
  留带墙钟时间的版本，包按其终态事件时刻对齐当时白名单，**不套用查看时的当前策略**。
* **与规则写入协调**：所有 nft 重写统一走 `ruleset` 协调层，trace 与白名单在同一原子
  事务内。诊断期间**应用/确认/30 秒自动回退照常**，trace 不丢失、不覆盖新白名单、
  不改变 30 秒期限；结束时用“当前白名单 + 无 trace”原子重写回收。
* **只操作容器内专用表**：trace 事件按表名/链名过滤，其他 nft 表的事件不会混入。

### 浏览器操作流程

1. 打开 http://localhost:8080/ ，滚到“短时入站诊断”。
2. 点 **“读取发包端源 IP”**，自动填入独立发包端容器的非回环 IPv4（也可手填真实源）。
3. 点 **“启动 10 秒诊断”**，页面进入倒计时。
4. 在窗口内点 **“浏览器触发发包端探测”**（可多次）：发包端向 8080/8090/9000
   发起若干新的真实 TCP 连接（每次新临时源端口）。
5. 10 秒后自动出结果：每个包的源/目标 IP、端口、本专用表最终放行/丢弃、
   判定时白名单、交错事件明细；无法判定的包单列说明。

> 9000 端口默认无服务且不在白名单，会被链策略丢弃（页面显示“丢弃 drop”），
> 用来直观看到“被防火墙拦住”的判定；8080/8090 在白名单内显示“放行 accept”。

### 命令行（API）

```bash
# 启动诊断（源 IPv4 用发包端实际 IP，可先 GET /info 查）
SRC=$(curl -s http://localhost:9000/info | python3 -c 'import sys,json;print(json.load(sys.stdin)["source_ips"][0])')
SID=$(curl -s -X POST http://localhost:8080/api/diag/start \
  -H 'Content-Type: application/json' -d "{\"source_ip\":\"$SRC\"}" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["session_id"])')
# 触发真实探测
curl -s -X POST http://localhost:8080/api/prober/probe -H 'Content-Type: application/json' -d '{}'
# 等待约 10 秒后查看结果
sleep 11
curl -s "http://localhost:8080/api/diag/session?session_id=$SID" | python3 -m json.tool
```

容器内核对实际规则（只读）：

```bash
docker compose exec port-mgmt nft list table inet port_mgmt   # 诊断期间可见链首 nftrace 规则
docker compose exec port-mgmt nft -j monitor trace            # 手动观察原始 trace（可选）
```

## 演示：误封网页后自动恢复

1. 打开 http://localhost:8080/ ，点击 **“演示：移除网页端口（模拟误封失联）”**
   （或手动输入仅含 `8090` 的白名单并应用）。
2. 规则立即生效：网页端口 8080 被丢弃，页面进入失联重试状态；
   回显服务 http://localhost:8090/ 仍可正常访问。
3. 不要点确认。等待 30 秒：看护进程自动回退到旧白名单，
   页面自动恢复访问，变更记录中该单显示“已过期回退”。

命令行端到端演示：

```bash
./demo.sh
```

容器内查看实际 nft 规则（只读）：

```bash
docker compose exec port-mgmt nft list table inet port_mgmt
```

## HTTP API

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/config` | 端口与确认窗口配置 |
| GET | `/api/status` | 已确认白名单、pending 倒计时、生效规则、历史变更 |
| POST | `/api/apply` | body `{"ports":[8080,8090]}` 应用新白名单（pending 时 409） |
| POST | `/api/confirm` | body `{"change_id":1}` 窗口内确认（过期/旧单 409） |
| GET | `/api/diag/config` | 诊断时长、最大包数、发包端地址 |
| GET | `/api/diag/active` | 当前占用中的诊断会话（含倒计时），无则 `active=null` |
| GET | `/api/diag/session?session_id=N` | 指定（或最近一次）诊断会话与按包结果 |
| POST | `/api/diag/start` | body `{"source_ip":"172.18.0.3"}` 启动 10 秒诊断（同期已有则 409） |
| POST | `/api/prober/info` | 后端代理：读取独立发包端信息（含其源 IPv4） |
| POST | `/api/prober/probe` | 后端代理：触发发包端发起真实 TCP 探测 |

诊断结果对象要点：`status`（running/finalizing/done/error）、`packets[]`
（含 `src_ip/dst_ip/sport/dport/verdict/verdict_label/whitelist_at_verdict/
decidable/note/events`）、`packets_dropped_cap`（超 100 上限数）、
`monitor_failed`、`error_detail`、`whitelist_versions`（诊断期间版本时间线）。

## 配置（环境变量，见 docker-compose.yml）

| 变量 | 默认 | 说明 |
|---|---|---|
| `WEB_PORT` | 8080 | 管理网页端口（初始白名单） |
| `ECHO_PORT` | 8090 | HTTP 回显端口（初始白名单） |
| `CONFIRM_WINDOW_SECONDS` | 30 | 确认窗口时长（诊断不改变该期限） |
| `WATCHDOG_INTERVAL_SECONDS` | 0.5 | 看护进程轮询周期 |
| `NFT_TABLE_NAME` | port_mgmt | 容器内专用 nft 表名 |
| `DB_PATH` | /data/mgmt.db | SQLite 路径（命名卷持久化） |
| `DIAG_DURATION_SECONDS` | 10 | 单次诊断采集时长 |
| `DIAG_MAX_PACKETS` | 100 | 单次诊断最多纳入展示的包数 |
| `DIAG_STATE_DIR` | /data/diag | 监听进程 PID 等运行期文件目录 |
| `PROBER_URL` | http://prober:9000 | 独立发包端地址（后端代理用） |
| `PROBER_TIMEOUT_SECONDS` | 12 | 后端代理发包端请求超时 |

## 说明与注意事项

* 能力要求：管理容器需 `NET_ADMIN`（配置 nft 规则）与 `NET_RAW`（含 trace 监听）；
  **独立发包端不申请任何特权**。宿主内核需支持 nftables
  （现代 Docker Desktop / Linux 发行版默认支持）。
* 回退 nft 命令本身失败时，看护进程不会把变更单标记过期，而是在下个轮询周期
  重试，直到规则真正恢复，避免“状态显示回退但规则未恢复”。
* 健康检查走容器回环接口（回环永远放行），因此网页端口被封时健康检查仍可工作。
* 页面强制白名单至少保留一个端口，避免提交空规则导致永久失联。
* 诊断的 trace 规则只观察不裁决，不改变任何放行/丢弃；服务重启会把未完成的
  诊断一律判为 `error`（结果不可信）并恢复无 trace 的干净规则集。
* 诊断结果持久化在 SQLite `diag_sessions` 表，规则版本时间线在 `rule_versions`，
  与变更单一样跨容器重启保留（仅未完成会话在启动时作废）。
* 单元/接线测试（无需 docker/nft，使用替身）：

  ```bash
  python3 -I tests/test_diag_logic.py        # 按包关联/判定/上限/版本对齐（44 项）
  python3 -I tests/test_diag_concurrency.py  # 诊断与应用/确认/回退并发协调（19 项）
  python3 -I tests/test_main_wiring.py       # FastAPI 路由与代理接线（19 项）
  ```
