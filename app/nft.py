"""nftables 适配层（仅操作容器内专用表 ``inet port_mgmt``）。

约束：
* 只操作容器内专用表，不使用宿主网络，不触碰其他任何表；
* 整条规则集通过一次 ``nft -f`` 原子批量提交：成功即整体生效，
  失败则旧规则原样保留（内核事务语义），满足“应用失败保留旧规则”；
* 链策略为 drop，白名单之外的非回环入站 TCP（含已有连接）一律被丢弃；
  非 TCP 的已建立/相关连接（如 UDP DNS 应答）放行，保证容器基础网络可用。

诊断扩展（trace）：
* 诊断开始时在同一条原子事务里重建规则集，并在链首插入只观察、不裁决的
  ``trace`` 规则（``meta nftrace set 1`` 后继续走后续规则），因此诊断
  不会改变任何放行/丢弃语义；
* 所有规则集写入（应用/确认/回退/诊断启停）都经过 :mod:`ruleset` 的统一
  入口，诊断期间的任何规则重写都会把当前 trace 规则原样带进新事务，
  绝不覆盖新白名单，也不会让 trace 规则残留或丢失；
* :func:`spawn_trace_monitor` 启动独立的 ``nft monitor trace`` 监听进程，
  每次诊断一个新进程，结束时由诊断模块回收，旧事件不可能进入下次诊断。
"""
from __future__ import annotations

import ipaddress
import shutil
import subprocess
from typing import Sequence

from config import (
    NFT_CHAIN_NAME,
    NFT_CHAIN_PRIORITY,
    NFT_TABLE_FAMILY,
    NFT_TABLE_NAME,
)


class NftError(RuntimeError):
    """nftables 命令执行失败。"""


def ensure_nft_available() -> None:
    if shutil.which("nft") is None:
        raise NftError(
            "容器内找不到 nft 可执行文件，请确认镜像已安装 nftables 且以 "
            "NET_ADMIN（及 NET_RAW）能力启动"
        )


def _trace_rule(trace_source_v4: str) -> str:
    """生成链首 trace 规则文本：只对真实非回环入站 IPv4 TCP 包打 trace 标记。

    要求：
    * ``ip saddr`` 隐含 IPv4，配合 ``meta l4proto tcp`` 仅匹配 IPv4 TCP；
    * ``iif != lo`` 排除回环；
    * ``iifname != \"lo\"`` 同理（不同 nft 版本二选一语法，用接口索引为主）；
    * 规则无 verdict，仅 ``meta nftrace set 1``，包继续接受后续白名单规则裁决。
    """
    # 入口处已做地址校验，这里再防御性校验一次，杜绝把非法输入拼进 nft 脚本
    ip = ipaddress.IPv4Address(trace_source_v4)
    return (
        f"add rule {NFT_TABLE_FAMILY} {NFT_TABLE_NAME} {NFT_CHAIN_NAME} "
        f"iif != lo ip saddr {ip} meta l4proto tcp meta nftrace set 1 "
        f'comment "diag trace only (observe, no verdict)"'
    )


def render_ruleset(tcp_ports: Sequence[int], trace_source_v4: str | None = None) -> str:
    """根据 TCP 白名单生成原子规则集文本。

    ``destroy`` 与 ``create`` 在同一个批量事务中提交，中间不存在
    “无表”窗口；若批量中任何一句失败，整个事务回滚，旧规则不变。

    若提供 ``trace_source_v4``，trace 规则插在链首（先于回环放行规则），
    但因其匹配条件本身排除回环，回环流量不受影响。
    """
    lines = [
        f"destroy table {NFT_TABLE_FAMILY} {NFT_TABLE_NAME}",
        f"create table {NFT_TABLE_FAMILY} {NFT_TABLE_NAME}",
        (
            f"create chain {NFT_TABLE_FAMILY} {NFT_TABLE_NAME} {NFT_CHAIN_NAME} "
            f"{{ type filter hook input priority {NFT_CHAIN_PRIORITY}; policy drop; }}"
        ),
    ]
    if trace_source_v4 is not None:
        # 链首：诊断 trace（只观察，不裁决），其余规则与无诊断时完全一致
        lines.append(_trace_rule(trace_source_v4))
    lines += [
        # 回环接口全部放行
        f"add rule {NFT_TABLE_FAMILY} {NFT_TABLE_NAME} {NFT_CHAIN_NAME} "
        f"iif lo accept comment \"loopback always allowed\"",
        # 非 TCP 的已建立/相关连接放行（UDP/ICMP 应答等，不影响 TCP 过滤语义）
        f"add rule {NFT_TABLE_FAMILY} {NFT_TABLE_NAME} {NFT_CHAIN_NAME} "
        f"ct state established,related meta l4proto != tcp accept "
        f"comment \"non-tcp established traffic (e.g. dns replies)\"",
    ]
    for port in sorted(set(tcp_ports)):
        lines.append(
            f"add rule {NFT_TABLE_FAMILY} {NFT_TABLE_NAME} {NFT_CHAIN_NAME} "
            f"tcp dport {port} accept comment \"whitelisted tcp {port}\""
        )
    # 链策略 drop 兜底：其余所有非回环入站（含 TCP 已有连接）均被丢弃
    return "\n".join(lines) + "\n"


def apply_ruleset(tcp_ports: Sequence[int], trace_source_v4: str | None = None) -> None:
    """原子应用白名单规则；失败抛 NftError，旧规则保持不变。

    诊断期间传入 ``trace_source_v4`` 可在同一事务内保留 trace 规则，
    因此规则重写（应用/确认/回退）与诊断启停互不破坏。
    """
    ensure_nft_available()
    ruleset = render_ruleset(tcp_ports, trace_source_v4)
    proc = subprocess.run(
        ["nft", "-f", "-"],
        input=ruleset,
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise NftError(
            f"nft 应用失败(exit={proc.returncode}): {proc.stderr.strip() or proc.stdout.strip()}"
        )


def spawn_trace_monitor() -> subprocess.Popen:
    """启动一个全新的 ``nft monitor trace`` 监听进程（JSON 行输出）。

    每次诊断都启动新进程：进程创建之后产生的 trace 事件才会被读到，
    结束时由调用方 terminate/wait 回收，从机制上保证“旧事件不得进入
    下次诊断”。``-n`` 禁用反向解析，避免 DNS 卡顿。
    """
    ensure_nft_available()
    # 独立进程组，便于异常清理时整组回收
    return subprocess.Popen(
        ["nft", "-n", "-j", "monitor", "trace"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        start_new_session=True,
    )


def list_active_rules() -> list[str]:
    """返回专用表当前生效的规则行（用于状态页展示）。"""
    ensure_nft_available()
    proc = subprocess.run(
        [
            "nft", "-n", "-a",
            "list", "chain",
            NFT_TABLE_FAMILY,
            NFT_TABLE_NAME,
            NFT_CHAIN_NAME,
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        # 表尚不存在时返回非零，视为空规则集
        return []
    rules: list[str] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if line.startswith(("table ", "chain ", "}")) or not line:
            continue
        rules.append(line)
    return rules


def delete_table() -> None:
    """删除专用表（仅用于清理/测试）。"""
    ensure_nft_available()
    proc = subprocess.run(
        ["nft", "delete", "table", NFT_TABLE_FAMILY, NFT_TABLE_NAME],
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0 and "No such file or directory" not in proc.stderr:
        raise NftError(proc.stderr.strip())
