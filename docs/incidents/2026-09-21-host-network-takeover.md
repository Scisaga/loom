# 2026-09-21 Linux 宿主网络接管事故

## 状态

- 严重级别：阻断开发宿主管理面与基础联网能力。
- 当前状态：宿主已恢复；`loom-client.service` 为 disabled/inactive，并有持久 systemd quarantine drop-in；临时
  逃生 rule 已在基线验收后删除。
- 产品状态：control service 保持运行，但合并在危险 hybrid runtime 内的 server relay/egress 也随隔离而停止；
  它们尚未恢复。应先以前述无 TUN server plane 恢复，再实现专用 access namespace。

本文只记录脱敏的工程事实。真实节点、地址、域名、端口、密钥和运行指标不进入仓库；受保护现场证据只进入
被忽略的 `deploy/evidence/`。

## 影响

Loom 为 access runtime 生成 `auto_route=true` 的 TUN，却让它在开发宿主初始 network namespace 中以
`CAP_NET_ADMIN` 运行。sing-box/sing-tun 随后创建 `tun0`，向 table 2022 写入几乎覆盖全部 IPv4 的拆分路由，
并安装 priority 9000～9010 的 policy rules。结果包括：

- 外部 SSH 请求到达物理接口后，返回流量进入 TUN；
- LAN、现有 WireGuard、默认公网、DNS 和 HTTP proxy 的宿主路径被接管或依赖故障；
- enabled 且 `Restart=always` 的 service 在失败和重启后反复施加同一状态；
- 业务 selector/report 可以成功，但不能证明宿主控制平面安全。

## 直接原因与责任链

1. 控制投影生成只有 `auto_route=true`、没有正向 `route_address` 的 TUN。
2. Linux HostAdapter 添加固定 TUN 地址和 `auto_detect_interface`，只排除认证 endpoint 的精确主机地址。
3. 正式 systemd unit 向宿主 netns 中的进程开放 `/dev/net/tun` 和 `CAP_NET_ADMIN`，没有 namespace 隔离。
4. sing-tun 在 route set 为 `0.0.0.0/0` 的基础上减去一个 endpoint `/32`，把补集展开为一组拆分路由；
   缺省 table/rule index 分别为 2022 和 9000。
5. installer 启用并重启 service，readiness 只检查 service 与 selector status，不检查宿主 SSH、LAN、WireGuard、
   DNS、代理、默认路由或 rollback。

执行内核 netlink 调用的是 sing-box/sing-tun；选择危险配置、授予宿主权限、缺少隔离并部署它的是 Loom 和执行
该部署的开发会话。第三方默认值不是责任转移依据。

相关源码与部署提交：

- `190a9fa7`：引入宿主 service、`/dev/net/tun` 和 `CAP_NET_ADMIN`；
- `4bad678a`：当前 RuntimeProfile 投影写入 `auto_route=true`；
- `1cfb0716`：Linux HostAdapter 派生 TUN 地址、system stack 和接口自动检测；
- `8a21d6ce`：只加入 endpoint `/32`/`/128` 排除，并成为事故时部署版本。

## 促成因素

- 把“获授权业务流量应走候选路径”错误解释成“宿主全部 IPv4 应进入 TUN”。
- 模型缺少 capture 边界和宿主管理面不变量。
- 真实 TUN 测试使用独立 user/network namespace，且人为设置窄 `route_address`；生产配置反而两者都没有。
- 为促使报告成功而添加临时 endpoint 主路由，并把报告变绿误判为 TUN 边界正确。
- 没有独立管理通道、变更前基线、精确所有权清单、异常清理或停止后回读。
- Loom 只恢复运行配置与部分 WireGuard 事务，宿主 route/rule/resolver 完全依赖 sing-tun graceful close。

## 恢复经过

恢复严格保留临时 `lookup main` 逃生 rule，先禁止危险状态重建，再验证正常清理：

1. 只读确认 rules、table、TUN、resolved、service、进程/netns 和主路由状态。
2. 禁用 `loom-client.service` 的开机启动，再显式停止 service。
3. graceful close 成功移除 TUN、priority 9000～9010、经 TUN 的 table 2022 路由和 TUN 的 `~.` DNS。
4. table 2022 仍有一条无法从 netlink 证明创建者的 LAN connected route；因无 rule 引用且所有权未知，未盲删。
5. 在逃生 rule 仍存在时验证现有 SSH 返回路径、LAN、WireGuard、公网、DNS 和代理 HTTPS。
6. 最后删除临时逃生 rule，并在只剩 local/main/default rules 的状态下重复全部验证。

恢复没有 flush 路由表或防火墙，没有删除未知对象，没有重启机器、NetworkManager 或 systemd-networkd。
Loom 的 TUN `~.` DNS 已消失，libc/direct DNS 正常；一个事故前已存在、与 Loom 无关的 WireGuard link 仍声明
自己的 `~.` 域，因此不指定接口的 `resolvectl query` 仍会选择它。该外部配置未在本事故中改写，避免以“修 DNS”
为名破坏既有 WireGuard。

## 已落地防复发措施

- Linux access/hybrid preflight 与 runtime 比较 `/proc/self/ns/net` 和 `/proc/1/ns/net`；相同即失败关闭。
- systemd package 从 `Restart=always` 改为 `Restart=no`，避免失败网络激活循环重施。
- 已安装的旧二进制由 `/etc/systemd/system/loom-client.service.d/00-host-network-quarantine.conf` 以
  `ExecCondition=/usr/bin/false` 和 `Restart=no` 持久隔离；即使误 enable/start 也不会运行。只有专用 namespace
  生命周期和回滚验收完成后才能删除该 drop-in。
- 本事故、capture 边界、回滚语义和最小测试加入重建入口、客户端运行模型、安装文档与仓库工作提示。
- 当前实际 service 保持 disabled/inactive，源码门禁未完成正式隔离前不得绕过。

## 仍未完成的正式架构

事故恢复不等于 Linux 客户端完成。重新启用 access/hybrid 前必须在同一工作项完成：

1. 同机 control + server relay + 最终出网先以无 TUN 的 server plane 恢复；只有本机 access workload 进入专用
   network namespace，TUN、table、rules 和该 workload 的 DNS 全部位于其中。
2. generation-scoped namespace/veth/firewall 所有权清单及幂等 `ExecStopPost` 清理。
3. 正常停止、child/parent crash、SIGKILL、启动中途失败和重启恢复验收。
4. 启动前后实际回读宿主 SSH、LAN、默认网关、WireGuard、DNS、HTTP proxy 和公网路由。
5. cleanup 或不变量回读失败时保持 failed/inactive，禁止自动重启和状态上报成功。
6. installer 只有在隔离与回读全部成立后才允许 enable/start；失败不能恢复会接管宿主网络的旧 release。

开发机默认使用显式 Mixed/SOCKS/HTTP proxy。整机 TUN 语义只在专用 namespace、VM 或物理客户端验证；
host-network 容器、endpoint 排除和更多 policy-routing 补丁都不是可接受替代。

这项结论不是取消 TUN：TUN 是业务 overlay，物理接口或既有 WireGuard 是 tunnel underlay。对本开发宿主，overlay
必须移入隔离 namespace；对明确承担整机 VPN 的专用终端，TUN 可以存在，但 capture 之前必须证明管理与 underlay
流量稳定绕过。事故中物理接口始终能收包，失联来自返回路径被 policy routing 改道，因此“接口正常”不能替代
route 与真实连接回读。

本机承担中控、转发和最终出网并不是事故根因，也不是不现实的目标。这三项 server/control 职责本身不需要
捕获宿主流量；事故来自把可选的本机 access capture 与它们合并进同一个 root-netns `auto_route` runtime。
