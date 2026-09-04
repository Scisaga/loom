# Loom · Local Network 目标设计

> **状态:** 提案已收敛，**尚未实现**；不得用于解释当前生产能力
>
> **日期:** 2026-09-01
>
> **适用范围:** 通过受管 Device 显式访问其所在局域网中的 TCP/UDP 目标；不包含
> 透明三层组网、租户划分或根据当前 Wi-Fi 自动切换策略
>
> **上位约束:** [设计文档](design.md)中的不变量、SSOT 与单一 Agent 决策边界
> 仍是唯一事实来源；设备加入、Direct / Auto / 指定出口及平台接管方式服从
> [客户端接入设计](client-access.md)。实际是否实现、发布或部署只看
> [当前状态](status/current.md)。

---

## 1. 结论

Local Network 是一个**具名目标地址域**。它解决的问题是：让一个获授权的设备
明确访问“办公室 A 的 `192.168.1.10`”，同时允许“实验室 B”存在相同地址，
而不把两个重复网段安装进客户端的全局路由表。

用户指定的是目标网络，不是物理路径：

```text
-network office-a
        │
        │ 选择目标地址域与授权
        ▼
LocalNetwork + target
        │
        │ 复用 Declaration 的策略参数与同一个 Agent
        ▼
自动选择 ServerChain → 固定的 Gateway Device → 局域网目标
```

最小实现目标是显式的 TCP 访问。SSOT 从一开始区分 TCP/UDP 授权，避免未来协议
混用，但固定目标的单播 UDP 转发必须经过独立端到端验证后再交付。整个专题都不向
客户端安装 LAN 路由，不接管系统 `ping`，不构造第二套选路器，也不要求改造现有
WireGuard `/32` 隧道为站点到站点 VPN。

当前仓库中没有 `LocalNetwork`、`network_id`、对应 CLI、协议级授权和端到端测试。
sing-box 的 Hysteria2 与 Trojan 出站都能承载 TCP/UDP，只说明底层原语可用，不能
冒充 Loom 已经交付该功能：

- [sing-box Hysteria2 outbound](https://sing-box.sagernet.org/configuration/outbound/hysteria2/)
- [sing-box Trojan outbound](https://sing-box.sagernet.org/configuration/outbound/trojan/)
- [sing-box route rule](https://sing-box.sagernet.org/configuration/route/rule/)

---

## 2. 术语边界

### 2.1 `network_id` 只表示目标地址域

本文中的 `network_id`，例如 `office-a`，只回答：

> 这个可能重复的目标地址属于哪一个受管局域网？

它**不表示**：

- Loom deployment、租户或 CA 信任域；
- Device 的永久分组或加入码归属；
- 客户端当前连接的 Wi-Fi、SSID 或物理 LAN；
- 用户指定的中继、出口、首跳或完整路径；
- 一条新的 WireGuard 隧道或拓扑节点。

若以后引入多租户，registry、SSOT、CA、发布密钥、快照和凭据都必须完整隔离，
不能复用本文的 `network_id` 做一个表面上的租户字段。

### 2.2 Device、Gateway 与目标地址

本文采用统一后的 `Device` 目标术语。当前 registry 记录与 SSOT `Node` 并非严格
一一对应：前者可能仍在 provisioning，后者也可能是没有 registry 记录的历史节点。
落地本专题前必须建立共享的稳定 Device identity 与显式映射，不能靠名称推断。

- **Device**：Loom 管理并下发配置的机器；Access 与 Forwarding 是可组合能力。
- **Gateway**：某个 Local Network 引用的 Device，是该次路径的局域网边界；不是
  新设备类型，也不单独写 `gateway` capability。
- **目标地址**：局域网中的 IP 和端口；仍然不是 Device，不加入拓扑，也不安装 Agent。

一个 Device 被 Local Network 引用且具有 Forwarding 能力时，才在该网络中承担
Gateway 位置。能否作为公网出口是另一件事，不能复用 `egress_capable` 代表 LAN
授权。

---

## 3. 与现有 SSOT 和自动选路的关系

Local Network 不复制 Service、Policy 或 Agent。它新增一个 network-scoped route
scope；公网与局域网请求只在“如何分类目标与限制链末”这一步不同，随后复用同一套
ranking、selector、阻尼和 Agent 决策机制：

```text
普通业务：Host → Service ─────────────┐
                                       ├→ AccessDeclaration / Policy
显式内网：LocalNetwork + IP + 协议端口 ┘              │
                                                      ▼
                                             同一个 Agent
                                                      │
                                                      ▼
                                      自动选择完整 ServerChain
                                                      │
                          公网：链末 Device 直接出网   │
                          内网：链末必须是该 Network 的 Gateway
```

因此它与现有 SSOT 不变量不冲突：

1. 目标仍然只是地址，不变成节点；
2. 策略仍只裁剪候选集，Agent 仍是唯一选路者；
3. 当前选择与测量仍是运行态，不写回 SSOT；
4. 每台 Device 的配置仍由同一 SSOT 纯函数渲染；
5. 控制平面离线时继续使用最后一份验签配置；
6. 无授权或无候选时 fail closed，不偷偷改走客户端本地同名地址。

但当前 schema 和实现**尚不能表达**这一目标态，必须作为完整模型扩展落地，不能
只在 UI、CLI 或一台 Gateway 的 sing-box 配置上打补丁。

### 3.1 目标 SSOT 形状

首版保持一个 Local Network 对应一个 Gateway，建议的最小形状为：

```yaml
local_networks:
  - id: office-a
    name: 办公室 A
    gateway_device: office-gw
    access_devices: [laptop-a, server-a]
    prefixes:
      - 192.168.1.0/24
    declaration: office-auto
    tcp_ports: [22, 443, 5432]
    udp_ports: [] # 后续 UDP 交付前必须保持为空
    probe:
      tcp: 192.168.1.1:443
```

字段语义：

- `gateway_device`：终止该地址域的 Device；它必须具有 Forwarding 能力并对目标
  prefix 存在有效路由；
- `access_devices`：获准请求该地址域的 Device；加入码、registry 自报或“拥有普通
  from_request 声明”都不能自动扩大这份集合；
- `prefixes`：允许访问的目标范围，不代表需要写入客户端内核路由表；
- `declaration`：只复用现有 objective、allowed servers、max hops、窗口和阻尼；
  现有 `egress_axis`、隐式零跳和候选枚举不能原样套用；
- Local Network 首版固定 `fail_closed`，禁止 `direct` fallback；否则远端失败会
  错误访问客户端本地的同名地址；
- `tcp_ports` / `udp_ports`：分协议授权，不能合成一份端口清单；UDP 未交付前，
  校验器必须拒绝非空 `udp_ports`，不能接受后静默忽略；
- `probe.tcp`：可选的响应型目标，必须位于 prefix 与 TCP 授权内；它供每个 Access
  Agent 分候选测量，不代表整个 Local Network 全局 Healthy；
- Gateway 对该 prefix 的系统路由是前置条件，不由一个裸 `network_id` 自动产生。

首版不支持多个 Gateway 共同承载一个 Local Network。需要高可用时，应先明确多
Gateway 的终点测量、会话粘滞和故障语义，再扩展该字段，不能让任意转发 Device
临时宣称自己是 Gateway。

### 3.2 候选与 Agent

Local Network 候选仍是完整 ServerChain。这里复用的是既有候选算法与 Agent 机制，
不是当前依赖 `egress_capable` 的枚举函数原样复用。新 route scope 必须增加明确的
terminal Gateway 约束：

- 公网声明：链末必须满足现有公网出口约束；
- Local Network：链末必须是 `gateway_device`；
- 只有请求 Device 本身就是该 Gateway 时，才允许空的物理 transport chain；流量
  仍必须经过本机受控 Gateway data-plane/loopback inbound，执行与远端 Gateway
  相同的签名 network/CIDR/port ACL，不能退化为普通本机 `dial(target)`。若渲染器
  不能生成这条强制路径，首版就必须拒绝该组合；
- 中间跳继续复用 direction、可达性、隧道和最大跳数规则；
- 候选 tag、凭据、Agent 配置和 Measurement 必须包含 Local Network 作用域，避免
  两个重复 CIDR 的配置或样本串线；
- `-network` 只选择这一组候选，不能出现 `-via`、`-relay`、`-exit` 或
  `-path` 让用户改选物理路径。

当前 Agent 只用 HTTP 目标探测。Local Network 若要显示“自动最优”，必须新增
network-scoped TCP 探测，并按 Access Device × candidate 隔离样本。没有合格探针时
只能显示“允许的候选路径”和静态默认，不能显示“已验证最优”。Gateway 的 LAN
可达证据与 Access Agent 的候选质量是两种观测，不能合成一个全局 Healthy 状态。

---

## 4. CLI 目标语义

所有执行命令都必须显式携带 `-network`。不保存“当前网络”，不按 CIDR 猜测，
不在失败后回退本地 LAN。

### 4.1 信息命令

```bash
loom network list
loom network show office-a
```

`list` 只显示当前 Device 获授权的 Local Network。`show` 显示名称、CIDR、Gateway、
已交付协议的授权、签名配置版本和分层运行证据；不提供可手选的中继或 Current Path。

### 4.2 TCP 检查

```bash
loom network check -network office-a 192.168.1.10:22
```

它依次检查：本机最后应用的验签 generation 是否包含该 network 授权、目标是否在
授权 prefix 内、TCP 端口是否获准、当前是否存在合格候选，并按正常 Agent 决策真实
建立一次 TCP 连接。Gateway 的 Applied evidence 若可取得则一起展示；落后于最新
generation 或暂时取不到 evidence 只单独报告 stale/unknown，不能在最后已应用授权
仍合法时让控制面离线凭空阻断数据面。最终仍由 Gateway ACL 决定连接是否被接受。

成功只证明 TCP 建连成功；读取到 SSH banner 也不代表认证或登录成功。输出应区分
授权、自动 transport 和 Gateway→target 结果，不把多个阶段拼成一个含义不明的
“ping 延迟”。`check` 不允许选择 candidate，也不写回或锁定 Current Path。

### 4.3 TCP 字节流

```bash
loom network connect -network office-a 192.168.1.10:443
```

`connect` 建立一条 stdin/stdout TCP 字节流，退出即断开。它是供程序集成、协议
调试及 OpenSSH `ProxyCommand` 使用的基础原语，不安装路由，不开启任意目标代理。

### 4.4 SSH 便捷层

```bash
loom network ssh -network office-a -- user@192.168.1.10
```

它调用系统 OpenSSH，Loom 不自行实现 SSH。但不能仅在 argv 中追加一个
`ProxyCommand` 就宣称 transport 已固定：OpenSSH 还会读取用户配置，其中的
`ProxyJump`、`ProxyCommand`、`HostName`、`CanonicalizeHostname`、`Match exec` 和
`LocalCommand` 都可能改变连接或执行命令。

实现必须使用受控的临时 SSH 配置或一次性 loopback TCP bridge，并只透传经过明确
allowlist 的 OpenSSH 选项；目标、端口和 transport 由 Loom 固定。若选择
`ProxyCommand`，还必须处理它由 shell 执行的事实，严格校验所有替换值并覆盖配置
注入测试，不能用“argv 调用”掩盖这一层。

known_hosts 身份必须包含网络作用域。否则 `office-a/192.168.1.10` 与
`lab-b/192.168.1.10` 使用不同主机密钥时会被误报为中间人攻击。实现可使用稳定的
network-scoped `HostKeyAlias`，但不能关闭主机密钥校验。

### 4.5 后续候选：本地 TCP/UDP 转发

`forward` 不是 TCP 最小闭环的一部分。只有出现数据库、RDP、DNS 等不能使用
`connect`/SSH 的真实调用方后，再按固定目标转发实现：

```bash
# 数据库或其他 TCP 应用
loom network forward -network office-a \
  -tcp 127.0.0.1:15432=192.168.1.20:5432

# 内网 DNS 或其他固定目标 UDP 应用
loom network forward -network office-a \
  -udp 127.0.0.1:5353=192.168.1.53:53
```

`forward` 为不能使用单连接原语的现有应用提供固定目标映射。启动时传入的远端
目标必须落在 SSOT 授权范围内，随后该 listener 不能按请求更换目标。它默认只允许
监听 loopback，进程退出即撤销，不能成为 SOCKS/HTTP 式任意目标开放代理。

TCP 监听可接受多个独立连接，每个新连接使用当时的 Agent 选择；已有连接不迁移。
UDP 必须保留 datagram 边界，并按本地源端点维护独立 association。selector 变化只
影响新 association；路径断开时关闭旧 association，由调用方重建。

---

## 5. 后续 UDP 目标边界

UDP 不进入 TCP 最小实现。模型从一开始区分协议，是为了避免把 TCP/53 的授权误当成
UDP/53，而不是承诺当前或首版已可用。第一项候选应是经过真实查询/响应验证的内网
DNS；其他协议按具体需求与测试逐项增加，不能据“底层支持 UDP”宣称普遍兼容。

目标范围只考虑**客户端主动发起、启动时固定目标的单播 UDP**。

不支持：

- 广播、组播、mDNS、SSDP、DHCP 和 LAN discovery；
- ICMP、raw IP 或系统原生 `ping`；
- 远端主动连接客户端；
- 保留客户端源 IP 或稳定源端口；
- 把 UDP 包伪装成可靠、有序或不会重复的流；
- 用“send 成功”判断 UDP 服务在线。

通用 UDP 不使用 stdin/stdout `connect`，因为流接口会丢失报文边界。诊断必须基于
具体协议的有效响应，例如 DNS transaction ID 与响应内容；超时只能报告 timeout /
indeterminate，不能一律宣称端口关闭。

承载层协议与目标应用协议相互独立。理论上应用 UDP 可以经 Hysteria2 或 Trojan
候选传输，但只有在固定生产 sing-box 版本上完成一跳、两跳、回复关联、超时、
大报文和断路重建测试的候选，才可标记为 UDP-capable。

---

## 6. 重复网段

### 6.1 不同 Gateway：允许

```text
office-a → gw-office → 192.168.1.0/24
lab-b    → gw-lab    → 192.168.1.0/24
```

客户端不安装两个 `192.168.1.0/24` 路由。`network_id` 先把请求放进不同目标域，
各自的候选再终止于不同 Gateway，因此下面两个目标没有歧义：

```text
(office-a, 192.168.1.10)
(lab-b,    192.168.1.10)
```

客户端自己当前也处在 `192.168.1.0/24` 不构成冲突；显式命令仍走获授权的远端
Local Network，失败时不得改连客户端本地同地址设备。

### 6.2 同一 Gateway：首版拒绝重叠

```text
gw01
├─ eth1 → office-a 192.168.1.0/24
└─ eth2 → lab-b    192.168.1.0/24
```

请求到达 `gw01` 后，普通 socket 只剩目标 `192.168.1.10`。如果两个网络共用同一
Linux 主路由表，内核无法仅凭 Loom 的名字决定走 eth1 还是 eth2；仅配置
`bind_interface` 也不能普遍证明 ARP、源地址选择与回程都正确。

因此校验器必须拒绝同一 Gateway 上互相重叠的 prefix，并指明冲突网络。将来只有在
Gateway 明确实现并验证每网络独立 netns、VRF 或策略路由表后，才能放开；这属于
独立高级能力，不进入首版表单。

---

## 7. 授权与服务端强制

客户端侧校验只用于尽早给出错误，不能成为安全边界。最终 Gateway 必须强制校验：

```text
Device 获得的 network-scoped authorization context
+ network_id
+ protocol ∈ {tcp, udp}
+ destination ∈ prefixes
+ destination port ∈ 对应协议端口清单
→ 允许从该 Local Network 的 direct outbound 发出
```

这份上下文必须由签名 SSOT 中的 `access_devices` 授予并贯穿本地入口、selector、
链上认证与终端规则；客户端不能自选或伪造。它最终是独立 credential、credential
中的 scope，还是其他可吊销认证材料，由凭据轮换和渲染规模评估决定；本文不提前
钉死成 Device × Network 的笛卡尔积。服务器规则顺序必须体现以下边界：

```text
允许的下一跳 Device 地址 + 它实际监听的 transport 与 inbound port
→ 显式 Local Network 凭据 + 协议 + CIDR + 端口
→ 普通公网凭据禁止私网和特殊地址
→ 普通公网 egress
→ final block
```

当前 `from_request` 公网路径的目标可能不受域名限制；若某台公网出口本身可达
RFC1918 地址，普通代理凭据可能绕过 Local Network ACL。实现本专题前必须为普通
公网凭据增加解析后私网/特殊地址阻断，并覆盖 DNS rebinding，不能把现有通用代理
偶然能访问 LAN 当成已授权功能。

Gateway 看到并连接的是最终目标，目标看到的源地址通常是 Gateway 的 LAN 地址或
NAT 地址。本文不提供客户端源地址透明、不提供目标到客户端的主动连接，也不允许
Device 从本机配置自行扩大 prefix 或端口。

---

## 8. 配置与证据分层

首个实现不要汇总成一个含义过宽的 Healthy。至少分开显示：

| 状态 | 来源 | 能说明什么 |
|---|---|---|
| Declared | 签名 SSOT | 谁可以访问哪个 network、Gateway、prefix 与 TCP 端口 |
| Applied | 各 Device 实际应用的验签 generation | 该 Device 是否已经拿到这份授权/ACL |
| Candidate health | 各 Access Agent 的分候选测量 | 该 Access 到 Gateway 的哪些自动路径可用 |
| On-demand check | 发起命令的 Access Device | 一个具体目标经当前自动候选是否可连接 |

观测不能扩大 Declared 权限。首个实现也不自动发现或建议 LAN；操作者明确填写并
发布 Local Network，按需检查只收缩或解释状态。以后若增加接口/路由发现，也不能
自动发布容器、VPN、虚拟接口或其他直连网段。

首个实现的检查边界为：

1. 请求 Device 已应用包含该 Local Network 的签名 generation；
2. Gateway 是否已应用对应 ACL 作为独立 evidence 展示，未知或 stale 不冒充 current；
3. 每个 Access Device 的 candidate health 独立记录，不能用 A 的成功证明 B 可用；
4. 按需 TCP 检查只说明本次 Access、候选与目标组合，不升级成全局 Network Healthy；
5. 证据带来源、时间和签名，过期后只标 stale，不改写 SSOT。

内核存在一条能匹配 prefix 的 route 可能只是默认路由，不能单独证明“预期 LAN”或
Verified。需要稳定的接口/路由表绑定时，必须先扩展 SSOT attachment 模型再声称已
验证；手工声明在此之前仍只是 Declared。

---

## 9. 客户端模式与 UI

Direct / Auto / 指定出口继续治理普通 TUN/mixed 公网业务流量。显式执行
`loom network ... -network office-a` 是一次获授权的 Local Network 请求，不是
第四个客户端全局模式，也不受“指定公网出口”覆盖。

最小 UI 只包含：

- **Local Networks** 列表、详情和新增/编辑表单：名称、稳定 ID、Gateway、获授权
  Device、prefix、TCP 端口、策略、Applied generation 与分层运行证据；
- **Devices** 上由 Local Network 引用派生一个 Gateway/可访问网络摘要，不做自动
  LAN 发现；
- **客户端**只列当前 Device 获授权的网络和命令示例，不显示完整拓扑。

Topology 色彩叠加、UDP 控件、自动 LAN 发现与高级 attachment 均延后。若以后增加
Topology 叠加，它仍只能只读展示，不能出现 Apply 或候选选择。

状态文案不得把以下事实混为一体：Gateway 已声明、Device 在线、LAN route 存在、
目标探针成功、当前候选被 Agent 选中。

---

## 10. DNS

首版建议目标参数只接受数值 IP，先把重复 CIDR、授权和转发语义做实。不能先用客户
端系统 DNS 解析内部名称：split DNS、重名域和重复地址会丢失 Local Network 作用域，
还可能把查询泄漏到公网解析器。

确有名称需求时，再增加按 Local Network 声明的解析器与命令，例如：

```bash
loom network resolve -network office-a host.internal
```

解析必须通过该 Local Network 的数值 DNS 地址完成，返回 IP 必须仍落在获授权
prefix 内；DNS 截断后的 TCP/53 fallback 也必须单独获得 TCP 授权。名称解析不能
依赖 Device 全局 DNS，更不能把返回地址写回 SSOT 冒充稳定声明。

---

## 11. 实现顺序

本专题后续实现时按以下依赖顺序推进：

1. 建立 registry 与 SSOT 共用的稳定 Device identity/映射；完整产品术语迁移可独立
   推进，但不能继续产生两个互不相干的身份；
2. 扩展 SSOT、Access Device assignment、terminal Gateway constraint、严格校验、
   快照 schema、认证作用域和纯函数渲染；
3. 先封住普通公网凭据访问私网/特殊地址，以及中继访问下一跳任意端口的绕过路径；
4. 实现单 Gateway Local Network、TCP `check/connect/ssh` 与 network-scoped TCP 探针；
5. 同步 Local Networks 最小 UI、客户端文案和回归测试；
6. 有真实调用方后再实现 TCP `forward`；
7. 在生产钉住版本上验证 UDP 后，再实现固定目标 UDP；
8. 有真实需求后再决定 per-network DNS、多 Gateway HA、Topology 叠加或同机 VRF/netns。

存在 schema 但 renderer、Agent、Gateway ACL 或 UI 任一层未实现时，必须在校验或
渲染阶段明确拒绝，不能静默降级成普通公网代理或本地直连。

---

## 12. TCP 最低验收矩阵

实现不能只验证进程存活，至少覆盖：

1. 同一目标 IP 在两个不同 Gateway 的重复 CIDR 中分别到达正确设备；
2. 同一 Gateway 的重叠 prefix 在保存 SSOT 前被拒绝；
3. 未分配该 network 的 Device、越界 CIDR 和未授权 TCP 端口全部 fail closed；
4. 普通公网凭据无法绕过 Local Network ACL 访问私网或特殊地址；
5. 中继凭据只能访问声明的下一跳 transport/inbound port，不能横向访问其他端口；
6. TCP 在零跳、一跳、两跳候选上的建连、拒绝、超时与新连接切换；零跳仍经过
   本机受控 Gateway ACL，不能由客户端校验后直接拨目标；
7. selector 切换不迁移已有 TCP 会话，只影响新连接；
8. 控制面离线时沿用仍合法且包含授权的最后验签配置；stale 可见但不自动阻断；
9. 客户端本地存在同 CIDR 时，远端失败不会回退到本地同地址；
10. SSH wrapper 覆盖用户配置与 `-F`、`-o ProxyCommand`、`ProxyJump`、`HostName`、
    `CanonicalizeHostname`、`Match exec`、`LocalCommand` 等 transport 注入；
11. UI、CLI、日志和观测明确区分声明、应用、按需检查与每 Access 候选状态；
12. 同一 SSOT 在任何机器上渲染得到相同字节，回滚不依赖运行时探测结果。

---

## 13. 明确延后

以下能力不是本专题首版的一部分：

- 系统原生 `ping`、traceroute、任意 raw IP；
- 本地 TCP/UDP `forward`（有真实调用方后分阶段实现）；
- 自动安装 LAN 路由、透明站点到站点 VPN 或完整 L3 overlay；
- 广播、组播和局域网发现；
- 同一 Gateway 上的重叠 CIDR；
- 多 Gateway 高可用与会话迁移；
- 客户端源 IP 透明与远端主动连接；
- 根据 SSID、地理位置或自报网络自动扩大权限；
- 让用户手选中继、出口或完整 Current Path。

这些需求出现时应另立设计，不能通过放宽现有 ACL、增加隐式 fallback 或给 UI
添加一个路径下拉框来实现。
