# 身份、秘密与加入网络

[文档地图](../../README.md) · [架构入口](../../design.md) · [控制面规范](../../distributed-control-plane.md) · [实现对照](../../implementation.md) · [本机部署信息](../../operations/local-deployment.md)

**职责：控制面架构映射。** 本文解释全系统关系和标明的 v1 契约；v2 对象、认证、状态机与验收规则统一定义在控制面专题，本文不另设 wire schema。

---

## 13. 密钥与信任

> **迁移边界:** v1 使用单在线平台签名 key 和指定控制节点；以下多签、admin/control
> 证书分域与 recovery root 是目标态。是否仍运行 v1 只见[实现对照](../../implementation.md)。
> [§13.2](#132-ssh-证书-ca-替代-authorized_keys) 的 SSH User/Host CA 是运维目标设计，不是
> Device Enrollment 机制。完整迁移见
> [分布式控制平面 §6、§19](../control-plane/identity.md#6-信任域与密钥)。

### 13.1 私钥不集中生成

| 密钥类型 | 在哪生成 | 控制平面持有 |
|---|---|---|
| **节点 WG 私钥** | **节点本地** | 仅公钥 |
| **节点 SSH 主机密钥** | 节点本地 | 仅公钥 |
| **SSH 用户证书** | CA 签发流程 | 受约束 CA 私钥；不等于 admin cert |
| **Device 身份私钥** | **Device 本地** | 仅证书/SPKI 与 certified membership |
| **control peer mTLS cert/key** | **每个 control Device 各自生成** | 只持本 peer 私钥；只用于 Raft/anti-entropy transport identity |
| **control membership/config/enrollment keys** | **每个 control Device 按用途分别生成三把** | 只持本成员对应私钥；三者互不复用，也不与 peer/Device/admin/CA/TLS/code-signing/recovery key 复用 |
| **BootstrapIssuer key** | 受约束 control executor 本地生成；按 epoch 轮换 | 只签 Invite/QC 派生且不越过 policy 上限的短期 tunnel capability；公开验证 key 经 ControlSet 认证 |
| **admin 私钥** | 管理员终端/硬件；新签发为 P-256，TLS 与操作签名共用 | 仅验证完整签发链与 certified ACL；换证见 [v2 §6.1 管理员轮换](../control-plane/identity.md#61-初始-adminca-与轮换) |
| **internal service TLS key** | 每个 control Device 本地 | 只持本机 key；证书限定 control_api/Enrollment/Raft/config/report 的独立 EKU/profile 与 overlay IP SAN |
| **公开 TLS/ACME 私钥** | TLS 终止 Device 本地 | 证书、SPKI 摘要和状态，不持有节点私钥 |
| **客户端数据面凭据** | approval commit 前生成并 sealed 给既定接收者 | 只提交 ciphertext hash/secret ref；接替 executor 只能重放同一制品 |
| **混淆参数** | 提案方生成、随 certified proposal 固化 | 是公开参数，不是私钥 |
| **recovery root** | 离线介质/可选多人门槛 | 日常 control Device 不持有 |

> **核心安全属性（`q > 1` 时）：单个 control Device 沦陷既拿不到节点私钥，也不能
> 独自篡改 certified 拓扑。** `N=1, q=1` 的迁移态不具备这项性质。CFT 多数不是 Byzantine
> 容错；一旦攻击者控制达到 quorum，仍能批准恶意新配置，
> 因此密钥分域、最小 admin scope、离线恢复与审计不能省略。

Agent 首次接入时在本地生成 WG 密钥对,只上报公钥。**私钥永不离开节点。**

### 13.2 SSH 证书 CA 替代 authorized_keys

手工步骤(每台主机**一次性**):放 CA 公钥 → `sshd_config` 设 `TrustedUserCAKeys` → 重载 sshd。

此后:签发**短期用户证书**(如 TTL 1 小时);主机只信任 CA 签名;**密钥轮换、新增运维、临时授权 = 签一张新证书,零接触主机**;证书自带过期;用 `principals` 做细粒度授权。

反向也建议用 **Host CA** 签发主机证书,免去 `known_hosts` 分发和 TOFU 风险。

### 13.3 CA 与恢复私钥是最高价值目标

CA root 泄露会允许伪造其证书域，recovery root 泄露会允许在灾难恢复时重建
`ControlSet`。两者必须分开，离线保管；在线只使用按 EKU/profile 受约束的中间 CA，
所有签发与恢复写入不可变审计。公开 WebPKI、Device、control peer、admin 与配置投票
签名不能共用证书或私钥。普通证书本身也不授予权限，接收方还要核对 certified
registry/ACL/ControlSet。

当前 CA、ACME 与 control 服务密钥使用本地软件保护和受限加密封装，不强制 KMS/HSM。
密钥版本、用途隔离、PoP、备份恢复、授权接管与 fencing 仍按
[分布式控制平面 §6.2](../control-plane/secret-artifacts.md#62-权威-secret-artifact) 执行。
KMS/HSM 仅列入[后续强化计划](../../kms-hsm-hardening-plan.md)，不构成当前上线依赖。

---

### 13.4 凭据轮换:必须分两步

`cred/*` 是**跨节点共享**的:同一份密码,接入节点用它连、每台服务器用它认。
所以一台服务器下线之后,它硬盘上还留着全网在用的凭据 —— [§14.4](lifecycle.md#144-节点生命周期四个状态加和删要对称) 因此要求
"移除节点之后必须轮换它持有过的凭据"。

**不能轮换,"删除节点"就是不安全的。**

#### 为什么不能一步切

分发是**最终一致**的:节点各自每 45 秒取配置,并带最多 15 秒随机抖动。
客户端和服务器不可能在同一刻切换 —— 中间那段时间里,一边发新密码、另一边
只认旧的,连接全断。

所以必须有一段**两代都收**的过渡窗口:

```
第一步   generation +1,accept_previous: true
         服务器两代都收;客户端换成新的
         ↓ 等全网都取到这一版(loom status 看快照一致)
第二步   accept_previous: false
         旧的失效
         ↓ 发布并等全网取到
第三步   loom secrets retire —— 把旧值从秘密层删掉
```

#### 命名:第一代不带后缀

| 代次 | 秘密层引用 | 服务器上的用户名 |
|---|---|---|
| 1(或未声明) | `cred/x` | `<id>` |
| 2 | `cred/x@2` | `<id>`,外加过渡期的 `<id>@1` |
| 3 | `cred/x@3` | `<id>`,外加过渡期的 `<id>@2` |

第一代不带后缀,是为了让 **v1 迁移基线的秘密层不必因为引入这个字段而全网重发**。

上一代的用户名**不能和当前代同名**:同名两条 user 的行为取决于 sing-box 的
实现细节,而且路由规则按名字匹配 —— 分不开就没法确认过渡窗口真的生效了。

#### 路由规则要匹配两个名字

过渡期的规则是 `auth_user: ["<id>", "<id>@1"]`。**只匹配当前代的话**,用旧
凭据连上来的流量**认证过了却没有规则接**,落到 `final: block`。那种失败比
认证失败难查得多:客户端看到的是"连上了然后没反应"。

#### 顺序不能反,而且工具会挡

| 做错的顺序 | 后果 | 挡在哪 |
|---|---|---|
| 先改 SSOT 再生成新值 | 秘密层缺引用,hydrate 整体失败,全网卡在一个装不上的快照上 | `loom secrets split` 报"总表里缺这些引用" |
| 窗口还开着就退役旧值 | 服务器仍引用它,同样装不上 | `loom secrets retire` 拒绝并说明 |
| `accept_previous` 配在第一代上 | 没有上一代可接受 | 校验器 |
| 已吊销却还开着窗口 | 吊销掉的那一代继续放行,吊销白做 | 校验器 |

#### 忘了第二步,是这套流程最可能出的错

过渡窗口一直开着,旧凭据就永远有效 —— 而轮换的全部意义就是让旧的失效。
校验器挡不住"忘了",因为那要看时间。

所以上报者从**本机 sing-box 配置**里认出过渡窗口(存在 `<id>@<代次>` 形式的
user),报成一条状态,进事件历史。于是"开了三天还没关"是一条持续中的记录,
而不是没人知道的事。


### 13.5 客户端加入网络复用 certified SSOT 与发布链

加入网络是 certified 状态变更：管理员经私有控制服务创建 Invite；未入网客户端从公开
静态 distribution 验证 catalog/proof，经受限 bootstrap tunnel 到达私有 Enrollment，
内层 TLS 承载 claim。事务完成后才激活 Device 身份与 view，客户端安装 permanent connectivity
并销毁 bootstrap 状态。`ready` 表示认证材料可取，不等于设备已安装、健康或在线。

对象、预算、精确绑定与重试语义只有以下规范正文：

- [§11.1–§11.2：端到端流程、Invite 与二维码](../control-plane/enrollment-invite.md)；
- [§11.3：Bootstrap capability、transport 认证和入口 ACL](../control-plane/bootstrap-capability.md)；
- [§11.4：内层 TLS、PoP、reservation → issuance → approval → completion](../control-plane/enrollment-transaction.md)；
- [§11.5：正式 Device 配置与报告](../control-plane/device-services.md)。

v1 严格 schema 不接受 v2 字段。版本替换须按[§19 迁移完成条件](../control-plane/migration.md)
保留原身份与数据、接通正常流程并删除旧公开 claim 等被替换入口；兼容验证不授权永久保留旧业务路径。
