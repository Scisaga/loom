# 客户端规范 · 配置制品、安全存储与恢复

[客户端规范入口](../../client-access.md) · [文档地图](../../README.md) · [源码能力](../../implementation.md)

**规范状态：已批准的客户端契约。** 本文负责 配置制品、安全存储与恢复；标为 v1 的内容仅适用于迁移输入，
v2 认证、对象与事务以[控制面规范](../../distributed-control-plane.md)的对应条款定义。
平台运行情况由验收回执确认；本文保留原章节编号，不记录部署进度。

## 10. 配置制品

### 10.1 两层制品

客户端包拆为平台无关期望态与平台安装层：

| 层 | 内容 | 是否跨平台 |
|---|---|---|
| common | 节点绑定、候选、声明、组件约束、签名/generation 元数据 | 是 |
| sing-box | 该设备的 inbounds、outbounds、route、DNS | 大部分可复用，需平台校验 |
| secrets map | 占位符到本机安全存储键的映射 | 语义复用，存储实现不同 |
| lifecycle | systemd / Windows Service / Android App profile | 否 |
| update policy | 最低客户端版本、兼容 schema、强制更新时间 | 语义复用，执行不同 |

同一 snapshot 可以含多个平台包，但每台设备只能下载并安装绑定给自己的包。

### 10.2 渲染目标必须显式

旧的 `desktop` 无法决定路径、服务管理器和安全存储，目标平台枚举拆成不可含糊的部署目标：

```text
linux-server
windows-desktop
android
```

部署目标是输入事实，不是根据运行时猜测。校验器必须拒绝 Android + systemd、
Windows + `/etc/loom`、Linux server + TUN 等矛盾组合。

### 10.3 原子安装

所有平台都遵循同一事务语义：

```text
下载 → 验签/防回退 → secret hydrate → 平台预检
     → 写入新槽 → 启动验证 → 提交为 current
                          └失败→恢复 previous
```

配置文件不得在原路径上逐个覆盖。客户端至少保留 current 与 previous；失败日志
不得包含凭据明文。

---

## 11. 安全存储

| 平台 | 设备身份 | 访问凭据 | 配置状态 |
|---|---|---|---|
| Linux | root 0600 文件；有 TPM 时可增强 | root 0600 secrets 文件 | `/etc/loom` + `/var/lib/loom` |
| Windows Portable | 当前用户 DPAPI | 当前用户 DPAPI | `%LocalAppData%\LoomPortable` |
| Windows Installed（目标态） | CNG/DPAPI，优先机器范围不可导出密钥 | DPAPI machine scope | DPAPI candidate + ProgramData ACL |
| Android | Android Keystore，优先硬件支持 | Keystore 包装的应用私有存储 | app private storage |

日志、崩溃报告和持久 UI 状态都不得包含完整 token、私钥、密码或可直接导入的配置。
access-only 的加入二维码、截图、加入文件和剪贴板文本都携带同一个短时 bearer secret，
必须只交给目标设备，不得保存到相册、诊断导出、聊天记录或工单。诊断导出默认脱敏，
并由用户显式操作。

---

## 12. 配置更新与程序更新

配置更新和客户端程序更新不能混为一条通道。

| 平台 | 配置更新 | 程序更新 |
|---|---|---|
| Linux | Loom 签名 snapshot + pull/apply | Loom release/A-B 机制 |
| Windows | Loom 签名 snapshot | 代码签名安装包，服务级回滚 |
| Android | Loom 签名 profile/ranking | 商店、MDM 或同签名密钥 APK |

配置可以高频收敛；程序升级必须显式推进、验证兼容 schema 并控制爆炸半径。
Android 签名密钥是应用升级身份，必须备份和严格控制；丢失后不能把新 APK 当作
原应用升级。

---

## 13. 状态与观测

客户端 UI 至少区分以下状态：

- 应用/系统服务是否运行；
- TUN 或 mixed 是否已接管流量；
- 当前配置 snapshot 与 generation；
- 目标 v2 的 recovery epoch/statement/policy hash、control epoch/set hash、
  certified head revision/hash/QC、Device generation/leaf/view hash 四组 floor，以及
  bootstrap transition hash 和 protocol latch；
- EndpointSet generation/digest、当前 endpoint/listener generation、preferred/draining 状态和
  本 Device 的轮换 applied/ACK；v1 界面必须明确这些字段不可用，而不是填入默认绿色；
- 当前命中的只读规则、Service、声明和候选路径；
- 当前顶层路由模式；指定出口模式还显示目标节点及其在当前签名配置中的可用状态；
- 数据平面最近是否成功；
- 控制面最近是否成功 pull；
- 当前是否使用 previous/离线配置；
- 凭据是否临近过期或已被吊销。

“VPN 图标存在”不等于数据平面健康，“某个 private `device_config` 服务
入口可达”也不等于有 quorum 或
用户流量可达。
客户端只按证据范围分别报告本机运行面、入口单次结果、已验签服务器分段观测与
实际连接/握手反馈；不为健康结论新增业务 DNS/HTTPS 或完整路径探测，未覆盖范围保持未知。

客户端只上报调度与排障必要的 L4 信息：时间、候选、连接/握手结果、延迟、有限
吞吐和版本状态。默认不上传域名访问历史、URL、请求头、响应内容或应用清单。

---

## 14. 故障与恢复

| 故障 | 行为 |
|---|---|
| QR 中某个 distribution mirror 不可达 | 不携 token 尝试其他已列镜像；不听从重定向或无签名发现 |
| catalog/proof bundle hash 或 QC 无效 | 在任何 capability/token 离机前 fail closed |
| HY2 bootstrap 入口全部失败 | 正式版才尝试已签独立 Trojan/TLS TCP fallback；首版明确报告 UDP 不可用 |
| capability 过期/超次数/超限流 | 停止自动重试并关闭临时隧道，不用 enrollment token 作为替代 transport 密码；已 commit 事务只可导入管理员带外交付的 exact-bound resume descriptor |
| 内层 Enrollment 证书/IP 不匹配 | 不发送 token/CSR/PoP，关闭临时隧道 |
| intent preflight 的 opening 与公开 hiding commitment 不匹配 | 不生成 claim submission、不发 token，关闭临时隧道 |
| resume descriptor 与本机 `claim_core_hash`/身份/事务绑定不同 | 拒绝恢复，不替换 pending identity，不重新消费 token |
| `ControlServiceDirectoryV1` 中 `role=device_config` 的全部已授权私有服务不可达 | 继续 current，显示配置入口离线 |
| 只能访问少数派/无 quorum | 继续 current；可读旧状态但不接受未认证变更 |
| head 已提交但 QC 未齐 | 标记 `committed_not_certified`，继续 LKG；不授权、不发布 mutable current、不驱动外部副作用 |
| 新配置 QC 不足、signer/用途错误 | 拒绝，不触碰 current |
| recovery epoch/statement/policy hash 或 control epoch 无合法 transition proof | 拒绝新信任集合并产生安全事件 |
| control revision、device generation 回退或同坐标异 hash | 拒绝并产生安全事件 |
| 新 listener 失败但旧代仍 advertised | 保持/回退旧入口，报告新代失败，不切换路由模式 |
| EndpointSet 中所有数据 listener 均不可达 | 代理模式 fail closed，不静默 Direct |
| hydrate 缺秘密 | 整包失败，不留下半成品 |
| sing-box 预检失败 | 不切换；保留 previous |
| TUN/本地路由/selector 启动失败 | 回滚 previous；若本地接管破坏系统网络，停止 TUN 并恢复本机路由 |
| 实际连接或握手在运行中失败 | 保留当前已验证配置，按证据范围标记失败/未知并重算授权候选；不因单个业务目标失败回滚配置 |
| 程序版本过旧读不懂 schema | 拒绝配置并提示升级客户端 |
| 设备被吊销 | 停止获取新配置；服务器侧凭据移除后数据面失败 |
| Android 被系统回收 | 按用户授权与系统规则恢复前台 VPN，不伪装成始终在线 |

Installed MSI 卸载停止并移除服务、程序和活动 TUN 路由；受限机器身份与操作用户记录
保留，重装继续使用同一 Device。主动清除身份须在客户端断开后确认“删除本机 Device”。
本机删除不等于控制平面吊销；需要重新加入时使用 control UI 的 Rejoin Device 流程生成替代身份与
二维码，不能手工修补 registry 或静默改绑。

Windows Portable 界面只在数据面已断开时启用“删除”操作，并二次确认后清除本机身份、
签名配置与运行状态；它不会伪装成控制平面吊销。操作者仍须经 control quorum 下线并吊销原 Device。

---
