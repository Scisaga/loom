# 客户端规范 · 交付依赖、测试与未决项

[客户端规范入口](../../client-access.md) · [文档地图](../../README.md) · [源码能力](../../implementation.md)

**规范状态：已批准的客户端契约。** 本文负责 交付依赖、测试与未决项；标为 v1 的内容仅适用于迁移输入，
v2 认证、对象与事务以[控制面规范](../../distributed-control-plane.md)的对应条款定义。
平台运行情况由验收回执确认；本文保留原章节编号，不记录部署进度。

## 15. 依赖顺序

本节定义先后依赖，不维护完成勾选；源码接线见[实现对照](../../implementation.md)，
部署与真机结果按[验收记录](../../operations/local-deployment.md)核对。

### 阶段 C0：拆分渲染目标

- 引入明确部署目标；
- 把 common/sing-box 与 lifecycle 产物分开；
- Android/Windows 包中禁止出现 systemd 和 Linux 路径；
- 为每个平台建立 golden 与矛盾配置校验。

**完成判据：** `phone` bundle 不再含 systemd、Linux Agent 和 `/etc/loom` 安装
假设；未知部署目标硬失败，并由三平台参考矩阵与矛盾配置测试锁定。

### 阶段 C1：固化 Linux 接入

- Linux Server 的加入、pull、一个 `1080` 日常 mixed、Agent、report、回滚形成安装流程；
- 将旧端口入口迁到命名明确的 Linux 兼容/高级覆盖，并验证不会扩权；
- 生成统一二进制分发包，并提供可重复安装和卸载路径；
- 不建设 Linux GUI 或托盘客户端。

**完成判据：** 新 Linux 设备从导入一次性加入码到首份可信在线状态无需手工复制秘密。

### 阶段 C2：设备加入与吊销

- 一次性加入码与二维码；
- 设备本地密钥生成；
- 设备绑定配置；
- 控制面和数据面双重吊销；
- 审计与过期处理。

**完成判据：** 被吊销设备即使保留旧配置，也在服务器收敛后无法继续使用。

### 阶段 C3：Windows v1

- 从 `cmd/loom` 拆出纯 Go `clientcore` 和独立 Windows 程序入口；
- Windows Service、路径和安全存储；
- 一个 mixed 首通，再完成 TUN；两种接入面渲染同一份已验签 v1 snapshot 规则；
- 客户端只读展示 matcher、Service、声明与路径，只提供 Direct / Auto / 指定出口；
- Portable 原生 GUI 直接读取用户态状态；Installed 托盘通过受限本机 IPC 读取 Service 状态；
- 签名安装器与 previous 恢复；
- Linux 交叉编译进入 CI，Windows VM/实体机完成安装、权限、驱动和签名验证。

**完成判据：** 睡眠、网络切换、服务重启和配置失败后都能恢复，卸载不残留活动
路由或服务。

### 阶段 C4：Android v1

- Kotlin/Compose `VpnService` 宿主与钉住版本的 sing-box libbox 集成；
- 二维码加入、Keystore、签名 pull；
- 共享分段决策、实际 selector 读回、离线可信证据和逐连线路径展示；
- 按已验签 v1 snapshot 的 package/domain/IP matcher 渲染规则，并提供 Direct / Auto / 指定出口；
- Emulator 覆盖 UI、权限和基本 TUN，真机覆盖前后台、网络切换与省电策略；
- 签名 APK 发布和升级演练。

选路按[客户端消费规范](../../client-observation-reuse.md#客户端消费边界)验证。
开发签名 APK、纯函数调度测试和 Emulator
均不能替代生产受管配置、网络故障切换、前后台、Wi-Fi、厂商省电限制、固定升级
签名及覆盖升级的分别验收。蜂窝与 Wi-Fi/蜂窝切换保留为协议能力，但在独立
[GitHub Issue #16](https://github.com/Scisaga/loom/issues/16) 使用具备 telephony 的真机验收，
不阻塞当前 Wi-Fi 真机主矩阵。

**完成判据：** 飞行模式、进程回收、重启、配置损坏和全部已授权
private `device_config` 服务入口离线下均有可解释
状态，且不会泄露凭据或把系统网络留在不可用状态。

### 阶段 C5：分布式控制协议迁移（目标态）

- 并行发布 schema 2 QR/current/view，不修改 v1 strict JSON 字节契约；
- 三平台保存 bootstrap/recovery/ControlSet checkpoint/transition、提交后 QC、Device proof、
  recovery（epoch/statement/policy hash）、control（epoch/set hash）、head（revision/hash）、
  Device view（generation/leaf/view hash）四组 durable floor，以及 bootstrap transition hash 和不可逆 v2 latch；
- 实现紧凑 QR，精确携带 catalog/proof hash、2～3 个公网 Nginx mirror、
  有界 `PrivateEnrollmentServiceRefV1` 和 capability；无 token 下载并验证 immutable catalog/public proof，
  public proof 只含 hiding commitment；
- 三平台对 `BootstrapIngressEndpointSetV1` 做一次实际 transport 测量，先实现 HY2，
  正式版增加独立 Trojan/TLS TCP fallback；
- 实现短期限路由 capability 隧道、私有 Enrollment 内层 TLS、token-free intent
  preflight、稳定 claim core、identity-key detached PoP、Raft CAS、带外 resume descriptor 和完成后临时状态清理；
- `DistributionEndpointSetV1` / `BootstrapIngressEndpointSetV1` / `DataIngressEndpointSetV2` 是公网用途；
  `ControlServiceDirectoryV1` 的 `enroll/control_api/device_config/device_report` 条目为
  overlay-only typed services，与公网 set 彼此不可推导；
- 正式身份就绪后建立持久 WG control/L3 overlay，WG 不是首版 bootstrap；
- 同一 Hysteria2/Trojan logical data endpoint 支持新旧 listener overlap、prefer、drain 与 retire；
  WireGuard 未完成专用双 interface/peer profile 时只能显式 disruptive maintenance；
- 先完成 reader 覆盖，再从单成员 ControlSet 扩容并最终撤销 v1 signer。

完整依赖与验收见
[分布式控制平面 §19～§20](../../distributed-control-plane.md#19-从当前实现迁移)。

---

## 16. 测试矩阵

每个平台至少覆盖：

1. 首次加入、同一公钥幂等重试、其他公钥重复消费、过期加入码、未知平台，以及客户端
   拒绝安装部署目标不匹配的 bundle；
2. v1 latch 前迁移兼容，以及 v2 正确/不足/重复/未知 signer 提交后 QC、
   `committed_not_certified` 门禁、Device Merkle proof 篡改、recovery epoch/statement/policy hash、
   control epoch/set hash、revision/head hash 和 Device generation/leaf/view hash 回退、同坐标分叉与未知 schema；
3. secret 缺失、凭据轮换与设备吊销；
4. current → candidate → previous 的原子安装与进程中断恢复；
5. 控制面离线但数据面继续工作；
6. TUN/mixed 的 DNS、IPv4、IPv6、局域网与回环行为；同一业务 FQDN 在不同最终出口返回
   不同 A/AAAA 时，Android/Windows TUN 与 Linux `socks5h` 必须命中各自出口解析结果，
   Direct 仍本地解析；EndpointSet transport hostname 走独立 underlay resolver/cache 且不形成
   VPN 回环。具名远端局域网另按 [Local Network 专题](../../local-network.md)的显式作用域与
   fail-closed 边界测试；
7. 睡眠、重启、网络切换、无网启动和系统时间异常；
8. 客户端旧版本配新配置、客户端新版本配旧配置；
9. 日志、诊断包、UI 和崩溃报告不含秘密；
10. 人工验收可以由操作者显式发起真实业务流量，但结果不进入客户端健康/排名、不成为激活门槛，
    也不转化为周期性 DNS/HTTPS 或完整路径探测。
11. Windows 的 TUN 与 mixed 对相同请求应用相同顶层模式；Auto 模式命中相同
    Service/声明，Android matcher 与中控预览一致；除三态偏好外，本地新增规则或
    扩大出口集合必须被拒绝。
12. 多端口声明覆盖只在 Linux 兼容/高级模式出现，默认回环监听，且不能扩大目标
    授权或绕过 fail-closed。
13. Direct / Auto / 指定出口切换只复用现有入口；指定出口固定最后一跳但前置路径
    仍自动择优；控制面离线时可基于最后一份已验证配置切换，已撤权或非
    `egress_capable` 的固定出口必须 fail closed。
14. Current Paths 在所有模式下均为只读；任何路径选择或 Apply 控件都视为回归。
15. N=1/2/3/5 的动态 quorum、joint ControlSet 迁移、少数分区拒绝写、全部控制入口离线
    继续 LKG，以及 recovery transition 必须连续绑定 statement/policy hash 而不重置其他 floor。
16. QR 只携 token/commitment、trust checkpoint、catalog/proof hash、2～3 个镜像、有界
    `PrivateEnrollmentServiceRefV1` 和 capability；镜像请求无 token，Nginx 不能观察或转发 claim。
    public proof 只含 hiding commitment，镜像故障、两个内容 hash/QC 错误、重定向、假 endpoint 和回退均 fail closed。
17. 客户端从当前网络对每个实际 bootstrap transport 各测至多一次，不以 Nginx
    RTT 代替；HY2 成功、UDP 全阻断后 Trojan/TLS TCP fallback、全失败均有明确结果。
18. bootstrap capability 过期、限流、限次数、并发重放和 ACL 越界均被拒；隧道只可达
    私有 Enrollment IP/port。公网入口无法看到内层 token/CSR/PoP，内层证书/IP 不匹配或
    token-free preflight opening 不匹配 hiding commitment 时不发 token。
19. 同 token + stable `EnrollmentClaimCoreV2` 跨入口重试幂等；每个新 server nonce 可以
    产生新 detached PoP，但 core/hash 不得变化，Raft CAS 只消费一次，换 key/core 重放失败。
    已 commit claim 的 `EnrollmentResumeDescriptorV1` 必须不含 token、绑定原 exact core/transaction，
    由私有 control API 确认后带外交付，不得自动刷新；只返回既有结果且不重消费 token。
    ready 后必须原子安装正式 cert/view/creds 并清除临时隧道所有材料。
20. 数据入口轮换期间新旧端口重叠，新连接优先新代且可回退、旧连接排空；端口变化不
    改变出口/三态。Android 轮换沿用[客户端消费预算](../../client-observation-reuse.md#客户端消费边界)，
    检查新增 listener 只接受被动证据、同代不增加主动测量。
21. 首次 v2 接受原子保存 bootstrap hash、四组 floors（含 recovery policy hash）和 latch；
    冲突 bootstrap、latch 后 v1 current/
    invite/recovery replay、删除非关键 cache 后诱导降级均失败关闭；身份状态丢失必须重新入网。

---

## 17. 尚需决定的问题

以下是协议刻意不替部署者决定的实现/运维选择；启用相应能力前必须把选择、责任人和
轮换/恢复步骤写进私有部署记录：

1. Windows 安装器与代码签名证书的持有、轮换和 CI 签名方式；
2. Android 首版已选固定包名和升级密钥连续的私有签名 APK；若以后迁移到应用商店或企业
   MDM，如何保持同一 package/signing lineage、回滚与离线安装能力；
3. **已定方向：** v2 私有 control/config/report 通道使用分用途 mTLS，配置授权仍由 QC；
   当前采用本地软件中间 CA，仍需落实持久存储、授权接管和存量迁移；
   KMS/HSM 仅见[后续强化计划](../../kms-hsm-hardening-plan.md)，不是私有通道的部署前提；
4. 客户端规模是否仍是少量自建固定设备；若面向多用户，设备库存和授权关系不能
   继续全部塞进拓扑 SSOT，需要独立的设备/租户模型。
5. 三态本地偏好在系统升级、用户切换与配置回滚时的存储位置和恢复细节；它不是
   SSOT，也不复用 `default_declaration` 运维 API。
6. DNS provider adapter 的首个实现、委派 zone 和最小权限 credential；provider 选择不
   改变协议。
7. EndpointSet 的最大离线兼容窗口、旧会话 quiet period 与 emergency retire 审批门槛。

v1 已明确只提供 Direct / Auto / 指定出口这一项三态路由偏好，不提供 matcher、
Service、声明定义、fallback 或同域名多账号 profile 的本地编辑。若后续要引入这些
能力，必须新增模型、安全边界和决策记录，不能借用旧端口覆盖隐式实现。

在这些问题确定前，不启用会强迫所有平台 fork 客户端的自定义协议参数。
