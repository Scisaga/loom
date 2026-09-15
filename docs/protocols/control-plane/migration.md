# 迁移与旧路径删除

[文档地图](../../README.md) · [架构入口](../../architecture/README.md) · [控制面规范](README.md) · [实现对照](../../development/implementation.md) · [本机部署信息](../../operations/local-deployment.md)

**规范状态：已批准的 v2 目标协议。** 实现、接通、部署、验收须分别核对；本文不证明当前源码或生产已经具备所列能力。

---

## 从当前实现迁移

迁移按下列依赖顺序进行。每个阶段都可单独验收；目标字段不能提前塞入严格 v1 wire schema。
阶段完成必须落实本阶段列出的全部功能与完成条件，不能把 wire、reducer 或测试齐全等同于
daemon 已接入或生产已上线。执行与交接按
[实施规程](../../development/control-plane.md)和 `AGENTS.md` 的完成判定进行。

每个阶段涉及的功能均须从正常 UI/CLI/客户端入口贯穿实际 daemon、持久状态和生效结果，并在
已授权的生产迁移中部署验收。对应旧实现随新版替换删除；最终检查负责全局核对，不是把前面阶段的
接线、部署和清理拖到最后的理由。存量身份与数据通过迁移保留，不得靠重新 bootstrap、手工改
Head/ACL、双写或静默回退绕过新协议。当前未完成事项只记录在 [实现对照](../../development/implementation.md)，不改低目标标准。

### 协议、不变量与 golden

- 固化本文逐边 LinkIntent、三类公网 EndpointSet/两类私有 directory、listener generation、
  PublicAccessProfile、Invite hiding/opening、capability/claim/admission/issuance wire；
- 同步更新架构、Device 生命周期和客户端契约；
- canonical bytes/hash/signature/QC、unknown-field、排序、过期和 anti-rollback golden；
- 加入 repo safety 与“公开 Nginx 无动态 handler”静态检查。

**完成条件：** Go/Android/Windows/Linux 对同一向量产生相同 hash、签名验证和失败结果。

### 单成员私有 ControlSet

- 把现有指定 control 迁移为 N=1、q=1 的 ControlSet；
- control_api、Raft、Enrollment、config/report 只绑定 overlay IP/internal cert；
- admin/control/Device/Enrollment EKU 与 listener 分离；
- 将本阶段对应的现网调用迁入私有通道；新版接管后删除被替换的 v1 transport 与调用路径。
  切换期间尚存的旧依赖属于未完成项，不能作为最终兼容功能交付。

**完成条件：** 公网扫描无法访问 control 服务；overlay admin 可提交并取得 QC。
这些边界必须由正式 daemon 的实际服务实现，不能用未挂载路由、空处理器或测试专用 listener 代替。

### Reader、静态 distribution 与 bootstrap tunnel

- 先升级本次迁移实际在用的 server 和客户端 reader，识别拆分后的 endpoint sets；其他平台继续完成其实现要求，不成为现网替换的虚假门禁；
- 每个 active forward server 建立 FQDN/PublicAccessProfile/Nginx static distribution；
- 实现 HY2 capability validator、双层 tunnel ACL 和 private Enrollment TLS；
- Android/Windows/Linux 实现紧凑 QR/文件、catalog 验签、真实 HY2 probe、Keystore/PoP；
- 正式发布前补独立 Trojan/TLS TCP fallback。

**完成条件：** Nginx 收不到 token；UDP 可用时走 HY2，UDP 全阻断时走 TCP fallback；临时 tunnel
不能访问除 Enrollment tuple 外的任何地址。

### 多 voter 与动态成员

- learner catch-up、joint consensus、FinalControlSet、private peer directory；
- 从 N=1 在线扩到 N=3/5 或其他 1..N 集合，再安全缩容；
- control 候选必须先是 enrolled Device；
- 验证分区、leader 切换、key possession 和 directory hiding。

**完成条件：** 单副本不能越过 quorum 改安全关键状态，数据面在 control 故障时保持 LKG。

### 分布式 Enrollment、Device API 与发布

- Invite commit/QC、BootstrapIssuer authorization registry/root、token CAS、stable claim core、
  admission QC、provisional issuance、approval/completion 与 exact-bound resume；
- private device_config/report 与 per-Device proof；
- immutable publisher/镜像接管、CRDT anti-entropy、certified current lineage；
- secret artifact wrapping 与审批收敛。

**完成条件：** 任一健康 control 可接续同一 claim/request；不同 key 重放失败；镜像失陷不能伪造
Device view 或配置 authority。
正常创建邀请必须进入同一 certified 状态机；客户端完成私有入网、取得可用配置并提交已接受的
签名报告。证据必须贯穿真实入口和 daemon，不能仅分别调用组件后拼接成“端到端通过”。

### 域名、DNS-01、证书与三类公网部署

- 按[托管 DNS 规范](public-access.md#托管域名的受理与执行)完成七字符名称、存量迁移/预留、
  非 control executor、凭据封装与生命周期任务；provider 条件写/删及并行 TXT 不得由本地 generation 替代；
- direct_standard、direct_alternate，以及 nat_mapped intent/readback reconcile；
- 节点本地 CSR/private key、ACME DNS-01、SPKI overlap；
- Nginx fake/static distribution 配置模板和外部 reachability verification。

**完成条件：** 每个 active forward server 有已验证 FQDN/profile；不能用 443 或位于 NAT 后的
server 通过签名 public port/mapping 正确发布，同时 control 服务保持私有。

### HY2/Trojan 重叠轮换与 WG 独立轮换

- listener port pool、frozen rotation intent、prepare/verify/advertise/prefer/drain/retire guard；
- NAT 预映射范围与资源冲突校验；
- 客户端同 logical endpoint generation overlap；
- WG 双 interface/peer 状态机单独实现和验收。

**完成条件：** 新连接迁移到新 listener，旧会话在 deadline 内保持；HY2/WG UDP tuple 不冲突；
重启 reconciler 不会重复分配或提前删除。

### 收口与废弃旧路径

- 删除公开 enroll/control/config/report seed、handler、Nginx route 和 UI 文案；
- v2 latch 后拒绝 v1 authority、旧 QR、旧 public role 和 v1 的 1 小时自动恢复窗口；
- 完成 server 与当前实际部署的 Linux/Android 全矩阵、升级/回滚/撤权/灾难恢复；
- 发布运维手册、source/licence、签名制品与实测记录。

**完成条件：** 仓库、部署和网络扫描均无旧公开控制路径；当前部署平台使用同一目标 wire 与失败语义。

---
