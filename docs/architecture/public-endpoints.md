# 域名、公开证书与入口轮换

[文档地图](../README.md) · [架构入口](README.md) · [控制面规范](../protocols/control-plane/README.md) · [实现对照](../development/implementation.md) · [本机部署信息](../operations/local-deployment.md)

**职责：控制面架构映射。** 本文解释全系统关系和标明的 v1 契约；v2 对象、认证、状态机与验收规则统一定义在控制面专题，本文不另设 wire schema。

---

## 拉取通道的保护

- v1 基线是服务器节点上的公开 HTTPS 静态只读目录，不提供管理 API，也不要求
  拉取端 mTLS；不能把目标设计写成 v1 安全边界；
- **目标 v2 的配置包与 current 都由当前 ControlSet 的提交后 QC 认证**。manifest 保证内容，
  Device Merkle proof 证明本机 view 属于 certified head，提交后 QC 证明授权，跨
  recovery epoch/statement/policy、control epoch/set、revision/head、Device generation/leaf/view
  floor 与 v2 latch 防回退；当前 v1 的单平台
  签名和 `/var/lib/loom/release-floor.json` 在兼容期保留；
- 严格 v1 reader 不能忽略或接收原位增加的 envelope 字段；迁移必须并行发布独立 v1/v2
  资源。旧 reader 只读原 v1 bytes，新 reader 在 latch 前验证受限 v1 和完整
  BootstrapTransition，首次接受 v2 后永久拒绝 v1 authority。v2 新装/丢 floor 必须从 QR、
  已知 ControlSet checkpoint 或 recovery 流程获得新鲜度锚点；
- 目标 v2 的 `device_config` 必须只在 permanent overlay 监听，使用独立 Device 身份认证
  （首版为 profile-scoped mTLS）并只返回本机最小 view；公网 Nginx 的 `distribution` 只承载
  fake website、公开 head/QC/transition、bootstrap catalog 和通用 immutable 制品。mTLS 是隐私与
  下载范围控制，不替代签名 envelope、Merkle proof 或 floor 的反重放。

最后一条关键:**它让"传输通道"与"配置真实性"解耦** —— 即使中继被攻破也无法注入恶意配置。

## 托管域名与证书

DNS/公开 TLS 只提供发现和传输身份，不授予 control membership 或私有服务权限。
具有 `forward` 职责的 Device 按 certified profile 配置公网入口；管理、Enrollment、配置、报告
与 peer RPC 使用 overlay 私有服务目录。

完整的 PublicAccessProfile、节点本地 TLS key、DNS-01、secret 引用、NAT/直接公网部署规则见
[公网 profile 与证书](../protocols/control-plane/public-access.md)，端点用途和身份见[端点用途](../protocols/control-plane/endpoints.md)。

## 公网 listener 与端口无中断轮换

稳定逻辑 endpoint 与多代 listener 分离；端口代次变化不等于出口变化。轮换以
allocate → prepare → advertise → prefer → drain → retire 为序，新旧监听重叠，
旧连接不承诺跨端口迁移。准备失败保留旧 listener，撤权可能中断且必须明确显示。

完整 generation schema、冻结依赖、NAT 映射和外部验证规则见
[端点集合](../protocols/control-plane/endpoints.md)与[监听器轮换](../protocols/control-plane/listener-rotation.md)。
WireGuard 只有完成独立双 peer/interface 状态机才能宣称无中断，不能套用 HY2/Trojan 的实现。
Windows/Android 的测量预算统一见[客户端消费边界](../clients/observations.md#客户端消费边界)；
Linux/server Agent 复用其既有预算，轮换本身不增加探测循环。
