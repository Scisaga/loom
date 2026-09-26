# 代码提取白名单与生产保护

[设计入口](README.md) · [唯一现行契约](core/current-contract.md) · [实施状态](progress.md)

本清单只约束从 `archive/v2-overgrown-20260917` 等旧代码中提取产品资产和窄组件。
归档只作为取证与窄组件来源，不定义当前 schema、权威状态、运行入口或生产切换办法。旧代码默认不移植；
不得整提交、整目录复制，也不得把一个必要 adapter 连同旧状态机和依赖一起搬入。

## 保留的产品资产

Web、Android 和 Windows 已有的页面、样式、图标、品牌资源及有效交互尽量保留，
包括设备与拓扑、路径、服务、发布和 profile 管理的正常入口。双环拓扑的布局和只读当前路径叠加、
浏览器 TLS 与管理员证书边界、签名制品下载体验也属于保留范围。
这些资产只消费[控制面 Web 投影](clients/web-ui-projection.md)、[Enrollment 模型](core/enrollment-endpoint-model.md)
和[客户端模型](clients/client-runtime-model.md)定义的当前状态；页面、旧 DTO 或旧 manager 不因此取得权威。

## 可提取的窄组件

| 能力 | 允许提取的部分 | 当前输入与限制 |
|---|---|---|
| 规范编码、typed hash、签名与 Merkle | 必需的纯函数 | 仅服务当前 `Material`、`ControlConfig`、`DeviceView` 等规范字节与证明；不连带旧格式 decoder 或 proof 分支。 |
| 私有 TLS 与设备认证 | TLS/SPKI、设备挑战及 listener adapter | 受限引导和私有设备入口来自认证 `EndpointGeneration`；不自行维护 endpoint 生命周期或从公网提供设备配置。 |
| HY2/Trojan 数据面 listener 与 relay | 已能真实 bind/accept/dial 的传输代码 | `forward`/`internet_egress` 业务入口、users/ACL 与下一跳由当前认证 `DeviceView`/运行时投影；transport 不决定授权。 |
| 节点间加密承载 | WG、hy2 或私有 TLS tunnel 的实际连接 adapter | 共享资源来自认证 `NetworkIntent.transport_resources` 中的 `TransportResource`；普通 access 首跳按授权投影，显式 `NetworkLink` 只定义中继邻接；新增节点不自动创建 WG。不得为差量同步、报告和业务各建一份链路权威。 |
| sealed artifact 与 capability 限额 | 不可重算秘密的原子保存、持久消费计数 | 只执行当前 Artifact 或 BootstrapCapability 的既定语义，不形成第二套授权或状态机。 |
| 公网静态站点与制品发布 | fake website、不可变 Nginx renderer、按精确对象写入及回读 | 公开范围只由认证投影决定；不公开设备 view、配置或 secret，也不由 publisher 自选 latest。 |
| 纯渲染与运行安装 | 确定性配置、preflight、apply/readback、精确回滚 | 输入来自当前认证 `Projection`/`DeviceView`；删除旧配置兼容分支和重复 runtime store。 |
| 客户端安全存储 | 平台密钥、证书、floor、latch 与完整 LKG 的原子保存 | 只保存当前认证对象；不恢复旧网络 fallback、旧 scheduler 或重复 LKG。 |
| 本机 `.env` loader | 严格白名单解码与必要部署引用 | 服从[配置模型](operations/configuration-model.md)；不带回无消费者变量、命令字符串、运行状态或重复默认目录。 |

每项提取都须指出它满足的当前需求和模型映射，只取最小代码与必要测试；正式入口接通、持久化与运行回读
后，在同一工作项删除被替代路径。旧 fixture 或源码存在不能证明当前业务已完成。

## 必须保护的现网状态

现网身份、密钥与证书、业务数据、已认证原始字节、不可回退 floor、v2 latch、设备完整 LKG 及实际部署坐标
必须保全。源码和文档的整理不授权清空、降低、改写或静默重解释这些值。

保护原始状态不等于允许当前 daemon 解码或接受旧格式 Material、旧设备协议或旧投影分支。
若现网状态不能按[唯一现行契约](core/current-contract.md)验证，当前加载与新写入失败关闭；
生产切换保持受阻，所需的身份、信任与 floor 处理以及验证和回读方案另由用户明确决定。
本白名单不定义 importer、历史重放或自动生成替代 genesis。

## 不在白名单

旧 SSOT、registry、重复 Head/QC/store、独立 Enrollment sequencer、receipt/gate/phase、
旧 Material decoder/reducer、`runtime_contract` 多值分支、旧设备协议 fallback、无正式入口的生产实现，
以及未接线的 DNS/ACME/provider executor 均不得因抽取组件而恢复。
