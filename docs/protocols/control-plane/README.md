# v2 控制面规范

[文档入口](../../README.md) · [架构总览](../../architecture/README.md) · [实现对照](../../development/implementation.md)

**状态：已批准的目标协议。** 本目录定义 v2 对象、认证、状态机及验收要求；
标明的 v1 内容只作为存量迁移输入，不向严格 v1 schema 填入新字段。
源码接线、实际部署与实机结果分别核对，不能从规范推断已交付。

## 协议边界

- 一个逻辑 SSOT，由动态 ControlSet 认证。CRDT 复制材料，Raft durable commit、
  apply/recompute 和提交后 QC 共同产生 effective head；成员模型只承诺崩溃及分区安全。
- 管理、Enrollment、Device 配置/报告及 peer RPC 使用 overlay 私有服务；公网 Nginx
  仅承载 fake website 与不可变静态分发。bootstrap 外层 capability 与内层 TLS 各有职责。
- 签名与 proof 决定 authority，DNS、WebPKI、镜像及 executor 只提供可达性或执行副作用。
  丢失 quorum 保留 last-known-good；恢复、成员变化和权限变更必须走各自认证事务。

## 按任务阅读

| 任务 | 规范正文 |
|---|---|
| Device 控制能力、quorum 与故障模型 | [Device 能力与控制角色](membership-model.md) |
| 信任域、管理员与 CA | [信任域与密钥](identity.md) |
| 权威 secret artifact | [权威 secret artifact](secret-artifacts.md) |
| CRDT、Raft、QC 与读写 | [复制模型：CRDT 保存材料，共识决定生效](consensus.md) |
| ControlSet 加入与移除 | [ControlSet 成员变化](membership-transition.md) |
| 丢失 quorum 的显式恢复 | [丢失 quorum](recovery.md) |
| Recovery policy 计划轮换 | [recovery policy 的计划轮换](recovery-policy.md) |
| 签名发布、Device view 与 anti-rollback | [发布、签名与客户端 anti-rollback](publication.md) |
| Enrollment 流程、Invite 与二维码 | [Enrollment、邀请与报告](enrollment-invite.md) |
| Bootstrap tunnel capability | [Bootstrap tunnel capability](bootstrap-capability.md) |
| Enrollment TLS、claim 与事务完成 | [内层 TLS、token、Keystore PoP 与一次性提交](enrollment-transaction.md) |
| 私有 Device 配置与报告 | [稳态配置与报告](device-services.md) |
| 公网 profile、DNS 与证书 | [域名、公开服务与证书管理](public-access.md) |
| EndpointSet、catalog 与端口模型 | [EndpointSet、catalog 与公网端口模型](endpoints.md) |
| Listener 与端口轮换 | [Listener 与端口无中断轮换](listener-rotation.md) |
| 外部副作用、租约与 UI/API | [外部副作用与租约](reconciliation-ui.md) |
| 故障、备份与垃圾回收 | [故障语义](failure-backup.md) |
| 迁移与旧路径删除 | [从当前实现迁移](migration.md) |
| v2 验收矩阵 | [验收矩阵](acceptance.md) |

涉及功能替换时，必须同时阅读[迁移完成条件](migration.md)与
[对应验收条款](acceptance.md)，不能只读兼容安排。

## 实施与操作

实现使用[实施规程](../../development/control-plane.md)；已授权的实际发布、恢复和管理员轮换
使用[控制面操作](../../operations/control-plane.md)。密钥、公网 profile 与轮换细节按上表进入对应正文，
不需要为单一任务通读所有主题。任何未实现步骤都必须显式报告，不能用兼容回退代替目标契约。
