# 文档入口

按本次任务选择下面的一行，阅读适用规范和操作规程。无需通读决策历史。
全局工作边界见 [AGENTS.md](../AGENTS.md)；本页负责选路，不重复定义协议。

## 文档职责

| 要回答的问题 | 入口 | 使用边界 |
|---|---|---|
| 系统有哪些概念、不变量和依赖？ | [架构总览](design.md) | 专题负责各自领域的完整规则 |
| 某项功能必须满足什么协议？ | 下表的专题规范 | 区分已批准目标、v1 迁移输入和提案；目标不代表已实现 |
| 本工作区有哪些正常入口、还缺什么？ | [实现对照](implementation.md) | 以所列源码入口为证，不代表其他工作区或生产版本 |
| 如何构建、操作、发布和验收？ | 下表的操作规程 | 按当前任务授权执行；阅读规程不产生新的任务或上线授权 |
| 为什么做过某个决定？ | [决策索引](decisions.md) | 历史解释；有效规则合入专题，不通过追加记录覆盖规范 |
| 具体部署在哪里、实际运行什么？ | [本机配置与部署](operations/local-deployment.md) | 私有参数在 `.env` 等正式配置；运行结果以部署回执和实际状态核对 |

## 按任务阅读

| 任务 | 必需规范 | 操作与实现入口 |
|---|---|---|
| 模型、渲染、服务器调度 | [架构总览](design.md)对应章节 | [实现对照](implementation.md)、[本机部署](operations/local-deployment.md) |
| 控制面、共识、私有 Enrollment | [控制面规范](distributed-control-plane.md)对应主题及迁移验收条款 | [控制面实施规程](control-plane-implementation-prompt.md)、[控制面运维](control-plane-operations.md) |
| Device 产品生命周期与权限 | [Device 生命周期](device-lifecycle-and-delivery.md) | 协议字段和信任规则由[控制面规范](distributed-control-plane.md)定义 |
| 跨平台客户端接入 | [客户端接入](client-access.md) | [实现对照](implementation.md) |
| 客户端观测与选路 | [观测消费规范](client-observation-reuse.md) | Windows / Android 手册的宿主接线；不扩展服务器测量协议 |
| Android 构建、界面、APK | [客户端接入](client-access.md)对应平台章节 | [双包交付](android-client-delivery-prompt.md)、[ADB 操作](operations/android-device.md)、[客户端 README](../clients/android/README.md) |
| Windows 加入和报告 | [客户端接入](client-access.md)、[v1 报告契约](windows-client-reporting.md) | [报告验收](windows-client-reporting-prompt.md)、[客户端 README](../clients/windows/README.md)；v2 任务另读控制面规范 |
| Linux 安装 | [Linux 安装规程](linux-client-install.md) | [部署参数与管理边界](operations/local-deployment.md) |
| 管理员证书 | [管理员证书边界](operations/admin-certificates.md) | [控制面操作命令](control-plane-operations.md) |
| 入网耗时排查 | [阶段排查规程](server-enrollment-latency-prompt.md) | 从实际业务入口定位，按涉及平台选择上面的规范 |
| Local Network | [Local Network 提案](local-network.md) | 提案不表示已交付，先核对[实现对照](implementation.md) |
| 签名与密钥强化 | [代码签名政策](code-signing-policy.md)、[KMS/HSM 扩展计划](kms-hsm-hardening-plan.md) | 可选强化不构成当前软件密钥基线的上线门槛 |

## 引用和维护规则

1. **每个主题有一个规范正文。** 架构总览给出概念和不变量；专题定义详细契约；平台文档只补宿主差异。
   文档中的“规范依据”“实现对应”“历史理由”分别说明引用用途，避免用模糊的优先级覆盖关系裁决冲突。
2. **版本、规范状态和交付状态分开。** 已批准的 v2 目标可以尚未实现；仍存在的 v1 代码不能授权恢复已退出的业务入口。
   新发现的冲突在对应正文修正，不把免责声明追加到旧指令上。
3. **实现对照只记录本工作区源码。** 正常入口、实际依赖和缺口要一起更新；其他分支、制品和运行环境必须分别标识。
   部署信息、验收回执、密钥及配置不能写入公开文档。
4. **决策记录用于解释。** 新决定接受后同步修改规范；被取代内容退出日常任务入口。查理由时才读取具体 D 条目。
5. **文档变更同时检查入链。** 原 `§` / `D` 编号保留可达的入口，移动章节必须更新相对链接；不得把代码、配置快照或构建产物放进文档目录。

文档检查：`python3 scripts/check_documentation.py`。仓库数据边界检查：
`python3 scripts/check_repository_safety.py`。前者验证结构和引用，技术准确性仍须对照源码与业务证据。
