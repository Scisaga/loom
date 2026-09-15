# 控制面实施与交接规程

**适用条件：** 当前任务要求实现、迁移或上线控制面功能时使用。本文规定执行顺序与交付检查，
不自行启动任务、不预设 issue 范围，也不授予生产操作权限。当前对话已明确的范围和授权继续有效。

先读 [AGENTS.md](../../AGENTS.md) 的完成判定、[源码能力对照](implementation.md)，再读
[控制面规范](../protocols/control-plane/README.md) 中本任务的完整条款及 [从当前实现迁移](../protocols/control-plane/migration.md#从当前实现迁移)与[验收矩阵](../protocols/control-plane/acceptance.md#验收矩阵)。
规范说明目标，源码对照说明接线；生产状态由[部署记录](../operations/local-deployment.md)核实。

## 开始时核对

1. 检查工作区和未提交改动，保护其他任务的工作。将当前要求及 issue 完成条件对应到正常 UI/CLI
   入口、daemon 启动、业务处理、持久状态、客户端消费、部署配置和旧路径，列出具体缺口。
2. 分别记录组件实现、正常入口接通、部署和验收。缺少必需环节时仍未完成，不提前关闭 issue。
3. 复用原网络身份、密钥、日志与数据；不重新 bootstrap，不手工改 Head/ACL/registry，不建立
   空网络替代存量验收。迁移必须验证旧 authority，并留下可重验的正常事务结果。
4. 实现前核对软件 CA 的持久密钥、完整证书链、不可变封装、授权接管、executor/fencing 和
   客户端本地密钥接口。KMS/HSM 是[可选强化](../proposals/key-protection.md)，不作为默认交付前提。
   测试密钥、固定 availability hash、fixture 配置或只有 `crypto.Signer` 接口不证明实际接通。

## 沿正常业务流程接通

- 从管理员创建 Device/邀请开始，经过私有控制服务鉴权、base head/request binding、状态机重算、
  Raft durable commit、提交后 QC 与持久投影。`control_ping` 只验证其自身。
- 邀请必须生成客户端可消费的交付物；静态 distribution、catalog/proof、HY2 bootstrap、独立
  TCP fallback、受限 capability 与内层 Enrollment TLS 按控制面规范接线，公网不承接动态 claim。
- reservation、provisional issuance、approval、completion 使用同一 daemon 的真实证书、封装、
  制品存储与认证状态；不能用固定结果、空配置或另一套 Head 代替。
- 客户端正常保存身份、取得私有配置并激活，提交有效签名报告；控制面回读持久结果和 inventory。
  端口可达、证书通过、页面打开和未签名请求被拒绝都不代替业务成功。
- 涉及动态 ControlSet 时，接入正常晋升/移除、learner catch-up、joint/final 和独立副本重算。
  组件故障注入不证明多成员已部署；少数副本不能完成安全关键写入。
- 按改动验证重试、重启及中断恢复；同一事务返回原结果，不重复消费邀请或重新签发身份。
  客户端选路遵守[消费边界](../clients/observations.md#客户端消费边界)，不增加完整路径扫描或启动等待。

## 替换、发布与验收

1. 运行相关测试和仓库检查，提交可复核实现。已授权上线时，继续执行
   [精确制品发布流程](../operations/local-deployment.md)，直到激活与相关正常业务验收结束。
   当前仅要求文档、代码或检查时按其范围执行。
2. 新版接管时删除对应旧 handler、路由、反代、配置、启动项、客户端回退及失效文案/测试。
   数据和历史证明的保留不授权旧业务路径继续运行；阶段性旧依赖必须明确列为未完成项。
3. 核对实际制品与生效配置，验证正常成功请求、持久结果/客户端生效及旧路径消失。仅执行本次
   相关验收，不追加全网轮询或无关平台矩阵。在用设备范围由当前部署输入及任务要求确认。
4. 真实节点、提交/制品坐标及结果存入忽略的 `deploy/evidence/`，关联必要外部证据。
   源码缺口同步更新 [implementation.md](implementation.md)，不在操作规程追加部署历史。

Windows 专项、Android 蜂窝和 Linux arm64 实机要求按当前任务及对应平台手册处理；未部署的平台
不构成无限保留旧业务入口的理由。DNS 等独立工作不得替代本项正常流程验收。

交接写明下一处具体接线/迁移位置、已运行检查、实际部署范围与阻碍条件。核心调用链缺失时，
不能把它列作“功能完成”之后的普通后续工作。
