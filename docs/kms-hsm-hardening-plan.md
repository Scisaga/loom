# KMS/HSM 密钥保护强化：后续扩展计划

**规范状态：可选强化提案。** 已批准基线允许本地软件密钥与不可变 sealed artifact；
约束由[控制面 §6.2](distributed-control-plane.md#62-权威-secret-artifact)定义，
[D139](decisions.md#d139--软件密钥作为当前基线kmshsm-单列后续强化)解释选择理由。
本计划不构成私有入网、daemon 接线、存量迁移或旧路径删除的前置条件。
源码能力见[实现对照](implementation.md)，具体后端及部署结果由[部署记录](operations/local-deployment.md)核对。

## 当前基线与扩展边界

当前基线允许签发进程使用软件私钥，目录 `0700`、私钥文件 `0600`；权限隔离限制本机读取范围，
不提供硬件不可导出性质。备份、复制与接管使用已授权接收者的加密封装和不可变版本；密钥用途、
SPKI/PoP、availability、当前 executor/fencing、首次结果持久化与恢复仍须核验。

KMS/HSM 可在将来提高私钥提取难度，并把密钥访问策略、撤权与审计放到独立保护域。它增加服务
部署、权限维护、签名延迟、故障处理与恢复成本，也不能阻止已获签名权限的受控进程滥用该权限。
是否采用、选择哪种服务，应在实际需求明确后另行确定。

可选范围包括在线 Device 中间 CA、ACME account、BootstrapIssuer 与服务 TLS/peer key；每类按
用途独立评估。不改变 Device 身份/WG 私钥在设备本地生成的边界，不把根 CA 或 recovery 私钥
集中到普通在线 control。Android 已有 Keystore 是客户端当前实现边界，不依赖本计划。

## 将来启用时的接口与证据

现有 `crypto.Signer` 和 `kms_or_hardware_key` wire variant 可作为接入边界。接口或测试 handle
本身不能证明私钥不可导出、服务可用或生产已经接通；需要实际 provider adapter 与正常 daemon
调用链。候选后端须满足：

- 支持被使用 profile 的精确算法与签名格式，返回公钥逐字节匹配已认证 issuer/service SPKI。
- 固定 `provider/object_id/exact_version/policy_hash`；禁止 `latest`、可变 alias、可覆盖路径和
  只存在于进程内的句柄。已有软件密钥迁入或新 issuer 轮换都须显式迁移，不静默换身份。
- 明确 executor 的签名权限、接管权限、撤权和当前 fencing 检查。普通投票成员不自动取得签名权；
  无论采用哪种保护方式，证书仍须配合当前 registry/QC/ACL 才能取得业务权限。
- availability receipt 的 `artifact_or_version_digest` 等于实际 provider 返回、按约定规范化的
  exact version digest；KMS/HSM receipt 不带 sealed `recipient_key_ref`，授权 principal 由固定
  provider policy 表达。不能用固定测试 hash 或仅成功取到公钥代替实际持钥证明及签名可用性。
- recovery custody 若采用该 variant，custodian/receipt 的 optional recipient key 都必须缺失，
  不伪造 sealed recipient；仍需每个 custodian 对同一 custody artifact 做真实 key-test 签名，
  保留 quorum、故障域、离线恢复与完整证据约束。
- 在失败、超时、撤权和节点接管后恢复原事务及首次结果，不重复消费邀请或重新签发；不得在
  provider 失败时静默回退另一把软件 key。backend/版本变化必须形成受认证的新 generation。

## 后续实施与验收

1. 选择适用密钥用途和实际后端，记录算法能力、权限模型、费用、延迟、故障与恢复责任。
2. 实现 provider adapter、持久版本引用与访问策略，验证与现有软件签发器相同的业务授权边界。
3. 通过受认证迁移接入正常 daemon，保留存量 Device 身份、历史证明和恢复能力；不重建网络。
4. 完成正常入网/config/report、签发中断恢复、撤权、executor 切换与服务不可用的实际验收，
   再决定扩大适用范围。wire 格式测试、模拟 handle 或厂商宣称不代替这些证据。

本计划被明确启动前，主设计、提示词、issue 完成判定及部署脚本不得重新引入强制 KMS/HSM 门禁。
