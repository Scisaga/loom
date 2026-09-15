# 私有 Device 配置与报告

[文档地图](../../README.md) · [架构入口](../../architecture/README.md) · [控制面规范](README.md) · [实现对照](../../development/implementation.md) · [本机部署信息](../../operations/local-deployment.md)

**规范状态：已批准的 v2 目标协议。** 实现、接通、部署、验收须分别核对；本文不证明当前源码或生产已经具备所列能力。

---

## 稳态配置与报告

Enrollment 完成后，客户端关闭 bootstrap listener、删除 descriptor/token/capability 的持久副本，
并通过正式 Loom channel 使用 Device mTLS：

- device_config 返回与 Device 授权相符的 Merkle-proofed private view；
- device_report 接收 Device 签名的健康、版本和观测；
- distribution 仍可从公开 mirror 拉取通用、无秘密、可验签制品；
- control_api 只接受 admin cert；Device identity 不能提升为 admin；
- Raft/peer RPC 只接受 control peer profile。

`device_report` 的首版 exact envelope 为：

```text
DeviceReportBodyV2
  schema = 2, cluster_id, device_id, report_id, report_sequence
  generated_at
  accepted_floors: ClientFloorsV2
  kind, payload_schema, payload_hash

DeviceReportSignatureV1
  algorithm = "ecdsa-p256-sha256"
  identity_spki_hash
  signature                         # canonical DER、low-S、无 padding base64url

DeviceReportEnvelopeV2
  schema = 2
  body: DeviceReportBodyV2
  payload                           # 按 kind/schema 严格解码的 canonical JSON object
  signature: DeviceReportSignatureV1
```

`payload_hash=H(frame("loom-device-report-payload-v2",payload_bytes))`；签名覆盖
`frame("loom-device-report-signature-v2",JCS(DeviceReportBodyV2))`。私有服务在交给 report sink 前必须
同时验证 Device mTLS、certified CA profile registry、当前 Device view/QC/inclusion、exact floors、
payload reader contract、freshness 和 identity signature。sink 以 `(Device ID,certificate hash)` 为 key
原子推进 `report_sequence`；同序号仅接受 exact report 的幂等重试，拒绝内容冲突或回退。

这些应用服务不得挂到公网 Nginx。是否由一个 control 进程复用内部 socket 不影响协议角色；
证书 EKU、ACL、端口和 handler 必须分别校验。报告失败不停止已安装数据面，配置不可达时继续
使用 LKG；任何过期 bootstrap capability 都不能充当稳态恢复通道。

Linux 稳态客户端只从已原子安装的 identity/certificate/LKG 组装 Device mTLS，
且只拨号 private directory 中的 exact overlay tuple。它同时校验 TLS 1.3、internal CA、
overlay IP SAN 和 SPKI pin。现有 `config_qc` 是 parent Head 的 QC，不单独承诺
`ControlServiceDirectoryV1` 的 bytes；因此 Linux 路径还必须从 root-owned 配置接收
exact `control_service_directory_hash`，禁止将目录和其自带 QC 从同一不可信输入中自我证明。
Device view 只有重新验过 QC/Merkle/identity/floors 后才替换 LKG。报告签名后如果响应丢失，
重试必须持久化并复用 exact envelope，不得在同一 `report_sequence` 上重新签名。
各平台 reporter 在网络发送前先原子保存 pending envelope。`204 No Content`，或 exact
绑定原报告的 `200` 回执，才推进最后确认序号。回执可附现有服务器观测；客户端继续按原 CA、
签名及新鲜度规则验证，TLS 成功不能替代观测验签，也不能为回执追加探测。

pending 不阻塞正常配置刷新。重新验证并持久化的新 Device state 若已覆盖原 floors，或原报告
已超出 freshness window，客户端保留原签名 envelope、退休原因和当前 floors，消费其已占用
序号后才能生成下一份报告。退休不表示服务端接受，不改变最后确认序号；不得在同一序号上
重签新正文。仍适用的 pending 继续 exact 重放，错误响应本身不授权退休或推进配置。

---
