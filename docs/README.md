# Loom 设计文档

本目录是 Loom 的唯一设计入口，规定业务模型、协议、持久化、运行时和界面的统一语义；
[实施状态](progress.md)单独记录哪些业务链已经通过正式入口验收。

## 核心模型

- [控制权威模型](core/control-model.md)：签名事实、control 成员门禁、增量同步与业务投影。
- [Enrollment 与 Endpoint 模型](core/enrollment-endpoint-model.md)：私有加入、配置、报告与入口轮换。
- [统一契约](core/current-contract.md)：每种权威对象的规范编码、严格拒绝边界与修订规则。

节点可组合承担 `access`、`forward`、`internet_egress`、`control` 四项职责；不受管的目标地址不是节点。
单个或多个 control 使用同一模型：任一有效 control 签发普通事实并以 CRDT 差量同步；control 成员表
变化由旧成员多数签名。设备通过受限引导与私有认证通道加入、取得配置并报告。
Direct、Auto 和指定最终出口复用同一候选模型；授权与真实可用性分开。Web 只投影认证状态和运行观测。
`TransportResource` 可供多个接入会话和显式中继 `NetworkLink` 复用；新 access 不生成专属 WG 接口，
首跳与中继分别保留稳定身份和真实观测。共享 HTTPS 业务探测目标按 Service 和授权过滤。
精确 `.loom` DNS 及经 control 签发的局域网映射属于同一 `NetworkIntent`。

## 主要流程设计

1. [控制写入、读取、分区与成员变化](core/control-model.md)；
2. [私有 Enrollment、配置、报告与入口轮换](core/enrollment-endpoint-model.md#正常业务链)；
3. [客户端加入、恢复、选路与撤权](clients/client-runtime-model.md#状态转换与恢复)；
4. [本机配置加载与发布](operations/configuration-model.md#正常加载与执行链)。

## 客户端与界面设计

- [客户端运行与选路模型](clients/client-runtime-model.md)：授权候选、实际观测、偏好与选择。
- [Android 本机配置模型](clients/android-profile-model.md)：多份配置的命名、选择与隔离。
- [控制面 Web 投影](clients/web-ui-projection.md)：认证状态到页面与管理操作的映射。
- [客户端 UI 视觉审查](clients/client-ui-visual-review.md)、[Android 客户端](../clients/android/README.md)和
  [Windows 客户端](../clients/windows/README.md)。

## 运维与验收

- [本机部署配置模型](operations/configuration-model.md)：严格 `.env` 输入及其与控制权威的关系。
- [Linux 客户端安装与运行安全](operations/linux-client-install.md)。
- [同机 Windows 测试虚拟机](operations/windows-test-vm.md)。
- [Windows 代码签名策略](operations/code-signing-policy.md)。
- [代码提取白名单](migration-whitelist.md)、[实施状态](progress.md)与
  [宿主网络事故记录](incidents/2026-09-21-host-network-takeover.md)。

## 同构与权威

对每个权威领域值 `D`、规范 wire `W` 和耐久状态 `P`，必须满足：

```text
decode(encode(D)) = D
load(save(D))      = D
decode(W)          = error，若 W 含未知、歧义或非规范内容
```

每种权威对象只允许一个当前可写的规范编码。错误或预期不一致时修订同一模型、实现和测试；
新增协议或版本须由用户明确提出。已经认证的字节、身份和不可回退 floor 不能被静默重解释。
运行时和 UI 只能由权威状态单向投影；派生缓存和索引必须能由权威状态重新生成。保存用户命名、稳定本机 ID
或恢复意图的 profile catalog/index 是本机权威值，须规范持久往返。

每份核心模型须定义有限概念及必要性、关系与状态转换、失败和恢复语义、domain/wire/persistent/runtime/UI
映射、可逆边界、正常业务链及最小测试。新增权威实体前，先证明现有概念无法表达哪项明确需求。

## 运行安全

公网 Nginx 只提供伪装网站和认证为公开的通用不可变制品；管理、Enrollment、设备配置与报告走私有认证服务。
Linux access/hybrid 的 TUN 只可在专用 network namespace 内启动；隔离与宿主网络回读未完成时，正式 service
失败关闭。详细约束见[宿主网络安全记录](incidents/2026-09-21-host-network-takeover.md)。

## 完成判定

一项业务只有经过正式 UI/CLI 入口、daemon 认证处理、权威状态和必要副作用持久化、重启恢复、运行时消费、
用户可见回读，以及本任务范围内的部署验收，才可标为完成。并行的重复权威和业务入口必须收敛为一条。
具体进度与证据限制见[实施状态](progress.md)。
