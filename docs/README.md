# Loom 设计文档

本目录是 Loom 的唯一设计入口，规定业务模型、协议、持久化、运行时和界面的统一语义；
[实施状态](progress.md)单独记录哪些业务链已经通过正式入口验收。

用户明确要求与现行模型确定目标行为，三端原型表达对应交互和视觉；已有实现、原生截图和历史验收
用于核对有效能力、回归风险及实现差距，不反向限定目标。原型与模型的差异须在设计审查中明确修订。
原型完成不表示功能已经实现，以下概览均描述目标能力，实际结果以[实施状态](progress.md)为准。

WG 与 Hy2 必须可以独立承担传输，禁止为了复用权限代码把 Hy2 套在 WG 内，或让 WG 依赖 Hy2。
当前源码已替换相应执行路径，生产前向切换仍待验收；原普通 WG 启用方案已被用户否决，不能继续部署。
纠偏边界与尚未完成的替换见[传输实现纠偏](progress.md#传输实现纠偏)。

## 功能概览

| 使用场景 | 目标能力与设计入口 |
|---|---|
| 管理网络节点 | 同一节点组合承担 access、forward、internet_egress、control；单个与多个 control 使用同一治理规则，见[控制模型](core/control-model.md) |
| 添加和管理设备 | 按职责通过二维码、SSH 或脚本交付邀请；同事务恢复加入，后续改权与身份替换分开，见[加入模型](core/enrollment-endpoint-model.md) |
| 授予服务访问 | Service 定义目标，Policy 固定所属服务并可复用，设备选择策略；共享修改与单设备替换分开，见[服务与策略](core/control-model.md#8-servicepolicy偏好与业务探测) |
| 选择访问路径 | Direct、Auto、指定最终出口复用授权候选；一跳与同出口中继并存，实际选择与业务结果分别回读，见[客户端运行模型](clients/client-runtime-model.md) |
| 访问私有名称与局域网 | 精确 `.loom` DNS、固定网关和虚拟 IPv4 前缀；授权设备主动访问 LAN，见[DNS overlay](core/control-model.md#9-dns-overlay)与[共享局域网](core/control-model.md#10-共享局域网映射) |
| 使用客户端 | Android 多配置与单 VPN；Windows Installed、Portable TUN、Portable Mixed；Linux 显式代理与隔离 access，见[Android](../clients/android/README.md)、[Windows](../clients/windows/README.md)及[Linux](operations/linux-client-install.md) |
| 观察和维护网络 | 设备、拓扑、服务路径、策略、事件、成员、管理员和证书统一管理，见[Web 投影](clients/web-ui-projection.md)与[管理员访问](operations/admin-access.md) |
| 下载和发布组件 | 验签制品、期望组件和实际运行结果分别展示，见[签名发布流程](operations/configuration-model.md#签名发布记录到实际运行的闭环) |

## 核心模型

- [控制权威模型](core/control-model.md)：签名事实、control 成员门禁、增量同步与业务投影。
- [Enrollment 与 Endpoint 模型](core/enrollment-endpoint-model.md)：私有加入、配置、报告与入口轮换。
- [统一契约](core/current-contract.md)：每种权威对象的规范编码、严格拒绝边界与修订规则。

节点可组合承担 `access`、`forward`、`internet_egress`、`control` 四项职责；不受管的目标地址不是节点。
单个或多个 control 使用同一模型：任一有效 control 签发普通事实并以 CRDT 差量同步；control 成员表
变化由旧成员多数签名。设备通过受限引导与私有认证通道加入、取得配置并报告。
Direct、Auto 和指定最终出口复用同一候选模型；授权与真实可用性分开。Web 只投影认证状态和运行观测。
`TransportResource` 可供多个接入会话和显式中继 `NetworkLink` 复用；新 access 不生成专属 WG 接口，
首跳与中继分别保留稳定身份和真实观测。Service 定义访问目标，Policy 固定属于一个 Service，
保存允许/禁止及路径规则，并可被多台节点复用。节点只选择 PolicyIDs，同一节点对同一服务最多选择一条策略；
同一服务在不同节点上可使用不同策略。未设置路径限制明确表示“不限”，未分配策略则没有该服务权限。
共享策略在 Policies 管理；只改单节点时替换它的策略选择，或复制策略后分配。共享 HTTPS 探测目标按
策略所属 Service 与节点有效权限过滤，服务关系、ACL 和界面摘要均从同一授权投影。
LAN mapping 属于局域网 Service，Services 统一管理，节点详情按网关显示它提供的服务。
精确 `.loom` DNS 及经 control 签发的局域网映射属于同一 `NetworkIntent`。
离网管理员通过 SSH 转发访问指定 control 的回环 Web 入口；已接入设备通过网络 DNS 的
`control.loom` 访问处于服务状态的 control。SSH 转发不提供 `.loom` 解析，两条路径分别验收。

## 主要流程设计

1. [控制写入、读取、分区与成员变化](core/control-model.md)；
2. [私有 Enrollment、配置、报告与入口轮换](core/enrollment-endpoint-model.md#正常业务链)；
3. [客户端加入、恢复、选路与撤权](clients/client-runtime-model.md#状态转换与恢复)；
4. [本机配置加载与发布](operations/configuration-model.md#正常加载与执行链)。
5. [管理员证书交付与 Web 访问](operations/admin-access.md)。

## 客户端与界面设计

- [客户端运行与选路模型](clients/client-runtime-model.md)：授权候选、实际观测、偏好与选择。
- [Android 本机配置模型](clients/android-profile-model.md)：多份配置的命名、选择与隔离。
- [控制面 Web 投影](clients/web-ui-projection.md)：认证状态到页面与管理操作的映射。
- [客户端 UI 视觉审查](clients/client-ui-visual-review.md)、[Android 客户端](../clients/android/README.md)和
  [Windows 客户端](../clients/windows/README.md)。
- [目标原型与实现对照](clients/prototype-review.md)：三端目标原型、业务场景及当前实现差距。

## 运维与验收

- [本机部署配置模型](operations/configuration-model.md)：严格 `.env` 输入及其与控制权威的关系。
- [管理员证书交付与 Web 访问](operations/admin-access.md)：control 生成交付包、离网调试与入网访问。
- [Linux 客户端安装与运行安全](operations/linux-client-install.md)。
- [同机 Windows 测试虚拟机](operations/windows-test-vm.md)。
- [Windows 代码签名策略](operations/code-signing-policy.md)。
- [代码提取白名单](migration-whitelist.md)、[实施状态](progress.md)与
  [宿主网络事故记录](incidents/2026-09-21-host-network-takeover.md)。

## 同构与权威

每个权威领域值的往返等式、拒绝规则与现行编号（schema 3）以[唯一现行契约](core/current-contract.md)为准。
每种权威对象只允许一个当前可写的规范编码。错误或预期不一致时修订同一模型、实现和测试；
新增协议或版本须由用户明确提出。已经认证的字节、身份和不可回退 floor 不能被静默重解释；
成员多数证书仅对明确封存的验证键提供验收前沿例外，原已认证高水位仍作为受保护证据保存。
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
