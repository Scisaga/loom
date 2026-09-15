# Loom · 客户端接入规范入口

[文档地图](README.md) · [架构与不变量](design.md) · [源码能力与缺口](implementation.md) · [部署证据](operations/local-deployment.md)

**规范状态：已批准的客户端契约。** 适用于 Windows、Linux Server 与 Android；v1 不包含 Linux Desktop。
本文按任务链接完整主题，沿用原 §1–§17 编号。单 control/平台签名/endpoint 是明确的 v1 迁移输入，
ControlSet/QC/EndpointSet 属于 v2；两者都不表示已经部署。

**引用关系：** [架构](design.md)定义系统模型和不变量；本专题定义客户端策略、宿主与交付；
[Device 生命周期](device-lifecycle-and-delivery.md)定义产品动作，
[控制面规范](distributed-control-plane.md)定义协议字段、认证与状态机。
探测和观测消费由[客户端消费边界](client-observation-reuse.md#客户端消费边界)统一定义；
[Local Network](local-network.md)为独立提案。重复规则应合入所属规范，冲突应修正正文，不按日期或文件名裁决。

## 按任务阅读

| 任务 | 完整规范正文 |
|---|---|
| 范围与迁移输入 | [§1–§3](specs/clients/scope.md) |
| 共同不变量与组件边界 | [§4–§6](specs/clients/common.md) |
| 流量接管与 Windows 发行形态 | [§7](specs/clients/traffic.md) |
| 平台宿主与开发环境 | [§8](specs/clients/platforms.md) |
| 加入网络与设备身份 | [§9](specs/clients/enrollment.md) |
| 配置制品、安全存储与恢复 | [§10–§14](specs/clients/artifacts.md) |
| 交付依赖、测试与未决项 | [§15–§17](specs/clients/delivery.md) |

平台构建和操作使用 [Windows README](../clients/windows/README.md)、
[Android README](../clients/android/README.md)及[Linux 安装手册](linux-client-install.md)，
不要求每次任务通读全部平台规范。

## 原章节链接

下列锚点保留旧引用；展开内容在对应主题。新增引用直接指向主题正文。

<a id="loom--客户端接入设计"></a>
<a id="1-结论"></a>[1. 结论](specs/clients/scope.md#1-结论)
<a id="2-v1-实现边界与迁移输入"></a>[2. v1 实现边界与迁移输入](specs/clients/scope.md#2-v1-实现边界与迁移输入)
<a id="3-目标与非目标"></a>[3. 目标与非目标](specs/clients/scope.md#3-目标与非目标)
<a id="31-目标"></a>[3.1 目标](specs/clients/scope.md#31-目标)
<a id="32-非目标"></a>[3.2 非目标](specs/clients/scope.md#32-非目标)
<a id="4-客户端共同不变量"></a>[4. 客户端共同不变量](specs/clients/common.md#4-客户端共同不变量)
<a id="41-数据平面只有一个实现"></a>[4.1 数据平面只有一个实现](specs/clients/common.md#41-数据平面只有一个实现)
<a id="42-配置与秘密分离"></a>[4.2 配置与秘密分离](specs/clients/common.md#42-配置与秘密分离)
<a id="43-签名高于传输信任"></a>[4.3 签名高于传输信任](specs/clients/common.md#43-签名高于传输信任)
<a id="44-离线继续运行"></a>[4.4 离线继续运行](specs/clients/common.md#44-离线继续运行)
<a id="45-fail-closed"></a>[4.5 fail closed](specs/clients/common.md#45-fail-closed)
<a id="46-顶层路由模式是唯一可写偏好"></a>[4.6 顶层路由模式是唯一可写偏好](specs/clients/common.md#46-顶层路由模式是唯一可写偏好)
<a id="47-v1-服务端接口与本地三模式的边界"></a>[4.7 v1 服务端接口与本地三模式的边界](specs/clients/common.md#47-v1-服务端接口与本地三模式的边界)
<a id="48-endpointset域名与端口轮换"></a>[4.8 EndpointSet、域名与端口轮换](specs/clients/common.md#48-endpointset域名与端口轮换)
<a id="5-总体架构"></a>[5. 总体架构](specs/clients/common.md#5-总体架构)
<a id="6-客户端组件边界"></a>[6. 客户端组件边界](specs/clients/common.md#6-客户端组件边界)
<a id="7-流量接管方式"></a>[7. 流量接管方式](specs/clients/traffic.md#7-流量接管方式)
<a id="71-tun"></a>[7.1 TUN](specs/clients/traffic.md#71-tun)
<a id="72-mixed"></a>[7.2 mixed](specs/clients/traffic.md#72-mixed)
<a id="721-业务域名由最终出口解析"></a>[7.2.1 业务域名由最终出口解析](specs/clients/traffic.md#721-业务域名由最终出口解析)
<a id="73-windows-portable-与安装版"></a>[7.3 Windows Portable 与安装版](specs/clients/traffic.md#73-windows-portable-与安装版)
<a id="8-平台设计"></a>[8. 平台设计](specs/clients/platforms.md#8-平台设计)
<a id="81-linux-server"></a>[8.1 Linux Server](specs/clients/platforms.md#81-linux-server)
<a id="82-windows"></a>[8.2 Windows](specs/clients/platforms.md#82-windows)
<a id="83-android"></a>[8.3 Android](specs/clients/platforms.md#83-android)
<a id="84-开发构建与验证环境"></a>[8.4 开发、构建与验证环境](specs/clients/platforms.md#84-开发构建与验证环境)
<a id="9-加入网络与设备身份"></a>[9. 加入网络与设备身份](specs/clients/enrollment.md#9-加入网络与设备身份)
<a id="91-加入码与交付方式"></a>[9.1 加入码与交付方式](specs/clients/enrollment.md#91-加入码与交付方式)
<a id="92-加入流程"></a>[9.2 加入流程](specs/clients/enrollment.md#92-加入流程)
<a id="93-稳态认证"></a>[9.3 稳态认证](specs/clients/enrollment.md#93-稳态认证)
<a id="94-吊销"></a>[9.4 吊销](specs/clients/enrollment.md#94-吊销)
<a id="10-配置制品"></a>[10. 配置制品](specs/clients/artifacts.md#10-配置制品)
<a id="101-两层制品"></a>[10.1 两层制品](specs/clients/artifacts.md#101-两层制品)
<a id="102-渲染目标必须显式"></a>[10.2 渲染目标必须显式](specs/clients/artifacts.md#102-渲染目标必须显式)
<a id="103-原子安装"></a>[10.3 原子安装](specs/clients/artifacts.md#103-原子安装)
<a id="11-安全存储"></a>[11. 安全存储](specs/clients/artifacts.md#11-安全存储)
<a id="12-配置更新与程序更新"></a>[12. 配置更新与程序更新](specs/clients/artifacts.md#12-配置更新与程序更新)
<a id="13-状态与观测"></a>[13. 状态与观测](specs/clients/artifacts.md#13-状态与观测)
<a id="14-故障与恢复"></a>[14. 故障与恢复](specs/clients/artifacts.md#14-故障与恢复)
<a id="15-依赖顺序"></a>[15. 依赖顺序](specs/clients/delivery.md#15-依赖顺序)
<a id="阶段-c0拆分渲染目标"></a>[阶段 C0：拆分渲染目标](specs/clients/delivery.md#阶段-c0拆分渲染目标)
<a id="阶段-c1固化-linux-接入"></a>[阶段 C1：固化 Linux 接入](specs/clients/delivery.md#阶段-c1固化-linux-接入)
<a id="阶段-c2设备加入与吊销"></a>[阶段 C2：设备加入与吊销](specs/clients/delivery.md#阶段-c2设备加入与吊销)
<a id="阶段-c3windows-v1"></a>[阶段 C3：Windows v1](specs/clients/delivery.md#阶段-c3windows-v1)
<a id="阶段-c4android-v1"></a>[阶段 C4：Android v1](specs/clients/delivery.md#阶段-c4android-v1)
<a id="阶段-c5分布式控制协议迁移目标态"></a>[阶段 C5：分布式控制协议迁移（目标态）](specs/clients/delivery.md#阶段-c5分布式控制协议迁移目标态)
<a id="16-测试矩阵"></a>[16. 测试矩阵](specs/clients/delivery.md#16-测试矩阵)
<a id="17-尚需决定的问题"></a>[17. 尚需决定的问题](specs/clients/delivery.md#17-尚需决定的问题)
