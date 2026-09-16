# 客户端规范与操作

[文档入口](../README.md) · [架构总览](../architecture/README.md) · [实现对照](../development/implementation.md)

适用于 Windows、Linux Server 与 Android。正文中的 v1 契约只说明迁移输入；v2 对象、
认证与事务统一由[控制面规范](../protocols/control-plane/README.md)定义。版本支持和实际交付分别核对。

## 跨平台规范

| 主题 | 正文 |
|---|---|
| 产品边界与迁移输入 | [范围](scope.md) |
| 共同不变量与组件职责 | [共同契约](common.md) |
| 日常三模式与服务匹配 | [选路模式](routing.md) |
| 业务使用最终出口 DNS、入口独立解析 | [DNS 归属](routing.md#业务域名由最终网络出口解析) |
| 网络代探测预算、观测复用与未知数据 | [观测消费](observations.md) |
| TUN、mixed 与 Windows 发行形态 | [流量接管](traffic.md) |
| 平台宿主与开发环境 | [平台设计](platforms.md) |
| 多配置、状态与路由展示 | [客户端交互](ui.md) |
| 加入网络与设备身份 | [客户端加入](enrollment.md) |
| 制品、安全存储与恢复 | [配置制品](artifacts.md) |
| 交付依赖、测试与未决项 | [交付验收](delivery.md) |

## 按平台操作

| 平台 | 操作与源码入口 |
|---|---|
| Android | [双包交付](android-delivery.md)、[ADB 操作](../operations/android-device.md)、[构建与应用说明](../../clients/android/README.md) |
| Windows | [构建与应用说明](../../clients/windows/README.md)；涉及 v1 报告时读[报告契约](windows-reporting.md)与[报告验收](windows-reporting-acceptance.md) |
| Linux | [安装与身份迁移](linux-install.md) |

Device 创建与权限由[生命周期规范](../architecture/device-lifecycle.md)定义；
[Local Network](../proposals/local-network.md)是独立提案。操作范围和授权以当前任务为准。
