# 入网耗时排查规程

**适用条件：** 当前任务要求定位或优化正常入网耗时。协议规则按
[控制面规范](../protocols/control-plane/README.md)，交付按[实施规程](../development/control-plane.md)。
本页不预设继续某个旧专项，也不以单 registry、公开 Enrollment 等旧实现约束新版。

## 排查步骤

1. 先用[实现对照](../development/implementation.md)确认当前源码有哪些正常入口，再核对实际部署制品和
   相关[验收记录](local-deployment.md)。其他分支或测试组件不能当作正在运行的服务。
2. 沿真实流程分段计时：创建邀请、静态分发/catalog 验签、bootstrap 隧道、私有 Enrollment、
   reservation、证书准备、approval/completion、配置获取、实际激活。标明失败或等待的具体步骤。
   DNS 问题先核对[业务与入口解析的边界](../clients/routing.md#业务域名由最终网络出口解析)：业务
   FQDN 由最终出口解析，建立外层隧道的入口 FQDN 使用独立 underlay resolver。私有 API 使用
   overlay IP，仍可能因外层入口解析失败而超时；不能据此推断 Wi-Fi 限制，也不能把 TUN 返回
   FakeIP 当作入口真实解析成功。
3. 只优化证据支持的瓶颈；保留身份与数据、认证及提交语义。不提前返回 ready，不减少验证，
   不使用空制品、伪造结果或静默回退旧协议。客户端排查不授权修改路由器/NAT 或追加业务探测。
4. 服务端修改接入正式 daemon，完成当前授权的发布和相关正常流程验收；新版替换同时移除
   对应旧实现。真实耗时、节点及制品信息存入 `deploy/evidence/`，不在本页追加任务记录。

## Android 静态制品下载

先区分底层网络解析、TCP 建连、TLS 身份与 pin、HTTP 状态、制品摘要及安装验证。
系统进程或构建机可达不证明 Android 应用可达；检查时保留应用身份、实际选中的底层
`Network` 和失败异常链，不用另一进程的请求代替应用成功。

需要进一步定位时，可显式运行
[`ConfigMirrorDeviceInstrumentedTest`](../../clients/android/app/src/androidTest/java/io/github/scisaga/loom/ConfigMirrorDeviceInstrumentedTest.kt)：
传入 `configMirror=true`，并在目标应用的外部文件目录提供管理员导出的
`diagnostic.loom-config`。它使用现有身份验证配置交付物，通过正常 reader 对每个认证镜像
下载一次运行制品，只写诊断结果，不激活配置、推进 floor 或产生选路观测。
插桩运行会重启应用，须遵守 [ADB 操作边界](android-device.md)。测试框架返回成功只说明
诊断执行完毕；实际下载结果看每个镜像的 `verified` 与异常链，配置生效和私有报告另行验收。
