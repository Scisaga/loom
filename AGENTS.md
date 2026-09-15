# 项目工作指引

工作前阅读 [CLAUDE.md](CLAUDE.md)，遵守其中的执行边界、客户端选路约束及提交约定。
用户在对话中的明确要求优先于仓库旧设计、实现和测试；向子任务传递同样的约束。

功能交付须遵守 `CLAUDE.md` 的“功能交付与完成判定”：正常业务入口、daemon 接线、生产部署和
被替换旧路径的删除属于同一交付；组件测试不能代替。继续 v2 控制面任务时，先阅读
[实施与交接提示词](docs/control-plane-implementation-prompt.md)，按要求继续执行，不能只更新计划或状态。

Android 客户端改动和 APK 更新先阅读
[Android 构建与交付提示词](docs/android-client-delivery-prompt.md)。默认从同一份应用源码及原生
AAR 完成 Debug 与已签名 Release 双包交付，校验制品、签名并生成 Release SBOM；
真机安装 Debug 不能代替更新 `app-release.apk`，回复须提供 Release 链接并说明实际安装变体。
后续界面、颜色、图标修正同样适用；仅文档/原型改动或用户明确限定范围时按该范围执行。
