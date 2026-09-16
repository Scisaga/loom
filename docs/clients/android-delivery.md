# Android 构建与交付规程

用于 Android 客户端实现、修正及 APK 更新任务。先阅读
[AGENTS.md](../../AGENTS.md) 的执行边界与功能交付、
[ADB 真机操作](../operations/android-device.md)，以及
[Android README 构建说明](../../clients/android/README.md#reproducible-linux-build)。
用户当前明确要求优先于旧文档和测试；当前对话已有安装授权继续有效，本文不自行授权安装。

## 任务范围与完成条件

- 提取本次实际要求和明确排除，继续完成已授权的构建、安装与验收。
- 源码、资源、颜色、图标、Manifest、构建设置、原生核心改动或 APK 构建/更新请求，默认
  从同一份应用源码与 AAR 交付 **Debug、已签名 Release 和 Release SBOM**。
  后续小修正也要同步更新双包，不能把 Debug 安装成功当作 `app-release.apk` 已更新。
- 用户明确只要某一变体、代码或检查时遵守其范围；仅文档或原型改动不触发 APK 重建。
- 任一必需制品构建失败或仍是旧版时继续处理；确实缺少签名材料等外部条件时如实说明具体
  未完成项。不得展示旧 Release 链接并称“已更新”，也不得只汇报测试通过后结束交付。

## 构建

1. 核对当前改动和应用源码提交，保留无关工作。确认 AAR 对应所需原生输入，且哈希与
   `clients/android/third_party/NOTICE.md` 一致。仅原生源码/依赖变化或 AAR 缺失时，先运行
   `build-mobile-aar.sh`，审核并更新来源记录；不能通过沿用旧 AAR 漏掉核心改动。
2. 使用已有 `deploy/android/android-signing.env`（或 `LOOM_ANDROID_SIGNING_ENV_FILE`）
   和部署公共信任锚。不得输出凭据，不因一次构建创建或替换发布密钥。
3. 在 `clients/android` 执行完整默认流程，期间保持两包的应用源码及原生输入一致：

   ```bash
   export ANDROID_HOME="${ANDROID_HOME:-/opt/android-sdk}"
   ./gradlew --no-daemon --max-workers=4 lintDebug assembleDebug && \
     ./scripts/build-release.sh
   ```

   Release 助手负责 JVM 单测、Release Lint、打包、签名验证、排除调试控制入口、
   核对 NOTICE/license 并生成 SBOM。不能只执行第一行 Gradle 就结束。
4. 确认以下制品均对应本次构建，核对两包的包名、版本和签名，记录应用源码提交、AAR 与
   制品 SHA-256。已有发布包时，确认 Release 仍使用原发布证书。
   文件存在或时间较新不足以证明内容已更新；检查构建结果及与改动相关的包内内容。

   | 制品 | 相对 `clients/android` 的路径 |
   |---|---|
   | Debug | `app/build/outputs/apk/debug/app-debug.apk` |
   | 已签名 Release | `app/build/outputs/apk/release/app-release.apk` |
   | Release SBOM | `app/build/reports/sbom/loom-android-release.spdx.json` |

   两个 APK 是不同变体，哈希不要求相同；需要一致的是本次应用源码与原生输入。
   图标修改检查 APK Application 的五档 PNG 与 Launcher activity 的自适应图标，
   不能仅检查源 SVG、应用内页头或 Debug 截图。

## 已授权的安装与验收

- 使用显式 `$ANDROID_HOME/platform-tools/adb`，按[真机操作规程](../operations/android-device.md)解析并核对已授权目标设备。
  优先使用 `clients/android/scripts/install-device-apk.sh` 核对包名、哈希和现有签名后覆盖安装。
  所需参数和显式安装确认环境变量见
  [README 真机流程](../../clients/android/README.md#emulator-and-device-acceptance)。
- 保留已加入身份、配置、密钥和防回退状态。已装 Debug 的设备可以继续安装同签名 Debug，
  同时完成 Release 制品交付；不得为改用发布签名擅自卸载、清数据或重新加入。
- 回读实际安装 APK 并核对哈希，启动并检查本次修改相关的正常界面或操作。记录实测的是
  Debug 还是 Release；Debug 的真机结果不证明 Release 已在真机安装或通过相同测试。
- 图标验收须检查已有桌面快捷方式。若安装包、应用信息与底栏已显示新版而桌面仍旧，
  先核对快捷方式指向的包与 Activity，再刷新桌面进程并回到同一页面确认。
  不清除桌面数据，不通过卸载应用处理图标缓存；仅包内资源正确不能算桌面修复完成。
- 按改动选择必要检查，需要设备插桩测试时才构建 `assembleDebugAndroidTest`。复用仍适用的证据；
  不为颜色/图标修正重复连接矩阵，不增加 VPN、业务路径或入口探测。
  网络逻辑改动遵守[客户端消费边界](observations.md#客户端消费边界)。

## 交付回复与记录

- 默认给出可点击的 **`app-release.apk`** 路径；Debug 链接如需提供，明确标注变体。
- 分别说明 Debug/Release 是否已构建、Release 签名验证结果、设备实际安装的变体或尚未安装，
  以及与本次修改相关的验证结果和未完成项。不得用一句“已构建并安装”掩盖变体差异。
- 真实设备信息、签名指纹、构建/验收回执存入忽略的 `deploy/evidence/`，关联正式 APK 与 SBOM
  路径；源码接线变化更新[实现对照](../development/implementation.md)。后续文档提交不能改写已有 APK 的源码
  归属，也无需因此重建。部署配置与证据分工见[本机操作说明](../operations/local-deployment.md)。
- 运行仓库安全检查，按提交约定只提交本次相关文件。
