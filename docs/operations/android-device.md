# Android / ADB 真机操作

> 类型：操作边界。适用于设备发现、安装和验收；构建与双包交付见
> [Android 交付规程](../android-client-delivery-prompt.md)。是否进行安装、停 VPN 或故障注入由当前任务授权决定。

- 本环境不得依赖 shell `PATH` 中存在裸 `adb`。先把 ADB 解析为
  `${ANDROID_HOME:-/opt/android-sdk}/platform-tools/adb`，确认该文件可执行，再运行任何
  设备命令；仓库 Android 脚本继续使用显式 `ANDROID_HOME` 和 `ANDROID_SERIAL`。
- 设备发现命令的 stderr 不得丢弃，也不得用 `adb ... 2>/dev/null | ...` 的空输出计算
  “0 台设备”。`adb` 不存在、server 启动失败和设备列表为空是三个不同结果；命令失败时
  必须原样报告失败层，不能推断手机已拔线。
- 真机状态按顺序核对：ADB 可执行文件 -> `adb start-server` -> `adb devices -l` 中的
  `device` / `unauthorized` / `offline` -> 必要时再看 USB 枚举。USB 能看到 Android 设备但
  ADB 没有 `device` 时，只能表述为“USB 可见，ADB 会话不可用”，继续检查授权、udev、
  server/socket 或 USB 转发；后台存在 adb 进程也不能单独证明设备在线。
- 只做状态检查时使用只读命令，不安装 APK、不清数据、不切网络、不启动或停止 VPN。
  安装、覆盖、`force-stop`、广播调试控制或网络故障注入必须来自当前任务的明确授权，并优先
  使用 `clients/android/scripts/` 中的 fail-closed 助手。
- 多设备时禁止隐式选择；只有一个已授权 USB 设备也要在运行变更脚本前解析并核对目标。
  设备序列号和真实设备信息只留在忽略的本机证据中，不写入回答、tracked 文档或 fixture。
- Android 报告的 `arm64-v8a` 是手机 ABI，不得把它当作 Linux arm64 主机验收；反之亦然。
