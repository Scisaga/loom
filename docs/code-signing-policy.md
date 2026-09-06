# Code signing policy

Loom 自有代码使用 [Apache License 2.0](../LICENSE)。Windows 发行计划通过
[SignPath Foundation](https://signpath.org/) 申请签名；申请获批和实际签名结果
以发行说明为准，未签名的包继续标为预览版。

## 范围与来源

签名范围为 Loom 自己维护的 Windows 客户端 EXE 和 MSI。提交给 SignPath 的产物
须由 GitHub 托管 runner 从对应仓库提交构建，保持源码、构建与签名请求的关联。
签名后的文件经验证再生成下载校验清单。

上游 sing-box、Wintun 随包保留原文件、许可证及已有签名，不以 Loom 的签名资格
重新签名上游代码。sing-box 使用 GPL-3.0-or-later；官方 Wintun DLL 使用其单独的
预编译许可。Loom 的 Apache-2.0 许可不改变这些条件；Wintun 在 SignPath 申请中的
可接受性须另经审核。

## 维护与批准

仓库维护者 [Scisaga](https://github.com/Scisaga) 负责提交代码、审查外部贡献和
批准发行签名。正式启用前须在 SignPath 配置实际批准人，为参与签名的 GitHub 和
SignPath 账号启用 MFA。每个正式发行版本的签名均须由维护者人工批准。

## Privacy policy

用户通过邀请选择加入的网络。Windows 客户端与该网络控制面交换加入信息、
下载签名配置，并在数据面运行期间自动发送签名健康报告。报告包含设备身份、
时间、已应用配置标识、健康结果和诊断类别；探测响应正文不进入报告。
设备私钥在本机生成并由 Windows DPAPI 保护。

应用流量、DNS 和健康探测按所加入网络的签名配置及用户的出口偏好处理。
所选控制面、DNS、代理和目标服务的运营方可能处理相关请求，其数据处理规则
由相应运营方提供。SignPath 用于构建期间的签名，客户端不向其上报运行信息。

Installed 版创建 Windows 服务和受限机器状态目录，连接时创建 TUN 接口及路由。
通过 Windows 已安装应用界面卸载会停止服务并移除活动路由，保留受保护身份供
重装使用。需要清除身份时，在客户端断开后确认“删除本机 Device”。
Portable TUN 在连接期间接管配置范围内的流量；Portable Mixed 供显式配置代理的应用使用。

## 提供方声明

只有获得 SignPath 接纳并实际启用签名后，发行页才使用以下声明：

Free code signing provided by [SignPath.io](https://signpath.io), certificate by
[SignPath Foundation](https://signpath.org).

申请条件见 [SignPath Foundation terms](https://signpath.org/terms)。
