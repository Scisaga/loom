# Android 真机蜂窝网络与 Wi-Fi 切换专项

对应 [GitHub Issue #16](https://github.com/Scisaga/loom/issues/16)。本专项从 Android
Wi-Fi 主验收 #15 拆出，不阻塞 #15、服务端或 Linux 的开发与验收。

## 环境与边界

- 使用 API 31+、具备 telephony、有效 SIM/eSIM 和可用移动数据的 Android 真机；仅 Wi-Fi
  真机和模拟器不能替代本专项。
- 不要求项目购买、开通或管理 SIM/eSIM、套餐、APN 或运营商网络，也不修改系统安全策略、
  不绕过 Android VPN consent。
- 证据只进入忽略目录或受控存储；公开结果不得包含真实设备 ID、号码、运营商账号、APN、
  域名、地址、证书或 token。

## 验收

- 证明实际默认网络 transport 是 cellular，而不是仍经 Wi-Fi；记录脱敏设备/API 与
  APK/commit hash。
- Wi-Fi → 蜂窝 → Wi-Fi 每次默认 Network 变化都建立新的 underlay generation，旧代主动或
  被动证据不得进入新代。
- Direct 在每代不主动探测；每代首次进入 Auto/指定出口时只对冻结的授权入口按地址与源接口
  去重，各探测至多一次。同代重连、模式切换及 Activity/Agent/profile/config 重启不重复探测。
- 蜂窝允许 UDP 时实际使用已授权 HY2；受控阻断 UDP 时使用独立 Trojan/TLS fallback，
  不扫描邻近端口、不把失败入口涂绿。
- 切换前后的 TCP、UDP、IPv4/IPv6、DNS、网页/API 和长连接行为可诊断；业务 FQDN 仍在最终
  egress 解析，bootstrap DNS 不进入 FakeIP。
- Wi-Fi/蜂窝切换、瞬断、前后台、锁屏/解锁、Doze、省电限制、进程回收和重启后只恢复正式
  LKG，不恢复 bootstrap secret。
- Gate A 后，蜂窝网络下的 HY2/Trojan/certificate/SPKI 与 WG generation 切换遵守
  preferred/draining/retirement guard。
- 自动化与人工流量抽查一致，失败项具有可复现记录并完成复测。
