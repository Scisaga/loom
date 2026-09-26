# 实施状态

核对日期：2026-09-26。本文只记录已核实结果与缺口，不定义第二套协议。完成须满足
[正式入口与回读门禁](README.md#完成判定)。本轮修订设计文档及项目指引，没有执行生产部署、
读取生产私有证据或重做实体机验收；文档、组件、测试和页面存在均不等于业务完成。

## 已完成的局部结果

| 结果 | 已核实的范围 | 不代表 |
|---|---|---|
| 设计入口与单一目标契约 | [设计入口](README.md)、[控制模型](core/control-model.md)及[现行契约](core/current-contract.md)描述一套目标语义；[项目指引](../AGENTS.md)同步了四项职责、普通事实同步、成员多数门禁及旧材料拒绝规则。 | 源码、已签名现网数据或正式入口已按新模型运行。 |
| 客户端与 Web 产品资产 | Web、Android、Windows 界面源码及既有视觉基准仍在工作树；[视觉审查模型](clients/client-ui-visual-review.md)规定回读办法。 | 真机交互、签名发行或线上运行验收。 |
| Linux 宿主事故处置 | [事故记录](incidents/2026-09-21-host-network-takeover.md#已落地防复发措施)记录了宿主恢复、初始 netns 拒绝、service quarantine 与禁自动重启。 | 专用 capture namespace、无 TUN 转发/出网恢复或 Linux 客户端完成；本轮未重新读回宿主生产状态。 |

## 未完成的业务结果

| 工作项 | 当前可确认的基础 | 尚缺的完成证据或结果 |
|---|---|---|
| 签名事实与大规模同步 | 现有 Material 存储、控制通信和[目标模型](core/control-model.md)可供改造。 | 当前控制实现仍以 Raft 日志和 QC 决定普通写入，并按完整材料 ID 列表轮询；尚无单 control 签发的规范事实、逐签发者序列/前哈希、因果依赖、差量前沿、确定性并发处理、分区/重启恢复及只向受影响设备分发视图的正式闭环。 |
| control 成员门禁 | 现有成员身份和验证键有代码基础。 | 旧成员多数签名的后继表链、持久单票、旧表事实截止前沿、整体删除的同证书节点墓碑、分票暂停、双签分叉失败关闭、N=1/2/3、离线设备成员证明及生产回读均未按目标模型实现；现有 joint/Raft/QC 不能抵扣。 |
| Invite 与节点生命周期 | 私有 claim/resume/report、Endpoint 入口及平台加入代码存在。 | SSH、bootstrap 脚本、扫码共用规范 Invite；扫码签名内容及服务端仅许 `access`；首次 claim 只由签发者处理；无第二次人工批准；加入时申请 control 自动收集多数签名；任一后续 control 可改权或删除、普通节点墓碑与依赖投影清理，以及正式持久/运行时回读尚未闭环。 |
| 可复用传输与中继链路 | 现有 WG `NetworkLink`、设备报告和部分私有 TLS/Hy2 adapter 存在；Enrollment 不自动添加 WG 链路。 | 不随逐设备参与而改写的稳定 `TransportResource`、普通 access 按授权复用首跳、仅中继需显式 LinkID、同节点对 WG/hy2 并存、链路规范摘要、每链路真实探测和运行时读回尚未接通。现有报告字段偏向 WG，不能填造 Hy2 的 WG interface/handshake。 |
| Direct／Auto／指定出口与业务探测 | [客户端模型](clients/client-runtime-model.md)规定同出口一跳和中继并存、真实观测与 selector 回读。 | 一份认证 HTTPS 目标池按 Service 和授权派生目标集合、同 Policy 不同 Service 各自探测/选路、无目标 `unknown` 及最小真实探测尚未实现；当前 DeviceView 仍是平铺列表，Linux 运行时只取首项目标并有硬编码公网回退。不得把传输成功或 ICMP 提示冒充业务成功。 |
| DNS overlay | 目标只允许精确 `.loom` A/AAAA，`control.loom` 指向私有 Web 入口，解析不授予权限。 | 规范签名记录、冲突拒绝、按设备投影、私有解析器、网站证书名称验证、隔离运行与正式回读均未实现；DNS provider、DNS-01 和 ACME 自动签发/续期仍不在本工作项。 |
| 共享局域网 | 目标由 `forward` 声明、control 签发等长 IPv4 虚拟映射，复用 Policy grant。 | 自动无池分配与三次冲突重分配、已入网 access 授权编辑、CIDR Service 匹配、网关 ACL、精确路由、DNAT/必要 SNAT、停止/删除回读与隔离运行均未实现；不得修改宿主初始 netns 或 LAN 路由器。 |
| 控制面 Web | 页面与[Web 投影模型](clients/web-ui-projection.md)保留。 | 代码仍有 reader 证书和 read capability；目标只保留网站证书与 admin 证书，普通 access 仅见入口页。签名事实写入、成员变更多数门禁、forward 节点局域网配置、已有设备授权编辑、敏感数据权限和旧 SSOT/registry 路径退出均缺正式闭环。 |
| Android | 界面源码和[本机配置模型](clients/android-profile-model.md)已有。 | 签名 Release、私有入网、一跳与同出口中继 fallback、切网/重启/撤权及真实设备显示回读；历史 debug 包或旧勾选不能抵扣。 |
| Linux | 本机身份/LKG、runtime 与 fail-closed 门禁已有代码基础。 | 无 TUN 的转发/出网平面恢复；专用 namespace 内 access capture、精确清理、异常退出/重启以及 SSH、LAN、WG、DNS、代理和公网返回路径回读。[installer 失败路径](../internal/clientdist/package.go)仍可能重新 `enable --now` 先前 unit，必须加安全所有权门禁；正式 access service 维持安全暂停。 |
| Windows 既定客户端交付 | 三种交付形态的源码、UI 基准和[同机 VM](operations/windows-test-vm.md)流程存在。 | 私有入网到运行、报告、安装的正式入口与生产读回；VM 不能替代 ARM64、真实睡眠、物理网络切换和显示硬件实体机验收。外部签名尚未启用。 |
| 本机 `.env` 瘦身 | [配置模型](operations/configuration-model.md)定义严格六键目标。 | 现有私有配置的一次性迁移、严格 loader、正式部署结果及受保护读回；模型写好不等于迁移完成。 |
| 唯一规范输入 | [现行契约](core/current-contract.md)规定规范字节、严格拒绝和单向投影。 | [Material 解码器](../internal/control/model.go)仍接受旧格式，[控制存储](../internal/control/store.go)仍有旧初始化/恢复路径；[设备代码](../internal/control/enrollment.go)的 `runtime_contract` 仍有多个值和投影分支。需收为唯一当前语义，拒绝旧材料及分支，且不重放历史格式。 |
| 字段级同构 | 文档已规定 domain、wire、persistent、runtime、UI 的边界。 | 新签名事实、成员证明、按 Service 探测、DNS 与局域网映射的完整规范字节、拒绝规则、编码往返和正式读回尚未落地。 |
| 生产切换 | 现网身份、密钥、认证字节、floor 与不可回退 latch 受保护。 | 目标模型与已签名材料不兼容；尚无用户决定并验证的前向办法、受保护证据和生产读回。必须停止冲突写入并保持切换受阻，不能自动生成空 genesis、重置身份或以旧格式作长期 fallback。 |

## 反复投入仍未闭环的部分

1. **版本与权威分叉。** 多套状态曾各自充当“当前”；现有 `runtime_contract` 继续在同一格式内承载多套投影语义。
   需要统一写入、解码、持久恢复与客户端消费；不能再添格式号或兼容分支绕开已签名字节冲突。
2. **控制治理。** 已有 Raft/QC、成员转换及 Enrollment 局部实现，但它们未形成用户确认的单 control 普通治理、
   多数成员门禁和大规模差量传播；继续保留并行权威会延长混乱。生产迁移未解决前不能宣称完成。
3. **Linux capture 安全。** 宿主网络接管表明报告变绿、endpoint 排除与临时路由不能证明 underlay 安全；
   专用 namespace、所有权清理与真实新连接验收仍缺，正式 service 继续 disabled/inactive。
4. **客户端正式运行闭环。** Android、Windows 有源码、debug 包和 VM 投入，真机切网、ARM64、正式发行及
   同一私有模型的运行读回仍缺，不能把局部结果记为完成。

具名局域网和 DNS overlay 已纳入当前设计但仍未实现；公网 DNS provider/ACME 不属于当前核心范围。
更早设计只可作取证，不能成为现行规范或正常解码输入。
