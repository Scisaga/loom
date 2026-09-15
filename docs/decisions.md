# 决策记录索引

[文档地图](README.md) · [架构与规范入口](design.md) · [控制面规范](distributed-control-plane.md) · [实现对照](implementation.md)

**职责：解释为什么作过某个决定。** 各条记录按 D 编号独立保存，只有需要追溯理由时才阅读。
历史记录不构成当前执行指令；“当前”“生效”“已实现”“待部署”均是当时的描述。
源码能力见实现对照，部署输入与证据按[本机部署信息](operations/local-deployment.md)管理。

**维护方式：** 新决定先同步对应规范；历史条目保留原理由，并在索引注明明确的替代关系。
不得让读者通过“寻找最新 D”补齐规范。旧 D 编号及章节链接继续定位到归档原文。

**已明确的历史边界：**

- D1–D99 中的单指定 control、旧公开 API 或整路径测量只属于记录当时的版本；平台适用范围按现行专题。
- D100–D130 中的公开 Enrollment、Device-wide direction 与固定一小时 retry window 已由 D131 的结论修正并合入控制面规范。
- D132 的旧入口保留安排已被 D138 的逐功能迁移与删除要求取代；D133 明确未部署平台不阻塞现网替换。
- D70 的私有状态文档目录安排已取消；配置、源码实现对照、部署证据分别按文档地图归位。
- D139 的本地软件密钥基线已合入 secret artifact 规范；KMS/HSM 另见后续强化计划。

## 编号索引

| 编号 | 历史问题与理由 |
|---|---|
| <a id="d1--每条隧道一个-wireguard-接口不是一个接口挂多个-peer"></a>D1 | [每条隧道一个 WireGuard 接口,不是一个接口挂多个 peer](decisions/D001.md) |
| <a id="d2--私钥用-wg-quick-的-postup-引用本地文件"></a>D2 | [私钥用 `wg-quick` 的 `PostUp` 引用本地文件](decisions/D002.md) |
| <a id="d3--无法完整表达的输入一律硬报错不静默降级"></a>D3 | [无法完整表达的输入一律硬报错,不静默降级](decisions/D003.md) |
| <a id="d4--推导字段不进结构体靠严格解码拒绝"></a>D4 | [推导字段不进结构体,靠严格解码拒绝](decisions/D004.md) |
| <a id="d5--接口名为-wg-长度由校验器提前拦截"></a>D5 | [接口名为 `wg-<对端id>`,长度由校验器提前拦截](decisions/D005.md) |
| <a id="d6--校验返回全部发现并按-节点-条款-稳定排序"></a>D6 | [校验返回全部发现,并按 (节点, 条款) 稳定排序](decisions/D006.md) |
| <a id="d7--配置包哈希只覆盖渲染层"></a>D7 | [配置包哈希只覆盖渲染层](decisions/D007.md) |
| <a id="d8--技术栈"></a>D8 | [技术栈](decisions/D008.md) |
| <a id="d9--凭据在渲染层是占位符不是明文"></a>D9 | [凭据在渲染层是占位符,不是明文](decisions/D009.md) |
| <a id="d10--目标选择编码为目标在隧道中的地址-已被-d12-推翻"></a>D10 | [~~目标选择编码为"目标在隧道中的地址"~~ 已被 D12 推翻](decisions/D010.md) |
| <a id="d11--用-selector-而不是-urltest"></a>D11 | [用 selector 而不是 urltest](decisions/D011.md) |
| <a id="d12--目标不是节点出口是路径上的位置"></a>D12 | [目标不是节点,出口是路径上的位置](decisions/D012.md) |
| <a id="d13--隧道矩阵只覆盖-reverse_only-服务器"></a>D13 | [隧道矩阵只覆盖 `reverse_only` 服务器](decisions/D013.md) |
| <a id="d14--快照-id-是内容哈希时间从外部注入"></a>D14 | [快照 id 是内容哈希,时间从外部注入](decisions/D014.md) |
| <a id="d15--签名放在旁文件不放进-manifest"></a>D15 | [签名放在旁文件,不放进 manifest](decisions/D015.md) |
| <a id="d16--一台机器一把-wireguard-私钥放在-etcwireguardnodekey"></a>D16 | [一台机器一把 WireGuard 私钥,放在 `/etc/wireguard/node.key`](decisions/D016.md) |
| <a id="d17--clientprofile-并入-node端口范围改-61617-61799"></a>D17 | [`ClientProfile` 并入 `Node`,端口范围改 61617-61799](decisions/D017.md) |
| <a id="d18--惰性字段按能力拒绝-已被-d19-取代"></a>D18 | [~~惰性字段按能力拒绝~~ 已被 D19 取代](decisions/D018.md) |
| <a id="d19--角色字段分块capabilities-由块推导"></a>D19 | [角色字段分块,`capabilities` 由块推导](decisions/D019.md) |
| <a id="d20--selector-必须配一个能切它的端点"></a>D20 | [selector 必须配一个能切它的端点](decisions/D020.md) |
| <a id="d21--加字段之前先验证下游真的会用它"></a>D21 | [加字段之前先验证下游真的会用它](decisions/D021.md) |
| <a id="d22--selector-的默认值不许是直连"></a>D22 | [selector 的默认值不许是直连](decisions/D022.md) |
| <a id="d23--停在死候选上不受阻尼保护"></a>D23 | [停在死候选上不受阻尼保护](decisions/D023.md) |
| <a id="d24--调参字段之间的算术要校验"></a>D24 | [调参字段之间的算术要校验](decisions/D024.md) |
| <a id="d25--agent是两个角色拆开"></a>D25 | ["Agent"是两个角色,拆开](decisions/D025.md) |
| <a id="d26--上报接口只绑隧道内地址且这是硬错误"></a>D26 | [上报接口只绑隧道内地址,且这是硬错误](decisions/D026.md) |
| <a id="d27--按段量不按整条路线量"></a>D27 | [按段量,不按整条路线量](decisions/D027.md) |
| <a id="d28--推论与亲测必须分开标记"></a>D28 | [推论与亲测必须分开标记](decisions/D028.md) |
| <a id="d29--63-的建议是对的给的理由过时了"></a>D29 | [§6.3 的建议是对的,给的理由过时了](decisions/D029.md) |
| <a id="d30--apply-的五步顺序每一条都对应一个踩过的坑"></a>D30 | [apply 的五步顺序,每一条都对应一个踩过的坑](decisions/D030.md) |
| <a id="d31--备份加不加密必须显式选"></a>D31 | [备份加不加密必须显式选](decisions/D031.md) |
| <a id="d32--控制面是一棵签了名的静态树不需要被信任"></a>D32 | [控制面是一棵签了名的静态树,不需要被信任](decisions/D032.md) |
| <a id="d33--期望状态不只是文件内容"></a>D33 | [期望状态不只是文件内容](decisions/D033.md) |
| <a id="d34--装配置的东西自己也是被装的东西"></a>D34 | [装配置的东西自己也是被装的东西](decisions/D034.md) |
| <a id="d35--中控只在改变系统时需要不在运行系统时需要"></a>D35 | [中控只在"改变系统"时需要,不在"运行系统"时需要](decisions/D035.md) |
| <a id="d36--发布自动化之后界面就没有命令台"></a>D36 | [发布自动化之后,界面就没有"命令台"](decisions/D036.md) |
| <a id="d37--节点有四个状态加和删要对称"></a>D37 | [节点有四个状态,加和删要对称](decisions/D037.md) |
| <a id="d38--离线根密钥当前有意不做"></a>D38 | [离线根密钥当前有意不做](decisions/D038.md) |
| <a id="d39--发布器也要收敛不能只反应文件变化"></a>D39 | [发布器也要收敛,不能只反应文件变化](decisions/D039.md) |
| <a id="d40--装文件的那一步必须产出自检清单"></a>D40 | [装文件的那一步必须产出自检清单](decisions/D040.md) |
| <a id="d41--界面上的校验按钮不是守卫"></a>D41 | [界面上的校验按钮不是守卫](decisions/D041.md) |
| <a id="d42---形式的引用归那个节点"></a>D42 | [`<什么>/<节点 id>` 形式的引用归那个节点](decisions/D042.md) |
| <a id="d43--56-曾经假设地址不影响该选哪条链这是错的"></a>D43 | [§5.6 曾经假设"地址不影响该选哪条链",这是错的](decisions/D043.md) |
| <a id="d44--接入端只能选服务不能指定地址"></a>D44 | [接入端只能选服务,不能指定地址](decisions/D044.md) |
| <a id="d45--事件只记变化而且记在中控一处"></a>D45 | [事件只记变化,而且记在中控一处](decisions/D045.md) |
| <a id="d46--先装二进制后装配置"></a>D46 | [先装二进制,后装配置](decisions/D046.md) |
| <a id="d47--跑不起来的二进制装上去这台机器就再也拉不到修复了"></a>D47 | [跑不起来的二进制装上去,这台机器就再也拉不到修复了](decisions/D047.md) |
| <a id="d48--发布器在跑的时候手工-publish-曾经是个陷阱"></a>D48 | [发布器在跑的时候,手工 publish 曾经是个陷阱](decisions/D048.md) |
| <a id="d49--只测首字节会挑出连得快传得慢的路"></a>D49 | [只测首字节会挑出连得快、传得慢的路](decisions/D049.md) |
| <a id="d50--合成估计试过不成立"></a>D50 | [合成估计:试过,不成立](decisions/D050.md) |
| <a id="d51--探测有界当前那条必探其余轮换"></a>D51 | [探测有界:当前那条必探,其余轮换](decisions/D051.md) |
| <a id="d52--延迟与吞吐是两个测度用帕累托前沿而不是合成一个数"></a>D52 | [延迟与吞吐是两个测度,用帕累托前沿而不是合成一个数](decisions/D052.md) |
| <a id="d53--共同命运记录路由先给人看暂不进选路"></a>D53 | [共同命运:记录路由,先给人看,暂不进选路](decisions/D053.md) |
| <a id="d54--ttft-与-cost-是扩展点不是缺口"></a>D54 | [`ttft` 与 `cost` 是扩展点,不是缺口](decisions/D054.md) |
| <a id="d55--不是所有变化都是问题"></a>D55 | [不是所有变化都是问题](decisions/D055.md) |
| <a id="d56--隧道地址和端口由分配器算不靠手填"></a>D56 | [隧道地址和端口由分配器算,不靠手填](decisions/D056.md) |
| <a id="d57--该轮换哪几张凭据按候选链算不按-allowed_servers-算"></a>D57 | ["该轮换哪几张凭据"按候选链算,不按 allowed_servers 算](decisions/D057.md) |
| <a id="d58--转述来的节点也要进快照分布表"></a>D58 | [转述来的节点也要进快照分布表](decisions/D058.md) |
| <a id="d59--大块下载同时检测停顿与按签名大小计算的总时限"></a>D59 | [大块下载同时检测停顿与按签名大小计算的总时限](decisions/D059.md) |
| <a id="d60--二进制回滚靠钉住不靠重新编译"></a>D60 | [二进制回滚靠"钉住",不靠重新编译](decisions/D060.md) |
| <a id="d61--源头存档在中控本地不进分发树"></a>D61 | [源头存档在中控本地,不进分发树](decisions/D061.md) |
| <a id="d62--整份回滚源头跟着成品一起回去"></a>D62 | [整份回滚:源头跟着成品一起回去](decisions/D062.md) |
| <a id="d63--发布历史记在中控只记变化"></a>D63 | [发布历史记在中控,只记变化](decisions/D063.md) |
| <a id="d64--备份区分必须有与可以还没有"></a>D64 | [备份区分"必须有"与"可以还没有"](decisions/D064.md) |
| <a id="d65--链路通断要变成事件"></a>D65 | [链路通断要变成事件](decisions/D065.md) |
| <a id="d66--面板问当前状态时长才问历史"></a>D66 | [面板问当前状态,时长才问历史](decisions/D066.md) |
| <a id="d67--同一个测量两种含义target-是数据uplink-才是告警"></a>D67 | [同一个测量,两种含义:target 是数据,uplink 才是告警](decisions/D067.md) |
| <a id="d68--换端口要记住换掉了什么退役名单既是记忆也是盐"></a>D68 | [换端口要记住换掉了什么:退役名单既是记忆也是盐](decisions/D068.md) |
| <a id="d69--版本坐标commit-靠-go-的-vcs-戳不靠构建脚本"></a>D69 | [版本坐标:commit 靠 Go 的 VCS 戳,不靠构建脚本](decisions/D069.md) |
| <a id="d70--当前状态与历史分开一页快照--一堆归档"></a>D70 | [当前状态与历史分开:一页快照 + 一堆归档](decisions/D070.md) |
| <a id="d71--两种没版本性质不同不能都报成告警"></a>D71 | [两种"没版本"性质不同,不能都报成告警](decisions/D071.md) |
| <a id="d72--发布器要自报死活判据是上次成功之后又失败"></a>D72 | [发布器要自报死活,判据是"上次成功之后又失败"](decisions/D072.md) |
| <a id="d73--版本表要用真的答上来了不是拓扑上够得到修正-d71"></a>D73 | [版本表要用"真的答上来了",不是"拓扑上够得到"(修正 D71)](decisions/D073.md) |
| <a id="d74--签名私钥必须进默认备份清单"></a>D74 | [签名私钥必须进默认备份清单](decisions/D074.md) |
| <a id="d75--追溯不回-git-的二进制默认不许发到全网"></a>D75 | [追溯不回 git 的二进制,默认不许发到全网](decisions/D075.md) |
| <a id="d76--备份要递归子目录非普通文件要报出来"></a>D76 | [备份要递归子目录,非普通文件要报出来](decisions/D076.md) |
| <a id="d77--改代码要显式-loom-release改-ssot-才自动发布"></a>D77 | [改代码要显式 `loom release`,改 SSOT 才自动发布](decisions/D077.md) |
| <a id="d78--rollout-是显式状态机但先只观察不接管"></a>D78 | [rollout 是显式状态机,但先只观察不接管](decisions/D078.md) |
| <a id="d79--放行构建产物不放行正在跑的那份"></a>D79 | [放行构建产物,不放行"正在跑的那份"](decisions/D079.md) |
| <a id="d80--换完二进制起子进程续跑不等下一个定时器"></a>D80 | [换完二进制起子进程续跑,不等下一个定时器](decisions/D080.md) |
| <a id="d81--身份签名之后转述来的节点也能核对版本收窄-d73"></a>D81 | [身份签名之后,转述来的节点也能核对版本(收窄 D73)](decisions/D081.md) |
| <a id="d82--删除收敛照-dpkg-的文件清单模型不自己发明"></a>D82 | [删除收敛照 dpkg 的文件清单模型,不自己发明](decisions/D082.md) |
| <a id="d83--拓扑分四层候选存在与实时健康不能互相冒充"></a>D83 | [拓扑分四层，候选存在与实时健康不能互相冒充](decisions/D083.md) |
| <a id="d84--部署是可恢复事务不是按顺序跑完一串命令"></a>D84 | [部署是可恢复事务，不是按顺序跑完一串命令](decisions/D084.md) |
| <a id="d85--发布的原子单位包含输入时刻放行记录与可取回字节"></a>D85 | [发布的原子单位包含输入时刻、放行记录与可取回字节](decisions/D085.md) |
| <a id="d86--组件版本先闭合观测再增加自动升级"></a>D86 | [组件版本先闭合观测，再增加自动升级](decisions/D086.md) |
| <a id="d87--attestation-扩展必须两阶段启用兼容不是永久降级口"></a>D87 | [Attestation 扩展必须两阶段启用，兼容不是永久降级口](decisions/D087.md) |
| <a id="d88--用签名-deployment-envelope-同时闭合反重放与真实-canary"></a>D88 | [用签名 deployment envelope 同时闭合反重放与真实 canary](decisions/D088.md) |
| <a id="d89--控制中心是-ssot-的事务视图不是第二套网络模型"></a>D89 | [控制中心是 SSOT 的事务视图，不是第二套网络模型](decisions/D089.md) |
| <a id="d90--流量历史只由可信相邻-counter-样本推导"></a>D90 | [流量历史只由可信相邻 counter 样本推导](decisions/D090.md) |
| <a id="d91--保留-signed-pull用多镜像消除分发可用性单点"></a>D91 | [保留 signed pull，用多镜像消除分发可用性单点](decisions/D091.md) |
| <a id="d92--拓扑分环表达建连职责链路标签只使用可信滚动观测"></a>D92 | [拓扑分环表达建连职责，链路标签只使用可信滚动观测](decisions/D092.md) |
| <a id="d93--交互式代码发布默认用管理-ssh-并行直发"></a>D93 | [交互式代码发布默认用管理 SSH 并行直发](decisions/D093.md) |
| <a id="d94--v1-客户端收敛为一个中控托管入口端口覆盖退出主模型"></a>D94 | [v1 客户端收敛为一个中控托管入口，端口覆盖退出主模型](decisions/D094.md) |
| <a id="d95--设备默认出口是唯一客户端偏好并复用现有入口"></a>D95 | [设备默认出口是唯一客户端偏好并复用现有入口](decisions/D095.md) |
| <a id="d96--新增出口与全量自动策略池在同一-ssot-事务中收敛"></a>D96 | [新增出口与全量自动策略池在同一 SSOT 事务中收敛](decisions/D096.md) |
| <a id="d97--客户端路由偏好收敛为-directauto指定出口三模式"></a>D97 | [客户端路由偏好收敛为 Direct、Auto、指定出口三模式](decisions/D097.md) |
| <a id="d98--nat-device-只新增-observation-传输适配器不新增状态协议"></a>D98 | [NAT Device 只新增 Observation 传输适配器，不新增状态协议](decisions/D098.md) |
| <a id="d99--wireguard-发起方向与客户端公网数据入口分离"></a>D99 | [WireGuard 发起方向与客户端公网数据入口分离](decisions/D099.md) |
| <a id="d100--control-是节点能力控制集合不固定为三台"></a>D100 | [`control` 是节点能力，控制集合不固定为三台](decisions/D100.md) |
| <a id="d101--crdt-复制材料quorum-commit-定义唯一生效-ssot"></a>D101 | [CRDT 复制材料，quorum commit 定义唯一生效 SSOT](decisions/D101.md) |
| <a id="d102--控制成员管理员deviceca-与公开-tls-使用独立信任域"></a>D102 | [控制成员、管理员、Device、CA 与公开 TLS 使用独立信任域](decisions/D102.md) |
| <a id="d103--托管-dnsacme-与多代-listener-使用同一提交和协调边界"></a>D103 | [托管 DNS/ACME 与多代 listener 使用同一提交和协调边界](decisions/D103.md) |
| <a id="d104--raft-耐久日志决定提交signed-replication-qc-只证明已提交状态"></a>D104 | [Raft 耐久日志决定提交，signed replication QC 只证明已提交状态](decisions/D104.md) |
| <a id="d105--每台-device-的最小视图用-merkle-inclusion-proof-绑定到-quorum-head"></a>D105 | [每台 Device 的最小视图用 Merkle inclusion proof 绑定到 quorum head](decisions/D105.md) |
| <a id="d106--recovery-lineage-与-v2-latch-独立单调bootstrap-绑定旧-floor-和初始信任"></a>D106 | [Recovery lineage 与 v2 latch 独立单调，bootstrap 绑定旧 floor 和初始信任](decisions/D106.md) |
| <a id="d107--公网暴露必须显式授权endpointset-同时承诺地址与传输身份"></a>D107 | [公网暴露必须显式授权，EndpointSet 同时承诺地址与传输身份](decisions/D107.md) |
| <a id="d108--权威-secret-先固化再提交外部副作用按可逆性选择自动化等级"></a>D108 | [权威 secret 先固化再提交，外部副作用按可逆性选择自动化等级](decisions/D108.md) |
| <a id="d109--recovery-policy-的连续轮换必须由旧阈值授权并进入更高-recovery-epoch"></a>D109 | [Recovery policy 的连续轮换必须由旧阈值授权并进入更高 recovery epoch](decisions/D109.md) |
| <a id="d110--recovery-statement-hash-固定为建立该-epoch-的-canonical-statement-body"></a>D110 | [Recovery statement hash 固定为建立该 epoch 的 canonical statement body](decisions/D110.md) |
| <a id="d111--首次-v2-bootstrap-按-payload--transition--headqc-单向构造"></a>D111 | [首次 v2 bootstrap 按 payload → transition → head/QC 单向构造](decisions/D111.md) |
| <a id="d112--controlset-采用-exact-set-bytesjoint-commit-立即改变内部提交规则"></a>D112 | [ControlSet 采用 exact set bytes，Joint commit 立即改变内部提交规则](decisions/D112.md) |
| <a id="d113--计划-recovery-policy-轮换必须验证-intent--threshold-proof--activation"></a>D113 | [计划 recovery policy 轮换必须验证 Intent → threshold proof → Activation](decisions/D113.md) |
| <a id="d114--invite-token-与交付上下文使用两个无环-exact-commitment"></a>D114 | [Invite token 与交付上下文使用两个无环 exact commitment](decisions/D114.md) |
| <a id="d115--qr-只携带有界-descriptor完整证明按-hash-分离"></a>D115 | [QR 只携带有界 descriptor，完整证明按 hash 分离](decisions/D115.md) |
| <a id="d116--新-recovery-policy-与-controlset-的每把用途-key-都必须有-pop"></a>D116 | [新 recovery policy 与 ControlSet 的每把用途 key 都必须有 PoP](decisions/D116.md) |
| <a id="d117--endpoint-provenance-不得反向引用生成它的-head-或-operation-hash"></a>D117 | [Endpoint provenance 不得反向引用生成它的 head 或 operation hash](decisions/D117.md) |
| <a id="d118--joint-commit-后冻结普通提交final-必须紧接-joint"></a>D118 | [Joint commit 后冻结普通提交，Final 必须紧接 Joint](decisions/D118.md) |
| <a id="d119--首版-recovery-epoch-逐次增加不允许跳号"></a>D119 | [首版 recovery epoch 逐次增加，不允许跳号](decisions/D119.md) |
| <a id="d120--公网-listener-与端口轮换必须是-exact-certified-state-machine"></a>D120 | [公网 listener 与端口轮换必须是 exact certified state machine](decisions/D120.md) |
| <a id="d121--v1v2-bootstrap-分离-bodyproof-摘要-domain"></a>D121 | [v1→v2 bootstrap 分离 body/proof 摘要 domain](decisions/D121.md) |
| <a id="d122--公网-tls-稳定身份与例行签发分离"></a>D122 | [公网 TLS 稳定身份与例行签发分离](decisions/D122.md) |
| <a id="d123--invite-固定-exact-device-enrollment-intentclaim-不得扩权"></a>D123 | [invite 固定 exact Device enrollment intent，claim 不得扩权](decisions/D123.md) |
| <a id="d124--公开-controlset-与私有-peer-directory-分离final-payload-不再套空-wrapper"></a>D124 | [公开 ControlSet 与私有 peer directory 分离；Final payload 不再套空 wrapper](decisions/D124.md) |
| <a id="d125--secretdns-地址与公开证书均使用-exact-versioned-dependency-chain"></a>D125 | [secret、DNS 地址与公开证书均使用 exact versioned dependency chain](decisions/D125.md) |
| <a id="d126--invite-重新签发是原子生命周期事务活动-seed-会阻止过早退役"></a>D126 | [invite 重新签发是原子生命周期事务，活动 seed 会阻止过早退役](decisions/D126.md) |
| <a id="d127--活动-listener-rotation-冻结依赖变更必须等待取消或显式安全撤出"></a>D127 | [活动 listener rotation 冻结依赖，变更必须等待、取消或显式安全撤出](decisions/D127.md) |
| <a id="d128--enrollment-保留-direct_only两类-recovery-的-controlset-承诺不同"></a>D128 | [Enrollment 保留 direct_only；两类 recovery 的 ControlSet 承诺不同](decisions/D128.md) |
| <a id="d129--enrollment-claim-使用-token-authorized-operation不借用-admin-envelope"></a>D129 | [Enrollment claim 使用 token-authorized operation，不借用 admin envelope](decisions/D129.md) |
| <a id="d130--enrollment-采用-reservationissuanceapprovalcompletion-原子流程"></a>D130 | [Enrollment 采用 reservation→issuance→approval→completion 原子流程](decisions/D130.md) |
| <a id="d131--公网只承载静态分发与受控-tunnelenrollment-和控制服务退回-overlay"></a>D131 | [公网只承载静态分发与受控 tunnel，Enrollment 和控制服务退回 overlay](decisions/D131.md) |
| <a id="d132--浏览器控制中心采用-optional-client-certificate-的只读管理双边界"></a>D132 | [浏览器控制中心采用 optional client certificate 的只读/管理双边界](decisions/D132.md) |
| <a id="d133--未部署的-windows-不再阻塞活跃平台迁移或-v1-退役"></a>D133 | [未部署的 Windows 不再阻塞活跃平台迁移或 v1 退役](decisions/D133.md) |
| <a id="d134--浏览器入口增加-exact-loopback-端口转发边界"></a>D134 | [浏览器入口增加 exact loopback 端口转发边界](decisions/D134.md) |
| <a id="d135--浏览器-loopback-tls-与-native-control-identity-分离"></a>D135 | [浏览器 loopback TLS 与 native control identity 分离](decisions/D135.md) |
| <a id="d136--nat-映射由操作者提供ssh-与-enrollment-分离"></a>D136 | [NAT 映射由操作者提供，SSH 与 Enrollment 分离](decisions/D136.md) |
| <a id="d137--管理员证书统一签发完整-p-256-链并绑定认证轮换"></a>D137 | [管理员证书统一签发完整 P-256 链并绑定认证轮换](decisions/D137.md) |
| <a id="d138--功能交付包括正常流程生产上线与旧实现删除"></a>D138 | [功能交付包括正常流程、生产上线与旧实现删除](decisions/D138.md) |
| <a id="d139--软件密钥作为当前基线kmshsm-单列后续强化"></a>D139 | [软件密钥作为当前基线，KMS/HSM 单列后续强化](decisions/D139.md) |
