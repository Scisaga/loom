# 管理员访问与证书交付

[设计入口](../README.md) · [控制面 Web 投影](../clients/web-ui-projection.md) · [控制权威模型](../core/control-model.md) · [实施状态](../progress.md)

本文记录管理员已可登录中控的现状，并说明 schema 3 目标需补齐的操作链。操作者报告：control 生成的
`admin.p12` 与密码文件已经手动取回到 Windows 笔记本，管理员证书和网站信任材料已安装，能正常访问
中控；`admin-root.crt` 也已按原做法装入 Windows 通用“受信任的根证书颁发机构”存储。旧部署文档
记载了 SSH 回环转发的访问方法，操作者已将其确定为开发调试路径。本轮三个 control 的回环 HTTPS 已通过
浏览器授权、写入、撤权和重启回读，远端通过原 SSH 通道访问；这不替代用户笔记本的本轮复验。
当前证书的实际约束、指纹、存储范围及目标 schema 3 的登录链须分别读回验收。本轮服务器公开证书回读
已确认原 admin 根与叶的对应、clientAuth 用途及 Web 服务端的既有验链锚；匹配的签发私钥在受保护归档中
保留，仅比对公开键，不输出秘密。用户笔记本的安装历史保持成立，本轮存储回读仍由用户完成。
当前补发与授权入口见下文，历史轮换命令不是现行命令。

历史实现的 `control bootstrap` 在 control 上生成 P-256 管理员签发根和 clientAuth 叶，
`control export-admin` 将匹配的叶、私钥和链打成 `admin.p12` 并写独立密码文件；
`rotate-admin` 曾要求旧管理员私钥且只允许 N=1。这说明领证和手动交付已有可行做法，也说明旧轮换逻辑
不能直接承担目标的多 control 补发。历史代码不能证明笔记本当前安装材料与旧生成结果逐字节相同。

## 离网笔记本的开发调试入口

1. 首节点在本机 bootstrap 时生成管理员私钥、客户端叶证书、`admin.p12` 和独立的
   `admin.p12.password`；操作者从受保护的 control 交付目录手动取回包和密码文件。交付目录仅本机
   管理者可读，证书包与密码文件不进入仓库、公开网站、日志或设备配置。这个步骤描述已有业务做法；
   当前 `control admin issue` 生成等价交付物，首次公开叶值须在创建 genesis 时明确纳入；已有网络不能重建 genesis。
2. 在管理用 Windows 账户下，以密码文件中的密码导入 `admin.p12`，核对管理员叶子带对应私钥；
   按操作者已采用的步骤，将 `admin-root.crt` 导入 Windows 通用受信任根存储。网站 HTTPS 信任
   材料也按现网已跑通方式安装。`admin.p12` 提供浏览器客户端身份；网站证书由浏览器验证，
   admin 叶由 control 验证。读回已安装根的指纹、存储范围及实际证书链后，再决定迁移时如何处理；
   不能凭文件名假定两把根相同或不同，也不在本步骤移除任何现有证书。
3. 经已认证的 SSH 连接，把笔记本回环端口转发到**选定的一台** control 的回环 Web 端口。例如
   两端同为演示端口时：

   ```bash
   ssh -N -L 127.0.0.1:7443:127.0.0.1:7443 demo-control
   ```

   浏览器打开 `https://127.0.0.1:7443/`，核验网站 TLS、选择管理员证书并回读管理快照；目标
   写入验收还须沿正式入口提交一次 operation 并回读结果，不能由已有登录结果抵扣。演示端口应
   替换为已配置的实际 Web 端口；SSH 不让笔记本解析 `control.loom`，也不改变浏览器的 SNI 或证书校验名。

这条路径是开发调试通道，不把公网 Nginx、路由器映射或公网 DNS 作为管理入口。笔记本不必先加入
Loom；SSH 身份、浏览器网站 TLS 与管理员 mTLS 各自完成自己的认证。

## 入网设备的正式入口

设备加入 Loom 并取得已验证的配置后，由网络 DNS 将 `control.loom` 解析到处于 serving 的 web 模式
`EndpointGeneration`。浏览器访问 `https://control.loom/`；若已验证入口使用非默认 HTTPS 端口，
URL 须带该端口。同一 URL 使用的全部地址须在该客户端端口提供服务，DNS 的 A/AAAA 记录本身不提供端口。
浏览器用网站信任材料验证实际连接的 control；
管理页面与操作仍须提交有效 `admin.p12` 中的客户端证书。DNS 可以返回多台 control 的私有地址，
连接到其中可达的一台即可；解析成功不证明该节点健康、具备成员资格或有管理权限。该路径不依赖 SSH
转发，也不要求离网笔记本解析 `control.loom`。

## 首证、补发和撤权的目标操作链

- 首节点 bootstrap 在 control 本机生成首位管理员材料，genesis 固定首位管理员的精确受信叶子和
  验链所需的公开信任材料。私钥、`admin.p12` 和密码文件是受保护的交付物，不写入 genesis 或 Web。
- 后续补发仍由 control 端本机 root CLI 生成和交付新管理员私钥、叶证书、`admin.p12` 和独立密码文件；
  证书签发者、验链锚及多 control 如何取得签发能力见下表的当前规则。任一有效 control 可按同一管理 operation
  规则对已验链的新叶签发“加入管理员受信叶子”普通事实。操作者手动取回包并在 Windows
  导入，通过实际可达且已验证 TLS 的 Web 入口（SSH 回环调试或入网后的 `control.loom`）验证
  新叶已能读取管理快照、提交 operation 和回读结果。
  其他 control 收到并投影该事实后才能接受新叶；不得把本地接受写成全网即时生效。
- 补发不要求旧管理员私钥，不受 N=1 限制。需要使旧叶失效时另签“撤销管理员受信叶子”普通事实，
  并在已收到该事实的各 control 回读拒绝结果；已建立的管理 WebSocket 按
  [Web 投影规则](../clients/web-ui-projection.md#页面和状态)终止。证书包丢失时，若新叶尚未进入受信名单，
  清除本机未交付包即可；若已进入，则先撤销该叶，再重新生成和交付，不能只删文件就声称撤权。

现行补发沿用原 P-256 admin 签发根及安装的验链锚：目标是恢复正常领证和撤权；旧办法已经能生成完整 P12，
但轮换要求旧管理员私钥且仅允许 N=1。最小变化是将本机签发与普通叶授权分开，不新增共享 CA 私钥库，
也不恢复旧轮换 receipt。操作者仍手动取回 P12 和密码，增加的明确操作是用原管理员授予新叶，确认登录后再撤销旧叶。

| 边界 | 当前规则 |
|---|---|
| X.509 签发者 | 通过命令显式提供的既有 P-256 admin 根与匹配的 owner-only 私钥；沿用经公开键核验的原能力，不用成员或网站密钥代替 |
| 服务端验链 | 各 control 的 `node.json.browser_tls.trust_file` 指定受保护安装输入；本地 put 先检查该锚和有效期，真实 TLS 再独立验链并匹配精确授权叶 |
| 多 control 补发 | 只有持有操作者明确提供签发引用的 control 能生成包；其他有效 control 可经同一普通事实授信，不要求旧管理员私钥，不按成员数量分支；缺少能力明确失败 |
| 网站 TLS | 本项不改变原回环网站身份；`.loom` 受约束根、独立回环信任边界与两条入口验收继续按下节推进 |

正式本机入口示例：

```bash
sudo loom control admin issue \
  -issuer-cert /etc/loom/demo-admin-root.crt \
  -issuer-key /etc/loom/demo-admin-issuer.key \
  -name 'Demo administrator' -valid-days 365 \
  -out-dir /var/lib/loom/demo-admin-delivery
```

输出目录的父目录必须为当前操作者的 owner-only 目录。交付包含 `admin.crt`、`admin.key`、`admin-root.crt`、
`admin.p12`、`admin.p12.password` 和公开 `admin.json`；私钥只有新管理员叶的私钥，签发私钥不交付。
P12 使用固定的 [Modern2023 编码参数](https://pkg.go.dev/software.sslmate.com/src/go-pkcs12#Modern2023)，
时间与加密熵由调用方注入。同一目录重试验证并保留原证书、私钥和密码，损坏、不同名称或有效时长拒绝覆盖。

原管理员在 Settings 的 Administrators 中选择公开 `admin.json`，点击 Grant administrator access；
它提交 `admin_certificate.put`。CLI 使用同一 `control write` 普通操作。页面显示完整叶指纹和有效期，
Revoke 提交 `admin_certificate.delete`。交付值和授权生命周期的精确字段、依赖、重试、并发及重启规则见
[管理员叶契约](../core/current-contract.md#管理员精确叶授权与交付)。撤销所有浏览器叶时，root-only Unix 管理入口仍可补发和授予。
过期不删除签名历史，但包括已建立连接在内的请求和 WebSocket 不再接受该证书。

首证与补发仍须分别完成实际浏览器 P12 选证、管理写入和回读，不能以生成文件或既有登录结果推定新包可用。
实际部署与原生验证状态见[实施状态](../progress.md)。
临时交付文件可在取回与登录验收后清理，但没有“十分钟后删除”作为领证或证书有效性的前置规则；
删除 control 副本不会删除笔记本已取回的包，也不会改变受信叶子事实。

## 生产网站证书切换门禁

网站签发请求在承载 control 上通过以下入口准备；输出父目录须已存在且为 owner-only：

```bash
loom control website request -state-dir /var/lib/loom-control \
  -endpoint-id demo-web -generation 1 -o /var/lib/loom/demo-delivery/request.json
```

它只生成该 control 的叶私钥与公开 CSR 请求，不生成网站根或签发叶证书。叶私钥留在 control 根目录的
`website-requests/` 下；同一入口代重试保留原私钥和请求。操作者只取回公开的 `request.json`，在离线签发
环境用独立已核对的网络锚、当前成员配置及预期节点、入口代验证并导出标准 PKCS10：

```bash
loom control website verify-request -request /private/demo-delivery/request.json \
  -network-id demo-network -genesis-digest <trusted-genesis-digest> \
  -control-config-id <trusted-current-config-digest> \
  -control-id demo-control -node-id demo-node -endpoint-id demo-web -generation 1 \
  -csr-out /private/demo-delivery/request.pem
```

不要直接把待验证包里自报的值填成独立可信输入。上述命令成功仅证明 CSR 自签名、成员签名及指定入口绑定；
操作者仍须核对当前成员状态，使用受约束的离线网站根按固定模板签发，再将公开叶链交回。
CSR 不启动 listener，不改变 DNS 或现有证书，不代表 `control.loom` 已可访问。

签回后，用同一组独立可信坐标核验公开证书。`-root` 必须是操作者独立指定的公开根，不能从返回材料中
自动选根；根、叶各用一个 PEM 文件，不提供根私钥：

```bash
loom control website verify-certificate -request /private/demo-delivery/request.json \
  -network-id demo-network -genesis-digest <trusted-genesis-digest> \
  -control-config-id <trusted-current-config-digest> \
  -control-id demo-control -node-id demo-node -endpoint-id demo-web -generation 1 \
  -root /private/demo-delivery/website-root.pem -certificate /private/demo-delivery/website-leaf.pem
```

命令检查受约束根、原 CSR 公钥、精确名称、用途、有效期及直接签发链，回读公开摘要和到期时间。
它不导入浏览器信任或激活入口；后续正式安装还须核对本机叶私钥并完成 prepared 预检和实际浏览器回读。

在现有受认证 Web 的 Settings → Website trust 上传单个公开根 PEM，可发布该根并回读、导出或撤销。
设备下一次认证刷新后取得同一公开根；Linux 可从已验证本机 View 列出并显式导出：

```bash
loom client website-root -state /var/lib/loom-device/state.json
loom client website-root -state /var/lib/loom-device/state.json \
  -id <certified-website-root-id> -o /private/demo-delivery/website-root.pem
```

导出校验名称约束与当前有效期，不安装系统信任。撤销使后续 View 和导出入口不再交付该根，不会删除已由
用户导入浏览器的证书；既有浏览器信任须在受保护的换根流程中另行处理。公开根交付也不表示网站叶或入口
已经配置、可达或已通过浏览器验链。

目标 `.loom` 网站根带 critical 名称约束并排除所有 IP，目标网站叶 SAN 仅为 `control.loom`，
根私钥不在任何 control。该证书链不能验证开发调试浏览器使用的 `127.0.0.1`。
[控制模型](../core/control-model.md#9-dns-overlay)已将正式 `.loom` 入口和回环调试入口分开；
独立回环网站身份、信任材料和实际行为仍待核验。目标切换前须用 Windows 浏览器验证 IP SAN、
证书链、管理员登录与回读。该回环信任材料不得冒充受约束的 `.loom` 网站根，也不得成为公网管理入口。

这是生产证书切换的门禁，当前文档和代码尚未证明已通过。切换时读回笔记本上现有网站根、
`admin-root.crt` 的实际证书与信任存储，先让两条入口及新管理员身份
通过真实浏览器验收，再按受保护的前向迁移移除不符合目标约束的旧网站根。证书现状未读回前不宣称
新根已经安装，也不因目标模型已写好而删除当前可用证书。
