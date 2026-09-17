# 项目工作指引

本分支正在进行 v2 最小重建。开始工作前先完整阅读
[重建入口](docs/rebuild/README.md)，再阅读与任务直接相关的核心模型；涉及本机节点或部署参数时还须阅读
[配置模型](docs/rebuild/configuration-model.md)。用户在当前对话中的明确要求优先于仓库旧设计、旧实现、旧测试和旧 issue。

## 当前边界

- 重建源码基线是 `6be9e4c9`；旧 v2 实现封存在 `archive/v2-overgrown-20260917`，只用于取证和白名单移植。
- 源码回到基线不表示生产回退。现网身份、密钥、数据、认证 floor 和 v2 latch 必须保留，只允许经验证的前向迁移。
- 控制面 Web、Android 和 Windows 的页面、样式、图标与有效交互必须尽量保留；旧 SSOT、registry、report 拼接层和页面专用状态机不因此获得保留资格。
- Windows 原生功能实现与验收在另一台机器进行；本分支保留其 UI 产品资产，但不修改或抵扣原生验收。DNS provider、DNS-01、ACME 自动签发/续期也不属于核心重建。
- 不登录或修改路由器/NAT，只消费操作者已经提供的映射。

## 外部操作预检与完成证据

任务结果包含 GitHub issue 变更、远端 branch/push、release/publish 或其他外部写入时，必须在实质性本地工作开始前完成能力预检：

1. 列出本次必须发生的远端写入及各自所需权限；本地 commit、branch 和草稿不列作远端结果。
2. 先发现并优先复用当前会话或此前成功操作所用通道，包括已连接的 app/plugin/API、项目连接器、项目脚本、`gh` 和 Git credential。缺少 `gh` 只说明该命令不可用，不得据此断言 GitHub 不可写。
3. 分别确认通道处于“已发现、已安装、已连接、已认证、具有所需写权限”的哪一层。插件出现在目录、只读调用成功或历史上曾成功，都不证明本次写权限仍可用；使用不泄露凭据的权限查询、认证读回或受支持 dry-run 验证当前能力。
4. 能读取仓库或 issue 不等于能写。预检必须针对本任务所需动作本身；不得创建测试 issue 制造垃圾。
5. 既有成功通道是首选线索，不是当前可用性的替代证据；不得跳过它直接改用另一条通道，也不得把尚未安装、连接或认证的插件描述为可用。
6. **当前会话已经提供满足目标动作的已连接、已认证远端写通道时，必须直接使用；不得绕开它、降级成本地草稿或声称没有能力。** 其他命令缺失不能抵消这条能力；只有目标写调用、权限查询或受支持 dry-run 的实际拒绝才能证明受阻。
7. 所需写能力仍不可用时，立即报告受阻的具体远端结果、已检查通道及其当前层级/错误、需要的连接动作；不得等本地实现结束后才披露。未受阻的本地工作可继续，但必须始终与远端状态分开陈述。
8. 会话压缩、工具集变化或长任务恢复后，重新发现并复用原通道，不能把暂时未显示的工具误判为能力永久消失。

### 当前服务器的 GitHub HTTPS 凭据

本机已经验证可用的 GitHub 通道是 VS Code Git 扩展提供的 AskPass/IPC。新开的交互终端通常会继承
`GIT_ASKPASS` 和 `VSCODE_GIT_*`，但隔离启动的 agent 命令子进程可能没有继承。两者环境不同不表示
服务器没有凭据，也不能因为 `/root/.git-credentials`、`.netrc`、`gh` 或全局 credential helper 中没有记录
就宣称 GitHub 不可写。

当前进程缺少 AskPass 环境时，先在同一用户、同一仓库目录的现有交互 shell 中发现成功通道，只导入下面
五类变量，不能打印整个 `/proc/<pid>/environ`：

```bash
repo_root=$(git rev-parse --show-toplevel)
askpass_pid=''
for pid in $(pgrep -x bash); do
  [ "$(stat -c %u "/proc/$pid" 2>/dev/null || true)" = "$(id -u)" ] || continue
  [ "$(readlink "/proc/$pid/cwd" 2>/dev/null || true)" = "$repo_root" ] || continue
  if tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null | grep -q '^GIT_ASKPASS='; then
    askpass_pid=$pid
    break
  fi
done
test -n "$askpass_pid"

while IFS= read -r -d '' item; do
  case "$item" in
    GIT_ASKPASS=*|VSCODE_GIT_ASKPASS_EXTRA_ARGS=*|VSCODE_GIT_ASKPASS_MAIN=*|\
    VSCODE_GIT_ASKPASS_NODE=*|VSCODE_GIT_IPC_HANDLE=*) export "$item" ;;
  esac
done < "/proc/$askpass_pid/environ"
```

普通 `git ls-remote`、fetch 或 push 在导入这些变量后直接使用 AskPass。需要调用 GitHub API 时，凭据查询
必须包含精确仓库 `path`，并把 `GIT_TERMINAL_PROMPT=0` 施加在 `git credential fill` 上，而不是管道左侧的
`printf` 上：

```bash
credential=$(
  printf 'protocol=https\nhost=github.com\npath=Scisaga/loom.git\n\n' |
    GIT_TERMINAL_PROMPT=0 git credential fill
)
username=$(printf '%s\n' "$credential" | sed -n 's/^username=//p')
password=$(printf '%s\n' "$credential" | sed -n 's/^password=//p')
test -n "$username" && test -n "$password"
```

不得开启 `set -x`、输出 `credential`/用户名/密码、把 token 放进命令行参数或提交临时文件。API 调用只在
内存中解析密码；如 `curl` 需要认证 header，使用 `0600` 的临时 config 并用 `trap` 在退出时删除。完成后
`unset credential username password`。权限预检读取仓库的 `permissions`，目标写操作后仍按本节上方规则
回读；不得创建测试 issue。若同仓库交互 shell 也没有 AskPass 环境，再检查已连接 app/plugin、项目脚本、
`gh auth status` 和 Git credential helper，并报告各通道的真实层级。

完成状态必须逐层陈述：

- “已提交”至少给出本地 commit；“已推送”还必须回读远端 ref 指向同一 commit；
- “已创建/更新/关闭 issue”必须给出远端 issue URL/编号，并回读标题、正文或状态；
- 本地 branch、commit、issue 草稿或受保护操作稿不能冒充远端 branch、push 或 issue 变更。

发现写入能力中途丢失时，保留已有本地成果并在首次失败后立即报告，不重复盲试，不把整个任务误报为完成。

## 固定工作顺序

每项功能严格按以下五步推进：

1. 从原始需求提取必须结果、明确排除和真实业务入口；
2. 用最少概念设计模型，并先写清领域、wire、持久、运行时和 UI 的对应关系；
3. 枚举覆盖风险等价类的最小必要测试集；
4. 编码、调试，并沿正式入口完成持久化、运行时消费、回读及本任务授权范围内的部署验收；
5. 最小闭环完成后，才可增加有明确新风险依据的扩展测试。

功能由模型表达，不由路由分支、manager、store、receipt、gate、phase 或测试矩阵堆出来。测试不能发明需求，旧测试失败也不能成为恢复被明确删除行为的理由。

## 模型门禁

每个核心模型文档必须使读者无需阅读代码即可知道：

- 有限的领域概念、稳定身份及删除每个概念会破坏的需求；
- 关系、允许的状态转换、不变量和失败/恢复语义；
- domain、wire、persistent、runtime、UI 的逐项映射；
- 哪些映射必须可逆，哪些只是单向投影；
- 一条正常业务链、最小测试和明确禁止恢复的旧实体。

权威领域值 `D`、规范 wire `W` 和持久值 `P` 必须满足：

```text
decode(encode(D)) = D
load(save(D))      = D
```

未知、歧义和非规范输入必须拒绝。运行时和 UI 只能由权威状态单向投影，不能倒写事实。helper、DTO、adapter、缓存和索引不得拥有文档未定义的生命周期或完成判定；缓存必须可删除重建。

如实现需要新增权威实体，先在模型中证明：现有概念无法表达哪项明确需求，以及删除新实体为何会破坏该需求。不能完成该证明就不增加实体。

## 移植与删除

- 旧代码默认不移植；只按[白名单](docs/rebuild/migration-whitelist.md)提取最小纯组件或真实 transport adapter。
- 不整提交、整目录搬运旧状态机。必要能力若与错误权威逻辑混在一起，只提取必要部分并删除其余内容。
- 新路径接管后，在同一工作项删除相应旧 handler、路由、反代、启动项、客户端 fallback、重复 store 和失效测试。
- 注释、测试名和长期文档不引用 issue 编号作为语义来源；链接核心模型的有意义标题。
- 每次只推进一个核心 issue；实现、接线、部署、验收和旧路径删除不能拆成可分别关闭的 issue。

## `.env` 与私有资料

- `.env` 继续管理本机节点和部署输入，但必须经过配置模型定义的严格白名单解码；当前唯一允许直接保存的 provider secret 是 `GANDI_PAT_TOKEN`。它不是控制面 SSOT、运行状态、历史证据或派生值数据库。
- 不读取、打印、提交或在回答中复述秘密值。尽量保存密钥/证书文件引用而非秘密正文；节点别名由 `.ssh_config` 解析。
- 不为每个阶段、命令或默认目录增加环境变量。能由一个根目录、模型或确定性规则推导的值不重复配置。
- 真实部署回执只进入被忽略的 `deploy/evidence/`；可再生输出进入 `out/` 或 `dist/`。
- 文档、测试、注释和原型只使用 `demo-*`、RFC 5737 地址及 `example` 域名，不写真实设备、地址、域名、端口、指纹或运行指标。

## 完成与 issue 判定

除远端结果须满足前述读回门禁外，组件存在、测试通过、端口可达和 HTTP 拒绝都不等于完成。一个结果只有同时满足以下条件才可关闭：

1. 正式 UI/CLI 入口提交正常业务请求；
2. daemon 的真实调用链完成认证和业务处理；
3. 权威状态与必要副作用持久化，重启后可恢复；
4. Linux/Android 或服务运行时实际消费结果；
5. 用户可通过正常入口回读结果；
6. 本任务授权的生产配置和精确制品已激活并留有受保护证据；
7. 被替代旧路径从源码、配置和实际入口消失。

外部条件确实缺失时，报告精确阻碍、已完成内容和剩余业务结果，保持 issue open；不得用“主体完成”“待收尾”掩盖缺口。

## 架构不变量

- 只有接入节点 `access`、服务器节点 `server` 和不受管的目标地址；出口是路径位置，不是节点类型。
- N=1 和 N>1 使用同一控制模型；成员数量只是 `ControlConfig` 的数据，不存在 N=1 门禁或专用模式。
- CRDT 增量同步不可变材料，Raft 排序材料引用和成员变化，QC 只认证可对外消费的头部；三者不得互相替代或复制权威。
- 公网 Nginx 只提供 fake website 和明确认证为公开的通用不可变制品。管理、Enrollment、设备配置和报告只走私有认证服务或受限 bootstrap tunnel。
- 授权不等于可达。客户端用真实 transport/业务结果形成 `available / unavailable / unknown`；声明、ICMP 或 UI 颜色不能制造健康事实。
- Direct、Auto 和指定最终出口复用同一候选模型。指定出口时，一跳直达与经境内节点中继到同一出口可同时存在，由当前网络观测选择。
- 渲染与打包是纯函数：不读时钟、不使用随机数、不查询外部状态；遍历无序集合前稳定排序，时间等外部输入由调用方注入。

## 构建与检查

按改动先运行相关测试，提交前运行：

```bash
go build ./...
go test ./...
go vet ./...
git ls-files --cached --others --exclude-standard -z -- '*.go' | xargs -0 gofmt -l
python3 scripts/check_repository_safety.py
git diff --check
```

格式检查必须无输出。Golden 只能由渲染器更新，更新后人工检查 diff；不得用更新 golden 掩盖模型偏差。
