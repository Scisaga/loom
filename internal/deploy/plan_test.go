package deploy

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"
)

func bundle() map[string]string {
	return map[string]string{
		"sing-box/config.json":              `{"log":{}}`,
		"agent/config.json":                 `{"node":"n"}`,
		"report/config.json":                `{"node":"n"}`,
		"report/manifest.json":              `{"files":{}}`,
		"systemd/sing-box.service":          "[Unit]\n",
		"systemd/loom-agent.service":        "[Unit]\n",
		"systemd/loom-report.service":       "[Unit]\n",
		"systemd/loom-wg-reresolve.service": "[Unit]\n",
		"systemd/loom-wg-reresolve.timer":   "[Timer]\n",
		"systemd/loom-pull.service":         "[Unit]\n",
		"systemd/loom-pull.timer":           "[Timer]\n",
		"wireguard/wg-edge-a.conf":          "[Interface]\n",
		"某个没有约定位置的东西":                       "x",
	}
}

// oneshot 单元跑完就 inactive。把它放进"装完必须 active"的名单里,
// 每次部署都会"失败并回滚",而实际上一切正常。
func TestOneshotUnitIsNotVerified(t *testing.T) {
	p, _ := BuildPlan("n", bundle())
	for _, s := range p.Verify {
		if s == "loom-wg-reresolve" || s == "loom-pull" {
			t.Errorf("oneshot 的 %s 进了验证名单", s)
		}
	}
	want := map[string]bool{
		"wg-quick@wg-edge-a": true, "sing-box": true,
		"loom-report": true, "loom-agent": true,
		"loom-wg-reresolve.timer": true,
		"loom-pull.timer":         true,
	}
	got := map[string]bool{}
	for _, s := range p.Verify {
		got[s] = true
	}
	for s := range want {
		if !got[s] {
			t.Errorf("%s 应当被验证,却不在名单里(%v)", s, p.Verify)
		}
	}
}

// 只改了 sing-box 配置却把隧道也重启一遍,会白白断一次线。
func TestTriggersArePerFile(t *testing.T) {
	p, _ := BuildPlan("n", bundle())
	cases := map[string][]string{
		"/etc/loom/sing-box/config.json": {"sing-box"},
		"/etc/loom/agent/config.json":    {"loom-agent"},
		"/etc/loom/report/config.json":   {"loom-report"},
		"/etc/wireguard/wg-edge-a.conf":  {"wg-quick@wg-edge-a"},
	}
	for path, want := range cases {
		got := p.Triggers[path]
		if len(got) != len(want) || (len(got) > 0 && got[0] != want[0]) {
			t.Errorf("%s 触发 %v,期望 %v", path, got, want)
		}
	}
	// 清单只被读取,改了不该重启谁。
	if len(p.Triggers["/etc/loom/report/manifest.json"]) != 0 {
		t.Error("改清单竟然会触发重启")
	}
	// 常驻 unit 的 ExecStart/Capability/Sandbox 只有 restart 才生效；仅
	// daemon-reload 会让旧进程 is-active 假绿。
	for _, u := range []string{"sing-box", "loom-agent", "loom-report"} {
		got := p.Triggers["/etc/systemd/system/"+u+".service"]
		if len(got) != 1 || got[0] != u {
			t.Errorf("%s.service 变化没有触发自身重启:%v", u, got)
		}
	}
}

// 装不了的文件必须报出来 —— 静默少装会让人以为整套都到位了。
func TestUnmappedFilesAreReported(t *testing.T) {
	_, unmapped := BuildPlan("n", bundle())
	if len(unmapped) != 1 || unmapped[0] != "某个没有约定位置的东西" {
		t.Errorf("没有约定位置的文件没被报出来:%v", unmapped)
	}
}

// 含秘密的文件必须 0600。判据是路径而不是内容 —— 猜错的方向没有任何症状。
func TestSecretFilesAre0600(t *testing.T) {
	for _, p := range []string{
		"/etc/wireguard/wg-edge-a.conf",
		"/etc/loom/sing-box/config.json",
		"/etc/loom/agent/config.json",
	} {
		if Mode(p) != "0600" {
			t.Errorf("%s 的权限是 %s,含秘密的必须 0600", p, Mode(p))
		}
	}
	if Mode("/etc/systemd/system/sing-box.service") != "0644" {
		t.Error("unit 文件不该是 0600")
	}
}

// 预检必须在覆盖线上文件**之前**。顺序反了的话,检查失败时旧配置已经没了。
func TestPreCheckRunsBeforeInstall(t *testing.T) {
	p, _ := BuildPlan("n", bundle())
	sc := Script(p, "test")
	check := strings.Index(sc, "sing-box check")
	install := strings.Index(sc, "install -m")
	if check < 0 {
		t.Fatal("脚本里没有预检")
	}
	if install < 0 || check > install {
		t.Errorf("预检在安装之后(check@%d install@%d)", check, install)
	}
	// 预检必须跑在暂存目录上,不是线上路径。
	if !strings.Contains(sc, "sing-box check -c "+StagingRoot) {
		t.Error("预检没有跑在暂存目录上")
	}
}

// 什么都没装的时候,"回滚"必须是彻底的空操作 —— 否则一次干净的拒绝会
// 变成一次真实的扰动(实测踩过:预检失败却重启了三个隧道)。
func TestRestoreIsNoopWhenNothingChanged(t *testing.T) {
	p, _ := BuildPlan("n", bundle())
	sc := Script(p, "test")
	if !strings.Contains(sc, `case "$state" in`) || !strings.Contains(sc, `active)`) {
		t.Error("回滚没有只认持久化的 active 事务标记")
	}
	if !strings.Contains(sc, `'') rm -rf "$STAGE" "$PREV"`) {
		t.Error("没有 active 标记时回滚不是空操作")
	}
}

func TestNodeLockPrecedesTransactionCleanup(t *testing.T) {
	p := &Plan{Node: "n", Files: map[string]string{"/tmp/x": "y"}}
	sc := Script(p, "test")
	lock := strings.Index(sc, "flock -n 9")
	recover := strings.Index(sc, "\nrecover_pending\n")
	trap := strings.Index(sc, "trap on_exit EXIT")
	init := strings.Index(sc, `: > "$PREV/.manifest"`)
	if lock < 0 || recover < 0 || init < 0 || trap < 0 {
		t.Fatalf("脚本缺部署锁或事务恢复/初始化：lock=%d recover=%d init=%d trap=%d", lock, recover, init, trap)
	}
	if !(lock < recover && recover < init && init < trap) {
		t.Fatalf("必须先拿锁、恢复旧事务、初始化空清单，最后才挂回滚 trap：lock=%d recover=%d init=%d trap=%d", lock, recover, init, trap)
	}
	if !strings.Contains(sc, "write_txn_state active") || !strings.Contains(sc, "write_txn_state committed") {
		t.Fatal("脚本没有完整的 active/committed 持久事务协议")
	}
}

func TestScriptRejectsBroadOrRelativeTransactionRoots(t *testing.T) {
	for _, layout := range []scriptPaths{
		{stageRoot: "/", previousRoot: "/tmp/previous", lockPath: "/tmp/lock"},
		{stageRoot: "relative", previousRoot: "/tmp/previous", lockPath: "/tmp/lock"},
		{stageRoot: "/tmp/stage", previousRoot: "/tmp/previous", lockPath: "/"},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("危险事务路径没有在生成 shell 前被拒绝：%+v", layout)
				}
			}()
			script(&Plan{Node: "n", Files: map[string]string{}}, "test", layout)
		}()
	}
}

// wg-quick 不能用 systemctl restart:down 与 up 之间有竞态,报
// "already exists",而接口其实还在 —— unit 是 failed 而隧道看起来是好的。
func TestWgQuickRestartAvoidsTheRace(t *testing.T) {
	p, _ := BuildPlan("n", bundle())
	sc := Script(p, "test")
	if !strings.Contains(sc, "ip link del") {
		t.Error("wg-quick 重启没有先清掉残留接口")
	}
}

// 路径或服务名里的引号不能把脚本撑破。
func TestShellQuoting(t *testing.T) {
	if got := shq(`a'b`); got != `'a'"'"'b'` {
		t.Errorf("单引号转义不对:%s", got)
	}
}

func TestGeneratedScriptHasValidShellSyntax(t *testing.T) {
	p, _ := BuildPlan("n", bundle())
	sc := Script(p, "syntax-test")
	cmd := exec.Command("sh", "-n")
	cmd.Stdin = strings.NewReader(sc)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		lines := strings.Split(sc, "\n")
		if len(lines) > 235 {
			lines = lines[220:235]
		}
		t.Fatalf("生成脚本 shell 语法错误:%v\n%s\n附近脚本:\n%s", err, stderr.String(), strings.Join(lines, "\n"))
	}
}

func TestHashIsStable(t *testing.T) {
	a, _ := BuildPlan("n", bundle())
	b, _ := BuildPlan("n", bundle())
	if a.Hash() != b.Hash() {
		t.Error("同样的输入算出不同的哈希")
	}
	m := bundle()
	m["sing-box/config.json"] = `{"log":{"level":"debug"}}`
	c, _ := BuildPlan("n", m)
	if a.Hash() == c.Hash() {
		t.Error("内容变了哈希没变")
	}
}

// loom-pull.service 的 ExecStart 就是 `loom pull`。在一次 pull 的安装阶段
// 重启它,等于在一次安装里再套一次安装 —— 实测的后果是内层那次把外层的
// 回滚清单清空了,外层失败时"回滚"变成空操作,机器停在装了一半的状态。
func TestPullServiceIsNeverRestarted(t *testing.T) {
	p, _ := BuildPlan("n", bundle())
	if svcs := p.Triggers["/etc/systemd/system/loom-pull.service"]; len(svcs) != 0 {
		t.Errorf("loom-pull.service 变化会触发 %v —— 它会自己套自己", svcs)
	}
	for _, s := range p.Services() {
		if s == "loom-pull" {
			t.Error("loom-pull 出现在待重启列表里")
		}
	}
	if strings.Contains(Script(p, "x"), "restart_one 'loom-pull'") {
		t.Error("脚本里会重启 loom-pull")
	}
}

// 新装的单元必须 enable,否则重启一次机器就全没了 ——
// 而这件事只有在真的重启那天才会发现。
func TestNewUnitsGetEnabled(t *testing.T) {
	p, _ := BuildPlan("n", bundle())
	sc := Script(p, "x")
	if !strings.Contains(sc, "ensure_enabled 'loom-pull.timer'") {
		t.Error("timer 没有经过可验证的 enable 收敛")
	}
	if !strings.Contains(sc, `systemctl enable "$1"`) {
		t.Error("常驻服务没有 enable")
	}
	if strings.Contains(sc, "systemctl enable \"$1\" 2>/dev/null || true") {
		t.Error("enable 失败仍被吞掉")
	}
}

// enable 是期望状态的一部分,不是文件内容的一部分。只在文件变化时才 enable,
// 会留下"现在能用、重启就没了"的机器 —— cn-b 的 loom-pull.timer 就这样过。
// 所以确认 enable 必须在"无变化就早退"**之前**。
func TestEnableRunsEvenWhenNothingChanged(t *testing.T) {
	p, _ := BuildPlan("n", bundle())
	sc := Script(p, "x")
	ensure := strings.Index(sc, "is-enabled")
	early := strings.Index(sc, `if [ "$changed" = 0 ]`)
	if ensure < 0 {
		t.Fatal("脚本里没有确认 enable 的步骤")
	}
	if early < 0 || ensure > early {
		t.Errorf("确认 enable 在早退之后(ensure@%d early@%d)—— 无变化时就不会执行", ensure, early)
	}
}

// NRestarts 是 Service 的属性,Timer 没有。对 timer 查它会拿到空串,
// 而 [ "" = 0 ] 恒假 —— 于是每次部署都"失败并回滚",实测在 cn-a 上发生过。
func TestTimersAreNotCheckedForNRestarts(t *testing.T) {
	p, _ := BuildPlan("n", bundle())
	for _, line := range strings.Split(Script(p, "x"), "\n") {
		if strings.Contains(line, "NRestarts") && strings.Contains(line, ".timer") {
			t.Errorf("对 timer 查了 NRestarts:%s", line)
		}
	}
}

// 差集就是 dpkg 的模型:上次装了、这次不装了的才删。
func TestStaleFilesIsTheDifference(t *testing.T) {
	p := &Plan{Files: map[string]string{
		"/etc/wireguard/wg-a.conf":    "x",
		"/etc/loom/agent/config.json": "y",
	}}
	got := p.StaleFiles([]string{
		"/etc/wireguard/wg-a.conf",                  // 还在,不删
		"/etc/wireguard/wg-b.conf",                  // 不在了,删
		"/etc/systemd/system/wg-quick@wg-b.service", // 不在了,删
		"/etc/loom/agent/config.json",               // 还在,不删
	})
	want := []string{
		"/etc/systemd/system/wg-quick@wg-b.service",
		"/etc/wireguard/wg-b.conf",
	}
	if len(got) != len(want) {
		t.Fatalf("该删 %v,得到 %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("顺序或内容不对:%v vs %v", got, want)
		}
	}
}

// **清单为空 = 什么都不删。** "不知道上次装了什么"和"上次什么都没装"
// 在结果上必须一样 —— 猜错的代价是把一台正常机器清空。
func TestEmptyManifestRemovesNothing(t *testing.T) {
	p := &Plan{Files: map[string]string{"/etc/loom/agent/config.json": "y"}}
	if got := p.StaleFiles(nil); len(got) != 0 {
		t.Fatalf("清单为空时不该删任何东西,得到 %v", got)
	}
}

// 从绝对路径反推该停哪个服务 —— 要删的文件已经不在渲染输出里了,
// BuildPlan 那套 bundlePath → 服务的映射对它无能为力。
func TestUnitFor(t *testing.T) {
	for _, c := range []struct{ path, want string }{
		{"/etc/wireguard/wg-demo-a.conf", "wg-quick@wg-demo-a"},
		{"/etc/systemd/system/loom-agent.service", "loom-agent"},
		{"/etc/systemd/system/loom-pull.timer", "loom-pull.timer"},
		{"/etc/loom/sing-box/config.json", "sing-box"},
		{"/etc/loom/agent/config.json", "loom-agent"},
		{"/etc/loom/report/config.json", "loom-report"},
		{"/etc/systemd/system/some.conf", ""}, // 不是 unit
		{"/random/path", ""},
	} {
		if got := UnitFor(c.path); got != c.want {
			t.Errorf("UnitFor(%q) = %q,想要 %q", c.path, got, c.want)
		}
	}
}
