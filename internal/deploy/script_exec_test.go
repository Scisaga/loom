package deploy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runScript 真跑一遍生成出来的脚本,systemctl 用桩子顶掉。
//
// 现有测试全是对脚本**文本**的断言,而 trap 这类东西文本对了不代表行为
// 对 —— 只有真让一条命令失败,才知道回滚有没有发生。
func runScript(t *testing.T, p *Plan, stubExit int) (string, error) {
	t.Helper()
	bin := t.TempDir()
	// systemctl 桩:按 stubExit 决定成败。is-active 永远说 active,
	// 免得验证阶段先失败,盖住我们想测的那条路径。
	stub := "#!/bin/sh\ncase \"$1\" in is-active) echo active;; " +
		"show) echo 0;; esac\nexit " + itoa(stubExit) + "\n"
	if err := os.WriteFile(filepath.Join(bin, "systemctl"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-s")
	cmd.Stdin = strings.NewReader(Script(p, "test-run"))
	cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"))
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	return "1"
}

// **本文件存在的主要理由。**
//
// 脚本是 set -eu 的,install / daemon-reload / systemctl restart 失败时
// shell 立刻退出。以前只有验证阶段走 `|| fail`,所以这些路径上一失败就
// 停在装了一半的状态 —— 而回滚代码明明是有的,只是够不着。
func TestRollbackHappensWhenSystemctlFails(t *testing.T) {
	dir := t.TempDir()
	tgt := filepath.Join(dir, "app.conf")
	if err := os.WriteFile(tgt, []byte("旧内容\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p := &Plan{
		Node:     "n1",
		Files:    map[string]string{tgt: "新内容\n"},
		Triggers: map[string][]string{tgt: {"app.service"}},
	}
	out, err := runScript(t, p, 1) // systemctl 一律失败
	if err == nil {
		t.Fatalf("systemctl 失败了,脚本应该非零退出:\n%s", out)
	}
	got, _ := os.ReadFile(tgt)
	if string(got) != "旧内容\n" {
		t.Fatalf("没回滚 —— 文件是 %q,应该被还原成\"旧内容\"\n%s", got, out)
	}
	if !strings.Contains(out, "回滚") {
		t.Errorf("回滚要说出来,输出里没有:\n%s", out)
	}
}

// 成功时不能回滚 —— trap 撤得干净不干净,只有这条能验。
func TestNoRollbackOnSuccess(t *testing.T) {
	dir := t.TempDir()
	tgt := filepath.Join(dir, "app.conf")
	if err := os.WriteFile(tgt, []byte("旧内容\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p := &Plan{
		Node:     "n1",
		Files:    map[string]string{tgt: "新内容\n"},
		Triggers: map[string][]string{tgt: {"app.service"}},
		Verify:   []string{"app.service"},
	}
	out, err := runScript(t, p, 0)
	if err != nil {
		t.Fatalf("一切正常时不该失败:%v\n%s", err, out)
	}
	got, _ := os.ReadFile(tgt)
	if string(got) != "新内容\n" {
		t.Fatalf("成功了却没装上,文件是 %q\n%s", got, out)
	}
	if strings.Contains(out, "回滚中") {
		t.Errorf("成功时不该回滚 —— trap 没撤干净:\n%s", out)
	}
}

// 什么都没变时不该扰动任何东西,也不该触发回滚。
func TestUnchangedIsAQuietNoop(t *testing.T) {
	dir := t.TempDir()
	tgt := filepath.Join(dir, "app.conf")
	if err := os.WriteFile(tgt, []byte("一样的内容\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p := &Plan{
		Node:     "n1",
		Files:    map[string]string{tgt: "一样的内容\n"},
		Triggers: map[string][]string{tgt: {"app.service"}},
	}
	out, err := runScript(t, p, 1) // systemctl 会失败,但根本不该被调到
	if err != nil {
		t.Fatalf("无变化时不该走到任何 systemctl:%v\n%s", err, out)
	}
	if !strings.Contains(out, "无变化") {
		t.Errorf("应报告无变化:\n%s", out)
	}
	if strings.Contains(out, "回滚中") {
		t.Errorf("无变化时回滚是错的:\n%s", out)
	}
}
