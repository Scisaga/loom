package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 续跑的子进程正常情况下不会再换二进制(哈希已经对上了),所以深度天然
// 是 1。但**"正常情况"是个假设**,而这个假设错了的代价是 fork 炸弹 ——
// 每一层都再起一个子进程,直到机器躺下。所以显式挡一道,并且钉住。
func TestContinuePullRefusesToNest(t *testing.T) {
	t.Setenv(contEnv, "1")
	err := continuePull("/bin/true", nil)
	if err == nil {
		t.Fatal("已经在续跑里了还要再续跑,必须拒绝")
	}
	if !strings.Contains(err.Error(), "套娃") {
		t.Errorf("错误要说清楚为什么拒绝,得到:%v", err)
	}
}

// 标记必须真的传给子进程 —— 传不下去的话上面那道防护形同虚设。
// 用一个只做一件事的脚本来验:把它看到的环境变量写进文件。
func TestContinuePullMarksTheChild(t *testing.T) {
	if os.Getenv(contEnv) != "" {
		t.Skip("外层已经设了这个变量")
	}
	dir := t.TempDir()
	out := filepath.Join(dir, "seen")
	script := filepath.Join(dir, "probe.sh")
	// $1 是 continuePull 硬塞的 "pull",这里不关心。
	body := "#!/bin/sh\nprintf '%s' \"$" + contEnv + "\" > " + out + "\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := continuePull(script, nil); err != nil {
		t.Fatalf("子进程该正常退出:%v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "1" {
		t.Fatalf("子进程看到的 %s = %q,应该是 \"1\"", contEnv, got)
	}
}
