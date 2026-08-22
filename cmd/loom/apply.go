package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"loom/internal/deploy"
)

// apply 把渲染好的配置包装到机器上(§14)。
//
// 设计上这该由节点上的 Agent 拉取执行,但控制平面还没有(附录 C #14),
// 所以现在从工作站 ssh 推。**语义与将来的拉取一致**:先校验、失败就回滚、
// 装完必须验证。
//
// 在它出现之前,这些步骤是我一条条手打的 —— 于是每次都可能漏掉一步。
// 已经漏过一次:没跑 sing-box check 就重启,配置非法导致崩溃重启循环,
// 而只测了新功能没看服务起没起来。
func cmdApply(args []string) error {
	fs := flag.NewFlagSet("apply", flag.ExitOnError)
	in := fs.String("in", "", "已 hydrate 的产物目录(必需)")
	sshConf := fs.String("ssh-config", ".ssh_config", "ssh 配置文件")
	only := fs.String("node", "", "只装这一个节点(默认全部)")
	dry := fs.Bool("dry-run", false, "只打印会做什么,不连机器")
	timeout := fs.Duration("timeout", 3*time.Minute, "单个节点的超时")
	local := fs.String("local", "", "这个节点是本机,不走 ssh")

	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if *in == "" {
		return fmt.Errorf("需要 -in 指向 loom hydrate 的输出目录")
	}

	bundles, err := readBundles(*in)
	if err != nil {
		return err
	}
	nodes := make([]string, 0, len(bundles))
	for n := range bundles {
		if *only == "" || n == *only {
			nodes = append(nodes, n)
		}
	}
	sort.Strings(nodes)
	if len(nodes) == 0 {
		return fmt.Errorf("%s 里没有找到%s配置包", *in, nodeNote(*only))
	}

	// run id 只用于日志关联,不进任何被哈希的产物。
	runID := time.Now().UTC().Format("20060102-150405")
	fmt.Printf("apply run %s · %d 个节点\n", runID, len(nodes))

	var failed []string
	for _, n := range nodes {
		plan, unmapped := deploy.BuildPlan(n, bundles[n])
		fmt.Printf("\n%s(%d 个文件,涉及 %s)\n", n, len(plan.Files), strings.Join(plan.Verify, " "))
		// 装不了的必须说出来 —— 静默少装会让人以为整套都到位了。
		for _, u := range unmapped {
			fmt.Printf("   ! %s 没有约定的安装位置,不安装\n", u)
		}
		script := deploy.Script(plan, runID)
		if *dry {
			fmt.Printf("   (dry-run:脚本 %d 字节,预检 %d 项)\n", len(script), len(plan.PreCheck))
			for _, c := range plan.PreCheck {
				fmt.Printf("   预检:%s\n", c)
			}
			continue
		}
		if err := runScript(n, script, *sshConf, *local == n, *timeout); err != nil {
			fmt.Printf("   ❌ %v\n", err)
			failed = append(failed, n)
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("%d 个节点失败:%s(已在各自机器上回滚)", len(failed), strings.Join(failed, " "))
	}
	return nil
}

func nodeNote(only string) string {
	if only == "" {
		return ""
	}
	return " " + only + " 的"
}

// runScript 把脚本交给节点执行。脚本从 stdin 进 sh,不落盘 —— 它内嵌了
// 配置内容,其中含秘密。
func runScript(node, script, sshConf string, isLocal bool, timeout time.Duration) error {
	var cmd *exec.Cmd
	if isLocal {
		cmd = exec.Command("sh", "-s")
	} else {
		cmd = exec.Command("ssh", "-F", sshConf, "-o", "BatchMode=yes",
			"-o", fmt.Sprintf("ConnectTimeout=%d", 15), node, "sh -s")
	}
	cmd.Stdin = strings.NewReader(script)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out

	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { done <- cmd.Wait() }()

	var err error
	select {
	case err = <-done:
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		return fmt.Errorf("超过 %s 未完成", timeout)
	}
	for _, line := range strings.Split(strings.TrimRight(out.String(), "\n"), "\n") {
		if strings.TrimSpace(line) != "" && !strings.HasPrefix(line, "Warning:") {
			fmt.Printf("   %s\n", strings.TrimSpace(line))
		}
	}
	return err
}

// readBundles 读回 hydrate 的输出:<目录>/<节点>/<包内路径>。
func readBundles(root string) (map[string]map[string]string, error) {
	out := map[string]map[string]string{}
	ents, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		node := e.Name()
		files := map[string]string{}
		if err := walkInto(root+"/"+node, "", files); err != nil {
			return nil, err
		}
		if len(files) > 0 {
			out[node] = files
		}
	}
	return out, nil
}

func walkInto(dir, prefix string, into map[string]string) error {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range ents {
		if e.IsDir() {
			if err := walkInto(dir+"/"+e.Name(), prefix+e.Name()+"/", into); err != nil {
				return err
			}
			continue
		}
		b, err := os.ReadFile(dir + "/" + e.Name())
		if err != nil {
			return err
		}
		into[prefix+e.Name()] = string(b)
	}
	return nil
}
