package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"loom/internal/version"
)

// cmdVersion 回答"这个二进制是哪一版",并且把答案摆成能和别处对上的形状。
//
// 排障时四个标识老是混:git commit、二进制 sha、SSOT sha、快照 id。
// 这个命令负责前两个,并明说另外两个去哪儿查 —— 混淆的代价是把
// 二进制哈希当成 "HEAD" 写进文档,已经发生过。
func cmdVersion(args []string) error {
	fs := flag.NewFlagSet("version", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "输出 JSON,给脚本用")
	short := fs.Bool("short", false, "只印 commit")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}

	c := version.Self()

	if *short {
		if c.Commit == "" {
			return fmt.Errorf("这个二进制认不出自己是哪个 commit(构建时关掉了 VCS 戳)")
		}
		fmt.Println(c.Commit)
		return nil
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(c)
	}

	fmt.Println(c.Line())
	fmt.Println()
	fmt.Printf("  commit    %s\n", orUnknown(c.Commit))
	if c.Dirty {
		fmt.Printf("            ⚠️ 构建自脏工作区\n")
	}
	fmt.Printf("  binary    %s\n", orUnknown(c.Binary))
	fmt.Printf("            (磁盘上的文件;升级会原地换掉它,不一定等于正在跑的镜像)\n")
	if c.BinaryErr != "" {
		fmt.Printf("            ⚠️ %s\n", c.BinaryErr)
	}
	fmt.Printf("  snapshot  loom report        本机装着的配置是哪一版\n")
	fmt.Printf("  ssot      loom snapshots     发过哪些、源头分别是哪个 sha\n")

	if w := c.Warnings(); len(w) > 0 {
		fmt.Println()
		for _, s := range w {
			fmt.Printf("  ⚠️ %s\n", s)
		}
	}
	return nil
}

func orUnknown(s string) string {
	if s == "" {
		return "(不知道)"
	}
	return s
}
