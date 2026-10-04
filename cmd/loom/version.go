package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"loom/internal/version"
)

// cmdVersion reports executable build coordinates, independently of accepted configuration.
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
	fmt.Printf("  accepted  loom client inspect  已持久接受的认证 View\n")
	fmt.Printf("  runtime   loom client status   实际执行与观测回读\n")

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
