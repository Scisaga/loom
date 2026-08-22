package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// hydrate 把渲染产物里的 ${secret:REF} 占位符替换成真实值。
//
// **这是 Agent 的雏形。** 设计上这一步由节点上的 Agent 在写盘前完成
// (§12.1、D9):渲染层只写引用,秘密层单独存放,两者在最后一刻才合并。
// Agent 属于 L4,还不存在,所以先用一个命令顶着 —— 但语义与将来 Agent
// 要做的完全一致,不是临时妥协。
//
// 它**只写新目录,不改渲染产物**:渲染产物要进快照做哈希比对(§15.3),
// 掺了秘密就既不能 diff 也不能签。

var secretRe = regexp.MustCompile(`\$\{secret:([^}]+)\}`)

func cmdHydrate(args []string) error {
	fs := flag.NewFlagSet("hydrate", flag.ExitOnError)
	in := fs.String("in", "out", "渲染产物目录(只读)")
	out := fs.String("o", "hydrated", "输出目录")
	secretsPath := fs.String("secrets", "", "秘密文件,每行 ref=value")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if *secretsPath == "" {
		return fmt.Errorf("需要 -secrets 指向秘密文件")
	}

	secrets, err := readSecrets(*secretsPath)
	if err != nil {
		return err
	}

	var missing []string
	filled, files := 0, 0

	err = filepath.Walk(*in, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, err := filepath.Rel(*in, p)
		if err != nil {
			return err
		}
		body, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		result := secretRe.ReplaceAllFunc(body, func(m []byte) []byte {
			ref := string(secretRe.FindSubmatch(m)[1])
			v, ok := secrets[ref]
			if !ok {
				missing = append(missing, fmt.Sprintf("%s:%s", rel, ref))
				return m
			}
			filled++
			return []byte(v)
		})

		dst := filepath.Join(*out, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		// 含秘密的文件一律 0600 —— 它们不再是可以随便传阅的渲染产物了。
		mode := os.FileMode(0o644)
		if len(result) != len(body) || secretRe.Match(body) {
			mode = 0o600
		}
		files++
		return os.WriteFile(dst, result, mode)
	})
	if err != nil {
		return err
	}

	// 缺值就整体失败,不写出一份"看起来正常、实际连不上"的配置。
	// 占位符原样留在文件里时,sing-box 会因密码非法拒绝启动 —— 那是好事,
	// 但等到启动时才发现太晚了。
	if len(missing) > 0 {
		sort.Strings(missing)
		_ = os.RemoveAll(*out)
		return fmt.Errorf("以下占位符在秘密文件里找不到值,已放弃写出:\n  %s",
			strings.Join(missing, "\n  "))
	}

	fmt.Printf("✓ %d 个文件,填入 %d 处秘密 → %s\n", files, filled, *out)
	return nil
}

// readSecrets 读取 ref=value 格式的秘密文件。
func readSecrets(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if st, err := f.Stat(); err == nil && st.Mode().Perm()&0o077 != 0 {
		fmt.Fprintf(os.Stderr, "! 秘密文件 %s 权限是 %04o,建议 0600\n", path, st.Mode().Perm())
	}

	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for ln := 1; sc.Scan(); ln++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("%s 第 %d 行不是 ref=value 格式", path, ln)
		}
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out, sc.Err()
}
