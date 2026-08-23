package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"loom/internal/render"
	"loom/internal/report"
)

// hydrate 把渲染产物里的 ${secret:REF} 占位符替换成真实值。
//
// **节点自取(§14.2.2)之后,这个命令不再是主路径。** 现在合并发生在节点上:
// `loom pull` 取到的包全是占位符,用本机秘密层填(D9、D32)。这个命令留给
// 从工作站 ssh 推的备用路径(`loom apply`),以及本地看渲染结果。
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

	var missing, unmapped []string
	filled, files := 0, 0
	// 每个节点一份清单:机器上的绝对路径 → 内容哈希。节点上的 report
	// 靠它做配置自检 —— 渲染层只有占位符,hydrate 是最后一个知道文件
	// 最终字节的环节。
	hashes := map[string]map[string]string{}

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
		if err := os.WriteFile(dst, result, mode); err != nil {
			return err
		}

		node, bundlePath, ok := strings.Cut(filepath.ToSlash(rel), "/")
		if !ok {
			return nil
		}
		abs := render.InstallPath(bundlePath)
		if abs == "" {
			// 没有约定安装位置的文件不进清单,而不是猜一个路径写进去 ——
			// 猜错的后果是自检永远报 missing,人会以为是漂移。
			unmapped = append(unmapped, rel)
			return nil
		}
		if hashes[node] == nil {
			hashes[node] = map[string]string{}
		}
		h := sha256.Sum256(result)
		hashes[node][abs] = hex.EncodeToString(h[:])
		return nil
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

	// 清单最后写:它不能包含自己(哈希无法自指),也不该被自己的存在影响。
	nodes := make([]string, 0, len(hashes))
	for n := range hashes {
		nodes = append(nodes, n)
	}
	sort.Strings(nodes)
	for _, n := range nodes {
		m := report.Manifest{Node: n, Files: hashes[n]}
		b, err := json.MarshalIndent(&m, "", "  ")
		if err != nil {
			return err
		}
		dst := filepath.Join(*out, n, "report", "manifest.json")
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(dst, append(b, '\n'), 0o644); err != nil {
			return err
		}
	}

	fmt.Printf("✓ %d 个文件,填入 %d 处秘密,%d 份清单 → %s\n", files, filled, len(nodes), *out)
	if len(unmapped) > 0 {
		// 静默漏掉等于自检覆盖不到它,而报告里看不出来。
		sort.Strings(unmapped)
		fmt.Fprintf(os.Stderr, "! %d 个文件没有约定的安装位置,不进自检清单:\n  %s\n",
			len(unmapped), strings.Join(unmapped, "\n  "))
	}
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
