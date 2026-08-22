// Package secret 处理秘密层:占位符的解析与替换。
//
// **渲染层只写引用,秘密层单独存放,两者在最后一刻才合并**(§12.1、D9)。
// 这个"最后一刻"应当发生在**节点上** —— 分发出去的包里全是
// `${secret:REF}` 占位符,于是分发点、传输链路、乃至快照哈希,统统看不到
// 真实凭据。
package secret

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

var re = regexp.MustCompile(`\$\{secret:([^}]+)\}`)

// Refs 列出内容里引用到的全部秘密,去重并排序。
func Refs(content string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range re.FindAllStringSubmatch(content, -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			out = append(out, m[1])
		}
	}
	sort.Strings(out)
	return out
}

// Hydrate 把占位符换成真实值,返回结果与**缺失的引用**。
//
// 缺失时不报错也不留空 —— 原样保留占位符并如实返回缺了哪些,由调用方决定
// 是整体放弃还是继续。悄悄替换成空字符串会得到一份"看起来正常、实际连不上"
// 的配置。
func Hydrate(content string, secrets map[string]string) (string, []string) {
	var missing []string
	seen := map[string]bool{}
	out := re.ReplaceAllStringFunc(content, func(m string) string {
		ref := re.FindStringSubmatch(m)[1]
		v, ok := secrets[ref]
		if !ok {
			if !seen[ref] {
				seen[ref] = true
				missing = append(missing, ref)
			}
			return m
		}
		return v
	})
	sort.Strings(missing)
	return out, missing
}

// HasPlaceholder 报告内容里还有没有没换掉的占位符。
func HasPlaceholder(content string) bool { return re.MatchString(content) }

// Load 读取 ref=value 格式的秘密文件。
func Load(path string) (map[string]string, error) {
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

// Write 按 ref 排序写出一个秘密文件。用于把总表拆成每节点一份。
func Write(path string, secrets map[string]string, header string) error {
	refs := make([]string, 0, len(secrets))
	for k := range secrets {
		refs = append(refs, k)
	}
	sort.Strings(refs)

	var b strings.Builder
	b.WriteString(header)
	for _, r := range refs {
		fmt.Fprintf(&b, "%s=%s\n", r, secrets[r])
	}
	return os.WriteFile(path, []byte(b.String()), 0o600)
}
