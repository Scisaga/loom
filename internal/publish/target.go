package publish

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"loom/internal/netx"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Target 是分发点。
//
// **它不需要被信任**(D32),所以这个接口刻意很窄:能放文件、能说出自己
// 现在指向哪个快照,就够了。没有认证、没有回执 —— 内容的完整性由签名保证,
// 不由传输保证。
type Target interface {
	Push(t *Tree) error
	// Current 返回分发点上 current.json 指向的快照 id。
	Current() (string, error)
	String() string
}

// ParseTarget 解析分发目标。
//
//	/some/dir              本地目录(分发点就在本机)
//	ssh://host/some/dir    经 ssh 推到远端目录
func ParseTarget(spec, sshConfig string) (Target, error) {
	if rest, ok := strings.CutPrefix(spec, "ssh://"); ok {
		host, path, ok := strings.Cut(rest, "/")
		if !ok || host == "" || path == "" {
			return nil, fmt.Errorf("ssh 目标要写成 ssh://<主机>/<绝对路径>,收到 %q", spec)
		}
		return &sshTarget{host: host, dir: "/" + path, sshConfig: sshConfig}, nil
	}
	if !strings.HasPrefix(spec, "/") {
		return nil, fmt.Errorf("本地目标必须是绝对路径,收到 %q", spec)
	}
	return &localTarget{dir: spec}, nil
}

// ---------------------------------------------------------------------------

type localTarget struct{ dir string }

func (l *localTarget) String() string { return l.dir }

// Push 先把新快照那一层写完,**最后**才更新 current.json。
//
// 顺序反了会有一个窗口:current.json 已经指向新快照,而那个快照的文件还没
// 写全 —— 正好来取的节点会拿到 404 或者半截文件。
func (l *localTarget) Push(t *Tree) error {
	for _, p := range t.Paths() {
		if p == "current.json" {
			continue
		}
		dst := filepath.Join(l.dir, p)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(dst, t.Files[p], 0o644); err != nil {
			return err
		}
	}
	return os.WriteFile(filepath.Join(l.dir, "current.json"), t.Files["current.json"], 0o644)
}

func (l *localTarget) Current() (string, error) {
	b, err := os.ReadFile(filepath.Join(l.dir, "current.json"))
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	var c Current
	return c.Snapshot, json.Unmarshal(b, &c)
}

// ---------------------------------------------------------------------------

type sshTarget struct {
	host, dir, sshConfig string
}

func (s *sshTarget) String() string { return "ssh://" + s.host + s.dir }

// Push 用一次 ssh 传完:tar 从 stdin 进去,远端解开。
//
// 同样是**先铺快照层、最后写 current.json** —— 而且 current.json 单独用一次
// 写入完成,不跟在 tar 里,免得解包顺序决定了那个窗口有多长。
//
// 旧快照不删:节点可能正拿着旧 id 在取,而且留着才有回滚的余地。
func (s *sshTarget) Push(t *Tree) error {
	var buf bytes.Buffer
	tw := newTar(&buf)
	for _, p := range t.Paths() {
		if p == "current.json" {
			continue
		}
		if err := tw.add(p, t.Files[p]); err != nil {
			return err
		}
	}
	if err := tw.close(); err != nil {
		return err
	}

	// **命令走参数,数据走 stdin。** 两者挤在同一个 stdin 里的话,
	// 远端的 sh 会把数据的前几块当脚本读掉 —— 报出来的是
	// "tar: This does not look like a tar archive",跟真实原因毫不相干。
	cur := filepath.Join(s.dir, "current.json")
	if err := s.run(fmt.Sprintf("set -eu; mkdir -p %q; tar -C %q -xf -; chmod -R a+rX %q",
		s.dir, s.dir, s.dir), &buf); err != nil {
		return fmt.Errorf("推送快照层:%w", err)
	}
	if err := s.run(fmt.Sprintf("set -eu; cat > %q; chmod a+r %q", cur, cur),
		bytes.NewReader(t.Files["current.json"])); err != nil {
		return fmt.Errorf("更新 current.json:%w", err)
	}
	return nil
}

func (s *sshTarget) Current() (string, error) {
	var out bytes.Buffer
	cmd := s.cmd("cat " + filepath.Join(s.dir, "current.json") + " 2>/dev/null || true")
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return "", err
	}
	body := bytes.TrimSpace(out.Bytes())
	if len(body) == 0 {
		return "", nil
	}
	var c Current
	if err := json.Unmarshal(body, &c); err != nil {
		return "", err
	}
	return c.Snapshot, nil
}

func (s *sshTarget) run(remote string, stdin io.Reader) error {
	cmd := s.cmd(remote)
	cmd.Stdin = stdin
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w:%s", err, strings.TrimSpace(errBuf.String()))
	}
	return nil
}

func (s *sshTarget) cmd(remote string) *exec.Cmd {
	args := []string{"-o", "BatchMode=yes", "-o", "ConnectTimeout=15"}
	if s.sshConfig != "" {
		args = append(args, "-F", s.sshConfig)
	}
	return exec.Command("ssh", append(args, s.host, remote)...)
}

// VerifyServed 从节点视角确认分发点真的在提供这个快照。
//
// 推成功了不等于取得到:nginx 的 alias 写错、权限不对、路径多一层,都会让
// 推送这一侧看起来完全正常。**发布的终点是"节点能取到",不是"文件写完了"。**
func VerifyServed(url, want, dns string, timeout time.Duration) error {
	c := netx.Client(dns, timeout)
	base := strings.TrimRight(url, "/")
	resp, err := c.Get(base + "/current.json")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET current.json → HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return err
	}
	var cur Current
	if err := json.Unmarshal(b, &cur); err != nil {
		return err
	}
	if cur.Snapshot != want {
		return fmt.Errorf("分发点在提供 %s,期望 %s", short(cur.Snapshot), short(want))
	}
	// manifest 也取一下 —— current.json 对而快照层没铺全的情况见过。
	r2, err := c.Get(base + "/" + want + "/snapshot.sig")
	if err != nil {
		return err
	}
	defer r2.Body.Close()
	if r2.StatusCode != http.StatusOK {
		return fmt.Errorf("current.json 指向 %s,但取它的签名得到 HTTP %d", short(want), r2.StatusCode)
	}
	return nil
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	if s == "" {
		return "(空)"
	}
	return s
}
