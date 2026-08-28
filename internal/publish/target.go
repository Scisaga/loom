package publish

import (
	"bytes"
	"context"
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"loom/internal/netx"
	"loom/internal/render"
	"loom/internal/snapshot"
)

// Target 是分发点。
//
// **它不需要被信任**(D32),所以这个接口刻意很窄:能放文件、能说出自己
// 现在指向哪个快照,就够了。没有认证、没有回执 —— 快照内容真实性由
// snapshot 签名保证；current 的发布授权由 signed envelope 和节点持久化
// generation floor 共同保证，不由传输保证。
type Target interface {
	Push(t *Tree) error
	// ReadFile 读取分发树里的一个小文件。found=false 表示路径不存在；
	// 传输/权限错误必须原样返回，不能和“不存在”混在一起。
	//
	// 发布器用它核对 current 指向的整棵快照，而不只是内容寻址 blob。
	// 否则 snapshot.json、签名或某台节点正文被删后，current 仍相同会
	// 永远跳过重铺。
	ReadFile(path string) (body []byte, found bool, err error)
	// HasBlob 报告内容寻址的大文件是否存在且内容确实与路径里的哈希一致。
	// 路径是一个声明,磁盘仍可能被误改;不能把"同名文件在"当成"内容对"。
	HasBlob(path string) (bool, error)
	// Current 返回分发点上 current.json 指向的快照 id。
	Current() (string, error)
	String() string
}

const (
	// ReadFile 只用于 current、manifest、签名与节点配置。分发点不可信，
	// 不能让它用一个伪造的“大 JSON”把常驻 publisher 撑爆内存。
	maxTargetReadFileBytes = 16 << 20
	maxSSHStderrBytes      = 64 << 10
	maxSSHHashOutputBytes  = 4 << 10
	sshSmallCommandTimeout = 60 * time.Second
	sshPushMinTimeout      = 2 * time.Minute
	sshPushMaxTimeout      = 20 * time.Minute
)

var errSSHOutputLimit = errors.New("ssh 输出超过客户端上限")

// hardLimitBuffer 在超过 limit 时让 os/exec 的复制协程报错并关闭管道。
// 只截断后继续吞数据仍会让一个无限 stdout 的远端命令永久占住 publisher。
type hardLimitBuffer struct {
	buf      bytes.Buffer
	limit    int
	exceeded bool
}

func newHardLimitBuffer(limit int) *hardLimitBuffer { return &hardLimitBuffer{limit: limit} }

func (b *hardLimitBuffer) Write(p []byte) (int, error) {
	remaining := b.limit - b.buf.Len()
	if remaining >= len(p) {
		return b.buf.Write(p)
	}
	if remaining > 0 {
		_, _ = b.buf.Write(p[:remaining])
	}
	b.exceeded = true
	return max(remaining, 0), errSSHOutputLimit
}

func (b *hardLimitBuffer) Bytes() []byte { return b.buf.Bytes() }

// cappedBuffer 保留诊断的开头，但始终向子进程报告已消费全部 stderr。
// 错误输出再大也不会无界占内存或掩盖原始退出状态。
type cappedBuffer struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func newCappedBuffer(limit int) *cappedBuffer { return &cappedBuffer{limit: limit} }

func (b *cappedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	remaining := b.limit - b.buf.Len()
	if remaining > 0 {
		if remaining > len(p) {
			remaining = len(p)
		}
		_, _ = b.buf.Write(p[:remaining])
	}
	if remaining < len(p) {
		b.truncated = true
	}
	return n, nil
}

func (b *cappedBuffer) String() string {
	s := b.buf.String()
	if b.truncated {
		s += "\n…(stderr 已截断)"
	}
	return s
}

// ParseTarget 解析分发目标。
//
//	/some/dir              本地目录(分发点就在本机)
//	ssh://host/some/dir    经 ssh 推到远端目录
func ParseTarget(spec, sshConfig string) (Target, error) {
	if rest, ok := strings.CutPrefix(spec, "ssh://"); ok {
		host, pathPart, ok := strings.Cut(rest, "/")
		if !ok || host == "" || pathPart == "" {
			return nil, fmt.Errorf("ssh 目标要写成 ssh://<主机>/<绝对路径>,收到 %q", spec)
		}
		if err := validateSSHHost(host); err != nil {
			return nil, err
		}
		remotePath := "/" + pathPart
		if err := validateTargetRoot(remotePath, true); err != nil {
			return nil, fmt.Errorf("ssh 分发根目录不安全:%w", err)
		}
		return &sshTarget{host: host, dir: remotePath, sshConfig: sshConfig}, nil
	}
	if err := validateTargetRoot(spec, false); err != nil {
		return nil, fmt.Errorf("本地分发根目录不安全:%w", err)
	}
	return &localTarget{dir: spec}, nil
}

func validateSSHHost(host string) error {
	if host == "" || strings.HasPrefix(host, "-") || strings.ContainsRune(host, '\\') {
		return fmt.Errorf("ssh 主机 %q 不安全", host)
	}
	for _, r := range host {
		if r <= ' ' || r == 0x7f {
			return fmt.Errorf("ssh 主机 %q 含空白或控制字符", host)
		}
	}
	return nil
}

func validateTargetRoot(root string, remote bool) error {
	clean := filepath.Clean(root)
	if remote {
		clean = path.Clean(root)
	}
	if root == "" || !strings.HasPrefix(root, "/") || root == "/" || clean != root ||
		strings.ContainsAny(root, "\\\x00\r\n") {
		return fmt.Errorf("%q 必须是非根目录、规范且无反斜杠的绝对路径", root)
	}
	return nil
}

// ---------------------------------------------------------------------------

type localTarget struct{ dir string }

func (l *localTarget) String() string { return l.dir }

func (l *localTarget) ReadFile(p string) ([]byte, bool, error) {
	if err := validateTreePath(p); err != nil {
		return nil, false, err
	}
	rootFD, err := openAbsoluteDirNoFollow(l.dir, false)
	if errors.Is(err, syscall.ENOENT) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer syscall.Close(rootFD)
	f, err := openFileAtNoFollow(rootFD, p)
	if errors.Is(err, syscall.ENOENT) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxTargetReadFileBytes+1))
	if err != nil {
		return nil, false, err
	}
	if len(b) > maxTargetReadFileBytes {
		return nil, false, fmt.Errorf("分发文件 %s 超过 %d 字节上限", p, maxTargetReadFileBytes)
	}
	return b, true, nil
}

// Push 先把新快照那一层写完,**最后**才更新 current.json。
//
// 顺序反了会有一个窗口:current.json 已经指向新快照,而那个快照的文件还没
// 写全 —— 正好来取的节点会拿到 404 或者半截文件。
func (l *localTarget) HasBlob(p string) (bool, error) {
	want, err := expectedBlobSHA(p)
	if err != nil {
		return false, err
	}
	rootFD, err := openAbsoluteDirNoFollow(l.dir, false)
	if errors.Is(err, syscall.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer syscall.Close(rootFD)
	got, _, err := hashFileAt(rootFD, p)
	if errors.Is(err, syscall.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return got == want, nil
}

func (l *localTarget) Push(t *Tree) error {
	// 先核对整棵树，再写第一个字节。否则一个带 ../ 的
	// node owner 可通过 filepath.Join 逃出分发根目录，而且
	// 报错前还可能已经留下半棵树。
	if err := validateTreePaths(t); err != nil {
		return err
	}
	rootFD, err := openAbsoluteDirNoFollow(l.dir, true)
	if err != nil {
		return fmt.Errorf("打开本地分发根目录:%w", err)
	}
	defer syscall.Close(rootFD)
	// 大文件先推:manifest 引用它们,而 current.json 最后才指过来。
	for p, body := range t.Blobs {
		want, err := expectedBlobSHA(p)
		if err != nil {
			return err
		}
		if got := sha256Bytes(body); got != want {
			return fmt.Errorf("blob %s 的内容实际是 %s,拒绝写入错误的内容寻址路径", p, short(got))
		}
		got, _, err := hashFileAt(rootFD, p)
		has := err == nil && got == want
		if err != nil && !errors.Is(err, syscall.ENOENT) {
			return fmt.Errorf("检查 blob %s:%w", p, err)
		}
		if has {
			continue
		}
		if err := writeAtomicAt(rootFD, p, body, 0o644); err != nil {
			return err
		}
		got, _, err = hashFileAt(rootFD, p)
		if err != nil || got != want {
			return fmt.Errorf("blob %s 原子落盘后校验失败(sha=%s,err=%v)", p, short(got), err)
		}
	}
	for _, p := range t.Paths() {
		if p == "current.json" {
			continue
		}
		// same-current 自愈时 current.json 仍指着这一层。直接 WriteFile
		// 会先 truncate，让节点在修复窗口读到半个 JSON；同目录 temp+rename
		// 保证读者只会看到旧的完整文件或新的完整文件。
		if err := writeAtomicAt(rootFD, p, t.Files[p], 0o644); err != nil {
			return err
		}
	}
	return writeAtomicAt(rootFD, "current.json", t.Files["current.json"], 0o644)
}

// writeAtomic 先写临时文件再 rename。
//
// **current.json 是节点看世界的入口**:它指向哪个快照,节点就装哪个。
// 直接覆写的话,写到一半断掉会留下一个截断的文件 —— 节点解析失败、报错、
// 这一轮什么都不做。不是灾难(它失败得很响),但每台机器都会卡一轮,
// 而 rename 是原子的,这一整类问题不用存在。
func writeAtomic(path string, b []byte, mode os.FileMode) error {
	return writeFileAtomic(path, b, mode)
}

// openAbsoluteDirNoFollow 从 / 开始逐级 openat(O_NOFOLLOW)。
// 只先 Lstat 再 filepath.Join 仍有 check→use 窗口：不可信的本地
// 分发树可在检查后把 snapshot 目录换成 /etc 的 symlink。持有
// 每级 dirfd 后，后续操作即使遇到 rename 竞态也不会逃出那个 inode。
func openAbsoluteDirNoFollow(root string, create bool) (int, error) {
	if err := validateTargetRoot(root, false); err != nil {
		return -1, err
	}
	flags := syscall.O_RDONLY | syscall.O_DIRECTORY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
	fd, err := syscall.Open("/", flags, 0)
	if err != nil {
		return -1, err
	}
	for _, component := range strings.Split(strings.TrimPrefix(root, "/"), "/") {
		next, openErr := syscall.Openat(fd, component, flags, 0)
		if errors.Is(openErr, syscall.ENOENT) && create {
			if mkdirErr := syscall.Mkdirat(fd, component, 0o755); mkdirErr != nil && !errors.Is(mkdirErr, syscall.EEXIST) {
				_ = syscall.Close(fd)
				return -1, fmt.Errorf("创建目录段 %q:%w", component, mkdirErr)
			}
			next, openErr = syscall.Openat(fd, component, flags, 0)
		}
		if openErr != nil {
			_ = syscall.Close(fd)
			return -1, fmt.Errorf("打开目录段 %q（拒绝符号链接/非目录）:%w", component, openErr)
		}
		_ = syscall.Close(fd)
		fd = next
	}
	return fd, nil
}

func openRelativeDirNoFollow(rootFD int, rel string, create bool) (int, error) {
	fd, err := syscall.Dup(rootFD)
	if err != nil {
		return -1, err
	}
	syscall.CloseOnExec(fd)
	if rel == "." {
		return fd, nil
	}
	if err := validateTreePath(rel); err != nil {
		_ = syscall.Close(fd)
		return -1, err
	}
	flags := syscall.O_RDONLY | syscall.O_DIRECTORY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
	for _, component := range strings.Split(rel, string(filepath.Separator)) {
		next, openErr := syscall.Openat(fd, component, flags, 0)
		if errors.Is(openErr, syscall.ENOENT) && create {
			if mkdirErr := syscall.Mkdirat(fd, component, 0o755); mkdirErr != nil && !errors.Is(mkdirErr, syscall.EEXIST) {
				_ = syscall.Close(fd)
				return -1, fmt.Errorf("创建分发目录段 %q:%w", component, mkdirErr)
			}
			next, openErr = syscall.Openat(fd, component, flags, 0)
		}
		if openErr != nil {
			_ = syscall.Close(fd)
			return -1, fmt.Errorf("打开分发目录段 %q（拒绝符号链接/非目录）:%w", component, openErr)
		}
		_ = syscall.Close(fd)
		fd = next
	}
	return fd, nil
}

func openFileAtNoFollow(rootFD int, p string) (*os.File, error) {
	if err := validateTreePath(p); err != nil {
		return nil, err
	}
	dirFD, err := openRelativeDirNoFollow(rootFD, filepath.Dir(p), false)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(dirFD)
	fd, err := syscall.Openat(dirFD, filepath.Base(p),
		syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), p)
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, fmt.Errorf("分发文件 %s 不是普通文件", p)
	}
	return f, nil
}

func hashFileAt(rootFD int, p string) (string, int64, error) {
	f, err := openFileAtNoFollow(rootFD, p)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", n, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func writeAtomicAt(rootFD int, p string, body []byte, mode os.FileMode) (retErr error) {
	if err := validateTreePath(p); err != nil {
		return err
	}
	dirFD, err := openRelativeDirNoFollow(rootFD, filepath.Dir(p), true)
	if err != nil {
		return err
	}
	defer syscall.Close(dirFD)

	var tmp string
	fd := -1
	for attempt := 0; attempt < 10; attempt++ {
		var nonce [8]byte
		if _, err := crand.Read(nonce[:]); err != nil {
			return err
		}
		tmp = "." + filepath.Base(p) + ".tmp-" + hex.EncodeToString(nonce[:])
		fd, err = syscall.Openat(dirFD, tmp,
			syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,
			uint32(mode.Perm()))
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EEXIST) {
			return err
		}
	}
	if fd < 0 || err != nil {
		return fmt.Errorf("创建 %s 的唯一临时文件:%w", p, err)
	}
	f := os.NewFile(uintptr(fd), tmp)
	renamed := false
	defer func() {
		_ = f.Close()
		if !renamed {
			_ = syscall.Unlinkat(dirFD, tmp)
		}
	}()
	if err := f.Chmod(mode); err != nil {
		return err
	}
	if _, err := f.Write(body); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := syscall.Renameat(dirFD, tmp, dirFD, filepath.Base(p)); err != nil {
		return err
	}
	renamed = true
	if err := syscall.Fsync(dirFD); err != nil {
		return err
	}
	return nil
}

func (l *localTarget) Current() (string, error) {
	b, found, err := l.ReadFile("current.json")
	if err != nil {
		return "", err
	}
	if !found {
		return "", nil
	}
	var c Current
	return c.Snapshot, json.Unmarshal(b, &c)
}

// ---------------------------------------------------------------------------

type sshTarget struct {
	host, dir, sshConfig string
	// commandTimeout 只供同包测试把分钟级生产期限缩成毫秒；ParseTarget
	// 从不设置它。所有生产命令仍按 small/push 的默认策略计算。
	commandTimeout time.Duration
}

func (s *sshTarget) String() string { return "ssh://" + s.host + s.dir }

// sshDirectoryGuard 生成一段远端 shell：从 / 开始逐级拒绝 symlink/非目录，
// 可选地逐级创建缺失目录，最后 cd -P 到目标目录并核对物理路径。
//
// 只在命令开始 Lstat 一次不够：`mkdir -p $DIR/bin` 会跟随任一既有 symlink，
// 把有权限的 publisher 诱导到分发根之外。这里不使用 mkdir -p；真正写文件
// 时又以已 cd 的目录为基准，让目标父目录的 rename 不再重新解析祖先路径。
func sshDirectoryGuard(root, rel string, create bool) (string, error) {
	if err := validateTargetRoot(root, true); err != nil {
		return "", err
	}
	absDir := root
	if rel != "." {
		if err := validateTreePath(filepath.ToSlash(rel)); err != nil {
			return "", err
		}
		absDir = path.Join(root, filepath.ToSlash(rel))
		if absDir != root && !strings.HasPrefix(absDir, root+"/") {
			return "", fmt.Errorf("远端目录 %q 逃出分发根 %q", absDir, root)
		}
	}

	rootDepth := len(strings.Split(strings.TrimPrefix(root, "/"), "/"))
	parts := strings.Split(strings.TrimPrefix(absDir, "/"), "/")
	var script strings.Builder
	script.WriteString("set -eu; ")
	for i := range parts {
		prefix := "/" + strings.Join(parts[:i+1], "/")
		q := shellQuote(prefix)
		fmt.Fprintf(&script, "if [ -L %s ]; then echo '拒绝远端符号链接目录' >&2; exit 90; fi; ", q)
		if create {
			fmt.Fprintf(&script, "if [ ! -e %s ]; then mkdir %s; fi; ", q, q)
		} else {
			fmt.Fprintf(&script, "if [ ! -e %s ]; then exit 0; fi; ", q)
		}
		fmt.Fprintf(&script, "if [ -L %s ] || [ ! -d %s ]; then echo '拒绝远端非目录或竞态替换' >&2; exit 90; fi; ", q, q)
		// 只调整分发根及其子目录，不触碰 /、/var 等系统祖先。
		// 在物理 cwd 上 chmod，避免路径在检查和 chmod 间被换成 symlink。
		if create && i+1 >= rootDepth {
			fmt.Fprintf(&script, "if ! (cd -P %s && [ \"$(pwd -P)\" = %s ] && chmod a+rx .); then echo '远端目录物理路径不符' >&2; exit 90; fi; ", q, q)
		}
	}
	qAbs := shellQuote(absDir)
	fmt.Fprintf(&script, "cd -P %s; if [ \"$(pwd -P)\" != %s ]; then echo '远端目录物理路径不符' >&2; exit 90; fi; ", qAbs, qAbs)
	return script.String(), nil
}

func (s *sshTarget) ReadFile(p string) ([]byte, bool, error) {
	if err := validateTreePath(p); err != nil {
		return nil, false, err
	}
	guard, err := sshDirectoryGuard(s.dir, filepath.Dir(p), false)
	if err != nil {
		return nil, false, err
	}
	// 一个前导字节把“不存在”和“存在但为空”分开。快照正文都是小文件；
	// 二进制仍走 HasBlob，只在远端算哈希，不会经 stdout 搬回来。
	out := newHardLimitBuffer(maxTargetReadFileBytes + 1)
	dst := shellQuote("./" + filepath.Base(p))
	remote := guard + fmt.Sprintf(
		"if [ -L %s ]; then echo '拒绝远端符号链接文件' >&2; exit 90; fi; "+
			"if [ -e %s ]; then if [ ! -f %s ]; then echo '拒绝远端非普通文件' >&2; exit 90; fi; printf '\\001'; cat %s; fi",
		dst, dst, dst, dst)
	ctx, cancel, timeout := s.commandContext(sshSmallCommandTimeout)
	defer cancel()
	cmd := s.cmd(ctx, remote, timeout)
	cmd.Stdout = out
	errBuf := newCappedBuffer(maxSSHStderrBytes)
	cmd.Stderr = errBuf
	runErr := cmd.Run()
	if out.exceeded {
		return nil, false, fmt.Errorf("读取 %s 超过 %d 字节上限", p, maxTargetReadFileBytes)
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return nil, false, fmt.Errorf("读取 %s 的 SSH 命令超过 %s 总期限:%w", p, timeout, context.DeadlineExceeded)
	}
	if runErr != nil {
		return nil, false, fmt.Errorf("%w:%s", runErr, strings.TrimSpace(errBuf.String()))
	}
	b := out.Bytes()
	if len(b) == 0 {
		return nil, false, nil
	}
	if b[0] != 1 {
		return nil, false, fmt.Errorf("读取 %s 的远端协议前缀无效", p)
	}
	return append([]byte(nil), b[1:]...), true, nil
}

// Push 用一次 ssh 传完:tar 从 stdin 进去,远端解开。
//
// 同样是**先铺快照层、最后写 current.json** —— 而且 current.json 单独用一次
// 写入完成,不跟在 tar 里,免得解包顺序决定了那个窗口有多长。
//
// 旧快照不删:节点可能正拿着旧 id 在取,而且留着才有回滚的余地。
func (s *sshTarget) HasBlob(p string) (bool, error) {
	want, err := expectedBlobSHA(p)
	if err != nil {
		return false, err
	}
	guard, err := sshDirectoryGuard(s.dir, filepath.Dir(p), false)
	if err != nil {
		return false, err
	}
	out := newHardLimitBuffer(maxSSHHashOutputBytes)
	// 不能只 test -s:同名内容寻址文件仍可能被误写。远端每次真正算 SHA,
	// 只有内容与路径一致才复用。
	qdst := shellQuote("./" + filepath.Base(p))
	remote := guard + fmt.Sprintf(
		"if [ -L %s ]; then echo '拒绝远端符号链接 blob' >&2; exit 90; fi; "+
			"if [ -e %s ]; then if [ ! -f %s ]; then echo '拒绝远端非普通 blob' >&2; exit 90; fi; sha256sum %s | awk '{print $1}'; fi",
		qdst, qdst, qdst, qdst)
	ctx, cancel, timeout := s.commandContext(sshSmallCommandTimeout)
	defer cancel()
	cmd := s.cmd(ctx, remote, timeout)
	cmd.Stdout = out
	errBuf := newCappedBuffer(maxSSHStderrBytes)
	cmd.Stderr = errBuf
	runErr := cmd.Run()
	if out.exceeded {
		return false, fmt.Errorf("检查 %s 时 ssh stdout 超过 %d 字节", p, maxSSHHashOutputBytes)
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return false, fmt.Errorf("检查 %s 的 SSH 命令超过 %s 总期限:%w", p, timeout, context.DeadlineExceeded)
	}
	if runErr != nil {
		return false, fmt.Errorf("%w:%s", runErr, strings.TrimSpace(errBuf.String()))
	}
	got := strings.TrimSpace(string(out.Bytes()))
	return got == want, nil
}

func (s *sshTarget) Push(t *Tree) error {
	if err := validateTreePaths(t); err != nil {
		return err
	}
	// 大文件单独推,而且**已经在的不重传** —— 12MB 每次发布都推是白费,
	// 而路径就是内容哈希,在即是对。
	for p, body := range t.Blobs {
		want, err := expectedBlobSHA(p)
		if err != nil {
			return err
		}
		if got := sha256Bytes(body); got != want {
			return fmt.Errorf("blob %s 的内容实际是 %s,拒绝推到错误的内容寻址路径", p, short(got))
		}
		has, err := s.HasBlob(p)
		if err != nil {
			return fmt.Errorf("查 %s:%w", p, err)
		}
		if has {
			continue
		}
		guard, err := sshDirectoryGuard(s.dir, filepath.Dir(p), true)
		if err != nil {
			return err
		}
		base := shellQuote("./" + filepath.Base(p))
		// 临时文件必须与目标同目录,最后 rename。下载/SSH 中断时只留下临时
		// 文件,不会让下一轮把一个截断的同名 blob 当作已存在。固定 `.tmp.$$`
		// 可被远端预置 symlink；mktemp 在已验真的 cwd 内排他创建普通文件。
		remote := guard + fmt.Sprintf(
			"tmp=$(mktemp './.loom-blob.XXXXXX'); "+
				"if [ -L \"$tmp\" ] || [ ! -f \"$tmp\" ]; then echo 'mktemp 未返回普通文件' >&2; exit 90; fi; "+
				"trap 'rm -f \"$tmp\"' EXIT; cat > \"$tmp\"; chmod a+r \"$tmp\"; "+
				"if [ -L %s ] || { [ -e %s ] && [ ! -f %s ]; }; then echo '拒绝远端非普通 blob 目标' >&2; exit 90; fi; "+
				"mv -fT \"$tmp\" %s; trap - EXIT; "+
				"if [ -L %s ] || [ ! -f %s ]; then echo 'blob rename 后不是普通文件' >&2; exit 90; fi",
			base, base, base, base, base, base)
		if err := s.run(remote, bytes.NewReader(body), sshPushTimeout(int64(len(body)))); err != nil {
			return fmt.Errorf("推送 %s:%w", p, err)
		}
		if ok, err := s.HasBlob(p); err != nil || !ok {
			return fmt.Errorf("推送 %s 后校验失败(ok=%v,err=%v)", p, ok, err)
		}
	}

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
	rootGuard, err := sshDirectoryGuard(s.dir, ".", true)
	if err != nil {
		return err
	}
	// 先把 tar 解到目标目录内的临时树，再逐文件 rename 到位。临时树与
	// 目标在同一文件系统，mv 是原子的；same-current 修复也不会把正在
	// 服务的 JSON truncate 成半截。
	var install strings.Builder
	install.WriteString(rootGuard)
	install.WriteString("ROOT=$(pwd -P); stage=$(mktemp -d './.loom-push.XXXXXX'); ")
	install.WriteString("if [ -L \"$stage\" ] || [ ! -d \"$stage\" ]; then echo 'mktemp 未返回普通目录' >&2; exit 90; fi; ")
	install.WriteString("STAGE=$(cd -P \"$stage\" && pwd -P); case \"$STAGE\" in \"$ROOT\"/.loom-push.*) ;; *) echo 'staging 逃出分发根' >&2; exit 90;; esac; ")
	install.WriteString("trap 'rm -rf \"$STAGE\"' EXIT; tar -C \"$STAGE\" -xf -; ")
	for _, p := range t.Paths() {
		if p == "current.json" {
			continue
		}
		if err := validateTreePath(p); err != nil {
			return err
		}
		guard, err := sshDirectoryGuard(s.dir, filepath.Dir(p), true)
		if err != nil {
			return err
		}
		install.WriteString(guard)
		src := shellQuote(filepath.ToSlash(p))
		dst := shellQuote("./" + filepath.Base(p))
		fmt.Fprintf(&install,
			"src=\"$STAGE\"/%s; if [ -L \"$src\" ] || [ ! -f \"$src\" ]; then echo 'staging 正文不是普通文件' >&2; exit 90; fi; "+
				"if [ -L %s ] || { [ -e %s ] && [ ! -f %s ]; }; then echo '拒绝远端非普通正文目标' >&2; exit 90; fi; "+
				"chmod a+r \"$src\"; mv -fT \"$src\" %s; "+
				"if [ -L %s ] || [ ! -f %s ]; then echo '正文 rename 后不是普通文件' >&2; exit 90; fi; ",
			src, dst, dst, dst, dst, dst, dst)
	}
	install.WriteString(rootGuard)
	install.WriteString("rm -rf \"$STAGE\"; trap - EXIT; ")
	if err := s.run(install.String(), &buf, sshPushTimeout(int64(buf.Len()))); err != nil {
		return fmt.Errorf("推送快照层:%w", err)
	}
	// 同样先落临时文件再 mv。**mv 在同一个文件系统上是原子的**,
	// 所以临时文件必须和目标同目录 —— 放 /tmp 的话跨设备,mv 退化成
	// copy+unlink,原子性就没了。
	qcur := shellQuote("./current.json")
	currentRemote := rootGuard + fmt.Sprintf(
		"tmp=$(mktemp './.loom-current.XXXXXX'); "+
			"if [ -L \"$tmp\" ] || [ ! -f \"$tmp\" ]; then echo 'mktemp 未返回普通文件' >&2; exit 90; fi; "+
			"trap 'rm -f \"$tmp\"' EXIT; cat > \"$tmp\"; chmod a+r \"$tmp\"; "+
			"if [ -L %s ] || { [ -e %s ] && [ ! -f %s ]; }; then echo '拒绝远端非普通 current 目标' >&2; exit 90; fi; "+
			"mv -fT \"$tmp\" %s; trap - EXIT; "+
			"if [ -L %s ] || [ ! -f %s ]; then echo 'current rename 后不是普通文件' >&2; exit 90; fi",
		qcur, qcur, qcur, qcur, qcur, qcur)
	if err := s.run(currentRemote, bytes.NewReader(t.Files["current.json"]), sshPushTimeout(int64(len(t.Files["current.json"])))); err != nil {
		return fmt.Errorf("更新 current.json:%w", err)
	}
	return nil
}

func expectedBlobSHA(p string) (string, error) {
	clean := filepath.Clean(p)
	want := filepath.Base(clean)
	if !validSHA256(want) {
		return "", fmt.Errorf("内容寻址路径 %q 没有合法 sha256 文件名", p)
	}
	if filepath.IsAbs(p) || clean != filepath.Join("bin", want) {
		return "", fmt.Errorf("内容寻址路径 %q 必须严格是 bin/<sha256>", p)
	}
	return want, nil
}

func validateTreePath(p string) error {
	clean := filepath.Clean(p)
	if p == "" || clean == "." || clean == ".." || filepath.IsAbs(p) || clean != p ||
		strings.HasPrefix(clean, ".."+string(filepath.Separator)) || strings.ContainsAny(p, "\\\x00\r\n") {
		return fmt.Errorf("分发树路径 %q 必须是规范的相对路径", p)
	}
	return nil
}

func validateTreePaths(t *Tree) error {
	if t == nil {
		return fmt.Errorf("分发树为 nil")
	}
	for p := range t.Files {
		if err := validateTreePath(p); err != nil {
			return err
		}
	}
	for p := range t.Blobs {
		if _, err := expectedBlobSHA(p); err != nil {
			return err
		}
	}
	return nil
}

func sha256Bytes(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func (s *sshTarget) Current() (string, error) {
	body, found, err := s.ReadFile("current.json")
	if err != nil {
		return "", err
	}
	if !found {
		return "", nil
	}
	var c Current
	if err := json.Unmarshal(bytes.TrimSpace(body), &c); err != nil {
		return "", err
	}
	return c.Snapshot, nil
}

// shellQuote 给远端 /bin/sh 生成单引号参数。fmt %q 产生的是双引号,其中的
// $() 和反引号仍会被 shell 执行；target 路径来自命令行,不能把它当脚本。
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

func sshPushTimeout(size int64) time.Duration {
	if size < 0 {
		size = 0
	}
	// 给握手和远端落盘至少两分钟；之后每 MiB 增加十秒，最大二十分钟。
	// 慢链路有余量，同时不允许任意大小的输入把 publish.lock 永久占住。
	mib := (size + (1 << 20) - 1) / (1 << 20)
	d := sshPushMinTimeout + time.Duration(mib)*10*time.Second
	if d > sshPushMaxTimeout {
		return sshPushMaxTimeout
	}
	return d
}

func (s *sshTarget) commandContext(defaultTimeout time.Duration) (context.Context, context.CancelFunc, time.Duration) {
	timeout := defaultTimeout
	if s.commandTimeout > 0 {
		timeout = s.commandTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	return ctx, cancel, timeout
}

func (s *sshTarget) run(remote string, stdin io.Reader, defaultTimeout time.Duration) error {
	ctx, cancel, timeout := s.commandContext(defaultTimeout)
	defer cancel()
	cmd := s.cmd(ctx, remote, timeout)
	cmd.Stdin = stdin
	errBuf := newCappedBuffer(maxSSHStderrBytes)
	cmd.Stderr = errBuf
	if err := cmd.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("SSH 推送命令超过 %s 总期限:%w", timeout, context.DeadlineExceeded)
		}
		return fmt.Errorf("%w:%s", err, strings.TrimSpace(errBuf.String()))
	}
	return nil
}

func (s *sshTarget) cmd(ctx context.Context, remote string, timeout time.Duration) *exec.Cmd {
	args := []string{"-o", "BatchMode=yes", "-o", "ConnectTimeout=15"}
	if s.sshConfig != "" {
		args = append(args, "-F", s.sshConfig)
	}
	cmd := exec.CommandContext(ctx, "ssh", append(args, s.host, remote)...)
	// CommandContext 杀掉 ssh 后，它的本地子进程仍可能暂时持有 stdout/stderr
	// pipe。WaitDelay 给这些 pipe 一个短清理窗口，之后强制关闭，避免“命令已
	// 超时但 Wait 仍被继承 fd 卡死”。测试注入的短期限也相应缩短。
	cmd.WaitDelay = min(timeout, 5*time.Second)
	return cmd
}

// VerifyServed 从节点视角确认分发点真的在提供这个快照。
//
// 推成功了不等于取得到:nginx 的 alias 写错、权限不对、路径多一层,都会让
// 推送这一侧看起来完全正常。**发布的终点是"节点能取到",不是"文件写完了"。**
func VerifyServed(url, want, dns string, timeout time.Duration, expected *Tree, pub ed25519.PublicKey) error {
	if expected == nil {
		return fmt.Errorf("缺少本地可信 Tree,无法核对节点视角正文")
	}
	if err := validateTreePaths(expected); err != nil {
		return fmt.Errorf("本地可信 Tree 路径无效:%w", err)
	}
	c := netx.Client(dns, timeout)
	base := strings.TrimRight(url, "/")
	b, err := getServedFile(c, base+"/current.json", "current.json", 1<<16)
	if err != nil {
		return err
	}
	wantCurrentBody, ok := expected.Files["current.json"]
	if !ok {
		return fmt.Errorf("本地可信 Tree 缺少 current.json")
	}
	wantCurrent, err := DecodeDeploymentCurrent(wantCurrentBody)
	if err != nil {
		return fmt.Errorf("本地可信 Tree 的 current.json 不是 signed deployment current:%w", err)
	}
	if err := wantCurrent.Verify(pub); err != nil {
		return fmt.Errorf("本地可信 Tree 的 current.json 签名无效:%w", err)
	}
	if wantCurrent.Snapshot != want {
		return fmt.Errorf("本地 signed current 指向 %s,调用方期望 %s",
			short(wantCurrent.Snapshot), short(want))
	}
	// Exact bytes matter here, not only snapshot.  A replayed/lowered
	// generation can legitimately point at the same immutable snapshot.
	if !bytes.Equal(b, wantCurrentBody) {
		return fmt.Errorf("节点视角 current.json 与本地 signed authority 不完全一致")
	}
	cur, err := DecodeDeploymentCurrent(b)
	if err != nil {
		return fmt.Errorf("节点视角 current.json 不是严格 signed envelope:%w", err)
	}
	if err := cur.Verify(pub); err != nil {
		return fmt.Errorf("节点视角 current.json 验签失败:%w", err)
	}
	if cur.Snapshot != want {
		return fmt.Errorf("分发点在提供 %s,期望 %s", short(cur.Snapshot), short(want))
	}
	wantManifestPath := expected.Snapshot + "/snapshot.json"
	var wantManifest snapshot.Manifest
	if err := json.Unmarshal(expected.Files[wantManifestPath], &wantManifest); err != nil {
		return fmt.Errorf("解析本地产物 %s:%w", wantManifestPath, err)
	}
	manifestPath := want + "/snapshot.json"
	manifestBytes, err := getServedFile(c, base+"/"+manifestPath, manifestPath, 4<<20)
	if err != nil {
		return err
	}
	var gotManifest snapshot.Manifest
	if err := json.Unmarshal(manifestBytes, &gotManifest); err != nil {
		return fmt.Errorf("解析节点视角 %s:%w", manifestPath, err)
	}
	if gotManifest.ID != want {
		return fmt.Errorf("current.json 指向 %s,但 manifest 自称 %s", short(want), short(gotManifest.ID))
	}
	signaturePath := want + "/snapshot.sig"
	sig, err := getServedFile(c, base+"/"+signaturePath, signaturePath, 1<<10)
	if err != nil {
		return err
	}
	if err := snapshot.VerifySignature(manifestBytes, sig, pub); err != nil {
		return fmt.Errorf("节点视角 manifest/signature 校验失败:%w", err)
	}
	if want == expected.Snapshot {
		if !sameSnapshotContent(&gotManifest, &wantManifest) {
			return fmt.Errorf("节点视角 manifest 与本地产物不符")
		}
	} else if !sameRuntimeContent(&gotManifest, &wantManifest) {
		return fmt.Errorf("保留的 current 快照与本轮运行产物不符")
	}

	// Phase 2 may assign older immutable snapshots to a canary subset.  The
	// envelope signature authenticates those IDs, but a green publish must also
	// prove every selected tree is actually reachable, internally complete, and
	// contains an actionable bundle/decommission instruction for that node.
	assignedManifests := map[string]*snapshot.Manifest{want: &gotManifest}
	for _, assignment := range cur.Assignments {
		selected, err := cur.Select(assignment.Node)
		if err != nil {
			return fmt.Errorf("核对节点 %s 的 assignment:%w", assignment.Node, err)
		}
		if selected != assignment.Snapshot {
			return fmt.Errorf("节点 %s assignment 选择 %s，记录却是 %s",
				assignment.Node, selected, assignment.Snapshot)
		}
		manifest := assignedManifests[selected]
		if manifest == nil {
			manifest, err = verifyServedAssignedSnapshot(c, base, selected, pub)
			if err != nil {
				return fmt.Errorf("assignment %s → %s 的节点视角表面不完整:%w",
					assignment.Node, short(selected), err)
			}
			assignedManifests[selected] = manifest
		}
		if !manifestAddressesNode(manifest, assignment.Node) {
			return fmt.Errorf("assignment %s → %s，但该快照既没有节点正文也没有 decommission 指令",
				assignment.Node, short(selected))
		}
	}

	// manifest 与签名完整仍不等于节点正文/二进制可取。逐个核所有小配置包；
	// 二进制也必须从节点实际使用的 HTTP 路径流式读取并核 size+SHA。
	// Target.HasBlob 只能证明落盘侧有文件，不能证明 nginx/CDN 的 bin 路由、
	// alias 和权限正确。
	for _, p := range expected.Paths() {
		if p == "current.json" || p == wantManifestPath || p == expected.Snapshot+"/snapshot.sig" {
			continue
		}
		servedPath := p
		if suffix, ok := strings.CutPrefix(p, expected.Snapshot+"/"); ok {
			servedPath = want + "/" + suffix
		}
		got, err := getServedFile(c, base+"/"+servedPath, servedPath, 8<<20)
		if err != nil {
			return err
		}
		if !bytes.Equal(got, expected.Files[p]) {
			return fmt.Errorf("节点视角正文 %s 内容与本地产物不符", servedPath)
		}
	}
	seenBlobs := make(map[string]struct{}, len(gotManifest.Binaries))
	for i := range gotManifest.Binaries {
		ref := &gotManifest.Binaries[i]
		if _, seen := seenBlobs[ref.Path()]; seen {
			continue
		}
		seenBlobs[ref.Path()] = struct{}{}
		if err := verifyServedBlob(c, base, ref, expected.Blobs[ref.Path()]); err != nil {
			return err
		}
	}
	return nil
}

// verifyServedAssignedSnapshot verifies an immutable snapshot without needing
// its local Tree.  Both current and manifest are signed by the platform key;
// manifest hashes then bind every node body and binary blob.
func verifyServedAssignedSnapshot(c *http.Client, base, id string, pub ed25519.PublicKey) (*snapshot.Manifest, error) {
	manifestPath := id + "/snapshot.json"
	manifestBytes, err := getServedFile(c, base+"/"+manifestPath, manifestPath, 4<<20)
	if err != nil {
		return nil, err
	}
	signaturePath := id + "/snapshot.sig"
	sig, err := getServedFile(c, base+"/"+signaturePath, signaturePath, 1<<10)
	if err != nil {
		return nil, err
	}
	if err := snapshot.VerifySignature(manifestBytes, sig, pub); err != nil {
		return nil, fmt.Errorf("manifest/signature 校验失败:%w", err)
	}
	var manifest snapshot.Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return nil, fmt.Errorf("解析 %s:%w", manifestPath, err)
	}
	if manifest.ID != id {
		return nil, fmt.Errorf("manifest 自称 %s，assignment 期望 %s", short(manifest.ID), short(id))
	}

	owners := make(map[string]struct{}, len(manifest.Bundles))
	for _, ref := range manifest.Bundles {
		if _, duplicate := owners[ref.Owner]; duplicate {
			return nil, fmt.Errorf("manifest 重复声明节点正文 %s", ref.Owner)
		}
		owners[ref.Owner] = struct{}{}
		bundlePath := id + "/nodes/" + ref.Owner + ".json"
		if err := validateTreePath(bundlePath); err != nil {
			return nil, fmt.Errorf("节点正文路径无效:%w", err)
		}
		body, err := getServedFile(c, base+"/"+bundlePath, bundlePath, 8<<20)
		if err != nil {
			return nil, err
		}
		bundle, err := decodeServedBundle(body)
		if err != nil {
			return nil, fmt.Errorf("解析节点正文 %s:%w", bundlePath, err)
		}
		if bundle.Owner != ref.Owner {
			return nil, fmt.Errorf("节点正文路径属于 %s，正文却自称 %s", ref.Owner, bundle.Owner)
		}
		if got := servedBundleHash(bundle.Files); got != ref.Hash {
			return nil, fmt.Errorf("节点正文 %s hash=%s，manifest 期望 %s",
				ref.Owner, short(got), short(ref.Hash))
		}
	}
	seenBlobs := make(map[string]struct{}, len(manifest.Binaries))
	for i := range manifest.Binaries {
		ref := &manifest.Binaries[i]
		if _, seen := seenBlobs[ref.Path()]; seen {
			continue
		}
		seenBlobs[ref.Path()] = struct{}{}
		if err := verifyServedBlob(c, base, ref, nil); err != nil {
			return nil, err
		}
	}
	return &manifest, nil
}

func manifestAddressesNode(manifest *snapshot.Manifest, node string) bool {
	if manifest == nil {
		return false
	}
	for _, ref := range manifest.Bundles {
		if ref.Owner == node {
			return true
		}
	}
	for _, dead := range manifest.Decommissioned {
		if dead == node {
			return true
		}
	}
	return false
}

func decodeServedBundle(body []byte) (*Bundle, error) {
	if err := rejectDuplicateJSONKeys(body); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var bundle Bundle
	if err := dec.Decode(&bundle); err != nil {
		return nil, err
	}
	if err := requireJSONEOF(dec); err != nil {
		return nil, err
	}
	return &bundle, nil
}

func servedBundleHash(files map[string]string) string {
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	bundle := render.Bundle{}
	for _, p := range paths {
		bundle.Files = append(bundle.Files, render.File{Path: p, Content: files[p]})
	}
	return bundle.Hash()
}

func verifyServedBlob(c *http.Client, base string, ref *snapshot.BinaryRef, expected []byte) error {
	p := ref.Path()
	if _, err := expectedBlobSHA(p); err != nil {
		return fmt.Errorf("节点视角 manifest 的二进制引用无效:%w", err)
	}
	if ref.Size < 0 {
		return fmt.Errorf("节点视角 manifest 的二进制 %s size=%d 无效", p, ref.Size)
	}

	wantSize := int64(ref.Size)
	if expected != nil && int64(len(expected)) != wantSize {
		return fmt.Errorf("本地可信 blob %s 长度=%d,manifest 期望 %d", p, len(expected), wantSize)
	}
	if wantSize == 0 {
		resp, err := c.Get(base + "/" + p)
		if err != nil {
			return fmt.Errorf("GET %s:%w", p, err)
		}
		return verifyFullServedBlobResponse(resp, p, ref)
	}

	// Push/HasBlob already computes the complete SHA256 at the distribution
	// origin, and every node computes it again before activation.  Re-downloading
	// a multi-megabyte immutable blob through the public route on every 30-second
	// publisher reconciliation adds no new trust boundary: on a slow route it
	// only holds publish.lock until the HTTP client times out.  Range probes here
	// verify the node-facing route, declared total size, and deterministic content
	// samples.  A server without Range support falls back to the old full-body
	// verification, preserving compatibility.
	offsets := []int64{0, wantSize / 2, wantSize - 1}
	seen := map[int64]bool{}
	for _, offset := range offsets {
		if seen[offset] {
			continue
		}
		seen[offset] = true
		req, err := http.NewRequest(http.MethodGet, base+"/"+p, nil)
		if err != nil {
			return fmt.Errorf("创建 Range GET %s:%w", p, err)
		}
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", offset, offset))
		resp, err := c.Do(req)
		if err != nil {
			return fmt.Errorf("Range GET %s@%d:%w", p, offset, err)
		}
		if resp.StatusCode == http.StatusOK {
			if offset != 0 {
				_ = resp.Body.Close()
				return fmt.Errorf("Range GET %s@%d 意外退化成完整响应", p, offset)
			}
			return verifyFullServedBlobResponse(resp, p, ref)
		}
		if resp.StatusCode != http.StatusPartialContent {
			_ = resp.Body.Close()
			return fmt.Errorf("Range GET %s@%d → HTTP %d", p, offset, resp.StatusCode)
		}
		wantRange := fmt.Sprintf("bytes %d-%d/%d", offset, offset, wantSize)
		if got := resp.Header.Get("Content-Range"); got != wantRange {
			_ = resp.Body.Close()
			return fmt.Errorf("Range GET %s@%d Content-Range=%q,期望 %q", p, offset, got, wantRange)
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 2))
		closeErr := resp.Body.Close()
		if readErr != nil {
			return fmt.Errorf("Range GET %s@%d 读取:%w", p, offset, readErr)
		}
		if closeErr != nil {
			return fmt.Errorf("Range GET %s@%d 关闭:%w", p, offset, closeErr)
		}
		if len(body) != 1 {
			return fmt.Errorf("Range GET %s@%d 返回 %d 字节,期望 1", p, offset, len(body))
		}
		if expected != nil && body[0] != expected[offset] {
			return fmt.Errorf("Range GET %s@%d 内容与本地产物不符", p, offset)
		}
	}
	return nil
}

func verifyFullServedBlobResponse(resp *http.Response, p string, ref *snapshot.BinaryRef) error {
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s → HTTP %d", p, resp.StatusCode)
	}
	wantSize := int64(ref.Size)
	if resp.ContentLength >= 0 && resp.ContentLength != wantSize {
		return fmt.Errorf("GET %s 长度=%d,期望 %d", p, resp.ContentLength, wantSize)
	}

	h := sha256.New()
	n, err := io.CopyN(h, resp.Body, wantSize)
	if err != nil {
		return fmt.Errorf("GET %s 只读到 %d/%d 字节:%w", p, n, wantSize, err)
	}
	var extra [1]byte
	nExtra, err := resp.Body.Read(extra[:])
	if nExtra != 0 || err == nil {
		return fmt.Errorf("GET %s 超过 manifest 声明的 %d 字节", p, wantSize)
	}
	if err != io.EOF {
		return fmt.Errorf("GET %s 核对结尾:%w", p, err)
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != ref.SHA256 {
		return fmt.Errorf("GET %s sha256=%s,期望 %s", p, got, ref.SHA256)
	}
	return nil
}

func getServedFile(c *http.Client, url, label string, limit int64) ([]byte, error) {
	resp, err := c.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s → HTTP %d", label, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("GET %s 超过 %d 字节上限", label, limit)
	}
	return b, nil
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
