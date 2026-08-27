package publish

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"loom/internal/version"
)

// Release 是"这份二进制批准发到全网"的**显式**记录。
//
// # 为什么必须显式
//
// 在此之前,发布器每轮重新读 `-binary` 指的那个文件,sha 一变就发。于是
// **任何一次 `go build` 都武装了一次全网升级** —— 改一行状态页面的措辞,
// 5 台机器就各下载 12.5 MB 并重启服务。而人在调试时会编译很多次。
//
// 分开之后规矩变成两条,各自对应一种改动:
//
//	改 SSOT   → 发布器自动发配置(它本来就是声明,改了就该生效)
//	改代码    → 必须 `loom release`(编译只是编译,不是决定)
//
// # 和 Pin 的关系:一对,但方向相反
//
//	Pin      往回锁 —— 出事了,把发布用的二进制钉在某个历史快照上
//	Release  往前放 —— 这份新的我验过了,可以发
//
// 两者同时存在时 **Pin 赢**:它是救火状态,而救火期间不该被一次 release
// 悄悄解开。
//
// # 二进制随记录一起存下来
//
// 记 sha 不够 —— 记完之后 `/usr/local/bin/loom` 还可能再变,那样发布器
// 拿到的就不是被批准的那一份了。所以 release 时按内容寻址复制一份到
// `bin/<sha256>`,发布器只认这个副本。
//
// 副作用是本机攒下了历史二进制,而**回滚因此不用回网络取** —— 这正是
// 快速回滚缺的那块。
type Release struct {
	SHA256 string `json:"sha256"`
	Size   int    `json:"size"`

	// Commit 与 Dirty 来自二进制自己的 VCS 戳(D69)。记在这里是为了
	// "全网跑的是哪个 commit"能从中控这一侧直接答出来,不用逐台问。
	Commit string `json:"commit,omitempty"`
	Dirty  bool   `json:"dirty,omitempty"`

	ReleasedAt string `json:"released_at"`
	By         string `json:"by,omitempty"`
	// Reason 必填。几天后翻到这个文件的人(可能就是你自己)要知道
	// 为什么当时决定发这一版。
	Reason string `json:"reason"`
}

const (
	// DefaultReleaseDir 是所有发布入口共用的显式二进制放行状态。
	DefaultReleaseDir = "deploy/released"
	releaseFile       = "current.json"
	releaseBins       = "bin"
)

// BinaryCandidate 是一次稳定读取到内存里的放行候选。
//
// release 的追溯检查、自检和最终入库必须面对**同一组字节**。如果三个步骤
// 都各自按路径重读,另一个进程可以在它们之间替换文件,最终放行的就不是人
// 刚刚检查过的那份。候选把这次决定所依据的字节钉在内存里,直到 current.json
// 原子落盘。
type BinaryCandidate struct {
	Body   []byte
	SHA256 string
	Size   int
}

// ReadBinaryCandidate 只读源文件一次。后续检查和入库都应携带返回值,不要再
// 回头按路径读。
func ReadBinaryCandidate(path string) (BinaryCandidate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return BinaryCandidate{}, fmt.Errorf("读 %s:%w", path, err)
	}
	if len(b) == 0 {
		return BinaryCandidate{}, fmt.Errorf("%s 是空文件,不能放行", path)
	}
	return newBinaryCandidate(b), nil
}

func newBinaryCandidate(b []byte) BinaryCandidate {
	s := sha256.Sum256(b)
	return BinaryCandidate{Body: b, SHA256: hex.EncodeToString(s[:]), Size: len(b)}
}

// InspectBinary 从候选字节本身读 Go 构建坐标,不再按路径重读。它与
// version.OfFile 的区别正是这个稳定性保证。
func InspectBinary(c BinaryCandidate) (version.Coordinate, error) {
	var out version.Coordinate
	if got := newBinaryCandidate(c.Body); got.SHA256 != c.SHA256 || got.Size != c.Size {
		return out, fmt.Errorf("放行候选在检查期间发生变化(%s → %s)",
			version.Short(c.SHA256), version.Short(got.SHA256))
	}
	bi, err := buildinfo.Read(bytes.NewReader(c.Body))
	if err != nil {
		return out, fmt.Errorf("读候选二进制的构建信息:%w", err)
	}
	out.Binary = c.SHA256
	out.Go = bi.GoVersion
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			out.Commit = s.Value
		case "vcs.modified":
			out.Dirty = s.Value == "true"
		case "GOOS":
			out.Platform = s.Value + out.Platform
		case "GOARCH":
			out.Platform += "/" + s.Value
		}
	}
	return out, nil
}

// checkBinaryCapability reruns the candidate itself from a stable byte copy.
// Release/pin already checked it when authorization was written, but the first
// signed-current publication is a one-way fleet protocol transition: stale or
// manually restored authorization state must not smuggle an old reader into
// generation 1.
func checkBinaryCapability(c BinaryCandidate, stageDir, capability string) error {
	got := newBinaryCandidate(c.Body)
	if got.SHA256 != c.SHA256 || got.Size != c.Size || got.Size == 0 {
		return fmt.Errorf("能力检查候选在读取后发生变化(%s → %s)",
			version.Short(c.SHA256), version.Short(got.SHA256))
	}
	if stageDir == "" {
		return fmt.Errorf("能力检查缺少可执行暂存目录")
	}
	if err := os.MkdirAll(stageDir, 0o700); err != nil {
		return fmt.Errorf("创建能力检查目录:%w", err)
	}
	f, err := os.CreateTemp(stageDir, ".loom-capability-check-*")
	if err != nil {
		return fmt.Errorf("暂存能力检查候选:%w", err)
	}
	path := f.Name()
	defer os.Remove(path)
	fail := func(err error) error {
		_ = f.Close()
		return err
	}
	if err := f.Chmod(0o700); err != nil {
		return fail(err)
	}
	if _, err := f.Write(c.Body); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "selfcheck", "-q", "-require", capability).CombinedOutput()
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("候选 Agent capability %s 自检超过 30s:%w", capability, ctx.Err())
		}
		return fmt.Errorf("候选 Agent 不具备 capability %s:%w\n%s",
			capability, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ReleaseBinPath 是某个 sha 对应的本地副本路径。
func ReleaseBinPath(dir, sha string) string {
	return filepath.Join(dir, releaseBins, sha)
}

// ReadRelease 读当前放行的二进制。没有 release 时返回 (nil, "", nil) ——
// 那是"还没批准过任何二进制",不是错误。
func ReadRelease(dir string) (*Release, string, error) {
	r, bin, _, err := ReadReleaseCandidate(dir)
	return r, bin, err
}

// ReadReleaseCandidate 给发布器返回已经校验过的**同一份字节**,避免先为
// ReadRelease 哈希 14MB、紧接着又为打包重读 14MB。没有 release 时候选
// 为零值。
func ReadReleaseCandidate(dir string) (*Release, string, BinaryCandidate, error) {
	if dir == "" {
		return nil, "", BinaryCandidate{}, nil
	}
	b, err := os.ReadFile(filepath.Join(dir, releaseFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, "", BinaryCandidate{}, nil
	}
	if err != nil {
		return nil, "", BinaryCandidate{}, err
	}
	var r Release
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, "", BinaryCandidate{}, fmt.Errorf("解析 %s:%w", filepath.Join(dir, releaseFile), err)
	}
	if !validSHA256(r.SHA256) {
		return nil, "", BinaryCandidate{}, fmt.Errorf("放行记录里的 sha256 %q 无效", r.SHA256)
	}
	if r.Size <= 0 {
		return nil, "", BinaryCandidate{}, fmt.Errorf("放行记录里的大小 %d 无效", r.Size)
	}
	if err := validateReleaseFields(&r); err != nil {
		return nil, "", BinaryCandidate{}, fmt.Errorf("放行记录无效:%w", err)
	}
	bin := ReleaseBinPath(dir, r.SHA256)
	body, err := os.ReadFile(bin)
	if err != nil {
		// 记录在、二进制副本不在 —— 半个状态。**不要默默回落到
		// 当前二进制**:那正好是 release 要防的事(见类型注释)。
		if errors.Is(err, os.ErrNotExist) {
			return nil, "", BinaryCandidate{}, fmt.Errorf("放行了 %s,但副本 %s 不见了 —— 重新 `loom release` 一次",
				version.Short(r.SHA256), bin)
		}
		return nil, "", BinaryCandidate{}, fmt.Errorf("读放行副本 %s 失败:%w", bin, err)
	}
	c := newBinaryCandidate(body)
	if c.Size != r.Size {
		return nil, "", BinaryCandidate{}, fmt.Errorf("副本 %s 大小对不上(记的 %d,实际 %d)—— 重新 `loom release` 一次",
			bin, r.Size, c.Size)
	}
	if c.SHA256 != r.SHA256 {
		return nil, "", BinaryCandidate{}, fmt.Errorf("副本 %s 内容哈希对不上(记的 %s,实际 %s)—— 重新 `loom release` 一次",
			bin, version.Short(r.SHA256), version.Short(c.SHA256))
	}
	if err := bindReleaseBuildInfo(&r, c); err != nil {
		return nil, "", BinaryCandidate{}, fmt.Errorf("放行记录与副本不一致:%w", err)
	}
	return &r, bin, c, nil
}

// WriteRelease 把 src 那份二进制按内容寻址存下来,并记成当前放行版本。
//
// **先落副本再落记录。** 反过来的话,中途失败会留下"记录指向不存在的
// 副本"这种半状态 —— 而 ReadRelease 只能把它当错误处理,等于发布器停摆。
func WriteRelease(dir, src string, r Release) error {
	c, err := ReadBinaryCandidate(src)
	if err != nil {
		return err
	}
	return WriteReleaseCandidate(dir, c, r)
}

// WriteReleaseCandidate 入库并放行**已经检查过的那一个候选**。
//
// 先原子落内容寻址副本,再原子更新 current.json。已有同名副本也不能因为
// “路径就是哈希”就盲信:磁盘内容仍可能被误改,所以会先核 SHA,不对就用这份
// 已验证候选修复。
func WriteReleaseCandidate(dir string, c BinaryCandidate, r Release) error {
	got := newBinaryCandidate(c.Body)
	if got.SHA256 != c.SHA256 || got.Size != c.Size {
		return fmt.Errorf("放行候选在检查之后发生变化(%s → %s)",
			version.Short(c.SHA256), version.Short(got.SHA256))
	}
	if r.SHA256 != "" && r.SHA256 != c.SHA256 {
		return fmt.Errorf("放行记录期待 %s,候选实际是 %s",
			version.Short(r.SHA256), version.Short(c.SHA256))
	}
	if err := validateReleaseFields(&r); err != nil {
		return fmt.Errorf("放行记录无效:%w", err)
	}
	if err := bindReleaseBuildInfo(&r, c); err != nil {
		return fmt.Errorf("放行记录与候选不一致:%w", err)
	}
	r.SHA256, r.Size = c.SHA256, c.Size

	binDir := filepath.Join(dir, releaseBins)
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return err
	}
	dst := ReleaseBinPath(dir, c.SHA256)
	storedSHA, storedSize, serr := hashFile(dst)
	validStored := serr == nil && storedSHA == c.SHA256 && storedSize == int64(c.Size)
	if serr != nil && !errors.Is(serr, os.ErrNotExist) {
		return fmt.Errorf("检查已有放行副本 %s:%w", dst, serr)
	}
	if !validStored {
		if err := writeFileAtomic(dst, c.Body, 0o755); err != nil {
			return fmt.Errorf("写放行副本 %s:%w", dst, err)
		}
		storedSHA, storedSize, serr = hashFile(dst)
		if serr != nil || storedSHA != c.SHA256 || storedSize != int64(c.Size) {
			return fmt.Errorf("放行副本 %s 原子入库后校验失败(sha=%s,size=%d,err=%v)",
				dst, version.Short(storedSHA), storedSize, serr)
		}
	}

	rb, err := json.MarshalIndent(&r, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(dir, releaseFile), append(rb, '\n'), 0o644)
}

func validateReleaseFields(r *Release) error {
	if strings.TrimSpace(r.Reason) == "" {
		return fmt.Errorf("reason 必填")
	}
	if strings.ContainsRune(r.Reason, '\x00') {
		return fmt.Errorf("reason 含 NUL")
	}
	if r.ReleasedAt == "" {
		return fmt.Errorf("released_at 必填")
	}
	if _, err := time.Parse(time.RFC3339, r.ReleasedAt); err != nil {
		return fmt.Errorf("released_at %q 不是 RFC3339:%w", r.ReleasedAt, err)
	}
	return nil
}

// bindReleaseBuildInfo 让展示用坐标也来自候选本身，而不是盲信 JSON。
//
// 兼容规则：早期记录可能完全没有 Commit/Dirty（两个字段都是零值），读取
// 时用实际 buildinfo 补齐；只要记录声称过任一坐标，就必须与二进制逐项
// 相等。新写入调用方省略坐标时也自动补齐，因此以后落盘的记录都是完整的。
func bindReleaseBuildInfo(r *Release, c BinaryCandidate) error {
	vc, err := InspectBinary(c)
	if err != nil {
		return err
	}
	if r.Commit == "" && !r.Dirty {
		r.Commit, r.Dirty = vc.Commit, vc.Dirty
		return nil
	}
	if r.Commit != vc.Commit || r.Dirty != vc.Dirty {
		return fmt.Errorf("构建坐标不符(记录 commit=%s dirty=%t,实际 commit=%s dirty=%t)",
			version.Short(r.Commit), r.Dirty, version.Short(vc.Commit), vc.Dirty)
	}
	return nil
}

func validSHA256(s string) bool {
	if len(s) != sha256.Size*2 {
		return false
	}
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == sha256.Size && s == hex.EncodeToString(b)
}

func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
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

// writeFileAtomic 用目标同目录里的唯一临时文件 + rename。唯一名避免两个
// publisher/release 进程互相踩固定的 .tmp；同目录保证 rename 不会跨设备
// 退化成 copy+unlink。
func writeFileAtomic(path string, b []byte, mode os.FileMode) (retErr error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if retErr != nil {
			_ = os.Remove(tmp)
		}
	}()
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	// 文件 Sync 只保证临时文件的内容；rename 这个目录项本身还可能在掉电
	// 后丢失。release/current.json 是安全门，必须把父目录也刷稳。
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	if err := dir.Sync(); err != nil {
		_ = dir.Close()
		return err
	}
	return dir.Close()
}

// ClearRelease 停止分发二进制。配置照发。
//
// **不删 bin/ 下的副本** —— 那些是回滚的本地缓存,删了就得回网络取。
func ClearRelease(dir string) error {
	return removeFileDurable(filepath.Join(dir, releaseFile))
}

// removeFileDurable 不只删除目录项，还把父目录刷稳。pin/release 是发布授权：
// 如果只相信 os.Remove，掉电后文件系统可能把已撤销的授权重新带回来。
func removeFileDurable(path string) error {
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("打开已删除文件的父目录 %s:%w", filepath.Dir(path), err)
	}
	if err := dir.Sync(); err != nil {
		_ = dir.Close()
		return fmt.Errorf("刷稳已删除文件的父目录 %s:%w", filepath.Dir(path), err)
	}
	return dir.Close()
}
