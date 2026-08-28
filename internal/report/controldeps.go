package report

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"loom/internal/enrollkey"
	"loom/internal/enrollssh"
	"loom/internal/model"
	"loom/internal/netx"
	"loom/internal/ssotedit"
	"loom/internal/validate"
	"loom/internal/webui"
)

// controlDeps 把中控配置接到界面上。
//
// 界面唯一能做的写操作是**改 SSOT**。发布是自动的 —— 发布器盯着同一个文件,
// 存盘之后 30 秒内接管(§14.2.3)。
func controlDeps(c *Control) *webui.ControlDeps {
	// HTTP handler 可能同时收到多个保存。原子 rename 能保证读者不会看到
	// 半截 YAML,这把锁则让同一个中控进程内的“校验 + 替换”成为一个串行事务。
	var saveMu sync.Mutex

	revision := func(content []byte) string {
		sum := sha256.Sum256(content)
		return fmt.Sprintf("%x", sum[:])
	}
	read := func() ([]byte, error) {
		snapshot, err := readSSOTSnapshot(c.SSOTPath)
		return snapshot.body, err
	}
	guardRevision := func(current []byte, expected string) error {
		if expected == "" {
			return fmt.Errorf("表单缺少 SSOT revision，请重新加载后再保存")
		}
		if got := revision(current); got != expected {
			return fmt.Errorf("SSOT 已被其他操作修改，请重新加载并合并变更后再保存")
		}
		return nil
	}
	validateContent := func(content []byte) error {
		s, err := model.Load(content)
		if err != nil {
			return fmt.Errorf("解析失败,未保存:%w", err)
		}
		if fs := validate.Validate(s); len(fs) > 0 {
			return fmt.Errorf("校验不通过,未保存")
		}
		return nil
	}
	save := func(content []byte, expected string, guarded bool) error {
		saveMu.Lock()
		defer saveMu.Unlock()
		return withSSOTLock(c.SSOTPath, func() error {
			snapshot, err := readSSOTSnapshot(c.SSOTPath)
			if err != nil {
				return fmt.Errorf("保存前读取 SSOT:%w", err)
			}
			if guarded {
				if err := guardRevision(snapshot.body, expected); err != nil {
					return err
				}
			}
			if err := validateContent(content); err != nil {
				return err
			}
			return saveSSOTAtomicFromSnapshot(c.SSOTPath, content, snapshot)
		})
	}
	mutateService := func(input *webui.ServiceInput, deleteID, expected string) error {
		saveMu.Lock()
		defer saveMu.Unlock()
		return withSSOTLock(c.SSOTPath, func() error {
			snapshot, err := readSSOTSnapshot(c.SSOTPath)
			if err != nil {
				return fmt.Errorf("读取 SSOT:%w", err)
			}
			if err := guardRevision(snapshot.body, expected); err != nil {
				return err
			}
			var next []byte
			if input != nil {
				next, err = ssotedit.UpsertService(snapshot.body, ssotedit.ServiceInput{
					ID: input.ID, Name: input.Name, Addresses: input.Addresses,
					Declaration: input.Declaration,
				})
			} else {
				next, err = ssotedit.DeleteService(snapshot.body, deleteID)
			}
			if err != nil {
				return err
			}
			return saveSSOTAtomicFromSnapshot(c.SSOTPath, next, snapshot)
		})
	}
	bootstrap := enrollkey.Manager{PrivatePath: c.BootstrapSSHKey}
	bootstrapView := func(ensure bool) (webui.BootstrapIdentityView, error) {
		var status enrollkey.Status
		var err error
		if ensure {
			status, err = bootstrap.Ensure()
		} else {
			status, err = bootstrap.Status()
		}
		if err != nil {
			return webui.BootstrapIdentityView{}, err
		}
		return webui.BootstrapIdentityView{
			Ready: status.Ready, PublicKey: status.PublicOpenSSH,
			Fingerprint: status.Fingerprint, PublicPath: status.PublicPath,
		}, nil
	}
	var enrollment *webui.NodeEnrollmentDeps
	// LoadControl fills both defaults. Keeping this nil for hand-constructed
	// Control values with incomplete paths prevents the UI from advertising a
	// workflow whose trust store or private identity cannot be isolated.
	if enrollmentPathsUsable(c) {
		enrollment = newNodeEnrollmentDeps(c, &saveMu, read, revision, guardRevision)
	}

	return &webui.ControlDeps{
		SSOTPath: c.SSOTPath,
		Enrich: func(v *webui.View) error {
			s, err := loadValidatedSSOT(c.SSOTPath)
			if err != nil {
				return err
			}
			enrichControlView(v, s, v.Self)
			return nil
		},
		Read: func() (string, error) {
			b, err := read()
			return string(b), err
		},
		Revision: func() (string, error) {
			b, err := read()
			if err != nil {
				return "", err
			}
			return revision(b), nil
		},
		Validate: func(content string) (string, error) {
			s, err := model.Load([]byte(content))
			if err != nil {
				return "", fmt.Errorf("解析失败:%w", err)
			}
			if fs := validate.Validate(s); len(fs) > 0 {
				return validate.Format(fs), nil
			}
			return "", nil
		},
		Save: func(content string) error {
			// **保存前自己再校验一次。** 界面上的校验按钮只是给人看的:
			// 表单可以被直接 POST,而一份坏 SSOT 存进去之后,发布器会拒绝
			// 发布,线上停在旧快照 —— 症状是"改了没生效",很难查。
			return save([]byte(content), "", false)
		},
		SaveIfRevision: func(content, expected string) error {
			return save([]byte(content), expected, true)
		},
		Services: &webui.ServiceControlDeps{
			Upsert: func(input webui.ServiceInput, expected string) error {
				return mutateService(&input, "", expected)
			},
			Delete: func(id, expected string) error {
				return mutateService(nil, id, expected)
			},
		},
		BootstrapIdentity: &webui.BootstrapIdentityDeps{
			Status: func() (webui.BootstrapIdentityView, error) { return bootstrapView(false) },
			Ensure: func() (webui.BootstrapIdentityView, error) { return bootstrapView(true) },
		},
		Enrollment: enrollment,
		Distributed: func() (string, error) {
			if c.DistributionURL == "" {
				return "", fmt.Errorf("中控配置里没有 distribution_url")
			}
			resp, err := netx.Client(c.DNS, 10*time.Second).
				Get(strings.TrimRight(c.DistributionURL, "/") + "/current.json")
			if err != nil {
				return "", err
			}
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				return "", fmt.Errorf("HTTP %d", resp.StatusCode)
			}
			var cur struct {
				Snapshot string `json:"snapshot"`
			}
			if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&cur); err != nil {
				return "", err
			}
			return cur.Snapshot, nil
		},
	}
}

func enrollmentPathsUsable(c *Control) bool {
	if c == nil || strings.TrimSpace(c.BootstrapSSHKey) != c.BootstrapSSHKey ||
		strings.TrimSpace(c.KnownHostsPath) != c.KnownHostsPath ||
		!filepath.IsAbs(c.BootstrapSSHKey) || !filepath.IsAbs(c.KnownHostsPath) {
		return false
	}
	// A bad bootstrap configuration must not let host-key confirmation replace
	// the SSH private key, its public half, or the SSOT itself.
	privatePath := filepath.Clean(c.BootstrapSSHKey)
	knownHostsPath := filepath.Clean(c.KnownHostsPath)
	ssotPath := filepath.Clean(c.SSOTPath)
	isolated := knownHostsPath != privatePath && knownHostsPath != privatePath+".pub" &&
		knownHostsPath != ssotPath && privatePath != ssotPath && privatePath+".pub" != ssotPath
	if !isolated {
		return false
	}
	if _, err := (enrollkey.Manager{PrivatePath: privatePath}).Status(); err != nil {
		return false
	}
	return enrollssh.ValidateKnownHostsPath(knownHostsPath) == nil
}

func loadValidatedSSOT(path string) (*model.SSOT, error) {
	snapshot, err := readSSOTSnapshot(path)
	if err != nil {
		return nil, fmt.Errorf("读 SSOT:%w", err)
	}
	s, err := model.Load(snapshot.body)
	if err != nil {
		return nil, fmt.Errorf("解析 SSOT:%w", err)
	}
	if fs := validate.Validate(s); len(fs) > 0 {
		return nil, fmt.Errorf("SSOT 校验不通过:%s", validate.Format(fs))
	}
	return s, nil
}

// saveSSOTAtomic 在目标同目录中写唯一临时文件,落盘后再原子替换。
// 同目录保证 rename 不跨文件系统;CreateTemp 使多进程/多实例同时保存
// 也不会共享一个 .ssot.tmp。失败路径总会尽力清理临时文件。
type ssotSnapshot struct {
	info os.FileInfo
	body []byte
}

const maxSSOTBytes = 8 << 20

func readSSOTSnapshot(path string) (ssotSnapshot, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return ssotSnapshot{}, err
	}
	if !info.Mode().IsRegular() {
		return ssotSnapshot{}, errors.New("SSOT must be a regular file; symlinks are not accepted")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Nlink != 1 {
		return ssotSnapshot{}, errors.New("SSOT must have exactly one hard link")
	}
	if info.Size() > maxSSOTBytes {
		return ssotSnapshot{}, fmt.Errorf("SSOT exceeds %d bytes", maxSSOTBytes)
	}
	f, err := os.Open(path)
	if err != nil {
		return ssotSnapshot{}, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return ssotSnapshot{}, err
	}
	if !os.SameFile(info, opened) {
		return ssotSnapshot{}, errors.New("SSOT changed while opening; retry")
	}
	body, err := io.ReadAll(io.LimitReader(f, maxSSOTBytes+1))
	if err != nil {
		return ssotSnapshot{}, err
	}
	if len(body) > maxSSOTBytes {
		return ssotSnapshot{}, fmt.Errorf("SSOT exceeds %d bytes", maxSSOTBytes)
	}
	return ssotSnapshot{info: info, body: body}, nil
}

func withSSOTLock(path string, fn func() error) error {
	lockPath := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".loom.lock")
	fd, err := syscall.Open(lockPath,
		syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("打开 SSOT 事务锁:%w", err)
	}
	f := os.NewFile(uintptr(fd), lockPath)
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		if err != nil {
			return fmt.Errorf("检查 SSOT 事务锁:%w", err)
		}
		return errors.New("SSOT 事务锁必须是私有普通文件")
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		return fmt.Errorf("取得 SSOT 事务锁:%w", err)
	}
	defer syscall.Flock(fd, syscall.LOCK_UN)
	return fn()
}

// ssotCommitError reports the only ambiguous filesystem outcome: rename has
// committed the new bytes, but directory durability could not be confirmed.
// Web callers can present this truthfully instead of saying SSOT was unchanged.
type ssotCommitError struct {
	err       error
	committed bool
}

func (e *ssotCommitError) Error() string   { return e.err.Error() }
func (e *ssotCommitError) Unwrap() error   { return e.err }
func (e *ssotCommitError) Committed() bool { return e.committed }

func saveSSOTAtomic(path string, content []byte) error {
	snapshot, err := readSSOTSnapshot(path)
	if err != nil {
		return err
	}
	return saveSSOTAtomicFromSnapshot(path, content, snapshot)
}

func saveSSOTAtomicFromSnapshot(path string, content []byte, snapshot ssotSnapshot) (err error) {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	f, err := os.CreateTemp(dir, "."+base+".*.tmp")
	if err != nil {
		return fmt.Errorf("创建 SSOT 临时文件:%w", err)
	}
	tmp := f.Name()
	closed := false
	defer func() {
		if !closed {
			_ = f.Close()
		}
		_ = os.Remove(tmp)
	}()

	if _, err := f.Write(content); err != nil {
		return fmt.Errorf("写 SSOT 临时文件:%w", err)
	}
	// Preserve the explicitly inspected target mode rather than silently
	// widening a private SSOT or changing an operator-enforced policy.
	if err := f.Chmod(snapshot.info.Mode().Perm()); err != nil {
		return fmt.Errorf("设置 SSOT 临时文件权限:%w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("落盘 SSOT 临时文件:%w", err)
	}
	if err := f.Close(); err != nil {
		closed = true
		return fmt.Errorf("关闭 SSOT 临时文件:%w", err)
	}
	closed = true

	current, err := readSSOTSnapshot(path)
	if err != nil {
		return fmt.Errorf("替换前重新检查 SSOT:%w", err)
	}
	if !os.SameFile(snapshot.info, current.info) || !bytes.Equal(snapshot.body, current.body) {
		return errors.New("SSOT 在事务提交前被外部修改，请重新加载后再保存")
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("原子替换 SSOT:%w", err)
	}
	// rename 落盘还需要同步目录项;这样掉电后不会只留下旧名字。
	d, err := os.Open(dir)
	if err != nil {
		return &ssotCommitError{err: fmt.Errorf("SSOT 已替换,但无法打开目录落盘:%w", err), committed: true}
	}
	if err := d.Sync(); err != nil {
		_ = d.Close()
		return &ssotCommitError{err: fmt.Errorf("SSOT 已替换,但目录落盘失败:%w", err), committed: true}
	}
	if err := d.Close(); err != nil {
		return &ssotCommitError{err: fmt.Errorf("SSOT 已替换,但关闭目录失败:%w", err), committed: true}
	}
	return nil
}
