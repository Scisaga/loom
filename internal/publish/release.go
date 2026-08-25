package publish

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

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
	releaseFile = "current.json"
	releaseBins = "bin"
)

// ReleaseBinPath 是某个 sha 对应的本地副本路径。
func ReleaseBinPath(dir, sha string) string {
	return filepath.Join(dir, releaseBins, sha)
}

// ReadRelease 读当前放行的二进制。没有 release 时返回 (nil, "", nil) ——
// 那是"还没批准过任何二进制",不是错误。
func ReadRelease(dir string) (*Release, string, error) {
	if dir == "" {
		return nil, "", nil
	}
	b, err := os.ReadFile(filepath.Join(dir, releaseFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	var r Release
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, "", fmt.Errorf("解析 %s:%w", filepath.Join(dir, releaseFile), err)
	}
	bin := ReleaseBinPath(dir, r.SHA256)
	st, err := os.Stat(bin)
	if err != nil {
		// 记录在、二进制副本不在 —— 半个状态。**不要默默回落到
		// 当前二进制**:那正好是 release 要防的事(见类型注释)。
		return nil, "", fmt.Errorf("放行了 %s,但副本 %s 不见了 —— 重新 `loom release` 一次",
			version.Short(r.SHA256), bin)
	}
	if int(st.Size()) != r.Size {
		return nil, "", fmt.Errorf("副本 %s 大小对不上(记的 %d,实际 %d)—— 重新 `loom release` 一次",
			bin, r.Size, st.Size())
	}
	return &r, bin, nil
}

// WriteRelease 把 src 那份二进制按内容寻址存下来,并记成当前放行版本。
//
// **先落副本再落记录。** 反过来的话,中途失败会留下"记录指向不存在的
// 副本"这种半状态 —— 而 ReadRelease 只能把它当错误处理,等于发布器停摆。
func WriteRelease(dir, src string, r Release) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("读 %s:%w", src, err)
	}
	sum := sha256.Sum256(b)
	got := hex.EncodeToString(sum[:])
	if r.SHA256 != "" && r.SHA256 != got {
		return fmt.Errorf("%s 的内容在算完哈希之后变了(%s → %s)", src, version.Short(r.SHA256), version.Short(got))
	}
	r.SHA256, r.Size = got, len(b)

	binDir := filepath.Join(dir, releaseBins)
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return err
	}
	dst := ReleaseBinPath(dir, got)
	if _, err := os.Stat(dst); errors.Is(err, os.ErrNotExist) {
		tmp := dst + ".tmp"
		if err := os.WriteFile(tmp, b, 0o755); err != nil {
			return err
		}
		if err := os.Rename(tmp, dst); err != nil {
			return err
		}
	}

	rb, err := json.MarshalIndent(&r, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, releaseFile+".tmp")
	if err := os.WriteFile(tmp, append(rb, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, releaseFile))
}

// ClearRelease 停止分发二进制。配置照发。
//
// **不删 bin/ 下的副本** —— 那些是回滚的本地缓存,删了就得回网络取。
func ClearRelease(dir string) error {
	err := os.Remove(filepath.Join(dir, releaseFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
