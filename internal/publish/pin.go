package publish

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Pin 把发布用的二进制钉在某个历史快照上。
//
// 为什么需要它:新二进制**起得来但是错的**时,现有的两道防线都够不着 ——
// `.prev` 只在服务起不来时自动换回去,而配置回滚不管二进制。这时唯一的
// 退路是 `git checkout` + 重新编译 + 重新发布,要求手上有源码树。
//
// 而分发点上历史二进制本来就都在(内容寻址,`bin/<sha256>`),钉住只是
// 让发布器改用其中一个。
//
// **钉住是一个粘性覆盖,所以它必须显眼。** 发布器每轮都会说自己被钉着,
// 否则"我重新编译了但没发出去"是个查不出来的怪事。Reason 是必填的,
// 理由是几天后翻到这个文件的人(可能就是你自己)需要知道为什么。
type Pin struct {
	Snapshot string `json:"snapshot"`
	SHA256   string `json:"sha256"`
	PinnedAt string `json:"pinned_at"`
	By       string `json:"by,omitempty"`
	Reason   string `json:"reason"`
}

const (
	// DefaultPinDir 是手工 publish、publisher、pin 与 rollback 必须共用的
	// 默认授权坐标；任一入口另起默认值都会绕过粘性 pin。
	DefaultPinDir = "deploy/pinned"
	pinFile       = "pin.json"
	pinBin        = "binary"
)

// ReadPin 读钉住状态。没钉住时返回 (nil, "", nil) —— 不是错误。
func ReadPin(dir string) (*Pin, string, error) {
	p, bin, _, err := ReadPinCandidate(dir)
	return p, bin, err
}

// ReadPinCandidate 与 ReadReleaseCandidate 同理:校验与发布复用一次稳定读取。
func ReadPinCandidate(dir string) (*Pin, string, BinaryCandidate, error) {
	if dir == "" {
		return nil, "", BinaryCandidate{}, nil
	}
	b, err := os.ReadFile(filepath.Join(dir, pinFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, "", BinaryCandidate{}, nil
	}
	if err != nil {
		return nil, "", BinaryCandidate{}, err
	}
	var p Pin
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, "", BinaryCandidate{}, fmt.Errorf("解析 %s:%w", filepath.Join(dir, pinFile), err)
	}
	if !validSHA256(p.SHA256) {
		return nil, "", BinaryCandidate{}, fmt.Errorf("钉住记录里的 sha256 %q 无效", p.SHA256)
	}
	bin := filepath.Join(dir, pinBin)
	body, err := os.ReadFile(bin)
	if err != nil {
		// 钉住记录在、二进制不在 —— 这是半个状态,发不出去也退不回来。
		// 说清楚,不要默默回落到当前二进制:那正好是钉住要防的事。
		if errors.Is(err, os.ErrNotExist) {
			return nil, "", BinaryCandidate{}, fmt.Errorf("钉住了 %s,但 %s 不见了 —— 用 `loom pin -clear` 解除,或重新钉一次", short(p.Snapshot), bin)
		}
		return nil, "", BinaryCandidate{}, fmt.Errorf("读钉住副本 %s 失败:%w", bin, err)
	}
	c := newBinaryCandidate(body)
	if c.SHA256 != p.SHA256 {
		return nil, "", BinaryCandidate{}, fmt.Errorf("钉住副本 %s 哈希对不上(记的 %s,实际 %s)—— 用 `loom pin -clear` 解除,或重新钉一次",
			bin, short(p.SHA256), short(c.SHA256))
	}
	return &p, bin, c, nil
}

// WritePin 落盘。二进制先写临时文件再改名,避免读到写了一半的。
func WritePin(dir string, p *Pin, bin []byte) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if len(bin) == 0 {
		return fmt.Errorf("不能钉住空二进制")
	}
	s := sha256.Sum256(bin)
	got := hex.EncodeToString(s[:])
	if p.SHA256 != "" && p.SHA256 != got {
		return fmt.Errorf("钉住记录期待二进制 %s,实际得到 %s", short(p.SHA256), short(got))
	}
	p.SHA256 = got
	binPath := filepath.Join(dir, pinBin)
	if err := writeFileAtomic(binPath, bin, 0o755); err != nil {
		return err
	}
	if diskSHA, diskSize, err := hashFile(binPath); err != nil || diskSHA != got || diskSize != int64(len(bin)) {
		return fmt.Errorf("钉住副本原子入库后校验失败(sha=%s,size=%d,err=%v)",
			short(diskSHA), diskSize, err)
	}
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(dir, pinFile), append(b, '\n'), 0o644)
}

// ClearPin 解除钉住。二进制一并删掉 —— 留着只会让人以为还钉着。
func ClearPin(dir string) error {
	if err := removeFileDurable(filepath.Join(dir, pinFile)); err != nil {
		return err
	}
	if err := removeFileDurable(filepath.Join(dir, pinBin)); err != nil {
		return err
	}
	return nil
}
