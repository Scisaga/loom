package publish

import (
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
	pinFile = "pin.json"
	pinBin  = "binary"
)

// ReadPin 读钉住状态。没钉住时返回 (nil, "", nil) —— 不是错误。
func ReadPin(dir string) (*Pin, string, error) {
	if dir == "" {
		return nil, "", nil
	}
	b, err := os.ReadFile(filepath.Join(dir, pinFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	var p Pin
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, "", fmt.Errorf("解析 %s:%w", filepath.Join(dir, pinFile), err)
	}
	bin := filepath.Join(dir, pinBin)
	if _, err := os.Stat(bin); err != nil {
		// 钉住记录在、二进制不在 —— 这是半个状态,发不出去也退不回来。
		// 说清楚,不要默默回落到当前二进制:那正好是钉住要防的事。
		return nil, "", fmt.Errorf("钉住了 %s,但 %s 不见了 —— 用 `loom pin -clear` 解除,或重新钉一次", short(p.Snapshot), bin)
	}
	return &p, bin, nil
}

// WritePin 落盘。二进制先写临时文件再改名,避免读到写了一半的。
func WritePin(dir string, p *Pin, bin []byte) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp := filepath.Join(dir, pinBin+".tmp")
	if err := os.WriteFile(tmp, bin, 0o755); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, pinBin)); err != nil {
		return err
	}
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, pinFile), append(b, '\n'), 0o644)
}

// ClearPin 解除钉住。二进制一并删掉 —— 留着只会让人以为还钉着。
func ClearPin(dir string) error {
	if err := os.Remove(filepath.Join(dir, pinFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Remove(filepath.Join(dir, pinBin)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
