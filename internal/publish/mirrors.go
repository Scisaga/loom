package publish

import (
	"bytes"
	"fmt"
	"strings"
)

// NewMirrorSet turns several independent static targets into one reconciliation
// surface.  A publish is green only after every configured mirror has accepted
// the exact tree.  Partial success is safe (all bytes remain signed) but is
// reported as failure so the next publisher loop repairs the lagging mirror.
func NewMirrorSet(targets ...Target) (Target, error) {
	clean := make([]Target, 0, len(targets))
	seen := map[string]bool{}
	for _, target := range targets {
		if target == nil {
			return nil, fmt.Errorf("分发镜像不能为 nil")
		}
		name := target.String()
		if seen[name] {
			return nil, fmt.Errorf("分发目标重复:%s", name)
		}
		seen[name] = true
		clean = append(clean, target)
	}
	if len(clean) == 0 {
		return nil, fmt.Errorf("至少需要一个分发目标")
	}
	if len(clean) == 1 {
		return clean[0], nil
	}
	return &mirrorSet{targets: clean}, nil
}

type mirrorSet struct{ targets []Target }

func (m *mirrorSet) String() string {
	names := make([]string, 0, len(m.targets))
	for _, target := range m.targets {
		names = append(names, target.String())
	}
	return "mirrors[" + strings.Join(names, ", ") + "]"
}

func (m *mirrorSet) Push(tree *Tree) error {
	var failures []string
	for _, target := range m.targets {
		if err := target.Push(tree); err != nil {
			failures = append(failures, fmt.Sprintf("%s:%v", target, err))
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("%d/%d 个镜像推送失败: %s", len(failures), len(m.targets), strings.Join(failures, "; "))
	}
	return nil
}

func (m *mirrorSet) ReadFile(path string) ([]byte, bool, error) {
	var reference []byte
	haveReference := false
	foundAll := true
	for i, target := range m.targets {
		body, found, err := target.ReadFile(path)
		if err != nil {
			return nil, false, fmt.Errorf("读镜像 %s:%w", target, err)
		}
		if !found {
			foundAll = false
			continue
		}
		if !haveReference {
			reference = body
			haveReference = true
			continue
		}
		if !bytes.Equal(reference, body) {
			return nil, false, fmt.Errorf("镜像在 %s 返回不同字节（发现于 %s）", path, m.targets[i])
		}
	}
	if !foundAll || !haveReference {
		return nil, false, nil
	}
	return reference, true, nil
}

func (m *mirrorSet) HasBlob(path string) (bool, error) {
	for _, target := range m.targets {
		has, err := target.HasBlob(path)
		if err != nil {
			return false, fmt.Errorf("核对镜像 %s:%w", target, err)
		}
		if !has {
			return false, nil
		}
	}
	return true, nil
}

func (m *mirrorSet) Current() (string, error) {
	current := ""
	for i, target := range m.targets {
		got, err := target.Current()
		if err != nil {
			return "", fmt.Errorf("读取镜像 %s current:%w", target, err)
		}
		if i == 0 {
			current = got
			continue
		}
		if got != current {
			return "", fmt.Errorf("镜像 current 不一致:%s 与 %s", current, got)
		}
	}
	return current, nil
}
