//go:build !windows

package publish

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
)

const (
	releaseAuthorityFile       = "release-authority.json"
	releaseAuthorityMarkerFile = "release-authority.enabled"
	releaseAuthorityMarkerBody = "loom-current-v1\n"
)

// ReleaseAuthorityPath returns the durable publisher-side generation state.
// It lives beside the SSOT archive because that directory is already required
// for production publishing and included in the control-plane backup set.
func ReleaseAuthorityPath(dir string) string {
	return filepath.Join(dir, releaseAuthorityFile)
}

func releaseAuthorityMarkerPath(dir string) string {
	return filepath.Join(dir, releaseAuthorityMarkerFile)
}

// ReleaseAuthorityBackupState tells backup/recovery code whether this control
// plane has crossed into the signed era.  It intentionally checks the pair as
// one state: backing up only the marker or only the authority creates a backup
// that cannot safely resume publishing.
func ReleaseAuthorityBackupState(dir string) (bool, error) {
	if dir == "" {
		return false, nil
	}
	authorityPath := ReleaseAuthorityPath(dir)
	markerPath := releaseAuthorityMarkerPath(dir)
	type fileState struct {
		body   []byte
		exists bool
	}
	readRegular := func(path string) (fileState, error) {
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			return fileState{}, nil
		}
		if err != nil {
			return fileState{}, err
		}
		if !info.Mode().IsRegular() {
			return fileState{}, fmt.Errorf("%s 不是普通文件", path)
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return fileState{}, err
		}
		return fileState{body: body, exists: true}, nil
	}
	authority, err := readRegular(authorityPath)
	if err != nil {
		return false, fmt.Errorf("检查 release authority 备份状态:%w", err)
	}
	marker, err := readRegular(markerPath)
	if err != nil {
		return false, fmt.Errorf("检查 signed-era marker 备份状态:%w", err)
	}
	if !authority.exists && !marker.exists {
		return false, nil
	}
	if authority.exists != marker.exists {
		return false, fmt.Errorf("release authority 与 signed-era marker 只剩一半；拒绝生成不可恢复的备份")
	}
	if string(marker.body) != releaseAuthorityMarkerBody {
		return false, fmt.Errorf("signed-era marker 内容损坏")
	}
	if _, err := DecodeDeploymentCurrent(authority.body); err != nil {
		return false, fmt.Errorf("release authority 结构损坏:%w", err)
	}
	return true, nil
}

// ReadReleaseAuthority returns nil only for a clean legacy installation which
// has never enabled signed current generations.  Once the signed-era marker
// exists, a missing authority is an availability failure, not permission to
// restart from generation one and equivocate with nodes that remember more.
func ReadReleaseAuthority(dir string, pub ed25519.PublicKey) (*DeploymentCurrent, error) {
	if dir == "" {
		return nil, nil
	}
	body, err := os.ReadFile(ReleaseAuthorityPath(dir))
	if errors.Is(err, os.ErrNotExist) {
		marker, markerErr := os.ReadFile(releaseAuthorityMarkerPath(dir))
		switch {
		case markerErr == nil:
			if string(marker) != releaseAuthorityMarkerBody {
				return nil, fmt.Errorf("release authority 缺失，且 signed-era marker 内容损坏")
			}
			return nil, fmt.Errorf("release authority 缺失，但 signed-era marker 已存在；拒绝从 generation 1 重新开始，请从备份恢复 %s",
				ReleaseAuthorityPath(dir))
		case !errors.Is(markerErr, os.ErrNotExist):
			return nil, fmt.Errorf("读取 signed-era marker:%w", markerErr)
		default:
			return nil, nil
		}
	}
	if err != nil {
		return nil, fmt.Errorf("读取 release authority:%w", err)
	}
	current, err := DecodeDeploymentCurrent(body)
	if err != nil {
		return nil, fmt.Errorf("release authority 损坏:%w", err)
	}
	if err := current.Verify(pub); err != nil {
		return nil, fmt.Errorf("release authority 不可信:%w", err)
	}
	return current, nil
}

// ensureReleaseAuthority returns the exact signed envelope to publish.  The
// caller holds publish.lock, so only this function allocates generations.
// Same logical target means the previous envelope is returned byte-for-byte;
// PublishedAt is set only when a new generation is allocated.
//
// The authority and marker are durably written before this function returns.
// publishOnce therefore cannot expose generation N and later forget it merely
// because Push or HTTP verification failed.
func ensureReleaseAuthority(dir, snapshot string, assignments []DeploymentAssignment,
	publishedAt string, priv ed25519.PrivateKey) (*DeploymentCurrent, bool, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, false, fmt.Errorf("release authority 私钥长度不对:%d", len(priv))
	}
	desired := &DeploymentCurrent{
		Schema: DeploymentCurrentSchema, Snapshot: snapshot,
		Assignments: sortedAssignments(assignments), PublishedAt: publishedAt,
	}
	pub := priv.Public().(ed25519.PublicKey)

	// Empty ArchiveDir is retained only for package-level compatibility tests;
	// production CLI entry points already refuse it.  It still emits a valid
	// signed generation, but deliberately makes no persistence promise.
	if dir == "" {
		desired.Generation = 1
		if err := desired.Sign(priv); err != nil {
			return nil, false, err
		}
		return desired, true, nil
	}

	current, err := ReadReleaseAuthority(dir, pub)
	if err != nil {
		return nil, false, err
	}
	if current != nil && sameDeploymentTarget(current, desired) {
		if err := ensureReleaseAuthorityMarker(dir); err != nil {
			return nil, false, err
		}
		return current, false, nil
	}

	if current == nil {
		desired.Generation = 1
	} else {
		if current.Generation == math.MaxUint64 {
			return nil, false, errors.New("release generation 已到 uint64 上限，拒绝回绕")
		}
		desired.Generation = current.Generation + 1
	}
	if err := desired.Sign(priv); err != nil {
		return nil, false, err
	}
	body, err := desired.Bytes()
	if err != nil {
		return nil, false, err
	}
	if err := writeFileAtomic(ReleaseAuthorityPath(dir), body, 0o600); err != nil {
		return nil, false, fmt.Errorf("耐久写 release authority:%w", err)
	}
	if err := ensureReleaseAuthorityMarker(dir); err != nil {
		return nil, false, err
	}
	return desired, true, nil
}

func ensureReleaseAuthorityMarker(dir string) error {
	path := releaseAuthorityMarkerPath(dir)
	body, err := os.ReadFile(path)
	if err == nil {
		if string(body) != releaseAuthorityMarkerBody {
			return fmt.Errorf("signed-era marker %s 内容损坏", path)
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("读取 signed-era marker:%w", err)
	}
	if err := writeFileAtomic(path, []byte(releaseAuthorityMarkerBody), 0o600); err != nil {
		return fmt.Errorf("耐久写 signed-era marker:%w", err)
	}
	return nil
}

func sameDeploymentTarget(a, b *DeploymentCurrent) bool {
	if a == nil || b == nil || a.Schema != b.Schema || a.Snapshot != b.Snapshot {
		return false
	}
	aa := sortedAssignments(a.Assignments)
	bb := sortedAssignments(b.Assignments)
	if len(aa) != len(bb) {
		return false
	}
	for i := range aa {
		if aa[i] != bb[i] {
			return false
		}
	}
	return true
}

func deploymentCurrentBytesEqual(a, b *DeploymentCurrent) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	ab, errA := a.Bytes()
	bb, errB := b.Bytes()
	return errA == nil && errB == nil && bytes.Equal(ab, bb)
}
