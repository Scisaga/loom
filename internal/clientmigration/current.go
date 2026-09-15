// Package clientmigration 只验证存量迁移输入；不提供网络、旧配置执行或回退入口。
package clientmigration

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"time"

	"loom/internal/wire"
)

type Floor struct {
	Schema           int    `json:"schema"`
	Generation       uint64 `json:"generation"`
	PayloadSHA256    string `json:"payload_sha256"`
	SelectedSnapshot string `json:"selected_snapshot"`
}

type assignment struct {
	Node     string `json:"node"`
	Snapshot string `json:"snapshot"`
}

type signedCurrent struct {
	Schema      int          `json:"schema"`
	Generation  uint64       `json:"generation"`
	Snapshot    string       `json:"snapshot"`
	Assignments []assignment `json:"assignments,omitempty"`
	PublishedAt string       `json:"published_at"`
	Signature   string       `json:"signature"`
}

// payload 字段顺序必须保持旧签名格式，不能用 JCS 重新解释历史签名。
type currentPayload struct {
	Schema      int          `json:"schema"`
	Generation  uint64       `json:"generation"`
	Snapshot    string       `json:"snapshot"`
	Assignments []assignment `json:"assignments,omitempty"`
	PublishedAt string       `json:"published_at"`
}

func ParseFloor(body []byte) (Floor, error) {
	var floor Floor
	if _, err := wire.DecodeStrict(body, 64<<10, &floor); err != nil {
		return Floor{}, err
	}
	if floor.Schema != 1 || floor.Generation < 1 || !lowerHex(floor.PayloadSHA256, 64) ||
		!lowerHex(floor.SelectedSnapshot, 12) {
		return Floor{}, errors.New("[设备迁移] 本机历史 floor 无效")
	}
	return floor, nil
}

// VerifyFloor 将平台原签名绑定到本机 Device 和已保存 floor。返回的两个 hash
// 分别是原始完整 current bytes 的 SHA-256 与原签名消息的 SHA-256。
// 新版 reader 不得通过此函数取得旧运行配置。
func VerifyFloor(currentBytes []byte, public ed25519.PublicKey, deviceID string,
	floor Floor) (wire.BootstrapDeviceFloorLeafV1, error) {
	var zero wire.BootstrapDeviceFloorLeafV1
	if len(public) != ed25519.PublicKeySize || deviceID == "" || floor.Schema != 1 ||
		floor.Generation < 1 || !lowerHex(floor.PayloadSHA256, 64) || !lowerHex(floor.SelectedSnapshot, 12) {
		return zero, errors.New("[设备迁移] 原平台信任、Device 或本机 floor 缺失")
	}
	var current signedCurrent
	if _, err := wire.DecodeStrict(currentBytes, 4<<20, &current); err != nil {
		return zero, err
	}
	if current.Schema != 1 || current.Generation < 1 || current.Generation > math.MaxInt64 || !lowerHex(current.Snapshot, 12) {
		return zero, errors.New("[设备迁移] 历史签名 current 无效")
	}
	if _, err := time.Parse(time.RFC3339Nano, current.PublishedAt); err != nil {
		return zero, err
	}
	sort.Slice(current.Assignments, func(i, j int) bool { return current.Assignments[i].Node < current.Assignments[j].Node })
	selected := current.Snapshot
	if len(current.Assignments) > 0 {
		selected = ""
		for i, entry := range current.Assignments {
			if entry.Node == "" || !lowerHex(entry.Snapshot, 12) || i > 0 && entry.Node == current.Assignments[i-1].Node {
				return zero, errors.New("[设备迁移] 历史 current assignments 无效或重复")
			}
			if entry.Node == deviceID {
				selected = entry.Snapshot
			}
		}
		if selected == "" {
			return zero, errors.New("[设备迁移] 历史 current 未授权本机 Device")
		}
	}
	payload, err := json.Marshal(currentPayload{current.Schema, current.Generation, current.Snapshot,
		current.Assignments, current.PublishedAt})
	if err != nil {
		return zero, err
	}
	message := append([]byte("loom-current-v1\x00"), payload...)
	signature, err := base64.StdEncoding.DecodeString(current.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize ||
		base64.StdEncoding.EncodeToString(signature) != current.Signature || !ed25519.Verify(public, message, signature) {
		return zero, errors.New("[设备迁移] 原平台签名验证失败")
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(message))
	if current.Generation < floor.Generation || current.Generation == floor.Generation &&
		(digest != floor.PayloadSHA256 || selected != floor.SelectedSnapshot) {
		return zero, errors.New("[设备迁移] 历史 current 低于本机 floor 或同代分叉")
	}
	return wire.BootstrapDeviceFloorLeafV1{Schema: 1, DeviceID: deviceID,
		V1Generation: int64(current.Generation), V1SignedCurrentHash: fmt.Sprintf("sha256:%x", sha256.Sum256(currentBytes)),
		V1PayloadHash: "sha256:" + digest}, nil
}

func lowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	parsed, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(parsed) == value
}
