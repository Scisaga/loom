package wire

import (
	"encoding/hex"
	"errors"
	"sort"
)

type CAProfileRegistryLeafV1 struct {
	ProfileKind string `json:"profile_kind"`
	ProfileID   string `json:"profile_id"`
	Generation  int64  `json:"generation"`
	ProfileHash string `json:"profile_hash"`
}

// CAProfileRoot 对每类 profile 的最新代构造统一 registry root；调用方不能
// 删除 retired/revoked Device state 或用 admin profile hash 冒充 Device state hash（D102）。
func CAProfileRoot(adminProfiles []AdminCertificateProfileV1,
	deviceProfiles []DeviceCertificateProfileStateV1) (string, error) {
	leaves := make([]CAProfileRegistryLeafV1, 0, len(adminProfiles)+len(deviceProfiles))
	for i := range adminProfiles {
		profile := &adminProfiles[i]
		hash, err := AdminCertificateProfileHash(profile)
		if err != nil {
			return "", err
		}
		leaves = append(leaves, CAProfileRegistryLeafV1{
			ProfileKind: "admin_certificate", ProfileID: profile.ProfileID,
			Generation: profile.Generation, ProfileHash: hash,
		})
	}
	for i := range deviceProfiles {
		profile := &deviceProfiles[i]
		hash, err := DeviceCertificateProfileStateHash(profile)
		if err != nil {
			return "", err
		}
		leaves = append(leaves, CAProfileRegistryLeafV1{
			ProfileKind: "device_certificate", ProfileID: profile.ProfileID,
			Generation: profile.Generation, ProfileHash: hash,
		})
	}
	sort.Slice(leaves, func(i, j int) bool {
		leftKind, rightKind := caProfileKindOrder(leaves[i].ProfileKind), caProfileKindOrder(leaves[j].ProfileKind)
		if leftKind != rightKind {
			return leftKind < rightKind
		}
		return leaves[i].ProfileID < leaves[j].ProfileID
	})
	canonical := make([][]byte, len(leaves))
	for i := range leaves {
		leaf := &leaves[i]
		if !oneOf(leaf.ProfileKind, "admin_certificate", "device_certificate") ||
			!validIdentifier(leaf.ProfileID, 128) || leaf.Generation < 1 {
			return "", errors.New("[D102 CA registry] profile leaf 无效")
		}
		if i > 0 && leaf.ProfileKind == leaves[i-1].ProfileKind && leaf.ProfileID == leaves[i-1].ProfileID {
			return "", errors.New("[D102 CA registry] 每类 profile ID 必须只保留最新一代")
		}
		canonical[i], _ = MarshalCanonical(leaf)
	}
	return canonicalMerkleRootHash(canonical), nil
}

func caProfileKindOrder(kind string) int {
	if kind == "admin_certificate" {
		return 0
	}
	return 1
}

func canonicalMerkleRootHash(leaves [][]byte) string {
	root := MerkleRoot(leaves)
	return "sha256:" + hex.EncodeToString(root)
}
