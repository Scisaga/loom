package wire

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
)

const (
	DomainControlApplicationSnapshot = "loom-control-application-snapshot-v2"
	DomainControlApplicationSection  = "loom-control-application-section-v2"
)

// 对命名部分分别承诺，使节点只取得它需要的安装计划，不必接收整个私有
// application（其中含 SSOT、邀请 opening 与恢复 custody）。
type ControlApplicationSnapshotV2 struct {
	Schema       int    `json:"schema"`
	ClusterID    string `json:"cluster_id"`
	SectionCount int64  `json:"section_count"`
	SectionsRoot string `json:"sections_root"`
}

type ControlApplicationSectionLeafV2 struct {
	Schema      int    `json:"schema"`
	ClusterID   string `json:"cluster_id"`
	Name        string `json:"name"`
	ContentHash string `json:"content_hash"`
}

type ControlApplicationSectionProofV2 struct {
	Schema    int                             `json:"schema"`
	Snapshot  ControlApplicationSnapshotV2    `json:"snapshot"`
	Leaf      ControlApplicationSectionLeafV2 `json:"leaf"`
	LeafIndex int64                           `json:"leaf_index"`
	AuditPath []string                        `json:"audit_path"`
	Content   json.RawMessage                 `json:"content"`
}

func ControlApplicationSnapshotHashV2(application []byte) (string, error) {
	snapshot, _, _, err := controlApplicationSections(application)
	if err != nil {
		return "", err
	}
	return HashObject(DomainControlApplicationSnapshot, snapshot)
}

func BuildControlApplicationSectionProofV2(application []byte, name string) (ControlApplicationSectionProofV2, error) {
	var empty ControlApplicationSectionProofV2
	snapshot, leaves, sections, err := controlApplicationSections(application)
	if err != nil {
		return empty, err
	}
	index := -1
	var leaf ControlApplicationSectionLeafV2
	for i, body := range leaves {
		var candidate ControlApplicationSectionLeafV2
		if err := json.Unmarshal(body, &candidate); err != nil {
			return empty, err
		}
		if candidate.Name == name {
			index = i
			leaf = candidate
			break
		}
	}
	if index < 0 {
		return empty, errors.New("[application snapshot] 缺所需部分")
	}
	path, err := MerkleInclusionPath(leaves, int64(index))
	if err != nil {
		return empty, err
	}
	proof := ControlApplicationSectionProofV2{Schema: 2, Snapshot: snapshot, Leaf: leaf, LeafIndex: int64(index), AuditPath: make([]string, len(path)), Content: sections[name]}
	for i, hash := range path {
		proof.AuditPath[i] = "sha256:" + hex.EncodeToString(hash)
	}
	return proof, nil
}

func VerifyControlApplicationSectionProofV2(proof *ControlApplicationSectionProofV2, snapshotHash, clusterID, name string) error {
	if proof == nil || proof.Schema != 2 || proof.Snapshot.Schema != 2 || !validIdentifier(clusterID, 128) ||
		proof.Snapshot.ClusterID != clusterID || proof.Leaf.ClusterID != clusterID || proof.Leaf.Schema != 2 || proof.Leaf.Name != name ||
		!validApplicationSectionName(name) || proof.Snapshot.SectionCount < 2 || proof.Snapshot.SectionCount > 128 {
		return errors.New("[application snapshot] 部分证明格式或身份无效")
	}
	hash, err := HashObject(DomainControlApplicationSnapshot, proof.Snapshot)
	if err != nil || hash != snapshotHash {
		return errors.New("[application snapshot] 未绑定认证 snapshot")
	}
	canonical, err := CanonicalizeStrict(proof.Content)
	if err != nil || !bytes.Equal(canonical, proof.Content) || HashRaw(DomainControlApplicationSection, canonical) != proof.Leaf.ContentHash {
		return errors.New("[application snapshot] 部分内容不属于证明")
	}
	root, err := ParseHash(proof.Snapshot.SectionsRoot)
	if err != nil {
		return err
	}
	path := make([][]byte, len(proof.AuditPath))
	for i, hash := range proof.AuditPath {
		path[i], err = ParseHash(hash)
		if err != nil {
			return err
		}
	}
	leaf, err := MarshalCanonical(proof.Leaf)
	if err != nil {
		return err
	}
	return VerifyMerkleInclusion(leaf, proof.LeafIndex, proof.Snapshot.SectionCount, path, root)
}

func controlApplicationSections(application []byte) (ControlApplicationSnapshotV2, [][]byte, map[string]json.RawMessage, error) {
	var empty ControlApplicationSnapshotV2
	var sections map[string]json.RawMessage
	canonical, err := DecodeStrict(application, 64<<20, &sections)
	if err != nil || !bytes.Equal(canonical, application) || len(sections) < 2 || len(sections) > 128 || string(sections["schema"]) != "2" {
		return empty, nil, nil, errors.New("[application snapshot] application 必须为规范 schema 2 对象")
	}
	var cluster string
	if err := json.Unmarshal(sections["cluster_id"], &cluster); err != nil || !validIdentifier(cluster, 128) {
		return empty, nil, nil, errors.New("[application snapshot] 网络身份无效")
	}
	names := make([]string, 0, len(sections))
	for name := range sections {
		if !validApplicationSectionName(name) {
			return empty, nil, nil, errors.New("[application snapshot] 部分名称无效")
		}
		names = append(names, name)
	}
	sort.Strings(names)
	leaves := make([][]byte, len(names))
	for i, name := range names {
		leaf := ControlApplicationSectionLeafV2{Schema: 2, ClusterID: cluster, Name: name, ContentHash: HashRaw(DomainControlApplicationSection, sections[name])}
		leaves[i], err = MarshalCanonical(leaf)
		if err != nil {
			return empty, nil, nil, err
		}
	}
	return ControlApplicationSnapshotV2{Schema: 2, ClusterID: cluster, SectionCount: int64(len(leaves)), SectionsRoot: "sha256:" + hex.EncodeToString(MerkleRoot(leaves))}, leaves, sections, nil
}

func validApplicationSectionName(name string) bool {
	if len(name) == 0 || len(name) > 128 {
		return false
	}
	for _, char := range name {
		if char != '_' && (char < 'a' || char > 'z') {
			return false
		}
	}
	return true
}
