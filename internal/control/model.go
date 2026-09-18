package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
)

const (
	LegacyMaterialSchema = 1
	MaterialSchema       = 2
	HeadSchema           = 1
	materialDomain       = "loom-material-v1\n"
	headDomain           = "loom-certified-head-v1\n"
)

type Member struct {
	ID string `json:"id"`
	// These two fields only decode already-committed schema-1 material. New
	// material identifies the existing private channel by node instead of
	// making two socket addresses part of membership authority.
	LegacyRaftAddress string `json:"raft_address,omitempty"`
	LegacyAPIAddress  string `json:"api_address,omitempty"`
	PublicKey         string `json:"public_key"`
	Node              string `json:"node,omitempty"`
}

type ControlConfig struct {
	Mode      string   `json:"mode"`
	Members   []Member `json:"members,omitempty"`
	Quorum    int      `json:"quorum,omitempty"`
	Old       []Member `json:"old,omitempty"`
	OldQuorum int      `json:"old_quorum,omitempty"`
	New       []Member `json:"new,omitempty"`
	NewQuorum int      `json:"new_quorum,omitempty"`
}

type Genesis struct {
	LegacyHead    string        `json:"legacy_head"`
	ControlConfig ControlConfig `json:"control_config"`
	Projection    WebProjection `json:"projection"`
}

type Material struct {
	Schema        int            `json:"schema"`
	Kind          string         `json:"kind"`
	RequestID     string         `json:"request_id"`
	BaseHead      string         `json:"base_head"`
	Genesis       *Genesis       `json:"genesis,omitempty"`
	Service       *Service       `json:"service,omitempty"`
	ControlConfig *ControlConfig `json:"control_config,omitempty"`
}

type ConsensusEntry struct {
	Index        uint64 `json:"index"`
	Term         uint64 `json:"term"`
	MaterialID   string `json:"material_id"`
	PrefixDigest string `json:"prefix_digest"`
}

type ConsensusState struct {
	Schema  int              `json:"schema"`
	Entries []ConsensusEntry `json:"entries"`
}

type Projection struct {
	Schema         int           `json:"schema"`
	Config         ControlConfig `json:"control_config"`
	ConfigMaterial string        `json:"control_config_material"`
	Applied        []string      `json:"applied_requests"`
	Web            WebProjection `json:"web"`
}

type HeadSignature struct {
	MemberID string `json:"member_id"`
	Value    string `json:"value"`
}

type GovernanceHead struct {
	Schema           int             `json:"schema"`
	Index            uint64          `json:"index"`
	LogDigest        string          `json:"log_digest"`
	ProjectionDigest string          `json:"projection_digest"`
	ConfigMaterial   string          `json:"control_config_material"`
	Signatures       []HeadSignature `json:"signatures"`
}

type CertifiedState struct {
	Schema     int            `json:"schema"`
	Head       GovernanceHead `json:"head"`
	Projection Projection     `json:"projection"`
}

func canonical(value any) ([]byte, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func decodeCanonicalValue(body []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON content")
	}
	want, err := canonical(value)
	if err != nil {
		return err
	}
	if !bytes.Equal(body, want) {
		return errors.New("non-canonical JSON")
	}
	return nil
}

func EncodeMaterial(material Material) ([]byte, string, error) {
	if err := material.Validate(); err != nil {
		return nil, "", err
	}
	body, err := canonical(material)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(append([]byte(materialDomain), body...))
	return body, "sha256:" + hex.EncodeToString(sum[:]), nil
}

func DecodeMaterial(body []byte) (Material, error) {
	var material Material
	if err := decodeCanonicalValue(body, &material); err != nil {
		return material, err
	}
	return material, material.Validate()
}

func (material Material) Validate() error {
	if material.Schema != LegacyMaterialSchema && material.Schema != MaterialSchema || material.RequestID == "" {
		return errors.New("material identity is incomplete")
	}
	count := 0
	if material.Genesis != nil {
		count++
	}
	if material.Service != nil {
		count++
	}
	if material.ControlConfig != nil {
		count++
	}
	if count != 1 {
		return errors.New("material must contain exactly one payload")
	}
	switch material.Kind {
	case "genesis":
		if material.Genesis == nil || material.BaseHead != "" || material.Genesis.LegacyHead == "" {
			return errors.New("genesis material is invalid")
		}
		if err := material.Genesis.ControlConfig.Validate(); err != nil {
			return err
		}
		if material.Schema == MaterialSchema && !currentMembers(material.Genesis.ControlConfig) {
			return errors.New("current genesis contains legacy member addresses")
		}
	case "service.put":
		if material.Service == nil || material.BaseHead == "" || material.Service.ID == "" || material.Service.Name == "" {
			return errors.New("service material is invalid")
		}
		for index, matcher := range material.Service.Matchers {
			if matcher == "" || index > 0 && material.Service.Matchers[index-1] >= matcher {
				return errors.New("service matchers are not uniquely sorted")
			}
		}
	case "control.config":
		if material.ControlConfig == nil || material.BaseHead == "" {
			return errors.New("control config material is invalid")
		}
		if err := material.ControlConfig.Validate(); err != nil {
			return err
		}
		if material.Schema == MaterialSchema {
			members := material.ControlConfig.Members
			if material.ControlConfig.Mode == "joint" {
				members = material.ControlConfig.New
			}
			for _, member := range members {
				if !member.current() {
					return errors.New("new control config contains legacy member addresses")
				}
			}
		}
	default:
		return fmt.Errorf("unknown material kind %q", material.Kind)
	}
	return nil
}

func (config ControlConfig) Validate() error {
	validateSet := func(members []Member, quorum int) error {
		if len(members) == 0 || quorum != len(members)/2+1 {
			return errors.New("control quorum is not canonical")
		}
		nodes := map[string]bool{}
		for index, member := range members {
			if member.ID == "" || !member.validTransport() {
				return errors.New("control member is incomplete")
			}
			if member.current() && nodes[member.Node] {
				return errors.New("control member nodes are not unique")
			}
			nodes[member.Node] = member.current()
			key, err := base64.RawURLEncoding.DecodeString(member.PublicKey)
			if err != nil || len(key) != ed25519.PublicKeySize {
				return errors.New("control member key is invalid")
			}
			if index > 0 && members[index-1].ID >= member.ID {
				return errors.New("control members are not uniquely sorted")
			}
		}
		return nil
	}
	switch config.Mode {
	case "stable":
		if len(config.Old) != 0 || len(config.New) != 0 || config.OldQuorum != 0 || config.NewQuorum != 0 {
			return errors.New("stable config contains joint fields")
		}
		return validateSet(config.Members, config.Quorum)
	case "joint":
		if len(config.Members) != 0 || config.Quorum != 0 {
			return errors.New("joint config contains stable fields")
		}
		if err := validateSet(config.Old, config.OldQuorum); err != nil {
			return err
		}
		return validateSet(config.New, config.NewQuorum)
	default:
		return errors.New("unknown control config mode")
	}
}

func (member Member) current() bool {
	return member.Node != "" && member.LegacyRaftAddress == "" && member.LegacyAPIAddress == ""
}

func (member Member) validTransport() bool {
	legacy := member.Node == "" && member.LegacyRaftAddress != "" && member.LegacyAPIAddress != ""
	return legacy || member.current()
}

func currentMembers(config ControlConfig) bool {
	for _, member := range uniqueConfigMembers(config) {
		if !member.current() {
			return false
		}
	}
	return true
}

func uniqueConfigMembers(config ControlConfig) []Member {
	if config.Mode == "stable" {
		return config.Members
	}
	byID := map[string]Member{}
	for _, member := range append(append([]Member{}, config.Old...), config.New...) {
		byID[member.ID] = member
	}
	result := make([]Member, 0, len(byID))
	for _, member := range byID {
		result = append(result, member)
	}
	return result
}

func StableConfig(members []Member) ControlConfig {
	members = append([]Member(nil), members...)
	sort.Slice(members, func(i, j int) bool { return members[i].ID < members[j].ID })
	return ControlConfig{Mode: "stable", Members: members, Quorum: len(members)/2 + 1}
}

func JointConfig(old, next []Member) ControlConfig {
	old = StableConfig(old).Members
	next = StableConfig(next).Members
	return ControlConfig{Mode: "joint", Old: old, OldQuorum: len(old)/2 + 1, New: next, NewQuorum: len(next)/2 + 1}
}

func sameMembers(left, right []Member) bool {
	a, _ := canonical(left)
	b, _ := canonical(right)
	return bytes.Equal(a, b)
}

func Reduce(previous Projection, material Material, materialID string) (Projection, error) {
	if contains(previous.Applied, material.RequestID) {
		return previous, nil
	}
	var next Projection
	clone, err := canonical(previous)
	if err != nil {
		return Projection{}, err
	}
	if err := json.Unmarshal(clone, &next); err != nil {
		return Projection{}, err
	}
	switch material.Kind {
	case "genesis":
		if previous.Schema != 0 {
			return Projection{}, errors.New("genesis may only be applied once")
		}
		next = Projection{Schema: 1, Config: material.Genesis.ControlConfig, ConfigMaterial: materialID, Web: material.Genesis.Projection}
		next.Web.UIState.Writable = true
		next.Web.UIState.Warnings = []string{}
	case "service.put":
		replaced := false
		for index := range next.Web.Services {
			if next.Web.Services[index].ID == material.Service.ID {
				next.Web.Services[index] = *material.Service
				replaced = true
			}
		}
		if !replaced {
			next.Web.Services = append(next.Web.Services, *material.Service)
		}
		sort.Slice(next.Web.Services, func(i, j int) bool { return next.Web.Services[i].ID < next.Web.Services[j].ID })
	case "control.config":
		if previous.Config.Mode == "stable" && material.ControlConfig.Mode == "joint" {
			if !sameMembers(previous.Config.Members, material.ControlConfig.Old) {
				return Projection{}, errors.New("joint old members do not match current config")
			}
		} else if previous.Config.Mode == "joint" && material.ControlConfig.Mode == "stable" {
			if !sameMembers(previous.Config.New, material.ControlConfig.Members) {
				return Projection{}, errors.New("stable members do not match joint new members")
			}
		} else if previous.Schema != 0 {
			return Projection{}, errors.New("invalid control config transition")
		}
		next.Config = *material.ControlConfig
		next.ConfigMaterial = materialID
	}
	next.Applied = append(next.Applied, material.RequestID)
	sort.Strings(next.Applied)
	return next, nil
}

func contains(values []string, value string) bool {
	index := sort.SearchStrings(values, value)
	return index < len(values) && values[index] == value
}

func projectionDigest(projection Projection) (string, error) {
	// UIState is a one-way runtime projection of the certified boundary, not a
	// second input to the authoritative Projection digest.
	projection.Web.UIState = UIState{}
	body, err := canonical(projection)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func logDigest(entries []ConsensusEntry) (string, error) {
	body, err := canonical(entries)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func headSigningBytes(head GovernanceHead) ([]byte, error) {
	head.Signatures = nil
	body, err := canonical(head)
	if err != nil {
		return nil, err
	}
	return append([]byte(headDomain), body...), nil
}

func HeadID(head GovernanceHead) string {
	body, _ := headSigningBytes(head)
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// HeadIDFromProjection is only used as the optimistic-concurrency coordinate
// before a new head is assembled. The runtime overwrites UIState.Head with the
// certified head identifier after certification.
func HeadIDFromProjection(projection Projection) string { return projection.Web.UIState.Head }

func VerifyHead(head GovernanceHead, projection Projection, entries []ConsensusEntry) error {
	if head.Schema != HeadSchema || head.Index == 0 || head.Index > uint64(len(entries)) || head.ConfigMaterial != projection.ConfigMaterial {
		return errors.New("certified head coordinates are invalid")
	}
	logHash, err := logDigest(entries[:head.Index])
	if err != nil || logHash != head.LogDigest {
		return errors.New("certified head log digest is invalid")
	}
	projectionHash, err := projectionDigest(projection)
	if err != nil || projectionHash != head.ProjectionDigest {
		return errors.New("certified head projection digest is invalid")
	}
	message, err := headSigningBytes(head)
	if err != nil {
		return err
	}
	valid := map[string]bool{}
	memberByID := map[string]Member{}
	for _, member := range append(append([]Member{}, projection.Config.Members...), append(projection.Config.Old, projection.Config.New...)...) {
		memberByID[member.ID] = member
	}
	for _, signature := range head.Signatures {
		if len(valid) > 0 {
			previous := head.Signatures[len(valid)-1].MemberID
			if previous >= signature.MemberID {
				return errors.New("head signatures are not uniquely sorted")
			}
		}
		if valid[signature.MemberID] {
			return errors.New("duplicate head signature")
		}
		member, ok := memberByID[signature.MemberID]
		if !ok {
			return errors.New("head signature is from a non-member")
		}
		key, _ := base64.RawURLEncoding.DecodeString(member.PublicKey)
		value, err := base64.RawURLEncoding.DecodeString(signature.Value)
		if err != nil || !ed25519.Verify(key, message, value) {
			return errors.New("head signature is invalid")
		}
		valid[signature.MemberID] = true
	}
	count := func(members []Member) int {
		total := 0
		for _, member := range members {
			if valid[member.ID] {
				total++
			}
		}
		return total
	}
	if projection.Config.Mode == "stable" {
		if count(projection.Config.Members) < projection.Config.Quorum {
			return errors.New("certified head lacks quorum")
		}
	} else if count(projection.Config.Old) < projection.Config.OldQuorum || count(projection.Config.New) < projection.Config.NewQuorum {
		return errors.New("certified joint head lacks both quorums")
	}
	return nil
}
