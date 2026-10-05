package publish

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
	"time"

	"loom/internal/model"
)

// DeploymentCurrentSchema identifies protected historical evidence only.
const DeploymentCurrentSchema = 1

const deploymentCurrentDomain = "loom-current-v1\x00"

// DeploymentAssignment selects the immutable snapshot a node should apply.
// An empty assignment list means every node selects DeploymentCurrent.Snapshot.
// Once assignments are present, absence is an error rather than an implicit
// fallback: silently falling back would turn an incomplete canary map into an
// accidental rollout.
type DeploymentAssignment struct {
	Node     string `json:"node"`
	Snapshot string `json:"snapshot"`
}

// DeploymentCurrent is the original signed pointer shape, retained only for
// offline verification of protected evidence. New publication and installation
// never consume it; its original signed bytes and persisted floors are preserved.
type DeploymentCurrent struct {
	Schema      int                    `json:"schema"`
	Generation  uint64                 `json:"generation"`
	Snapshot    string                 `json:"snapshot"`
	Assignments []DeploymentAssignment `json:"assignments,omitempty"`
	PublishedAt string                 `json:"published_at"`
	Signature   string                 `json:"signature"`
}

// deploymentCurrentPayload fixes both the signed field set and its JSON field
// order.  Do not sign DeploymentCurrent with Signature blanked: a future
// unsigned display field added to that struct could otherwise accidentally
// enter or leave the trust boundary.
type deploymentCurrentPayload struct {
	Schema      int                    `json:"schema"`
	Generation  uint64                 `json:"generation"`
	Snapshot    string                 `json:"snapshot"`
	Assignments []DeploymentAssignment `json:"assignments,omitempty"`
	PublishedAt string                 `json:"published_at"`
}

// DecodeDeploymentCurrent strictly decodes a signed current.json envelope.
// Signature authenticity is deliberately a separate Verify call because the
// caller owns the pinned public key. Unsigned pointers are not accepted.
// This decoder is used only by offline evidence inspection and backup checks.
func DecodeDeploymentCurrent(body []byte) (*DeploymentCurrent, error) {
	if err := rejectDuplicateJSONKeys(body); err != nil {
		return nil, fmt.Errorf("current.json 非法:%w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var current DeploymentCurrent
	if err := dec.Decode(&current); err != nil {
		return nil, fmt.Errorf("解析 current.json:%w", err)
	}
	if err := requireJSONEOF(dec); err != nil {
		return nil, fmt.Errorf("解析 current.json:%w", err)
	}
	current.Assignments = sortedAssignments(current.Assignments)
	if err := current.validate(true); err != nil {
		return nil, fmt.Errorf("current.json 无效:%w", err)
	}
	return &current, nil
}

// Verify checks the envelope with the locally pinned platform public key.
// The domain prefix prevents a valid snapshot/attestation signature from being
// transplanted onto this mutable release pointer.
func (c *DeploymentCurrent) Verify(pub ed25519.PublicKey) error {
	if c == nil {
		return errors.New("不能验证空 current")
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("公钥长度不对:%d", len(pub))
	}
	if err := c.validate(true); err != nil {
		return err
	}
	sig, err := decodeDeploymentSignature(c.Signature)
	if err != nil {
		return err
	}
	message, err := c.signingBytes()
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, message, sig) {
		return errors.New("current.json 签名校验失败")
	}
	return nil
}

// Select reads a historical assignment after verification. It never selects
// a running program, network configuration, or current release.
func (c *DeploymentCurrent) Select(node string) (string, error) {
	if c == nil {
		return "", errors.New("不能从空 current 选择快照")
	}
	if !model.ValidNodeID(node) {
		return "", fmt.Errorf("节点 id %q 格式非法", node)
	}
	if err := c.validate(false); err != nil {
		return "", err
	}
	if len(c.Assignments) == 0 {
		return c.Snapshot, nil
	}
	for _, assignment := range c.Assignments {
		if assignment.Node == node {
			return assignment.Snapshot, nil
		}
	}
	return "", fmt.Errorf("signed current 没有节点 %s 的 assignment", node)
}

// PayloadSHA256 is the stable coordinate nodes persist next to the highest
// accepted generation.  It hashes exactly the domain-separated canonical bytes
// verified by Ed25519 and intentionally excludes Signature itself.
func (c *DeploymentCurrent) PayloadSHA256() (string, error) {
	if c == nil {
		return "", errors.New("不能计算空 current 的 payload 哈希")
	}
	if err := c.validate(false); err != nil {
		return "", err
	}
	b, err := c.signingBytes()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// Bytes returns the stable, human-readable wire representation.  It validates
// the signature encoding but cannot establish authenticity without a public
// key; callers should Verify before serving decoded, externally supplied data.
func (c *DeploymentCurrent) Bytes() ([]byte, error) {
	if c == nil {
		return nil, errors.New("不能序列化空 current")
	}
	normalized := *c
	normalized.Assignments = sortedAssignments(c.Assignments)
	if err := normalized.validate(true); err != nil {
		return nil, err
	}
	b, err := json.MarshalIndent(&normalized, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func (c *DeploymentCurrent) signingBytes() ([]byte, error) {
	payload := deploymentCurrentPayload{
		Schema: c.Schema, Generation: c.Generation, Snapshot: c.Snapshot,
		Assignments: sortedAssignments(c.Assignments), PublishedAt: c.PublishedAt,
	}
	b, err := json.Marshal(&payload)
	if err != nil {
		return nil, fmt.Errorf("序列化 current 签名 payload:%w", err)
	}
	message := make([]byte, 0, len(deploymentCurrentDomain)+len(b))
	message = append(message, deploymentCurrentDomain...)
	message = append(message, b...)
	return message, nil
}

func (c *DeploymentCurrent) validate(requireSignature bool) error {
	if c.Schema != DeploymentCurrentSchema {
		return fmt.Errorf("不支持 current schema=%d", c.Schema)
	}
	if c.Generation == 0 {
		return errors.New("generation 必须大于 0")
	}
	if !validDeploymentSnapshot(c.Snapshot) {
		return fmt.Errorf("snapshot %q 必须是 12 位小写十六进制", c.Snapshot)
	}
	seen := make(map[string]struct{}, len(c.Assignments))
	for _, assignment := range c.Assignments {
		if !model.ValidNodeID(assignment.Node) {
			return fmt.Errorf("assignment 节点 %q 格式非法", assignment.Node)
		}
		if _, ok := seen[assignment.Node]; ok {
			return fmt.Errorf("节点 %s 出现重复 assignment", assignment.Node)
		}
		seen[assignment.Node] = struct{}{}
		if !validDeploymentSnapshot(assignment.Snapshot) {
			return fmt.Errorf("节点 %s 的 snapshot %q 必须是 12 位小写十六进制",
				assignment.Node, assignment.Snapshot)
		}
	}
	if err := validateDeploymentPublishedAt(c.PublishedAt); err != nil {
		return err
	}
	if requireSignature {
		if _, err := decodeDeploymentSignature(c.Signature); err != nil {
			return err
		}
	}
	return nil
}

func validateDeploymentPublishedAt(value string) error {
	if value == "" {
		return errors.New("published_at 不能为空")
	}
	if _, err := time.Parse(time.RFC3339Nano, value); err != nil {
		return fmt.Errorf("published_at %q 不是 RFC3339 时间:%w", value, err)
	}
	return nil
}

func decodeDeploymentSignature(encoded string) ([]byte, error) {
	if encoded == "" {
		return nil, errors.New("current.json 没有签名")
	}
	sig, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("current.json 签名不是标准 base64:%w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("current.json 签名长度不对:%d", len(sig))
	}
	// Reject non-canonical encodings so the same signature has one wire form.
	if base64.StdEncoding.EncodeToString(sig) != encoded {
		return nil, errors.New("current.json 签名不是规范 base64")
	}
	return sig, nil
}

func sortedAssignments(in []DeploymentAssignment) []DeploymentAssignment {
	if len(in) == 0 {
		return nil
	}
	out := append([]DeploymentAssignment(nil), in...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Node != out[j].Node {
			return out[i].Node < out[j].Node
		}
		return out[i].Snapshot < out[j].Snapshot
	})
	return out
}

func validDeploymentSnapshot(id string) bool {
	if len(id) != 12 {
		return false
	}
	for _, c := range []byte(id) {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func requireJSONEOF(dec *json.Decoder) error {
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("current.json 后还有第二个 JSON 值")
		}
		return err
	}
	return nil
}

// rejectDuplicateJSONKeys closes an ambiguity left by encoding/json: it
// normally accepts repeated object keys and keeps the last value.  Different
// implementations need not make the same choice, which is unsafe at a signed
// protocol boundary.  Walk the complete JSON once before strict decoding and
// reject duplicates at every object depth, including assignment objects.
func rejectDuplicateJSONKeys(body []byte) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := walkJSONValue(dec); err != nil {
		return err
	}
	return requireJSONEOF(dec)
}

func walkJSONValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		for dec.More() {
			keyToken, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON 对象键不是字符串")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("JSON 字段 %q 重复", key)
			}
			seen[key] = struct{}{}
			if err := walkJSONValue(dec); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil {
			return err
		}
		if end != json.Delim('}') {
			return errors.New("JSON 对象没有正确结束")
		}
	case '[':
		for dec.More() {
			if err := walkJSONValue(dec); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil {
			return err
		}
		if end != json.Delim(']') {
			return errors.New("JSON 数组没有正确结束")
		}
	default:
		return fmt.Errorf("意外的 JSON 分隔符 %q", delim)
	}
	return nil
}
