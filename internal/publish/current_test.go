package publish

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func deploymentCurrentKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func signedDeploymentCurrent(t *testing.T) (*DeploymentCurrent, ed25519.PublicKey) {
	t.Helper()
	pub, priv := deploymentCurrentKey(t)
	c := &DeploymentCurrent{
		Schema: DeploymentCurrentSchema, Generation: 7,
		Snapshot: "aaaaaaaaaaaa", PublishedAt: "2026-08-27T12:00:00Z",
		Assignments: []DeploymentAssignment{
			{Node: "hz01", Snapshot: "cccccccccccc"},
			{Node: "gz02", Snapshot: "bbbbbbbbbbbb"},
		},
	}
	if err := c.Sign(priv); err != nil {
		t.Fatal(err)
	}
	return c, pub
}

func TestDeploymentCurrentRoundTripAndLegacyCompatibility(t *testing.T) {
	c, pub := signedDeploymentCurrent(t)
	if got := []string{c.Assignments[0].Node, c.Assignments[1].Node}; got[0] != "gz02" || got[1] != "hz01" {
		t.Fatalf("Sign 没有规范化 assignment 顺序:%v", got)
	}
	if err := c.Verify(pub); err != nil {
		t.Fatalf("签名后不能自验:%v", err)
	}
	body, err := c.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeDeploymentCurrent(body)
	if err != nil {
		t.Fatal(err)
	}
	if err := decoded.Verify(pub); err != nil {
		t.Fatalf("往返后验签失败:%v", err)
	}
	if got, err := decoded.Select("gz02"); err != nil || got != "bbbbbbbbbbbb" {
		t.Fatalf("gz02 assignment=%q err=%v", got, err)
	}
	if _, err := decoded.Select("jm24"); err == nil {
		t.Fatal("显式 assignment 模式下缺少节点应 fail closed")
	}

	// The deployed legacy reader only knows these two fields.  New envelopes
	// must therefore retain them at the top level during migration.
	var legacy Current
	if err := json.Unmarshal(body, &legacy); err != nil {
		t.Fatalf("旧 Current 不能解析新 envelope:%v", err)
	}
	if legacy.Snapshot != c.Snapshot || legacy.PublishedAt != c.PublishedAt {
		t.Fatalf("旧 reader 没读到兼容坐标:%+v", legacy)
	}
}

func TestDeploymentCurrentGlobalSelection(t *testing.T) {
	_, priv := deploymentCurrentKey(t)
	c := &DeploymentCurrent{
		Generation: 1, Snapshot: "0123456789ab", PublishedAt: "2026-08-27T12:00:00Z",
	}
	if err := c.Sign(priv); err != nil {
		t.Fatal(err)
	}
	if c.Schema != DeploymentCurrentSchema {
		t.Fatalf("Sign 应给零值 schema 填 v1，收到 %d", c.Schema)
	}
	if got, err := c.Select("jm24"); err != nil || got != c.Snapshot {
		t.Fatalf("全局选择=%q err=%v", got, err)
	}
	if _, err := c.Select("bad/node"); err == nil {
		t.Fatal("非法调用方 node id 被接受")
	}
}

func TestDeploymentCurrentCanonicalizesWireAssignmentOrder(t *testing.T) {
	c, pub := signedDeploymentCurrent(t)
	// Reorder the semantic set on the wire without changing its signature.
	// Decode normalizes it, so all implementations verify the same payload.
	c.Assignments[0], c.Assignments[1] = c.Assignments[1], c.Assignments[0]
	body, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeDeploymentCurrent(body)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Assignments[0].Node != "gz02" || decoded.Assignments[1].Node != "hz01" {
		t.Fatalf("Decode 没有排序:%+v", decoded.Assignments)
	}
	if err := decoded.Verify(pub); err != nil {
		t.Fatalf("同一 assignment 集合换序后不应改变 canonical payload:%v", err)
	}
}

func TestDeploymentCurrentSignatureCoversPayload(t *testing.T) {
	original, pub := signedDeploymentCurrent(t)
	cases := []struct {
		name   string
		mutate func(*DeploymentCurrent)
	}{
		{"schema", func(c *DeploymentCurrent) { c.Schema = 2 }},
		{"generation", func(c *DeploymentCurrent) { c.Generation++ }},
		{"snapshot", func(c *DeploymentCurrent) { c.Snapshot = "dddddddddddd" }},
		{"published-at", func(c *DeploymentCurrent) { c.PublishedAt = "2026-08-27T12:00:01Z" }},
		{"assignment", func(c *DeploymentCurrent) { c.Assignments[0].Snapshot = "eeeeeeeeeeee" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			changed := *original
			changed.Assignments = append([]DeploymentAssignment(nil), original.Assignments...)
			tc.mutate(&changed)
			if err := changed.Verify(pub); err == nil {
				t.Fatal("被修改的 payload 仍通过验签")
			}
		})
	}

	otherPub, _ := deploymentCurrentKey(t)
	if err := original.Verify(otherPub); err == nil {
		t.Fatal("错误平台公钥仍通过验签")
	}
}

func TestDeploymentCurrentSignatureUsesDomainSeparation(t *testing.T) {
	pub, priv := deploymentCurrentKey(t)
	c := &DeploymentCurrent{
		Schema: DeploymentCurrentSchema, Generation: 1,
		Snapshot: "aaaaaaaaaaaa", PublishedAt: "2026-08-27T12:00:00Z",
	}
	payload, err := json.Marshal(deploymentCurrentPayload{
		Schema: c.Schema, Generation: c.Generation,
		Snapshot: c.Snapshot, PublishedAt: c.PublishedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	// A signature over JSON alone is not a Loom current signature.
	c.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload))
	if err := c.Verify(pub); err == nil {
		t.Fatal("缺少协议域分隔的签名被接受")
	}
}

func TestDeploymentCurrentPayloadSHA256StableAndExcludesSignature(t *testing.T) {
	c, _ := signedDeploymentCurrent(t)
	want, err := c.PayloadSHA256()
	if err != nil {
		t.Fatal(err)
	}
	if len(want) != 64 {
		t.Fatalf("payload sha 长度=%d", len(want))
	}
	copy := *c
	copy.Signature = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	got, err := copy.PayloadSHA256()
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("signature 不应进入 payload digest:%s != %s", got, want)
	}
	copy.Generation++
	changed, err := copy.PayloadSHA256()
	if err != nil {
		t.Fatal(err)
	}
	if changed == want {
		t.Fatal("generation 变化没有改变 payload digest")
	}
}

func TestDecodeDeploymentCurrentStrict(t *testing.T) {
	c, _ := signedDeploymentCurrent(t)
	body, err := c.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	valid := strings.TrimSpace(string(body))
	sig := c.Signature
	cases := []struct {
		name string
		body string
		want string
	}{
		{"unknown-field", strings.TrimSuffix(valid, "}") + `,"surprise":true}`, "unknown field"},
		{"trailing-value", valid + ` {}`, "第二个 JSON"},
		{"duplicate-top-level", `{"schema":1,"schema":1,"generation":1,"snapshot":"aaaaaaaaaaaa","published_at":"2026-08-27T12:00:00Z","signature":"` + sig + `"}`, "重复"},
		{"duplicate-assignment", `{"schema":1,"generation":1,"snapshot":"aaaaaaaaaaaa","assignments":[{"node":"gz02","snapshot":"bbbbbbbbbbbb"},{"node":"gz02","snapshot":"cccccccccccc"}],"published_at":"2026-08-27T12:00:00Z","signature":"` + sig + `"}`, "重复 assignment"},
		{"duplicate-assignment-key", `{"schema":1,"generation":1,"snapshot":"aaaaaaaaaaaa","assignments":[{"node":"gz02","node":"hz01","snapshot":"bbbbbbbbbbbb"}],"published_at":"2026-08-27T12:00:00Z","signature":"` + sig + `"}`, "重复"},
		{"bad-node", `{"schema":1,"generation":1,"snapshot":"aaaaaaaaaaaa","assignments":[{"node":"bad/node","snapshot":"bbbbbbbbbbbb"}],"published_at":"2026-08-27T12:00:00Z","signature":"` + sig + `"}`, "格式非法"},
		{"bad-root-snapshot", `{"schema":1,"generation":1,"snapshot":"AAAAAAAAAAAA","published_at":"2026-08-27T12:00:00Z","signature":"` + sig + `"}`, "12 位小写十六进制"},
		{"bad-assignment-snapshot", `{"schema":1,"generation":1,"snapshot":"aaaaaaaaaaaa","assignments":[{"node":"gz02","snapshot":"not-a-snap"}],"published_at":"2026-08-27T12:00:00Z","signature":"` + sig + `"}`, "12 位小写十六进制"},
		{"zero-generation", `{"schema":1,"generation":0,"snapshot":"aaaaaaaaaaaa","published_at":"2026-08-27T12:00:00Z","signature":"` + sig + `"}`, "大于 0"},
		{"future-schema", `{"schema":2,"generation":1,"snapshot":"aaaaaaaaaaaa","published_at":"2026-08-27T12:00:00Z","signature":"` + sig + `"}`, "不支持"},
		{"missing-signature", `{"schema":1,"generation":1,"snapshot":"aaaaaaaaaaaa","published_at":"2026-08-27T12:00:00Z"}`, "没有签名"},
		{"bad-base64", `{"schema":1,"generation":1,"snapshot":"aaaaaaaaaaaa","published_at":"2026-08-27T12:00:00Z","signature":"%%%"}`, "base64"},
		{"short-signature", `{"schema":1,"generation":1,"snapshot":"aaaaaaaaaaaa","published_at":"2026-08-27T12:00:00Z","signature":"YQ=="}`, "长度不对"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeDeploymentCurrent([]byte(tc.body))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err=%v，期望包含 %q", err, tc.want)
			}
		})
	}
}

func TestDeploymentCurrentRejectsBadKeyLengths(t *testing.T) {
	c := &DeploymentCurrent{
		Schema: 1, Generation: 1, Snapshot: "aaaaaaaaaaaa",
		PublishedAt: "2026-08-27T12:00:00Z",
	}
	if err := c.Sign(make([]byte, ed25519.PrivateKeySize-1)); err == nil {
		t.Fatal("错误长度私钥被接受")
	}
	c, _ = signedDeploymentCurrent(t)
	if err := c.Verify(make([]byte, ed25519.PublicKeySize-1)); err == nil {
		t.Fatal("错误长度公钥被接受")
	}
}

func TestDeploymentCurrentRejectsMissingOrInvalidPublishedAt(t *testing.T) {
	_, priv := deploymentCurrentKey(t)
	for _, value := range []string{"", "yesterday", "2026-08-27 12:00:00"} {
		t.Run(value, func(t *testing.T) {
			c := &DeploymentCurrent{
				Schema: 1, Generation: 1, Snapshot: "aaaaaaaaaaaa", PublishedAt: value,
			}
			if err := c.Sign(priv); err == nil || !strings.Contains(err.Error(), "published_at") {
				t.Fatalf("published_at=%q err=%v", value, err)
			}
		})
	}
}

func TestDecodeLegacyCurrentStrict(t *testing.T) {
	good := `{"snapshot":"aaaaaaaaaaaa","published_at":"2026-08-27T12:00:00.123Z"}`
	got, err := DecodeLegacyCurrent([]byte(good))
	if err != nil || got.Snapshot != "aaaaaaaaaaaa" {
		t.Fatalf("合法 legacy current 解码失败:%+v err=%v", got, err)
	}
	for _, tc := range []struct {
		name, body string
	}{
		{"unknown", strings.TrimSuffix(good, "}") + `,"generation":1}`},
		{"duplicate", `{"snapshot":"aaaaaaaaaaaa","snapshot":"bbbbbbbbbbbb","published_at":"2026-08-27T12:00:00Z"}`},
		{"trailing", good + `{}`},
		{"bad-snapshot", `{"snapshot":"not-a-snap","published_at":"2026-08-27T12:00:00Z"}`},
		{"missing-time", `{"snapshot":"aaaaaaaaaaaa","published_at":""}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DecodeLegacyCurrent([]byte(tc.body)); err == nil {
				t.Fatal("非法 legacy current 被接受")
			}
		})
	}
}
