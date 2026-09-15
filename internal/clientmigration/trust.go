package clientmigration

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"

	"loom/internal/wire"
)

// RuntimeActivationTrust 从本机原平台公钥构造完整信任锚；不从待验证迁移包
// 接受 key ID 或摘要，避免漏传摘要而拒绝合法包，也避免把自报字段当信任来源。
func RuntimeActivationTrust(public ed25519.PublicKey) (wire.InviteProofTrustV2, error) {
	id, err := wire.ControlKeyID(public)
	if err != nil {
		return wire.InviteProofTrustV2{}, err
	}
	return wire.InviteProofTrustV2{V1PlatformKey: append(ed25519.PublicKey(nil), public...), V1PlatformKeyID: id,
		V1MigrationAnchorDigest: fmt.Sprintf("sha256:%x", sha256.Sum256(public))}, nil
}
