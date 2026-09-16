package wire

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"errors"
)

const LocalWireGuardKeySecretID = "local-wireguard-key"

// 新入网必须绑定本机生成的公钥；没有此字段的旧 claim 只用于历史证明读取。
// 私钥不进入 claim、QR、控制日志或服务端签发材料。
func EnrollmentWireGuardPublicKey(core *EnrollmentClaimCoreV2) (string, error) {
	if _, err := EnrollmentClaimCoreHash(core); err != nil {
		return "", err
	}
	if err := validateEnrollmentWireGuardPublic(core.WireGuardPublicKey); err != nil {
		return "", err
	}
	return core.WireGuardPublicKey, nil
}

func VerifyEnrollmentLocalWireGuardKey(core *EnrollmentClaimCoreV2, private []byte) error {
	public, err := EnrollmentWireGuardPublicKey(core)
	if err != nil {
		return err
	}
	key, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil || base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()) != public {
		return errors.New("[Enrollment] 本机 WireGuard 密钥与原 claim 不一致")
	}
	return nil
}

func validateEnrollmentWireGuardPublic(encoded string) error {
	public, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(public) != 32 || base64.StdEncoding.EncodeToString(public) != encoded {
		return errors.New("[Enrollment] 缺规范的设备本地 WireGuard 公钥")
	}
	// 固定标量仅用于拒绝公开输入中的低阶点，不属于设备身份或生产秘密。
	probe, _ := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{0x42}, 32))
	peer, err := ecdh.X25519().NewPublicKey(public)
	if err == nil {
		var shared []byte
		shared, err = probe.ECDH(peer)
		clear(shared)
	}
	if err != nil {
		return errors.New("[Enrollment] WireGuard 公钥不是可用 peer")
	}
	return nil
}
