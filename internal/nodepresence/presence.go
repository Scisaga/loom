// Package nodepresence 定义 Device 在线心跳的最小签名协议。
//
// 心跳只证明节点私钥在某一时刻仍可用；它不携带、刷新或替代 Observation
// 中的健康、自检、配置、链路、测量和流量事实（§16.4）。
package nodepresence

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	Period           = 5 * time.Second
	Lease            = 15 * time.Second
	MaximumTransit   = 30 * time.Second
	MaximumClockLead = 30 * time.Second
	MaxEnvelopeBytes = 1024
	MaxBatchEntries  = 256
)

// Heartbeat 的三个字段就是完整线协议；证书和公钥由既有加入身份或已验签
// Observation 提供，不能在每五秒的包里重复发送（§16.4）。
type Heartbeat struct {
	Node      string `json:"node"`
	TS        string `json:"ts"`
	Signature string `json:"signature"`
}

// Message 返回跨平台签名的唯一原文。长度前缀避免节点名或时间文本产生边界歧义。
func Message(node, timestamp string) ([]byte, error) {
	if !validNodeID(node) {
		return nil, errors.New("[§16.4 在线心跳] node 无效")
	}
	if len(timestamp) > len(time.RFC3339Nano)+8 {
		return nil, errors.New("[§16.4 在线心跳] 时间文本过长")
	}
	if _, err := time.Parse(time.RFC3339Nano, timestamp); err != nil {
		return nil, errors.New("[§16.4 在线心跳] 时间必须是 RFC3339")
	}
	var output bytes.Buffer
	for _, value := range []string{"loom-presence-v1", node, timestamp} {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(value)))
		output.Write(size[:])
		output.WriteString(value)
	}
	return output.Bytes(), nil
}

// 心跳独立模块复刻 SSOT 的单 DNS-label 身份语法，避免 Android binding 为
// 三字段包拉入整个 model/YAML 依赖；协议测试锁住同一边界（§16.4）。
func validNodeID(node string) bool {
	if len(node) == 0 || len(node) > 63 {
		return false
	}
	for i := range len(node) {
		character := node[i]
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') {
			continue
		}
		if character != '-' || i == 0 || i == len(node)-1 {
			return false
		}
	}
	return true
}

func Timestamp(at time.Time) string {
	return at.UTC().Format(time.RFC3339Nano)
}

// Assemble 把平台密钥产生的 ASN.1 DER 签名装入最小心跳；Android Keystore
// 使用这个边界，私钥不离开平台存储（§16.4）。
func Assemble(node, timestamp string, signatureDER []byte) (Heartbeat, error) {
	if _, err := Message(node, timestamp); err != nil {
		return Heartbeat{}, err
	}
	if len(signatureDER) == 0 || len(signatureDER) > 128 {
		return Heartbeat{}, errors.New("[§16.4 在线心跳] P-256 签名长度无效")
	}
	return Heartbeat{
		Node: node, TS: timestamp,
		Signature: base64.RawStdEncoding.EncodeToString(signatureDER),
	}, nil
}

func Sign(node string, at time.Time, keyPEM []byte) (Heartbeat, error) {
	timestamp := Timestamp(at)
	message, err := Message(node, timestamp)
	if err != nil {
		return Heartbeat{}, err
	}
	key, err := parsePrivateKey(keyPEM)
	if err != nil {
		return Heartbeat{}, err
	}
	if key.Curve != elliptic.P256() {
		return Heartbeat{}, errors.New("[§16.4 在线心跳] 私钥必须使用 ECDSA P-256")
	}
	digest := sha256.Sum256(message)
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		return Heartbeat{}, fmt.Errorf("[§16.4 在线心跳] 签名失败:%w", err)
	}
	return Assemble(node, timestamp, signature)
}

// Verify 只验证心跳身份与传输时效，不赋予它任何 Observation 语义。
func Verify(heartbeat Heartbeat, publicKey *ecdsa.PublicKey, now time.Time, maximumAge time.Duration) (time.Time, error) {
	if publicKey == nil || publicKey.Curve != elliptic.P256() {
		return time.Time{}, errors.New("[§16.4 在线心跳] 公钥必须使用 ECDSA P-256")
	}
	message, err := Message(heartbeat.Node, heartbeat.TS)
	if err != nil {
		return time.Time{}, err
	}
	if maximumAge <= 0 {
		return time.Time{}, errors.New("[§16.4 在线心跳] 接收时效边界无效")
	}
	at, _ := time.Parse(time.RFC3339Nano, heartbeat.TS)
	age := now.UTC().Sub(at.UTC())
	if age < -MaximumClockLead {
		return time.Time{}, errors.New("[§16.4 在线心跳] 时间来自未来")
	}
	if age > maximumAge {
		return time.Time{}, errors.New("[§16.4 在线心跳] 已超过转发时效")
	}
	signature, err := base64.RawStdEncoding.Strict().DecodeString(heartbeat.Signature)
	if err != nil || base64.RawStdEncoding.EncodeToString(signature) != heartbeat.Signature ||
		len(signature) == 0 || len(signature) > 128 {
		return time.Time{}, errors.New("[§16.4 在线心跳] 签名编码无效")
	}
	digest := sha256.Sum256(message)
	if !ecdsa.VerifyASN1(publicKey, digest[:], signature) {
		return time.Time{}, errors.New("[§16.4 在线心跳] 签名验证失败")
	}
	return at.UTC(), nil
}

func ParsePublicKey(encoded string) (*ecdsa.PublicKey, error) {
	encoded = strings.TrimSpace(encoded)
	spki, err := base64.RawStdEncoding.Strict().DecodeString(encoded)
	if err != nil || base64.RawStdEncoding.EncodeToString(spki) != encoded {
		return nil, errors.New("[§16.4 在线心跳] 身份公钥编码无效")
	}
	parsed, err := x509.ParsePKIXPublicKey(spki)
	key, ok := parsed.(*ecdsa.PublicKey)
	if err != nil || !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("[§16.4 在线心跳] 身份公钥必须是 P-256 SPKI")
	}
	return key, nil
}

func parsePrivateKey(keyPEM []byte) (*ecdsa.PrivateKey, error) {
	rest := keyPEM
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			return nil, errors.New("[§16.4 在线心跳] 私钥里没有可用 PEM 块")
		}
		rest = remaining
		switch block.Type {
		case "EC PRIVATE KEY":
			key, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return nil, errors.New("[§16.4 在线心跳] EC 私钥格式无效")
			}
			return key, nil
		case "PRIVATE KEY":
			parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			key, ok := parsed.(*ecdsa.PrivateKey)
			if err != nil || !ok {
				return nil, errors.New("[§16.4 在线心跳] PKCS#8 私钥不是 ECDSA")
			}
			return key, nil
		}
	}
}
