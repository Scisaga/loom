package clientdist

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Published is verified metadata for a Web download surface. Callers must not
// construct download metadata from a sidecar alone: archive, checksum,
// signature, embedded manifest and the separately pinned public key are one
// verification transaction.
type Published struct {
	Manifest  Manifest
	SHA256    string
	Size      int64
	Archive   []byte
	Checksum  []byte
	Signature []byte
	PublicKey []byte
}

// VerifyFiles verifies the production archive and its adjacent sidecars.
func VerifyFiles(archivePath, publicKeyPath string) (Published, error) {
	var out Published
	archive, err := readRegularBounded(archivePath, maxArchiveBytes)
	if err != nil {
		return out, err
	}
	checksum, err := readRegularBounded(archivePath+".sha256", 4<<10)
	if err != nil {
		return out, err
	}
	signature, err := readRegularBounded(archivePath+".sig", 16<<10)
	if err != nil {
		return out, err
	}
	publicBody, err := readRegularBounded(publicKeyPath, 4<<10)
	if err != nil {
		return out, err
	}
	publicKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(publicBody)))
	if err != nil {
		publicKey, err = base64.RawStdEncoding.DecodeString(strings.TrimSpace(string(publicBody)))
	}
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return out, fmt.Errorf("[§4.3 签名高于传输信任] 带外平台公钥 %s 无效", publicKeyPath)
	}
	manifest, err := Verify(archive, checksum, signature, ed25519.PublicKey(publicKey))
	if err != nil {
		return out, err
	}
	wantName := "loom-client-linux-" + manifest.Arch + ".tar.gz"
	if filepath.Base(archivePath) != wantName {
		return out, fmt.Errorf("[§10.2 渲染目标必须显式] 客户端包文件名是 %q，期望 %q", filepath.Base(archivePath), wantName)
	}
	fields := strings.Fields(string(checksum))
	if len(fields) != 2 || fields[1] != wantName {
		return out, fmt.Errorf("客户端包校验附件声明的文件名无效")
	}
	// Return the exact verified bytes. A handler that reopens archivePath after
	// this point would reintroduce a verify/use race with the publisher.
	return Published{
		Manifest: manifest, SHA256: fields[0], Size: int64(len(archive)), Archive: archive,
		Checksum: checksum, Signature: signature, PublicKey: publicBody,
	}, nil
}

func readRegularBounded(path string, limit int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("检查客户端制品 %s:%w", path, err)
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() <= 0 || before.Size() > limit {
		return nil, fmt.Errorf("[§10.3 原子安装] 客户端制品 %s 必须是有界、非链接的普通文件", path)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("打开客户端制品 %s:%w", path, err)
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) || after.Size() != before.Size() {
		return nil, fmt.Errorf("[§10.3 原子安装] 客户端制品 %s 在验证期间发生变化", path)
	}
	if stat, ok := after.Sys().(*syscall.Stat_t); ok && stat.Nlink != 1 {
		return nil, fmt.Errorf("[§10.3 原子安装] 客户端制品 %s 不得是硬链接", path)
	}
	body, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(body)) != after.Size() || int64(len(body)) > limit {
		return nil, fmt.Errorf("读客户端制品 %s 失败", path)
	}
	return body, nil
}
