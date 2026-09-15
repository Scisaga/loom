//go:build windows

package windowsv2

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"runtime"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"

	"loom/internal/clientsecret"
)

const (
	windowsCNGIdentityProvider = "windows-cng-ms-ksp-p256-v1"
	windowsCNGProviderName     = "Microsoft Software Key Storage Provider"
	windowsCNGAlgorithm        = "ECDSA_P256"
	windowsCNGECCPublicBlob    = "ECCPUBLICBLOB"
	windowsCNGExportPolicy     = "Export Policy"
	windowsCNGKeyPrefix        = "Loom-v2-"

	ncryptMachineKeyFlag       = 0x00000020
	ncryptSilentFlag           = 0x00000040
	ncryptPersistFlag          = 0x80000000
	nteExists                  = 0x8009000f
	nteBadKeyset               = 0x80090016
	bcryptECDSAPublicP256Magic = 0x31534345
)

var (
	ncryptDLL                 = windows.NewLazySystemDLL("ncrypt.dll")
	ncryptOpenStorageProvider = ncryptDLL.NewProc("NCryptOpenStorageProvider")
	ncryptCreatePersistedKey  = ncryptDLL.NewProc("NCryptCreatePersistedKey")
	ncryptOpenKey             = ncryptDLL.NewProc("NCryptOpenKey")
	ncryptSetProperty         = ncryptDLL.NewProc("NCryptSetProperty")
	ncryptFinalizeKey         = ncryptDLL.NewProc("NCryptFinalizeKey")
	ncryptExportKey           = ncryptDLL.NewProc("NCryptExportKey")
	ncryptSignHash            = ncryptDLL.NewProc("NCryptSignHash")
	ncryptDeleteKey           = ncryptDLL.NewProc("NCryptDeleteKey")
	ncryptFreeObject          = ncryptDLL.NewProc("NCryptFreeObject")
)

type cngP256Signer struct {
	mu     sync.Mutex
	handle uintptr
	public ecdsa.PublicKey
}

func createPlatformIdentity(protector clientsecret.Protector, random io.Reader,
) (crypto.Signer, []byte, platformIdentityRecord, error) {
	if random == nil {
		return nil, nil, platformIdentityRecord{}, errors.New("[Windows CNG] key-name random source 缺失")
	}
	machine := windowsIdentityMachineScope(protector)
	provider, err := openWindowsCNGProvider()
	if err != nil {
		return nil, nil, platformIdentityRecord{}, err
	}
	defer freeWindowsCNGObject(provider)
	algorithm, _ := windows.UTF16PtrFromString(windowsCNGAlgorithm)
	property, _ := windows.UTF16PtrFromString(windowsCNGExportPolicy)
	for attempt := 0; attempt < 4; attempt++ {
		nameBytes := make([]byte, 16)
		if _, err := io.ReadFull(random, nameBytes); err != nil {
			return nil, nil, platformIdentityRecord{}, err
		}
		name := windowsCNGKeyPrefix + hex.EncodeToString(nameBytes)
		clear(nameBytes)
		nameUTF16, _ := windows.UTF16PtrFromString(name)
		var key uintptr
		flags := uintptr(ncryptSilentFlag)
		if machine {
			flags |= ncryptMachineKeyFlag
		}
		status, _, _ := ncryptCreatePersistedKey.Call(provider,
			uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(algorithm)),
			uintptr(unsafe.Pointer(nameUTF16)), 0, flags)
		if uint32(status) == nteExists {
			continue
		}
		if err := windowsCNGStatus("创建 persisted identity key", status); err != nil {
			return nil, nil, platformIdentityRecord{}, err
		}
		finalized := false
		cleanup := func() {
			if finalized {
				if status, _, _ := ncryptDeleteKey.Call(key, ncryptSilentFlag); status == 0 {
					key = 0
				}
			}
			if key != 0 {
				freeWindowsCNGObject(key)
			}
		}
		exportPolicy := uint32(0)
		status, _, _ = ncryptSetProperty.Call(key, uintptr(unsafe.Pointer(property)),
			uintptr(unsafe.Pointer(&exportPolicy)), unsafe.Sizeof(exportPolicy),
			ncryptSilentFlag|ncryptPersistFlag)
		if err := windowsCNGStatus("固定 identity key export policy", status); err != nil {
			cleanup()
			return nil, nil, platformIdentityRecord{}, err
		}
		status, _, _ = ncryptFinalizeKey.Call(key, ncryptSilentFlag)
		if err := windowsCNGStatus("finalize persisted identity key", status); err != nil {
			cleanup()
			return nil, nil, platformIdentityRecord{}, err
		}
		finalized = true
		public, publicDER, err := exportWindowsCNGP256Public(key)
		if err != nil {
			cleanup()
			return nil, nil, platformIdentityRecord{}, err
		}
		record := platformIdentityRecord{Provider: windowsCNGIdentityProvider,
			KeyName: name, MachineScope: machine}
		return &cngP256Signer{handle: key, public: public}, publicDER, record, nil
	}
	return nil, nil, platformIdentityRecord{}, errors.New("[Windows CNG] 无法分配唯一 persisted key 名称")
}

func loadPlatformIdentity(state protectedIdentityV1,
	protector clientsecret.Protector) (crypto.Signer, []byte, error) {
	record := platformIdentityRecord{Provider: state.IdentityProvider,
		KeyName: state.IdentityKeyName, MachineScope: state.IdentityMachineScope,
		PrivateKeyPKCS8: state.IdentityPrivateKeyPKCS8}
	if err := validateWindowsCNGRecord(record); err != nil {
		return nil, nil, err
	}
	if record.MachineScope != windowsIdentityMachineScope(protector) {
		return nil, nil, errors.New("[Windows CNG] key scope 与 DPAPI scope 不一致")
	}
	key, err := openWindowsCNGKey(record)
	if err != nil {
		return nil, nil, err
	}
	public, publicDER, err := exportWindowsCNGP256Public(key)
	if err != nil {
		freeWindowsCNGObject(key)
		return nil, nil, err
	}
	want, err := base64.RawURLEncoding.DecodeString(state.IdentityPublicKeySPKI)
	if err != nil || base64.RawURLEncoding.EncodeToString(want) != state.IdentityPublicKeySPKI ||
		!bytes.Equal(want, publicDER) {
		freeWindowsCNGObject(key)
		return nil, nil, errors.New("[Windows CNG] persisted key 与 DPAPI public binding 不一致")
	}
	return &cngP256Signer{handle: key, public: public}, publicDER, nil
}

func destroyPlatformIdentity(record platformIdentityRecord) error {
	if err := validateWindowsCNGRecord(record); err != nil {
		return err
	}
	key, err := openWindowsCNGKey(record)
	if err != nil {
		var statusError *windowsCNGError
		if errors.As(err, &statusError) && statusError.status == nteBadKeyset {
			return nil
		}
		return err
	}
	status, _, _ := ncryptDeleteKey.Call(key, ncryptSilentFlag)
	if err := windowsCNGStatus("删除 persisted identity key", status); err != nil {
		freeWindowsCNGObject(key)
		return err
	}
	return nil
}

func validateWindowsCNGRecord(record platformIdentityRecord) error {
	if record.Provider != windowsCNGIdentityProvider || record.PrivateKeyPKCS8 != "" ||
		len(record.KeyName) != len(windowsCNGKeyPrefix)+32 ||
		!strings.HasPrefix(record.KeyName, windowsCNGKeyPrefix) {
		return errors.New("[Windows CNG] persisted key descriptor 无效")
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(record.KeyName, windowsCNGKeyPrefix)); err != nil {
		return errors.New("[Windows CNG] persisted key name 无效")
	}
	return nil
}

func windowsIdentityMachineScope(protector clientsecret.Protector) bool {
	switch protector.(type) {
	case clientsecret.MachineProtector, *clientsecret.MachineProtector:
		return true
	default:
		return false
	}
}

func openWindowsCNGProvider() (uintptr, error) {
	name, _ := windows.UTF16PtrFromString(windowsCNGProviderName)
	var provider uintptr
	status, _, _ := ncryptOpenStorageProvider.Call(uintptr(unsafe.Pointer(&provider)),
		uintptr(unsafe.Pointer(name)), 0)
	if err := windowsCNGStatus("打开 Microsoft CNG KSP", status); err != nil {
		return 0, err
	}
	return provider, nil
}

func openWindowsCNGKey(record platformIdentityRecord) (uintptr, error) {
	provider, err := openWindowsCNGProvider()
	if err != nil {
		return 0, err
	}
	defer freeWindowsCNGObject(provider)
	name, _ := windows.UTF16PtrFromString(record.KeyName)
	var key uintptr
	flags := uintptr(ncryptSilentFlag)
	if record.MachineScope {
		flags |= ncryptMachineKeyFlag
	}
	status, _, _ := ncryptOpenKey.Call(provider, uintptr(unsafe.Pointer(&key)),
		uintptr(unsafe.Pointer(name)), 0, flags)
	if err := windowsCNGStatus("打开 persisted identity key", status); err != nil {
		return 0, err
	}
	return key, nil
}

func exportWindowsCNGP256Public(key uintptr) (ecdsa.PublicKey, []byte, error) {
	blobType, _ := windows.UTF16PtrFromString(windowsCNGECCPublicBlob)
	var size uint32
	status, _, _ := ncryptExportKey.Call(key, 0, uintptr(unsafe.Pointer(blobType)), 0,
		0, 0, uintptr(unsafe.Pointer(&size)), 0)
	if err := windowsCNGStatus("读取 CNG public key 大小", status); err != nil {
		return ecdsa.PublicKey{}, nil, err
	}
	if size != 72 {
		return ecdsa.PublicKey{}, nil, errors.New("[Windows CNG] P-256 public blob 大小无效")
	}
	body := make([]byte, size)
	status, _, _ = ncryptExportKey.Call(key, 0, uintptr(unsafe.Pointer(blobType)), 0,
		uintptr(unsafe.Pointer(&body[0])), uintptr(size), uintptr(unsafe.Pointer(&size)), 0)
	if err := windowsCNGStatus("导出 CNG public key", status); err != nil {
		clear(body)
		return ecdsa.PublicKey{}, nil, err
	}
	if binary.LittleEndian.Uint32(body[:4]) != bcryptECDSAPublicP256Magic ||
		binary.LittleEndian.Uint32(body[4:8]) != 32 {
		clear(body)
		return ecdsa.PublicKey{}, nil, errors.New("[Windows CNG] public blob magic/length 无效")
	}
	public := ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(body[8:40]),
		Y: new(big.Int).SetBytes(body[40:72])}
	clear(body)
	if !public.Curve.IsOnCurve(public.X, public.Y) {
		return ecdsa.PublicKey{}, nil, errors.New("[Windows CNG] public point 不在 P-256")
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&public)
	if err != nil {
		return ecdsa.PublicKey{}, nil, err
	}
	return public, publicDER, nil
}

func (signer *cngP256Signer) Public() crypto.PublicKey {
	if signer == nil {
		return nil
	}
	signer.mu.Lock()
	defer signer.mu.Unlock()
	if signer.handle == 0 {
		return nil
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).Set(signer.public.X),
		Y: new(big.Int).Set(signer.public.Y)}
}

func (signer *cngP256Signer) Sign(_ io.Reader, digest []byte,
	options crypto.SignerOpts) ([]byte, error) {
	if signer == nil || options == nil || options.HashFunc() != crypto.SHA256 ||
		len(digest) != crypto.SHA256.Size() {
		return nil, errors.New("[Windows CNG] 只允许 P-256 SHA-256 digest")
	}
	signer.mu.Lock()
	defer signer.mu.Unlock()
	if signer.handle == 0 {
		return nil, errors.New("[Windows CNG] signer 已关闭")
	}
	var size uint32
	status, _, _ := ncryptSignHash.Call(signer.handle, 0,
		uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)), 0, 0,
		uintptr(unsafe.Pointer(&size)), 0)
	if err := windowsCNGStatus("读取 CNG signature 大小", status); err != nil {
		return nil, err
	}
	if size != 64 {
		return nil, errors.New("[Windows CNG] P-256 signature 大小无效")
	}
	raw := make([]byte, size)
	status, _, _ = ncryptSignHash.Call(signer.handle, 0,
		uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)),
		uintptr(unsafe.Pointer(&raw[0])), uintptr(size), uintptr(unsafe.Pointer(&size)), 0)
	runtime.KeepAlive(digest)
	if err := windowsCNGStatus("CNG P-256 签名", status); err != nil {
		clear(raw)
		return nil, err
	}
	r := new(big.Int).SetBytes(raw[:32])
	s := new(big.Int).SetBytes(raw[32:])
	clear(raw)
	if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(elliptic.P256().Params().N) >= 0 ||
		s.Cmp(elliptic.P256().Params().N) >= 0 {
		return nil, errors.New("[Windows CNG] signature scalar 无效")
	}
	return asn1.Marshal(struct{ R, S *big.Int }{R: r, S: s})
}

func (signer *cngP256Signer) Close() error {
	if signer == nil {
		return nil
	}
	signer.mu.Lock()
	defer signer.mu.Unlock()
	if signer.handle != 0 {
		freeWindowsCNGObject(signer.handle)
		signer.handle = 0
	}
	return nil
}

func freeWindowsCNGObject(handle uintptr) {
	if handle != 0 {
		_, _, _ = ncryptFreeObject.Call(handle)
	}
}

type windowsCNGError struct {
	operation string
	status    uint32
}

func (err *windowsCNGError) Error() string {
	return fmt.Sprintf("[Windows CNG] %s 失败（status=0x%08x）", err.operation, err.status)
}

func windowsCNGStatus(operation string, status uintptr) error {
	if uint32(status) == 0 {
		return nil
	}
	return &windowsCNGError{operation: operation, status: uint32(status)}
}
