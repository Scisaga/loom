//go:build windows

package clientsecret

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

const dpapiDescriptionPrefix = "Loom Windows client "

const portableDPAPIDescriptionPrefix = "Loom Windows portable client "

// MachineProtector uses Windows DPAPI machine scope. File-system ACLs remain
// mandatory: machine scope permits service recovery across account changes but
// is not an authorization boundary between local users.
type MachineProtector struct{}

func (MachineProtector) Protect(purpose string, plaintext []byte) ([]byte, error) {
	return protectDPAPI(purpose, plaintext, dpapiDescriptionPrefix, purposeEntropy(purpose), windows.CRYPTPROTECT_LOCAL_MACHINE)
}

func (MachineProtector) Unprotect(purpose string, ciphertext []byte) ([]byte, error) {
	return unprotectDPAPI(purpose, ciphertext, dpapiDescriptionPrefix, purposeEntropy(purpose))
}

// UserProtector uses Windows DPAPI current-user scope for portable clients.
// Ciphertext cannot be decrypted by another Windows account and is also
// deliberately domain-separated from machine-scope Service ciphertext.
type UserProtector struct{}

func (UserProtector) Protect(purpose string, plaintext []byte) ([]byte, error) {
	return protectDPAPI(purpose, plaintext, portableDPAPIDescriptionPrefix, portablePurposeEntropy(purpose), 0)
}

func (UserProtector) Unprotect(purpose string, ciphertext []byte) ([]byte, error) {
	return unprotectDPAPI(purpose, ciphertext, portableDPAPIDescriptionPrefix, portablePurposeEntropy(purpose))
}

func protectDPAPI(purpose string, plaintext []byte, descriptionPrefix string,
	entropyBytes [sha256.Size]byte, flags uint32) ([]byte, error) {
	if err := validatePurpose(purpose); err != nil {
		return nil, err
	}
	if len(plaintext) == 0 || len(plaintext) > maxProtectedPlaintext {
		return nil, errors.New("DPAPI plaintext has invalid size")
	}
	input, entropy := dataBlob(plaintext), dataBlob(entropyBytes[:])
	description, err := windows.UTF16PtrFromString(descriptionPrefix + purpose)
	if err != nil {
		return nil, err
	}
	var output windows.DataBlob
	err = windows.CryptProtectData(&input, description, &entropy, 0, nil,
		flags|windows.CRYPTPROTECT_UI_FORBIDDEN, &output)
	runtime.KeepAlive(plaintext)
	runtime.KeepAlive(entropyBytes)
	if err != nil {
		return nil, fmt.Errorf("CryptProtectData: %w", err)
	}
	return copyAndFree(output)
}

func unprotectDPAPI(purpose string, ciphertext []byte, descriptionPrefix string,
	entropyBytes [sha256.Size]byte) ([]byte, error) {
	if err := validatePurpose(purpose); err != nil {
		return nil, err
	}
	if len(ciphertext) == 0 || len(ciphertext) > maxCiphertext {
		return nil, errors.New("DPAPI ciphertext has invalid size")
	}
	input, entropy := dataBlob(ciphertext), dataBlob(entropyBytes[:])
	var output windows.DataBlob
	var description *uint16
	err := windows.CryptUnprotectData(&input, &description, &entropy, 0, nil,
		windows.CRYPTPROTECT_UI_FORBIDDEN, &output)
	runtime.KeepAlive(ciphertext)
	runtime.KeepAlive(entropyBytes)
	if err != nil {
		freeBlob(output)
		if description != nil {
			_, _ = windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(description))))
		}
		return nil, fmt.Errorf("CryptUnprotectData: %w", err)
	}
	if description == nil {
		freeBlob(output)
		return nil, errors.New("DPAPI result is missing the protection description")
	}
	decryptedDescription := windows.UTF16PtrToString(description)
	_, _ = windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(description))))
	if decryptedDescription != descriptionPrefix+purpose {
		freeBlob(output)
		return nil, errors.New("DPAPI description does not match protection purpose")
	}
	return copyAndFree(output)
}

func purposeEntropy(purpose string) [sha256.Size]byte {
	return sha256.Sum256([]byte("loom-windows-dpapi-v1\x00" + purpose))
}

func portablePurposeEntropy(purpose string) [sha256.Size]byte {
	return sha256.Sum256([]byte("loom-windows-user-dpapi-v1\x00" + purpose))
}

func dataBlob(body []byte) windows.DataBlob {
	return windows.DataBlob{Size: uint32(len(body)), Data: &body[0]}
}

func copyAndFree(blob windows.DataBlob) ([]byte, error) {
	if blob.Data == nil || blob.Size == 0 || blob.Size > maxCiphertext {
		freeBlob(blob)
		return nil, errors.New("DPAPI returned an invalid output blob")
	}
	defer freeBlob(blob)
	return append([]byte(nil), unsafe.Slice(blob.Data, int(blob.Size))...), nil
}

func freeBlob(blob windows.DataBlob) {
	if blob.Data != nil {
		_, _ = windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(blob.Data))))
	}
}
