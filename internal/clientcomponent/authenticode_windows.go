//go:build windows

package clientcomponent

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// VerifyAuthenticode asks Windows trust policy to validate the embedded file
// signature without UI or network retrieval. The platform manifest separately
// pins the exact DLL hash, so startup remains deterministic while offline.
func VerifyAuthenticode(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("Authenticode target is not a regular file: %s", path)
	}
	wide, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	fileInfo := &windows.WinTrustFileInfo{Size: uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})), FilePath: wide}
	data := &windows.WinTrustData{
		Size:                            uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice:                        windows.WTD_UI_NONE,
		RevocationChecks:                windows.WTD_REVOKE_NONE,
		UnionChoice:                     windows.WTD_CHOICE_FILE,
		StateAction:                     windows.WTD_STATEACTION_VERIFY,
		ProvFlags:                       windows.WTD_CACHE_ONLY_URL_RETRIEVAL | windows.WTD_DISABLE_MD2_MD4,
		UIContext:                       windows.WTD_UICONTEXT_EXECUTE,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(fileInfo),
	}
	verifyErr := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	data.StateAction = windows.WTD_STATEACTION_CLOSE
	closeErr := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	if verifyErr != nil {
		return verifyErr
	}
	if closeErr != nil {
		return fmt.Errorf("close Authenticode verification state: %w", closeErr)
	}
	return nil
}

func InstallWindows(root string, packageBody []byte, publicKey ed25519.PublicKey) (InstallResult, error) {
	return Install(root, packageBody, publicKey, VerifyAuthenticode)
}

func InstallWindowsFile(root, packagePath string, publicKey ed25519.PublicKey) (InstallResult, error) {
	body, err := readRegularBounded(packagePath, maxPackageBytes)
	if err != nil {
		return InstallResult{}, err
	}
	return InstallWindows(root, body, publicKey)
}

func LoadWindows(root string, publicKey ed25519.PublicKey, arch, singBoxVersion string) (RuntimePaths, error) {
	return Load(root, publicKey, arch, singBoxVersion, VerifyAuthenticode)
}
