package clientdist

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"

	"loom/internal/control"
	"loom/internal/deviceclient"
)

// InspectInstallation performs no cache, identity, floor, lock-file, unit, or
// network writes. The signed temporary package can inspect an identity left by
// a failed first install even when neither current nor the normal CLI exists.
func InspectInstallation(ctx context.Context, options InstallOptions) (control.InstallationReadback, error) {
	value := control.InstallationReadback{Platform: "linux", Architecture: runtime.GOARCH}
	if !options.Inspect || options.validate() != nil {
		return value, errors.New("invalid read-only installation inputs")
	}
	keyPath := options.PublicKey
	if keyPath == "" {
		keyPath = installTrust
	}
	public, keyBody, err := readInstallKey(keyPath)
	if err != nil {
		return value, errors.New("independent installation trust is unavailable")
	}
	candidate, err := VerifyDirectory(options.PackageRoot, public)
	if err != nil || candidate.Manifest.Arch != runtime.GOARCH {
		return value, errors.New("candidate package cannot be verified for this architecture")
	}
	if err := checkDirectory(filepath.Dir(options.State), 0o700, false); err != nil && !errors.Is(err, os.ErrNotExist) {
		return value, errors.New("existing device directory cannot be verified")
	}
	if _, err := os.Lstat(options.State); err == nil {
		store, err := deviceclient.Load(options.State)
		if err != nil {
			return value, errors.New("existing device identity cannot be verified")
		}
		identity, err := store.IdentityReadback()
		if err != nil {
			return value, err
		}
		value.Identity = &identity
	} else if !errors.Is(err, os.ErrNotExist) {
		return value, errors.New("device identity presence could not be checked")
	}
	if _, err := os.Lstat(installTrust); err == nil {
		body, err := installedFile(installTrust, 4096, 0o644)
		if err != nil || !bytes.Equal(body, keyBody) {
			value.ErrorCode = "existing_trust_differs"
			return value, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		value.ErrorCode = "existing_trust_unavailable"
		return value, nil
	}
	currentPath, current, err := acceptedPackage(public)
	if err != nil {
		value.ErrorCode = "existing_package_unverified"
		return value, nil
	}
	if current != nil {
		generation := current.Generation
		value.AcceptedGeneration = &generation
	}
	if err := advancePackage(currentPath, current, candidate); err != nil {
		value.ErrorCode = "package_would_rollback_or_equivocate"
		return value, nil
	}
	release := filepath.Join(installRoot, "releases", candidate.ID)
	if _, _, err := installationInputs(ctx, options, release, currentPath, current); err != nil {
		value.ErrorCode = "existing_installation_unverified"
		return value, nil
	}
	value.CanInstall = true
	return value, value.Validate()
}
