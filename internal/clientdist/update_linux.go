package clientdist

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"

	"loom/internal/control"
	"loom/internal/deviceclient"
)

type UpdateOptions struct {
	State, ResourceInputs, Capture string
	UpdateUnitMigration            string
	Log                            io.Writer
}

func checkUpdateExpectation(options InstallOptions, next Manifest, current *Manifest) error {
	if options.ExpectedViewDigest == "" {
		return nil
	}
	store, err := deviceclient.Load(options.State)
	if err != nil || store.LKG() == nil || store.LKG().ViewDigest != options.ExpectedViewDigest {
		return errors.New("accepted configuration changed while preparing the update")
	}
	return packageMatchesExpected(next, current, store.LKG().View)
}

func manifestComponents(manifest Manifest) []control.ComponentReadback {
	platform := "linux-" + manifest.Arch
	return []control.ComponentReadback{{ComponentID: "agent", Platform: platform, Version: manifest.Version, ArtifactDigest: "sha256:" + manifest.Loom.SHA256}, {ComponentID: "sing-box", Platform: platform, Version: manifest.SingBox.Version, ArtifactDigest: "sha256:" + manifest.SingBox.SHA256}}
}

func packageMatchesExpected(next Manifest, current *Manifest, view control.DeviceView) error {
	count := 0
	for _, component := range manifestComponents(next) {
		found := false
		for _, expected := range view.ExpectedComponents {
			if expected.Platform == component.Platform && expected.ComponentID == component.ComponentID {
				if found || expected != component {
					return errors.New("package does not match every accepted component expectation")
				}
				found = true
				count++
			}
		}
		if !found {
			unchanged := false
			if current != nil {
				for _, previous := range manifestComponents(*current) {
					unchanged = unchanged || previous == component
				}
			}
			if !unchanged {
				return errors.New("package would change a component without an expectation")
			}
		}
	}
	if count == 0 {
		return errors.New("accepted View has no component expectation for this platform")
	}
	return nil
}

func verifyDelivery(delivery control.DeviceReleaseDelivery, public ed25519.PublicKey, view control.DeviceView) (Manifest, control.ReleaseEntry, error) {
	var zero Manifest
	if delivery.Validate() != nil {
		return zero, control.ReleaseEntry{}, errors.New("invalid release delivery")
	}
	digest, err := control.DeviceViewDigest(view)
	if err != nil || digest != delivery.ViewDigest || delivery.Platform != "linux-"+runtime.GOARCH || view.Platform != "linux" {
		return zero, control.ReleaseEntry{}, errors.New("release delivery differs from accepted device/platform")
	}
	catalogSignature, _ := base64.RawURLEncoding.DecodeString(delivery.CatalogSignature)
	catalog, err := control.VerifyReleaseCatalog([]byte(delivery.CatalogBody), catalogSignature, public)
	if err != nil {
		return zero, control.ReleaseEntry{}, err
	}
	manifestSignature, _ := base64.RawURLEncoding.DecodeString(delivery.ManifestSignature)
	manifest, err := VerifyManifest([]byte(delivery.ManifestBody), manifestSignature, public)
	if err != nil || delivery.Platform != "linux-"+manifest.Arch {
		return zero, control.ReleaseEntry{}, errors.New("signed release manifest is invalid for this platform")
	}
	for _, entry := range catalog.Entries {
		if entry.ComponentID == "linux-client-bootstrap" && entry.Platform == delivery.Platform && entry.ManifestDigest == control.ReleaseDigest([]byte(delivery.ManifestBody)) {
			return manifest, entry, nil
		}
	}
	return zero, control.ReleaseEntry{}, errors.New("signed catalog does not reference the original package manifest")
}

// Update is a bounded one-shot consumer. The original daemon writes Device
// state; the updater reads it and invokes the same locked installer.
func Update(ctx context.Context, options UpdateOptions) (resultErr error) {
	if options.Log == nil {
		options.Log = io.Discard
	}
	if options.State == "" {
		options.State = defaultInstallState
	}
	if os.Geteuid() != 0 || !installPath(options.State) || options.ResourceInputs != "" && !installPath(options.ResourceInputs) || options.Capture != "mixed" && options.Capture != "tun" || options.UpdateUnitMigration != "" && !installPath(options.UpdateUnitMigration) {
		return errors.New("update requires root and explicit canonical runtime inputs")
	}
	if options.UpdateUnitMigration != "" {
		if _, err := readUpdateUnitMigration(options.UpdateUnitMigration); err != nil {
			return err
		}
	}
	active, err := systemdProperty(ctx, "ActiveState")
	if err != nil || active != "active" {
		return errors.New("automatic update does not reactivate an inactive or failed client")
	}
	public, _, err := readInstallKey(installTrust)
	if err != nil {
		return err
	}
	currentPath, current, err := acceptedPackage(public)
	if err != nil || current == nil {
		return errors.New("automatic update requires an accepted canonical package")
	}
	store, err := deviceclient.Load(options.State)
	if err != nil || store.LKG() == nil {
		return errors.New("accepted Device configuration unavailable")
	}
	lkg := store.LKG()
	delivery, err := deviceclient.Release(ctx, store, "linux-"+runtime.GOARCH, func(delivery control.DeviceReleaseDelivery) error {
		manifest, _, err := verifyDelivery(delivery, public, lkg.View)
		if err != nil {
			return err
		}
		return packageMatchesExpected(manifest, current, lkg.View)
	})
	if err != nil {
		return err
	}
	manifest, entry, err := verifyDelivery(delivery, public, lkg.View)
	if err != nil {
		return err
	}
	if err := packageMatchesExpected(manifest, current, lkg.View); err != nil {
		return err
	}
	id := sha256Hex([]byte(delivery.ManifestBody))
	if err := advancePackage(currentPath, current, VerifiedDirectory{Manifest: manifest, ID: id}); err != nil {
		return err
	}
	if filepath.Base(currentPath) == id {
		if options.UpdateUnitMigration != "" {
			return errors.New("explicit update unit migration requires a new authenticated package; verify an unchanged package with an ordinary update")
		}
		verified, err := VerifyInstalledDirectory(ctx, currentPath, public)
		if err != nil {
			return err
		}
		defer func() { resultErr = errors.Join(resultErr, verified.Close()) }()
		if verified.ID != id || !reflect.DeepEqual(verified.Manifest, *current) {
			return errors.New("accepted package changed during update inspection")
		}
		actual, err := os.Readlink(filepath.Join(installRoot, "current"))
		if err != nil || actual != currentPath {
			return errors.New("accepted package pointer changed during update inspection")
		}
		if err := removeSupersededPrograms(public, verified.Manifest, currentPath); err != nil {
			return fmt.Errorf("current runtime remains active; superseded program cleanup remains incomplete: %w", err)
		}
		fmt.Fprintln(options.Log, "Current verified package satisfies the accepted expectation; no installation performed.")
		return nil
	}
	request := control.DeviceReleaseDownload{Schema: 3, Platform: delivery.Platform, ViewDigest: lkg.ViewDigest, CatalogDigest: control.ReleaseDigest([]byte(delivery.CatalogBody)), ArtifactDigest: entry.Artifact.Digest}
	if err := protectedDirectory(installRoot, 0755); err != nil {
		return err
	}
	temporary, err := os.MkdirTemp(installRoot, ".update-")
	if err != nil {
		return err
	}
	workspaceEntry, err := os.Lstat(temporary)
	if err != nil || !packageDirectoryPrivate(workspaceEntry) {
		return errors.New("private update workspace ownership differs")
	}
	workspace := &packageInput{root: temporary, entry: workspaceEntry, remove: true}
	defer func() { resultErr = errors.Join(resultErr, workspace.close()) }()
	if err := packageWorkRoot(temporary); err != nil {
		return err
	}
	archive, err := os.CreateTemp(temporary, "archive-")
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, archive.Close()) }()
	hash := sha256.New()
	if err := deviceclient.DownloadReleaseTo(ctx, store, request, int64(entry.Artifact.Size), temporary, io.MultiWriter(archive, hash)); err != nil {
		return err
	}
	if "sha256:"+hex.EncodeToString(hash.Sum(nil)) != entry.Artifact.Digest {
		return errors.New("downloaded archive differs from the signed digest")
	}
	if err := archive.Sync(); err != nil {
		return err
	}
	signed, err := VerifyArchiveFile(ctx, archive, public, temporary)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, signed.Close()) }()
	if !bytes.Equal(signed.ManifestBody, []byte(delivery.ManifestBody)) || base64.RawURLEncoding.EncodeToString(signed.Signature) != delivery.ManifestSignature {
		return errors.New("archive and delivered manifest originals differ")
	}
	return install(ctx, InstallOptions{PackageRoot: signed.Root, State: options.State, ResourceInputs: options.ResourceInputs, Capture: options.Capture, Upgrade: true, UpdateUnitMigration: options.UpdateUnitMigration, ExpectedViewDigest: lkg.ViewDigest, Log: options.Log}, &signed)
}
