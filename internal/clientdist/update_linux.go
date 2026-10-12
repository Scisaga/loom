package clientdist

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"loom/internal/control"
	"loom/internal/deviceclient"
)

type UpdateOptions struct {
	State, ResourceInputs, Capture string
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
func Update(ctx context.Context, options UpdateOptions) error {
	if options.Log == nil {
		options.Log = io.Discard
	}
	if options.State == "" {
		options.State = defaultInstallState
	}
	if os.Geteuid() != 0 || !installPath(options.State) || options.ResourceInputs != "" && !installPath(options.ResourceInputs) || options.Capture != "mixed" && options.Capture != "tun" {
		return errors.New("update requires root and explicit canonical runtime inputs")
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
	verified, err := VerifyDirectory(currentPath, public)
	if err != nil {
		return err
	}
	if err := verifyInstalledPayload(currentPath, verified); err != nil {
		return err
	}
	store, err := deviceclient.Load(options.State)
	if err != nil || store.LKG() == nil {
		return errors.New("accepted Device configuration unavailable")
	}
	lkg := store.LKG()
	delivery, err := deviceclient.Release(ctx, store, "linux-"+runtime.GOARCH)
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
		fmt.Fprintln(options.Log, "Current verified package satisfies the accepted expectation; no installation performed.")
		return nil
	}
	request := control.DeviceReleaseDownload{Schema: 3, Platform: delivery.Platform, ViewDigest: lkg.ViewDigest, CatalogDigest: control.ReleaseDigest([]byte(delivery.CatalogBody)), ArtifactDigest: entry.Artifact.Digest}
	archive, err := deviceclient.DownloadRelease(ctx, store, request, int64(entry.Artifact.Size))
	if err != nil {
		return err
	}
	if control.ReleaseDigest(archive) != entry.Artifact.Digest {
		return errors.New("downloaded archive differs from the signed digest")
	}
	signed, err := VerifyPackage(archive, public)
	if err != nil {
		return err
	}
	if !bytes.Equal(signed.ManifestBody, []byte(delivery.ManifestBody)) || base64.RawURLEncoding.EncodeToString(signed.Signature) != delivery.ManifestSignature {
		return errors.New("archive and delivered manifest originals differ")
	}
	if err := protectedDirectory("/run/loom-install", 0700); err != nil {
		return err
	}
	temporary, err := os.MkdirTemp("/run/loom-install", "download-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temporary)
	for name, body := range signed.Files {
		path := filepath.Join(temporary, name)
		if err := protectedDirectory(filepath.Dir(path), 0700); err != nil {
			return err
		}
		if err := installFile(path, body, packageFileMode(name)); err != nil {
			return err
		}
	}
	return Install(ctx, InstallOptions{PackageRoot: temporary, State: options.State, ResourceInputs: options.ResourceInputs, Capture: options.Capture, Upgrade: true, ExpectedViewDigest: lkg.ViewDigest, Log: options.Log})
}
