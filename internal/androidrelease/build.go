package androidrelease

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"loom/internal/clientcomponent"
	"loom/internal/control"
)

// AuditAPK uses the SDK only on the publishing workstation. Its private
// temporary copy fixes the exact bytes passed to both official inspectors.
// Consumers verify the platform signature and content binding without an SDK;
// Android independently enforces its APK signature when installing.
func AuditAPK(ctx context.Context, sdk string, apk []byte) error {
	metadata, err := InspectAPK(apk)
	if err != nil {
		return err
	}
	if !filepath.IsAbs(sdk) || filepath.Clean(sdk) != sdk {
		return errors.New("Android SDK path must be explicit and absolute")
	}
	directory, err := os.MkdirTemp("", "loom-android-audit-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(directory)
	file := filepath.Join(directory, Name)
	if err := os.WriteFile(file, apk, 0600); err != nil {
		return err
	}
	// SDK diagnostics can contain local paths; return only the failed operation.
	inspect := func(tool string, args ...string) ([]byte, error) {
		command := exec.CommandContext(ctx, filepath.Join(sdk, "build-tools", "35.0.1", tool), args...)
		command.Env = []string{}
		for _, entry := range os.Environ() {
			name, _, _ := strings.Cut(entry, "=")
			switch name {
			case "GANDI_PAT_TOKEN", "LOOM_ANDROID_RELEASE_STORE_PASSWORD", "LOOM_ANDROID_RELEASE_KEY_PASSWORD":
				continue
			}
			command.Env = append(command.Env, entry)
		}
		return command.Output()
	}
	signer, err := inspect("apksigner", "verify", "--verbose", "--print-certs", file)
	if err != nil || len(signer) > 1<<20 {
		return errors.New("official APK signature verification failed")
	}
	certificates := regexp.MustCompile(`(?m)^Signer #([0-9]+) certificate SHA-256 digest: ([0-9a-f]{64})\r?$`).FindAllSubmatch(signer, -1)
	if len(certificates) != 1 || string(certificates[0][1]) != "1" {
		return errors.New("APK must have one verified signing certificate")
	}
	badging, err := inspect("aapt2", "dump", "badging", file)
	if err != nil || len(badging) > 1<<20 {
		return errors.New("official APK manifest inspection failed")
	}
	packages := regexp.MustCompile(`(?m)^package: name='([^']+)' versionCode='([0-9]+)' versionName='([^']+)'(?: [^\r\n]*)?\r?$`).FindAllSubmatch(badging, -1)
	if len(packages) != 1 || string(packages[0][1]) != PackageID || string(packages[0][2]) != strconv.Itoa(metadata.VersionCode) || string(packages[0][3]) != metadata.VersionName {
		return errors.New("APK manifest differs from its executable BuildConfig")
	}
	return nil
}

// Build is deterministic: all audited APK bytes, AAR bytes, coordinates and
// signing capability are explicit inputs. It performs no I/O or clock reads.
func Build(apk, aar []byte, generation control.U64, key ed25519.PrivateKey) (Manifest, []byte, []byte, error) {
	var zero Manifest
	if len(key) != ed25519.PrivateKeySize || generation == 0 {
		return zero, nil, nil, errors.New("Android signing inputs are invalid")
	}
	metadata, err := InspectAPK(apk)
	if err != nil {
		return zero, nil, nil, err
	}
	if metadata.SingBoxVersion != clientcomponent.DataPlaneVersion {
		return zero, nil, nil, errors.New("Android publisher only writes the current reviewed data-plane artifact")
	}
	if metadata.AARSHA256 != fmt.Sprintf("%x", sha256.Sum256(aar)) {
		return zero, nil, nil, errors.New("APK does not name this audited AAR")
	}
	files, err := archiveFiles(aar)
	if err != nil {
		return zero, nil, nil, err
	}
	version, err := archiveSourceVersion(files)
	if err != nil || version != metadata.SingBoxVersion {
		return zero, nil, nil, errors.New("APK source provenance differs from its audited AAR")
	}
	for _, library := range metadata.Libraries {
		entry := files["jni/"+strings.TrimPrefix(library.Path, "lib/")]
		if entry == nil {
			return zero, nil, nil, errors.New("audited AAR native library is absent")
		}
		body, err := readEntry(entry, maxAPK)
		if err != nil || len(body) != library.Size || fmt.Sprintf("%x", sha256.Sum256(body)) != library.SHA256 {
			return zero, nil, nil, errors.New("APK native library differs from the audited AAR")
		}
	}
	m := Manifest{Schema: 3, Kind: Kind, Generation: generation, ApplicationID: PackageID, VersionCode: metadata.VersionCode, VersionName: metadata.VersionName, SourceCommit: metadata.Commit, AARSHA256: metadata.AARSHA256, SingBoxVersion: metadata.SingBoxVersion,
		Artifact: control.ReleaseArtifact{Name: Name, Digest: control.ReleaseDigest(apk), Size: control.U64(len(apk)), MediaType: MediaType, Audience: "public"}, NativeLibraries: metadata.Libraries}
	body, err := control.CanonicalEncode(m)
	if err != nil {
		return zero, nil, nil, err
	}
	signature := ed25519.Sign(key, append([]byte(signatureDomain), body...))
	verified, err := Verify(body, signature, apk, key.Public().(ed25519.PublicKey))
	if err != nil {
		return zero, nil, nil, err
	}
	roundTrip, err := control.CanonicalEncode(verified)
	if err != nil || !bytes.Equal(roundTrip, body) {
		return zero, nil, nil, errors.New("Android manifest did not round trip")
	}
	return m, body, signature, nil
}
