package clientrelease

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"loom/internal/control"
)

// Input is a publication call's exact bytes. Original archives carry their own
// metadata; a raw script has a separate signed manifest to avoid self-hashing.
type Input struct{ Body, Manifest, Signature []byte }

func InspectInput(name string, input Input, key ed25519.PublicKey) (control.ReleasePackage, error) {
	if (len(input.Manifest) == 0) != (len(input.Signature) == 0) {
		return control.ReleasePackage{}, errors.New("external package metadata is incomplete")
	}
	if name == "loom-bootstrap-linux.sh" {
		manifest, err := control.VerifyReleaseBootstrap(input.Manifest, input.Signature, key)
		if err != nil {
			return control.ReleasePackage{}, err
		}
		if len(input.Body) == 0 || len(input.Body) > 64<<10 || manifest.Artifact.Digest != control.ReleaseDigest(input.Body) || manifest.Artifact.Size != control.U64(len(input.Body)) {
			return control.ReleasePackage{}, errors.New("bootstrap script differs from its signed manifest")
		}
		return control.ReleasePackage{Entry: control.ReleaseEntry{ComponentID: manifest.Kind, Platform: "linux-any", ManifestDigest: control.ReleaseDigest(input.Manifest), Artifact: manifest.Artifact}, ManifestBody: bytes.Clone(input.Manifest), Signature: bytes.Clone(input.Signature), Generation: manifest.Generation, Version: strconv.FormatUint(uint64(manifest.Generation), 10), Bootstrap: &manifest}, nil
	}
	pkg, err := Inspect(name, input.Body, key)
	if err != nil {
		return control.ReleasePackage{}, err
	}
	if len(input.Manifest) > 0 && (!bytes.Equal(input.Manifest, pkg.ManifestBody) || !bytes.Equal(input.Signature, pkg.Signature)) {
		return control.ReleasePackage{}, errors.New("external metadata differs from original package bytes")
	}
	return pkg, nil
}

// BuildBootstrap consumes verified Linux entries. The script knows exact
// archive bytes and an independent key; it does not parse a second floor/store.
func BuildBootstrap(generation control.U64, entries []control.ReleaseEntry, key ed25519.PrivateKey) (Input, control.ReleasePackage, error) {
	var zero Input
	if len(key) != ed25519.PrivateKeySize || generation == 0 || len(entries) == 0 {
		return zero, control.ReleasePackage{}, errors.New("bootstrap build inputs are incomplete")
	}
	public := key.Public().(ed25519.PublicKey)
	body, err := renderBootstrap(entries, public)
	if err != nil {
		return zero, control.ReleasePackage{}, err
	}
	manifest := control.ReleaseBootstrapManifest{Schema: 3, Kind: "linux-bootstrap-script", Generation: generation, Packages: entries, Artifact: control.ReleaseArtifact{Name: "loom-bootstrap-linux.sh", Digest: control.ReleaseDigest(body), Size: control.U64(len(body)), MediaType: "text/x-shellscript", Audience: "public"}}
	encoded, signature, err := control.SignReleaseBootstrap(manifest, key)
	if err != nil {
		return zero, control.ReleasePackage{}, err
	}
	input := Input{Body: body, Manifest: encoded, Signature: signature}
	pkg, err := InspectInput(manifest.Artifact.Name, input, public)
	return input, pkg, err
}

func renderBootstrap(entries []control.ReleaseEntry, public ed25519.PublicKey) ([]byte, error) {
	if len(public) != ed25519.PublicKeySize {
		return nil, errors.New("bootstrap verification key is invalid")
	}
	var choices strings.Builder
	for index, entry := range entries {
		if entry.ComponentID != "linux-client-bootstrap" || entry.Validate() != nil || index > 0 && entries[index-1].Platform >= entry.Platform {
			return nil, errors.New("bootstrap Linux entries are invalid")
		}
		arch := strings.TrimPrefix(entry.Platform, "linux-")
		fmt.Fprintf(&choices, "  %s) loom_archive_sha='%s' ;;\n", arch, strings.TrimPrefix(entry.Artifact.Digest, "sha256:"))
	}
	return []byte(`#!/bin/sh
# Generic public bootstrap. The private invitation is only read by the installer.
set +x
set -eu
umask 077
fail() { printf '%s\n' "$1" >&2; exit 1; }
[ "$#" -eq 3 ] && [ "$1" = '--base-url' ] && [ "$3" = '--invite-stdin' ] || fail 'Expected an HTTPS distribution root and --invite-stdin.'
loom_base=$2
case "$loom_base" in https://*/) ;; *) fail 'Distribution root must be HTTPS.' ;; esac
case "$loom_base" in *'?'*|*'#'*|*'@'*|*'\'*|*'%'*) fail 'Distribution root is not canonical.' ;; esac
for loom_tool in curl sha256sum tar mktemp uname id; do command -v "$loom_tool" >/dev/null 2>&1 || fail 'Required installation tool is missing.'; done
[ "$(id -u)" -eq 0 ] || fail 'Run the complete installation block from a root shell.'
[ "$(uname -s)" = Linux ] || fail 'This installer requires Linux.'
case "$(uname -m)" in
  x86_64|amd64) loom_arch=amd64 ;;
  aarch64|arm64) loom_arch=arm64 ;;
  *) fail 'The target architecture is unsupported.' ;;
esac
case "$loom_arch" in
` + choices.String() + `  *) fail 'This release has no verified package for the target architecture.' ;;
esac
loom_bootstrap_dir=$(mktemp -d)
trap 'rm -rf -- "$loom_bootstrap_dir"' 0
trap 'exit 1' 1 2 15
curl --disable --fail --silent --show-error --proto '=https' --max-time 120 \
  "${loom_base}bin/${loom_archive_sha}" -o "$loom_bootstrap_dir/client.tar.gz"
printf '%s  %s\n' "$loom_archive_sha" "$loom_bootstrap_dir/client.tar.gz" | sha256sum --check --status -
tar -xzf "$loom_bootstrap_dir/client.tar.gz" -C "$loom_bootstrap_dir" --no-same-owner
printf '%s\n' '` + base64.StdEncoding.EncodeToString(public) + `' > "$loom_bootstrap_dir/platform-signing.pub"
sh "$loom_bootstrap_dir/loom-client-linux-$loom_arch/install.sh" \
  --capture mixed --pubkey "$loom_bootstrap_dir/platform-signing.pub" --invite-stdin
`), nil
}

func validateBootstrapBindings(set control.ReleaseSet) error {
	for _, pkg := range set.Packages {
		if pkg.Bootstrap == nil {
			continue
		}
		for _, wanted := range pkg.Bootstrap.Packages {
			found := false
			for _, actual := range set.Catalog.Entries {
				if actual == wanted {
					found = true
					break
				}
			}
			if !found {
				return errors.New("bootstrap archive is not bound to the same catalog")
			}
		}
	}
	return nil
}
