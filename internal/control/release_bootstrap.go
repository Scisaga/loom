package control

import (
	"crypto/ed25519"
	"errors"
	"net/url"
	"sort"
	"strings"
)

const ReleaseBootstrapDomain = "loom-linux-bootstrap-script-v3\x00"

type ReleaseBootstrapManifest struct {
	Schema     int             `json:"schema"`
	Kind       string          `json:"kind"`
	Generation U64             `json:"generation"`
	Artifact   ReleaseArtifact `json:"artifact"`
	Packages   []ReleaseEntry  `json:"packages"`
}

func (value ReleaseBootstrapManifest) Validate() error {
	if value.Schema != 3 || value.Kind != "linux-bootstrap-script" || value.Generation == 0 || len(value.Packages) == 0 {
		return errors.New("bootstrap manifest coordinates are invalid")
	}
	entry := ReleaseEntry{ComponentID: value.Kind, Platform: "linux-any", ManifestDigest: ReleaseDigest(nil), Artifact: value.Artifact}
	if entry.Validate() != nil {
		return errors.New("bootstrap artifact is invalid")
	}
	for index, pkg := range value.Packages {
		if pkg.ComponentID != "linux-client-bootstrap" || pkg.Validate() != nil || index > 0 && value.Packages[index-1].Platform >= pkg.Platform {
			return errors.New("bootstrap packages are not uniquely ordered Linux artifacts")
		}
	}
	return nil
}

func SignReleaseBootstrap(value ReleaseBootstrapManifest, key ed25519.PrivateKey) ([]byte, []byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, nil, errors.New("bootstrap signing key is invalid")
	}
	body, err := CanonicalEncode(value)
	if err != nil {
		return nil, nil, err
	}
	return body, ed25519.Sign(key, append([]byte(ReleaseBootstrapDomain), body...)), nil
}

func VerifyReleaseBootstrap(body, signature []byte, key ed25519.PublicKey) (ReleaseBootstrapManifest, error) {
	var value ReleaseBootstrapManifest
	if err := DecodeCanonical(body, &value, ContractDecodeLimits{MaxBytes: 64 << 10, MaxDepth: 16, MaxItems: 4096}); err != nil {
		return value, err
	}
	if len(key) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize || !ed25519.Verify(key, append([]byte(ReleaseBootstrapDomain), body...), signature) {
		return ReleaseBootstrapManifest{}, errors.New("bootstrap manifest signature is invalid")
	}
	return value, nil
}

// DistributionURL resolves only a signed content address under an authenticated
// HTTPS distribution root. Query strings and escaped path separators cannot
// turn a root into a second instruction or an unrelated download endpoint.
func DistributionURL(base, digest string) (string, error) {
	if ValidateHTTPSURL(base) != nil || ValidateDigest(digest) != nil {
		return "", errors.New("invalid distribution coordinates")
	}
	parsed, err := url.Parse(base)
	if err != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.RawPath != "" || strings.Contains(base, "%") || !strings.HasSuffix(parsed.Path, "/") {
		return "", errors.New("distribution URL must be an exact HTTPS directory")
	}
	parsed.Path += "bin/" + strings.TrimPrefix(digest, "sha256:")
	return parsed.String(), nil
}

func shellLiteral(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }

// ShellInviteDelivery receives an already verified script coordinate and the
// same complete Invite displayed by the private delivery page. It is pure.
func ShellInviteDelivery(bases []string, artifact ReleaseArtifact, invite string) (string, error) {
	return inviteBootstrapDelivery(bases, artifact, invite, "sh")
}

// SSHInviteDelivery is private execution input for the signed SSH medium. It
// does not silently turn a shell invitation into an automated installation.
func SSHInviteDelivery(bases []string, artifact ReleaseArtifact, invite string) (string, error) {
	return inviteBootstrapDelivery(bases, artifact, invite, "ssh")
}

// SSHInspectionDelivery downloads the same verified generic installer and
// performs only its read-only inspection. No invitation is sent to the target.
func SSHInspectionDelivery(bases []string, artifact ReleaseArtifact) (string, error) {
	return bootstrapDelivery(bases, artifact, "--inspect")
}

func inviteBootstrapDelivery(bases []string, artifact ReleaseArtifact, invite, medium string) (string, error) {
	decoded, err := DecodeInvite(invite)
	if err != nil {
		return "", errors.New("invalid delivery invite")
	}
	value, ok := decoded.Material.Payload.(Invite)
	if !ok || value.Medium != medium || medium == "ssh" && value.SSHTarget == "" {
		return "", errors.New("installation delivery differs from the signed medium or target")
	}
	if strings.ContainsAny(invite, "\r\n") {
		return "", errors.New("invite is not a single canonical URI")
	}
	return bootstrapDelivery(bases, artifact, "--invite-stdin <<'LOOM_SIGNED_INVITE'\n"+invite+"\nLOOM_SIGNED_INVITE")
}

func bootstrapDelivery(bases []string, artifact ReleaseArtifact, input string) (string, error) {
	entry := ReleaseEntry{ComponentID: "linux-bootstrap-script", Platform: "linux-any", ManifestDigest: ReleaseDigest(nil), Artifact: artifact}
	if entry.Validate() != nil {
		return "", errors.New("bootstrap artifact unavailable")
	}
	if len(bases) == 0 {
		return "", errors.New("no verified distribution roots")
	}
	bases = append([]string(nil), bases...)
	sort.Strings(bases)
	addresses, arguments := []string{}, []string{}
	for index, base := range bases {
		address, err := DistributionURL(base, artifact.Digest)
		if err != nil || index > 0 && base == bases[index-1] {
			return "", errors.New("invalid or repeated distribution root")
		}
		addresses = append(addresses, shellLiteral(address))
		arguments = append(arguments, "--base-url "+shellLiteral(base))
	}
	return "(\n  set +x\n  set -eu\n  umask 077\n  loom_install_dir=$(mktemp -d)\n  trap 'rm -rf -- \"$loom_install_dir\"' 0\n  trap 'exit 1' 1 2 15\n" +
		"  loom_script_ready=\n  for loom_script_url in " + strings.Join(addresses, " ") + "; do\n" +
		"    if curl --disable --fail --silent --show-error --proto '=https' --max-time 120 \\\n      \"$loom_script_url\" -o \"$loom_install_dir/installer.sh\" &&\n" +
		"      printf '%s  %s\\n' " + shellLiteral(strings.TrimPrefix(artifact.Digest, "sha256:")) + " \\\n        \"$loom_install_dir/installer.sh\" | sha256sum --check --status -; then\n" +
		"      loom_script_ready=1\n      break\n    fi\n  done\n" +
		"  [ \"$loom_script_ready\" = 1 ] || { printf '%s\\n' 'No distribution root supplied the verified installer.' >&2; exit 1; }\n" +
		"  sh \"$loom_install_dir/installer.sh\" " + strings.Join(arguments, " ") + " " + input + "\n)\n", nil
}
