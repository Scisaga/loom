//go:build !windows

package publish

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"loom/internal/snapshot"
)

// BuildCertified builds only the public release surface. Runtime DeviceView
// and ServerRuntime stay on the authenticated private device service.
func BuildCertified(inputBytes []byte, privateKey ed25519.PrivateKey, meta Meta) (*Tree, error) {
	input, err := DecodeCertifiedPublisherInput(inputBytes)
	if err != nil {
		return nil, err
	}
	refs, blobs, err := certifiedBinaryRefs(meta.Binaries)
	if err != nil {
		return nil, err
	}
	bundleRefs := make([]snapshot.BundleRef, 0, len(input.Devices))
	componentRefs := make([]snapshot.ComponentRef, 0, len(input.Devices))
	tree := &Tree{Files: map[string][]byte{}, Blobs: blobs}
	for _, device := range input.Devices {
		target := struct {
			Schema     int                           `json:"schema"`
			Head       string                        `json:"head"`
			Device     string                        `json:"device"`
			Platform   string                        `json:"platform"`
			Roles      []string                      `json:"roles"`
			Components []CertifiedPublisherComponent `json:"components"`
		}{2, input.Head, device.ID, device.Platform, device.Roles, device.Components}
		targetBody, err := json.Marshal(target)
		if err != nil {
			return nil, err
		}
		files := map[string]string{"deployment.json": string(targetBody)}
		bundleRefs = append(bundleRefs, snapshot.BundleRef{Owner: device.ID, Hash: servedBundleHash(files)})
		bundleBody, err := json.MarshalIndent(Bundle{Owner: device.ID, Files: files}, "", "  ")
		if err != nil {
			return nil, err
		}
		tree.Files["@snapshot@/nodes/"+device.ID+".json"] = append(bundleBody, '\n')
		component := snapshot.ComponentRef{Node: device.ID}
		for _, value := range device.Components {
			switch value.Name {
			case "agent":
				component.Agent = value.Version
			case "sing-box":
				component.SingBox = value.Version
			case "wireguard":
				component.WireGuard = value.Version
			case "tailscale":
				component.Tailscale = value.Version
			}
		}
		componentRefs = append(componentRefs, component)
	}
	manifest := snapshot.BuildAuthority(input.Head, inputBytes, bundleRefs, componentRefs,
		snapshot.Meta{CreatedAt: meta.CreatedAt, Author: meta.Author, Binaries: refs})
	manifestBody, err := manifest.Bytes()
	if err != nil {
		return nil, err
	}
	signature, err := snapshot.Sign(manifest, privateKey)
	if err != nil {
		return nil, err
	}
	tree.Snapshot = manifest.ID
	for oldPath, body := range tree.Files {
		delete(tree.Files, oldPath)
		tree.Files[strings.Replace(oldPath, "@snapshot@", manifest.ID, 1)] = body
	}
	tree.Files[manifest.ID+"/snapshot.json"] = manifestBody
	tree.Files[manifest.ID+"/snapshot.sig"] = signature
	legacyCurrent, err := json.MarshalIndent(Current{Snapshot: manifest.ID, PublishedAt: manifest.CreatedAt}, "", "  ")
	if err != nil {
		return nil, err
	}
	tree.Files["current.json"] = append(legacyCurrent, '\n')
	if err := validateTreePaths(tree); err != nil {
		return nil, err
	}
	return tree, nil
}

func certifiedBinaryRefs(binaries map[string][]byte) ([]snapshot.BinaryRef, map[string][]byte, error) {
	refs := make([]snapshot.BinaryRef, 0, len(binaries))
	blobs := map[string][]byte{}
	for platform, body := range binaries {
		goos, goarch, ok := strings.Cut(platform, "/")
		if !ok || !validPublisherToken(goos) || !validPublisherToken(goarch) {
			return nil, nil, fmt.Errorf("binary platform must be <os>/<arch>, got %q", platform)
		}
		sum := sha256.Sum256(body)
		ref := snapshot.BinaryRef{OS: goos, Arch: goarch, SHA256: hex.EncodeToString(sum[:]), Size: len(body)}
		refs = append(refs, ref)
		blobs[ref.Path()] = body
	}
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].OS != refs[j].OS {
			return refs[i].OS < refs[j].OS
		}
		return refs[i].Arch < refs[j].Arch
	})
	return refs, blobs, nil
}
