package publish

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"loom/internal/model"
	"loom/internal/render"
	"loom/internal/snapshot"
)

// VerifyPublishedSnapshot reads historical publication evidence. It never
// advances a release floor or supplies inputs to the current control authority.
func VerifyPublishedSnapshot(directory, id string, key ed25519.PublicKey) (*snapshot.Manifest, error) {
	if !validDeploymentSnapshot(id) || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("invalid snapshot coordinate or verification key")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	read := func(path string, limit int64) ([]byte, error) {
		file, err := root.Open(path)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() || info.Size() > limit {
			return nil, errors.New("publication evidence must be a bounded regular file")
		}
		body, err := io.ReadAll(io.LimitReader(file, limit+1))
		if err != nil || int64(len(body)) > limit {
			return nil, errors.New("publication evidence could not be read within bounds")
		}
		return body, nil
	}
	body, err := read(id+"/snapshot.json", 4<<20)
	if err != nil {
		return nil, err
	}
	signature, err := read(id+"/snapshot.sig", ed25519.SignatureSize)
	if err != nil {
		return nil, err
	}
	if err := snapshot.VerifySignature(body, signature, key); err != nil {
		return nil, err
	}
	if err := rejectDuplicateJSONKeys(body); err != nil {
		return nil, err
	}
	var manifest snapshot.Manifest
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return nil, err
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, err
	}
	if manifest.ID != id {
		return nil, errors.New("signed manifest does not match the requested snapshot")
	}
	owners := map[string]bool{}
	for _, ref := range manifest.Bundles {
		if !model.ValidNodeID(ref.Owner) || owners[ref.Owner] {
			return nil, errors.New("snapshot has an invalid or duplicate bundle owner")
		}
		owners[ref.Owner] = true
		body, err := read(id+"/nodes/"+ref.Owner+".json", 8<<20)
		if err != nil {
			return nil, err
		}
		bundle, err := decodeServedBundle(body)
		if err != nil {
			return nil, err
		}
		if bundle.Owner != ref.Owner || bundle.Files == nil || servedBundleHash(bundle.Files) != ref.Hash {
			return nil, errors.New("published bundle does not match its signed reference")
		}
	}
	platforms := map[string]bool{}
	for _, ref := range manifest.Binaries {
		platform := ref.OS + "/" + ref.Arch
		if ref.OS == "" || ref.Arch == "" || platforms[platform] || ref.Size < 0 {
			return nil, errors.New("snapshot has an invalid or duplicate binary platform")
		}
		platforms[platform] = true
		if !validSHA256Coordinate("sha256:" + ref.SHA256) {
			return nil, errors.New("snapshot binary reference is not a canonical SHA-256")
		}
		file, err := root.Open(ref.Path())
		if err != nil {
			return nil, err
		}
		info, statErr := file.Stat()
		if statErr != nil || !info.Mode().IsRegular() || info.Size() != int64(ref.Size) {
			file.Close()
			return nil, errors.New("published binary length or file type does not match its signed reference")
		}
		hash := sha256.New()
		n, readErr := io.Copy(hash, io.LimitReader(file, int64(ref.Size)))
		var extra [1]byte
		extraN, extraErr := file.Read(extra[:])
		file.Close()
		if readErr != nil || n != int64(ref.Size) || extraN != 0 || extraErr != io.EOF || hex.EncodeToString(hash.Sum(nil)) != ref.SHA256 {
			return nil, fmt.Errorf("published binary for %s does not match its signed reference", platform)
		}
	}
	return &manifest, nil
}

func decodeServedBundle(body []byte) (*Bundle, error) {
	if err := rejectDuplicateJSONKeys(body); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var bundle Bundle
	if err := dec.Decode(&bundle); err != nil {
		return nil, err
	}
	if err := requireJSONEOF(dec); err != nil {
		return nil, err
	}
	return &bundle, nil
}

func servedBundleHash(files map[string]string) string {
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	bundle := render.Bundle{}
	for _, p := range paths {
		bundle.Files = append(bundle.Files, render.File{Path: p, Content: files[p]})
	}
	return bundle.Hash()
}

func validSHA256Coordinate(value string) bool {
	raw, ok := strings.CutPrefix(value, "sha256:")
	if !ok || len(raw) != sha256.Size*2 || raw != strings.ToLower(raw) {
		return false
	}
	_, err := hex.DecodeString(raw)
	return err == nil
}
