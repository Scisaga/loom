package control

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// The signing reference reuses the already proven device key. Existing key
// bytes are never overwritten, and no key is returned as command output.
func InstallMemberSigningKey(config NodeConfig, key ed25519.PrivateKey) error {
	if config.Validate() != nil || len(key) != ed25519.PrivateKeySize {
		return errors.New("invalid member execution key input")
	}
	if _, err := os.Lstat(config.SigningKeyFile); err == nil {
		existing, err := config.PrivateKey()
		if err != nil || !existing.Equal(key) {
			return errors.New("existing member signing file has another identity")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := validateControlRoot(filepath.Dir(config.SigningKeyFile)); err != nil {
		return err
	}
	body, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	defer clear(body)
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: body})
	defer clear(encoded)
	return putControlBytes(config.SigningKeyFile, encoded)
}

// CollectMemberMaterials follows original signed tips and their dependencies.
// The callback uses an authenticated current member channel; no export snapshot
// or imported projection becomes an authority.
func CollectMemberMaterials(ctx context.Context, proof ControlProof, fetch func(context.Context, string) ([]byte, error)) ([]Material, error) {
	genesisID, err := MaterialID(proof.Genesis)
	if err != nil {
		return nil, err
	}
	if _, err = VerifyControlProof(proof, proof.Genesis.NetworkID, genesisID); err != nil {
		return nil, err
	}
	body, err := fetch(ctx, "/frontier")
	if err != nil {
		return nil, err
	}
	var frontier []FactFrontier
	if err = DecodeCanonical(body, &frontier, ContractDecodeLimits{MaxBytes: controlHTTPBodyLimit, MaxDepth: 16, MaxItems: 1 << 16}); err != nil {
		return nil, err
	}
	queue := []string{}
	for i, prefix := range frontier {
		if ValidateDigest(prefix.KeyID) != nil || ValidateDigest(prefix.TipMaterialID) != nil || i > 0 && frontier[i-1].KeyID >= prefix.KeyID {
			return nil, errors.New("member source has a noncanonical frontier")
		}
		if prefix.Sequence > 0 {
			queue = append(queue, prefix.TipMaterialID)
		}
	}
	for _, cert := range proof.Successors {
		for _, seal := range cert.Config.SealedKeys {
			if seal.Sequence > 0 {
				queue = append(queue, seal.TipMaterialID)
			}
		}
		if join := cert.Config.Join; join != nil {
			queue = append(queue, join.InviteMaterialID, join.BindingMaterialID)
			if join.AuthorizationMaterialID != "" {
				queue = append(queue, join.AuthorizationMaterialID)
			}
		}
		if invalidation := cert.Config.Invalidation; invalidation != nil {
			queue = append(queue, invalidation.InviteMaterialID, invalidation.BindingMaterialID)
		}
	}
	for cursor := ""; ; {
		body, err := fetch(ctx, "/material-conflicts?after="+url.QueryEscape(cursor))
		if err != nil {
			return nil, err
		}
		var page materialConflicts
		if err = DecodeCanonical(body, &page, ContractDecodeLimits{MaxBytes: 32 << 10, MaxDepth: 4, MaxItems: 1024}); err != nil {
			return nil, err
		}
		if page.MaterialIDs == nil || len(page.MaterialIDs) > materialConflictPageSize || page.More && len(page.MaterialIDs) == 0 {
			return nil, errors.New("member conflict source made no bounded progress")
		}
		for _, id := range page.MaterialIDs {
			if ValidateDigest(id) != nil || id <= cursor {
				return nil, errors.New("member conflict source is not ordered")
			}
			cursor = id
			queue = append(queue, id)
		}
		if !page.More {
			break
		}
	}
	known := map[string]Material{genesisID: proof.Genesis}
	for len(queue) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		id := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		if _, found := known[id]; found {
			continue
		}
		if ValidateDigest(id) != nil {
			return nil, errors.New("member source references an invalid fact")
		}
		body, err := fetch(ctx, "/material/"+strings.TrimPrefix(id, "sha256:"))
		if err != nil {
			return nil, err
		}
		material, actual, err := EncodeMaterialFromBytes(body)
		if err != nil || actual != id || material.Operation == "genesis" {
			return nil, errors.New("member source changed original fact identity")
		}
		known[id] = material
		queue = append(queue, material.Dependencies...)
		if material.Sequence > 1 {
			queue = append(queue, material.PreviousMaterialID)
		}
	}
	for _, prefix := range frontier {
		if prefix.Sequence == 0 {
			if prefix.TipMaterialID != emptyMaterialTip() {
				return nil, errors.New("member source changed empty frontier")
			}
			continue
		}
		material, found := known[prefix.TipMaterialID]
		if !found || material.IssuerKeyID != prefix.KeyID || material.Sequence != prefix.Sequence {
			return nil, errors.New("member frontier differs from its original tip")
		}
	}
	ids := []string{}
	for id := range known {
		if id != genesisID {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	materials := make([]Material, 0, len(ids))
	for _, id := range ids {
		materials = append(materials, known[id])
	}
	graph, err := newMaterialGraph(proof.Genesis, proof.Successors, materials)
	if err != nil {
		return nil, err
	}
	for _, id := range ids {
		if err = graph.validate(id); err != nil && !errors.Is(err, ErrMaterialEquivocation) {
			return nil, err
		}
	}
	return materials, nil
}
