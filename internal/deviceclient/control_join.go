package deviceclient

import (
	"context"
	"errors"
	"io"
	"net/http"

	"loom/internal/control"
)

// FetchMemberAuthority never sends a private key. The established device tunnel
// proves the same key that the current majority certificate made a member.
func FetchMemberAuthority(ctx context.Context, store IdentityStore) (control.ControlProof, []control.Material, error) {
	lkg := store.LKG()
	if lkg == nil || store.Platform() != "linux" {
		return control.ControlProof{}, nil, errors.New("member initialization requires its accepted Linux identity")
	}
	fetch := func(ctx context.Context, path string) ([]byte, error) {
		conn, err := deviceConnection(ctx, store)
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://loom.private/device/control"+path, nil)
		if err != nil {
			return nil, err
		}
		response, err := tunnelHTTPClient(conn).Do(request)
		if err != nil {
			return nil, err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return nil, errors.New("current member original-fact authentication rejected")
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, (8<<20)+1))
		if err != nil || len(body) > 8<<20 {
			return nil, errors.New("member original exceeds bounded response")
		}
		return body, nil
	}
	readProof := func() (control.ControlProof, error) {
		body, err := fetch(ctx, "/proof")
		if err != nil {
			return control.ControlProof{}, err
		}
		var proof control.ControlProof
		err = control.DecodeCanonical(body, &proof, control.ContractDecodeLimits{MaxBytes: 8 << 20, MaxDepth: 128, MaxItems: 1 << 20})
		return proof, err
	}
	proof, err := readProof()
	if err != nil {
		return control.ControlProof{}, nil, err
	}
	current, err := control.VerifyControlProofExtension(proof, lkg.ControlProof, lkg.NetworkID, lkg.GenesisDigest)
	if err != nil {
		return control.ControlProof{}, nil, err
	}
	found := false
	for _, member := range current.Members {
		found = found || member.NodeID == lkg.View.DeviceID && member.PublicKey == store.PublicKey()
	}
	if !found {
		return control.ControlProof{}, nil, errors.New("device does not own a current member key")
	}
	materials, err := control.CollectMemberMaterials(ctx, proof, fetch)
	if err != nil {
		return control.ControlProof{}, nil, err
	}
	projection, err := control.Project(proof.Genesis, proof.Successors, materials)
	if err != nil {
		return control.ControlProof{}, nil, err
	}
	seals := map[string]control.ControlSealedKey{}
	for _, cert := range proof.Successors {
		for _, seal := range cert.Config.SealedKeys {
			seals[seal.KeyID] = seal
		}
	}
	for _, required := range lkg.FactFrontier {
		if seal, found := seals[required.KeyID]; found && required.Sequence > seal.Sequence {
			required.Sequence, required.TipMaterialID = seal.Sequence, seal.TipMaterialID
		}
		found := false
		for _, available := range projection.Frontier {
			if available.KeyID == required.KeyID && (available.Sequence > required.Sequence || available.Sequence == required.Sequence && available.TipMaterialID == required.TipMaterialID) {
				found = true
			}
		}
		if !found {
			return control.ControlProof{}, nil, errors.New("member originals do not cover the device's authenticated frontier")
		}
	}
	after, err := readProof()
	if err != nil {
		return control.ControlProof{}, nil, err
	}
	final, err := control.VerifyControlProofExtension(after, proof, lkg.NetworkID, lkg.GenesisDigest)
	if err != nil {
		return control.ControlProof{}, nil, err
	}
	firstID, _ := control.ConfigID(current)
	lastID, _ := control.ConfigID(final)
	if firstID != lastID {
		return control.ControlProof{}, nil, errors.New("member table changed during initialization; resume with its new proof")
	}
	return proof, materials, nil
}
