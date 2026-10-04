package control

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
)

// These values describe the existing member proof, not another authority.
// Successor verification and durable voting must be implemented together;
// until then a nonempty successor chain is rejected at every entry point.
var ErrControlSuccessionUnsupported = errors.New("control successor verification is not implemented")

type ControlRound struct {
	Counter           U64    `json:"counter"`
	ProposerControlID string `json:"proposer_control_id"`
}

func (round ControlRound) Validate() error {
	if round.Counter == 0 || ValidateID(round.ProposerControlID) != nil {
		return errors.New("control round is invalid")
	}
	return nil
}

type ControlSealedKey struct {
	KeyID         string `json:"key_id"`
	Sequence      U64    `json:"sequence"`
	TipMaterialID string `json:"tip_material_id"`
}

func emptyMaterialTip() string {
	sum := sha256.Sum256([]byte("loom-empty-material-chain-v3\x00"))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (prefix ControlSealedKey) Validate() error {
	if ValidateDigest(prefix.KeyID) != nil || ValidateDigest(prefix.TipMaterialID) != nil ||
		(prefix.Sequence == 0) != (prefix.TipMaterialID == emptyMaterialTip()) {
		return errors.New("control prefix is invalid")
	}
	return nil
}

type FactFrontier = ControlSealedKey

type ControlJoinBinding struct {
	TransactionID           string `json:"transaction_id"`
	InviteMaterialID        string `json:"invite_material_id"`
	BindingMaterialID       string `json:"binding_material_id"`
	DevicePublicKey         string `json:"device_public_key"`
	AuthorizationMaterialID string `json:"authorization_material_id"`
}

type ControlJoinInvalidation struct {
	TransactionID     string `json:"transaction_id"`
	InviteMaterialID  string `json:"invite_material_id"`
	BindingMaterialID string `json:"binding_material_id"`
	Reason            string `json:"reason"`
}

type ControlVote struct {
	Schema         int          `json:"schema"`
	NetworkID      string       `json:"network_id"`
	BaseConfigID   string       `json:"base_config_id"`
	Round          ControlRound `json:"round"`
	ProposalID     string       `json:"proposal_id"`
	VoterControlID string       `json:"voter_control_id"`
	Signature      string       `json:"signature"`
}

type ControlVoteHistoryItem struct {
	Proposal ControlConfig `json:"proposal"`
	Vote     ControlVote   `json:"vote"`
}

type ControlPromise struct {
	Schema             int                      `json:"schema"`
	NetworkID          string                   `json:"network_id"`
	BaseConfigID       string                   `json:"base_config_id"`
	Round              ControlRound             `json:"round"`
	ResponderControlID string                   `json:"responder_control_id"`
	Votes              []ControlVoteHistoryItem `json:"votes"`
	Prefixes           []ControlSealedKey       `json:"prefixes"`
	Signature          string                   `json:"signature"`
}

type ControlCertificate struct {
	Config   ControlConfig    `json:"config"`
	Round    ControlRound     `json:"round"`
	Promises []ControlPromise `json:"promises"`
	Votes    []ControlVote    `json:"votes"`
}

func (ControlCertificate) Validate() error { return ErrControlSuccessionUnsupported }

func validateControlConfigSuccessor(ControlConfig) error { return ErrControlSuccessionUnsupported }

type ControlProof struct {
	Genesis    Material             `json:"genesis"`
	Successors []ControlCertificate `json:"successors"`
}

func (proof ControlProof) Validate() error {
	_, digest, err := EncodeMaterial(proof.Genesis)
	if err != nil {
		return err
	}
	_, err = VerifyControlProof(proof, proof.Genesis.NetworkID, digest)
	return err
}

// VerifyControlProof checks actual signed genesis bytes for any member count.
// The caller supplies the fixed anchor; a self-signed object cannot replace it.
func VerifyControlProof(proof ControlProof, networkID, genesisDigest string) (ControlConfig, error) {
	if proof.Successors == nil || ValidateID(networkID) != nil || ValidateDigest(genesisDigest) != nil {
		return ControlConfig{}, errors.New("control proof boundary is invalid")
	}
	if len(proof.Successors) != 0 {
		return ControlConfig{}, ErrControlSuccessionUnsupported
	}
	genesis, ok := proof.Genesis.Payload.(Genesis)
	if !ok || proof.Genesis.Operation != "genesis" || proof.Genesis.NetworkID != networkID || genesis.ControlConfig.NetworkID != networkID {
		return ControlConfig{}, errors.New("control proof has no matching genesis")
	}
	_, digest, err := EncodeMaterial(proof.Genesis)
	if err != nil || digest != genesisDigest {
		return ControlConfig{}, errors.New("control proof does not match the fixed genesis anchor")
	}
	member, found := proofMember(genesis.ControlConfig, proof.Genesis.IssuerControlID)
	keyID, keyErr := KeyID(member.PublicKey)
	key, decodeErr := base64.RawURLEncoding.DecodeString(member.PublicKey)
	if !found || keyErr != nil || decodeErr != nil || keyID != proof.Genesis.IssuerKeyID || len(key) != ed25519.PublicKeySize {
		return ControlConfig{}, errors.New("genesis issuer is not an initial member")
	}
	if err := VerifyMaterial(proof.Genesis, ed25519.PublicKey(key)); err != nil {
		return ControlConfig{}, err
	}
	return genesis.ControlConfig, nil
}

// VerifyControlProofExtension preserves an already accepted chain. No fallback
// to genesis is permitted if a longer member history has been seen.
func VerifyControlProofExtension(proof, previous ControlProof, networkID, genesisDigest string) (ControlConfig, error) {
	if len(previous.Successors) > len(proof.Successors) {
		return ControlConfig{}, errors.New("control proof rolls back the accepted member chain")
	}
	if _, err := VerifyControlProof(previous, networkID, genesisDigest); err != nil {
		return ControlConfig{}, err
	}
	return VerifyControlProof(proof, networkID, genesisDigest)
}

func proofMember(config ControlConfig, controlID string) (Member, bool) {
	for _, member := range config.Members {
		if member.ControlID == controlID {
			return member, true
		}
	}
	return Member{}, false
}
