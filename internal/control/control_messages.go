package control

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
)

func compareControlRound(a, b ControlRound) int {
	if a.Counter < b.Counter {
		return -1
	}
	if a.Counter > b.Counter {
		return 1
	}
	if a.ProposerControlID < b.ProposerControlID {
		return -1
	}
	if a.ProposerControlID > b.ProposerControlID {
		return 1
	}
	return 0
}

func (binding ControlJoinBinding) Validate() error {
	if ValidateID(binding.TransactionID) != nil || ValidateDigest(binding.InviteMaterialID) != nil || ValidateDigest(binding.BindingMaterialID) != nil || ValidatePublicKey(binding.DevicePublicKey) != nil || binding.AuthorizationMaterialID != "" && ValidateDigest(binding.AuthorizationMaterialID) != nil {
		return errors.New("control join binding is invalid")
	}
	return nil
}

func (value ControlJoinInvalidation) Validate() error {
	if ValidateID(value.TransactionID) != nil || ValidateDigest(value.InviteMaterialID) != nil || ValidateDigest(value.BindingMaterialID) != nil || value.Reason != "cancelled" && value.Reason != "expired" {
		return errors.New("control join invalidation is invalid")
	}
	return nil
}

func (vote ControlVote) Validate() error {
	if vote.Schema != 3 || ValidateID(vote.NetworkID) != nil || ValidateDigest(vote.BaseConfigID) != nil || vote.Round.Validate() != nil || ValidateDigest(vote.ProposalID) != nil || ValidateID(vote.VoterControlID) != nil || validateControlSignature(vote.Signature) != nil {
		return errors.New("control vote is invalid")
	}
	return nil
}

func (promise ControlPromise) Validate() error {
	if promise.Schema != 3 || ValidateID(promise.NetworkID) != nil || ValidateDigest(promise.BaseConfigID) != nil || promise.Round.Validate() != nil || ValidateID(promise.ResponderControlID) != nil || promise.Votes == nil || promise.Prefixes == nil || validateControlSignature(promise.Signature) != nil {
		return errors.New("control promise is invalid")
	}
	for i, item := range promise.Votes {
		vote := item.Vote
		if vote.Validate() != nil || vote.NetworkID != promise.NetworkID || vote.BaseConfigID != promise.BaseConfigID || vote.VoterControlID != promise.ResponderControlID || compareControlRound(vote.Round, promise.Round) >= 0 || i > 0 && compareControlRound(promise.Votes[i-1].Vote.Round, vote.Round) >= 0 {
			return errors.New("control promise vote history is invalid or not strictly earlier")
		}
	}
	for i, prefix := range promise.Prefixes {
		if prefix.Validate() != nil || i > 0 && promise.Prefixes[i-1].KeyID >= prefix.KeyID {
			return errors.New("control promise prefixes are invalid or not uniquely sorted")
		}
	}
	return nil
}

func unsignedControlVote(vote ControlVote) map[string]any {
	return map[string]any{"schema": vote.Schema, "network_id": vote.NetworkID, "base_config_id": vote.BaseConfigID, "round": vote.Round, "proposal_id": vote.ProposalID, "voter_control_id": vote.VoterControlID}
}
func unsignedControlPromise(promise ControlPromise) map[string]any {
	return map[string]any{"schema": promise.Schema, "network_id": promise.NetworkID, "base_config_id": promise.BaseConfigID, "round": promise.Round, "responder_control_id": promise.ResponderControlID, "votes": promise.Votes, "prefixes": promise.Prefixes}
}

func signControlValue(domain string, value any, key ed25519.PrivateKey) (string, error) {
	if len(key) != ed25519.PrivateKeySize {
		return "", errors.New("control signing key is invalid")
	}
	body, err := CanonicalEncode(value)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, append([]byte(domain), body...))), nil
}

func validateControlSignature(value string) error {
	body, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(body) != ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(body) != value {
		return errors.New("control signature encoding is invalid")
	}
	return nil
}

func validateControlSuccessorShape(config ControlConfig) error {
	if ValidateDigest(config.PreviousConfigID) != nil || ValidateID(config.TargetNodeID) != nil || config.TargetNodeID == "direct" || len(config.OriginPromises) == 0 {
		return errors.New("control successor lacks its original member promises or target")
	}
	switch config.Operation {
	case "add":
		if config.Join == nil || config.Join.Validate() != nil || config.Invalidation != nil {
			return errors.New("control addition requires exactly one join binding")
		}
	case "invalidate_join":
		if config.Invalidation == nil || config.Invalidation.Validate() != nil || config.Join != nil {
			return errors.New("control invalidation requires exactly one transaction binding")
		}
	case "resign", "revoke", "delete", "rotate":
		if config.Join != nil || config.Invalidation != nil {
			return errors.New("control operation contains unrelated join fields")
		}
	default:
		return errors.New("unknown control successor operation")
	}
	for i, promise := range config.OriginPromises {
		if promise.Validate() != nil || promise.NetworkID != config.NetworkID || promise.BaseConfigID != config.PreviousConfigID || compareControlRound(promise.Round, config.OriginPromises[0].Round) != 0 || i > 0 && config.OriginPromises[i-1].ResponderControlID >= promise.ResponderControlID {
			return errors.New("control origin promises are not a canonical same-round set")
		}
	}
	for i, prefix := range config.SealedKeys {
		if prefix.Validate() != nil || i > 0 && config.SealedKeys[i-1].KeyID >= prefix.KeyID {
			return errors.New("control sealed keys are invalid or not uniquely sorted")
		}
	}
	return nil
}

func validateControlCertificateShape(cert ControlCertificate) error {
	if cert.Config.Validate() != nil || cert.Config.Operation == "genesis" || cert.Round.Validate() != nil || len(cert.Promises) == 0 || len(cert.Votes) == 0 {
		return errors.New("control certificate is incomplete")
	}
	if compareControlRound(cert.Config.OriginPromises[0].Round, cert.Round) > 0 {
		return errors.New("control certificate precedes its proposal")
	}
	for i, promise := range cert.Promises {
		if promise.Validate() != nil || promise.NetworkID != cert.Config.NetworkID || promise.BaseConfigID != cert.Config.PreviousConfigID || compareControlRound(promise.Round, cert.Round) != 0 || i > 0 && cert.Promises[i-1].ResponderControlID >= promise.ResponderControlID {
			return errors.New("control certificate promises are invalid")
		}
	}
	for i, vote := range cert.Votes {
		if vote.Validate() != nil || vote.NetworkID != cert.Config.NetworkID || vote.BaseConfigID != cert.Config.PreviousConfigID || compareControlRound(vote.Round, cert.Round) != 0 || i > 0 && cert.Votes[i-1].VoterControlID >= vote.VoterControlID {
			return errors.New("control certificate votes are invalid")
		}
	}
	return nil
}
