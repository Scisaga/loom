package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

type ControlPrepareRequest struct {
	Schema       int          `json:"schema"`
	BaseConfigID string       `json:"base_config_id"`
	Round        ControlRound `json:"round"`
}

func (server *Server) memberSnapshot(snapshot *WebSnapshot) {
	snapshot.LocalNodeID = server.Config.NodeID
	if !snapshot.Capabilities.Admin {
		return
	}
	proof, err := server.Runtime.Authority.ControlProof()
	if err != nil {
		return
	}
	current, err := VerifyControlProof(proof, server.Config.NetworkID, server.Config.GenesisID)
	if err != nil {
		return
	}
	_, err = activeLocalMember(server.Config, current)
	snapshot.Capabilities.MemberChanges = err == nil
}

func (server *Server) controlChange(w http.ResponseWriter, r *http.Request) {
	if !server.admin(r) {
		http.Error(w, "administrator certificate required", http.StatusForbidden)
		return
	}
	if origin := r.Header.Get("Origin"); !localAdmin(r) && origin != "" && origin != "https://"+r.Host {
		http.Error(w, "same-origin request required", http.StatusForbidden)
		return
	}
	var request ControlChangeRequest
	if !readDeviceJSON(w, r, &request) {
		return
	}
	result, err := server.Runtime.ChangeControl(r.Context(), request, server.now())
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	writeCanonical(w, http.StatusOK, result)
}

func (request ControlPrepareRequest) Validate() error {
	if request.Schema != 3 || ValidateDigest(request.BaseConfigID) != nil || request.Round.Validate() != nil {
		return errors.New("invalid control prepare request")
	}
	return nil
}

type ControlVoteRequest struct {
	Schema   int              `json:"schema"`
	Config   ControlConfig    `json:"config"`
	Round    ControlRound     `json:"round"`
	Promises []ControlPromise `json:"promises"`
}

func (request ControlVoteRequest) Validate() error {
	if request.Schema != 3 || request.Config.Validate() != nil || request.Config.Operation == "genesis" || request.Round.Validate() != nil || len(request.Promises) == 0 {
		return errors.New("invalid control vote request")
	}
	return nil
}

func (server *Server) memberProposer(r *http.Request, controlID string) bool {
	return server.memberRequest(r) && r.TLS.PeerCertificates[0].Subject.CommonName == controlID
}
func (server *Server) internalControlPrepare(w http.ResponseWriter, r *http.Request) {
	var request ControlPrepareRequest
	if !readDeviceJSON(w, r, &request) {
		return
	}
	if r.URL.RawQuery != "" || !server.memberProposer(r, request.Round.ProposerControlID) {
		http.Error(w, "member proposer authentication failed", http.StatusForbidden)
		return
	}
	result, err := server.Runtime.Authority.PrepareControl(r.Context(), request.BaseConfigID, request.Round, server.Config)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	writeCanonical(w, http.StatusOK, result)
}
func (server *Server) internalControlVote(w http.ResponseWriter, r *http.Request) {
	var request ControlVoteRequest
	if !readDeviceJSON(w, r, &request) {
		return
	}
	if r.URL.RawQuery != "" || !server.memberProposer(r, request.Round.ProposerControlID) {
		http.Error(w, "member proposer authentication failed", http.StatusForbidden)
		return
	}
	member, _ := proofMember(server.Runtime.Authority.Snapshot().Config, request.Round.ProposerControlID)
	if err := server.Runtime.fetchMemberProposalMaterials(r.Context(), member, request.Config); err != nil {
		http.Error(w, "member proposal originals are unavailable", http.StatusConflict)
		return
	}
	result, err := server.Runtime.Authority.VoteControl(r.Context(), request.Config, request.Round, request.Promises, server.Config, server.now())
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	writeCanonical(w, http.StatusOK, result)
}
func (server *Server) internalControlProof(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		http.Error(w, "member proof query is invalid", http.StatusBadRequest)
		return
	}
	if r.Method == http.MethodGet {
		proof, err := server.Runtime.Authority.ControlProof()
		if err != nil {
			http.Error(w, "member proof unavailable", http.StatusServiceUnavailable)
			return
		}
		writeCanonical(w, http.StatusOK, proof)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, controlHTTPBodyLimit+1))
	var certificate ControlCertificate
	if err != nil || DecodeCanonical(body, &certificate, ContractDecodeLimits{MaxBytes: controlHTTPBodyLimit, MaxDepth: 128, MaxItems: 1 << 20}) != nil {
		http.Error(w, "invalid original member certificate", http.StatusBadRequest)
		return
	}
	member, _ := proofMember(server.Runtime.Authority.Snapshot().Config, r.TLS.PeerCertificates[0].Subject.CommonName)
	err = server.Runtime.acceptPeerCertificate(r.Context(), member, certificate, body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	writeCanonical(w, http.StatusOK, certificate)
}

func (runtime *Runtime) fetchMemberProposalMaterials(ctx context.Context, member Member, config ControlConfig) error {
	ids := []string{}
	for _, seal := range config.SealedKeys {
		if seal.Sequence > 0 {
			ids = append(ids, seal.TipMaterialID)
		}
	}
	if join := config.Join; join != nil {
		ids = append(ids, join.InviteMaterialID, join.BindingMaterialID)
		if join.AuthorizationMaterialID != "" {
			ids = append(ids, join.AuthorizationMaterialID)
		}
	}
	if invalidation := config.Invalidation; invalidation != nil {
		ids = append(ids, invalidation.InviteMaterialID, invalidation.BindingMaterialID)
	}
	for _, id := range sortedUniqueDependencies(ids) {
		if _, err := runtime.Authority.Material(id); err == nil {
			continue
		}
		if err := runtime.fetchMaterial(ctx, member, id); err != nil && !errors.Is(err, ErrMaterialEquivocation) {
			return err
		}
	}
	return runtime.fillDependencies(ctx, member)
}

func (runtime *Runtime) reconcileControlProof(ctx context.Context, member Member) error {
	var remote ControlProof
	body, err := runtime.peerBody(ctx, member, http.MethodGet, "/internal/control-proof", nil)
	if err != nil {
		return err
	}
	if err = DecodeCanonical(body, &remote, ContractDecodeLimits{MaxBytes: maxControlInputBytes, MaxDepth: 128, MaxItems: 1 << 20}); err != nil {
		return err
	}
	local, err := runtime.Authority.ControlProof()
	if err != nil {
		return err
	}
	current, err := VerifyControlProof(remote, runtime.Config.NetworkID, runtime.Config.GenesisID)
	if err != nil {
		return err
	}
	if _, inactive := activeLocalMember(runtime.Config, current); inactive != nil && len(remote.Successors) > len(local.Successors) {
		if _, err = VerifyControlProofExtension(remote, local, runtime.Config.NetworkID, runtime.Config.GenesisID); err == nil {
			return runtime.Authority.AcceptStoppingProof(ctx, remote, runtime.Config)
		}
	}
	common := min(len(local.Successors), len(remote.Successors))
	for i := 0; i < common; i++ {
		a, _ := ConfigID(local.Successors[i].Config)
		b, _ := ConfigID(remote.Successors[i].Config)
		if a != b {
			body, err := CanonicalEncode(remote.Successors[i])
			if err != nil {
				return err
			}
			return runtime.Authority.AcceptControlCertificate(ctx, body, runtime.Config)
		}
	}
	for i := len(local.Successors); i < len(remote.Successors); i++ {
		cert := remote.Successors[i]
		if err = runtime.fetchMemberProposalMaterials(ctx, member, cert.Config); err != nil {
			return err
		}
		body, err := CanonicalEncode(cert)
		if err != nil {
			return err
		}
		if err = runtime.acceptPeerCertificate(ctx, member, cert, body); err != nil {
			return err
		}
	}
	return nil
}

func (runtime *Runtime) acceptPeerCertificate(ctx context.Context, member Member, certificate ControlCertificate, body []byte) error {
	err := runtime.Authority.AcceptControlCertificate(ctx, body, runtime.Config)
	if errors.Is(err, ErrMissingDependencies) {
		if err = runtime.fetchMemberProposalMaterials(ctx, member, certificate.Config); err != nil {
			return err
		}
		err = runtime.Authority.AcceptControlCertificate(ctx, body, runtime.Config)
	}
	if !errors.Is(err, errControlWithdrawalPending) {
		return err
	}
	// The peer persisted its replacement under a table we already know before
	// activating this certificate. Fetch only missing old-table ranges; ordinary
	// new-table synchronization resumes after the same activation check succeeds.
	if err = runtime.fetchPreCertificateFacts(ctx, member, certificate.Config); err != nil {
		return err
	}
	return runtime.Authority.AcceptControlCertificate(ctx, body, runtime.Config)
}

func (runtime *Runtime) fetchPreCertificateFacts(ctx context.Context, source Member, next ControlConfig) error {
	proof, err := runtime.Authority.ControlProof()
	if err != nil {
		return err
	}
	base := runtime.Authority.Snapshot().Config
	for _, retained := range next.Members {
		before, found := proofMember(base, retained.ControlID)
		if !found || before != retained {
			continue
		}
		key, _ := KeyID(retained.PublicKey)
		after := frontierFor(runtime.Authority.Frontier(), key).Sequence
		for {
			path := "/internal/materials?key_id=" + url.QueryEscape(key) + "&after=" + fmt.Sprint(uint64(after))
			var batch struct {
				Materials []json.RawMessage `json:"materials"`
				More      bool              `json:"more"`
			}
			if err = runtime.peerJSON(ctx, source, http.MethodGet, path, nil, &batch); err != nil {
				return err
			}
			if batch.More && len(batch.Materials) == 0 {
				return errors.New("peer old-table range made no progress")
			}
			reachedNext := false
			for _, body := range batch.Materials {
				fact, err := DecodeMaterial(body)
				if err != nil {
					return err
				}
				if fact.IssuerKeyID != key || fact.Sequence <= after {
					return errors.New("peer old-table range is not ordered for the retained key")
				}
				if _, known := proofConfig(proof, fact.ControlConfigID); !known {
					reachedNext = true
					break
				}
				after = fact.Sequence
				if _, err = runtime.Authority.PutMaterial(body); err != nil {
					return err
				}
			}
			if reachedNext || !batch.More {
				break
			}
		}
	}
	return runtime.fillDependencies(ctx, source)
}
