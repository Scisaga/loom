package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Runtime uses the same local authority with or without an attached private
// transport. Transport availability is not signing authority or a quorum.
type Runtime struct {
	Config    NodeConfig
	Authority *Authority
	Reports   *ObservationStore
	Channel   *PrivateChannel
	stop      chan struct{}
	done      chan struct{}
	wake      chan struct{}
	once      sync.Once
}

func OpenRuntime(root string, channel *PrivateChannel) (*Runtime, error) {
	config, err := LoadNodeConfig(root)
	if err != nil {
		return nil, err
	}
	a, err := OpenAuthority(root)
	if err != nil {
		return nil, err
	}
	if _, err := activeLocalMember(config, a.Snapshot().Config); err != nil {
		return nil, err
	}
	reports, err := OpenObservationStore(root)
	if err != nil {
		return nil, err
	}
	if _, err := reports.reportIndexSnapshot(context.Background()); err != nil {
		return nil, err
	}
	runtime := &Runtime{Config: config, Authority: a, Reports: reports, Channel: channel, stop: make(chan struct{}), done: make(chan struct{}), wake: make(chan struct{}, 1)}
	if channel != nil {
		channel.AttachAuthority(a)
		go runtime.reconcileLoop()
	} else {
		close(runtime.done)
	}
	return runtime, nil
}
func (runtime *Runtime) Close() error {
	runtime.once.Do(func() { close(runtime.stop) })
	<-runtime.done
	return nil
}
func (runtime *Runtime) Writable() bool {
	return runtime.Authority != nil && runtime.Authority.signingReady(runtime.Config)
}
func (runtime *Runtime) Submit(ctx context.Context, body []byte) (Submission, error) {
	operation, err := DecodeOperation(body)
	if err != nil {
		return Submission{}, err
	}
	result, err := runtime.Authority.Submit(ctx, operation, runtime.Config)
	if err != nil {
		return Submission{}, err
	}
	if runtime.Channel != nil {
		select {
		case runtime.wake <- struct{}{}:
		default:
		}
	}
	return result, nil
}
func (a *Authority) signingReady(config NodeConfig) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	member, err := activeLocalMember(config, a.projection.Config)
	if err != nil {
		return false
	}
	keyID, err := KeyID(member.PublicKey)
	if err != nil {
		return false
	}
	sequence := U64(0)
	for _, frontier := range a.projection.Frontier {
		if frontier.KeyID == keyID {
			sequence = frontier.Sequence
		}
	}
	for _, m := range a.materials {
		if m.IssuerKeyID == keyID && m.Sequence > sequence {
			return false
		}
	}
	return true
}
func (runtime *Runtime) reconcileLoop() {
	defer close(runtime.done)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		runtime.reconcilePeers()
		select {
		case <-runtime.stop:
			return
		case <-runtime.wake:
		case <-ticker.C:
		}
	}
}
func (runtime *Runtime) reconcilePeers() {
	for _, member := range runtime.Authority.Snapshot().Config.Members {
		if member.ControlID == runtime.Config.ControlID {
			continue
		}
		select {
		case <-runtime.stop:
			return
		default:
		}
		// One report batch needs frontier, ranges, IDs and original bodies.
		// Each private request already has a 15-second bound; a shorter shared
		// deadline can repeatedly cancel the first batch before any progress.
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		_ = runtime.reconcilePeer(ctx, member)
		cancel()
	}
}
func frontierFor(values []FactFrontier, keyID string) FactFrontier {
	for _, value := range values {
		if value.KeyID == keyID {
			return value
		}
	}
	return FactFrontier{KeyID: keyID, Sequence: 0, TipMaterialID: emptyAuthorityChainID()}
}
func validateRemoteFrontier(values []FactFrontier) error {
	for i, value := range values {
		if ValidateDigest(value.KeyID) != nil || ValidateDigest(value.TipMaterialID) != nil || i > 0 && values[i-1].KeyID >= value.KeyID || value.Sequence == 0 && value.TipMaterialID != emptyAuthorityChainID() {
			return errors.New("peer fact frontier is invalid")
		}
	}
	return nil
}
func (runtime *Runtime) reconcilePeer(ctx context.Context, member Member) error {
	var remote []FactFrontier
	if err := runtime.peerJSON(ctx, member, http.MethodGet, "/internal/frontier", nil, &remote); err != nil {
		return err
	}
	if remote == nil {
		return errors.New("peer frontier is missing")
	}
	if err := validateRemoteFrontier(remote); err != nil {
		return err
	}
	for _, tip := range remote {
		local := frontierFor(runtime.Authority.Frontier(), tip.KeyID)
		if tip.Sequence > 0 && tip.Sequence <= local.Sequence {
			id, err := runtime.Authority.materialAtSequence(tip.KeyID, tip.Sequence)
			if err != nil {
				return err
			}
			if id != tip.TipMaterialID {
				if err := runtime.fetchMaterial(ctx, member, tip.TipMaterialID); err != nil {
					return err
				}
				return errors.New("peer has a conflicting signed fact frontier")
			}
		}
		for tip.Sequence > local.Sequence {
			path := "/internal/materials?key_id=" + url.QueryEscape(tip.KeyID) + "&after=" + fmt.Sprint(uint64(local.Sequence))
			var batch struct {
				Materials []json.RawMessage `json:"materials"`
				More      bool              `json:"more"`
			}
			if err := runtime.peerJSON(ctx, member, http.MethodGet, path, nil, &batch); err != nil {
				return err
			}
			if len(batch.Materials) == 0 {
				return errors.New("peer material batch made no progress")
			}
			last := local.Sequence
			for _, body := range batch.Materials {
				material, err := DecodeMaterial(body)
				if err != nil {
					return err
				}
				if material.IssuerKeyID != tip.KeyID || material.Sequence <= last {
					return errors.New("peer material batch is not ordered for the requested signing key")
				}
				last = material.Sequence
				if _, err := runtime.Authority.PutMaterial(body); err != nil {
					return err
				}
			}
			if err := runtime.fillDependencies(ctx, member); err != nil {
				return err
			}
			next := frontierFor(runtime.Authority.Frontier(), tip.KeyID)
			if next.Sequence <= local.Sequence {
				return errors.New("peer material prefix remains unresolved")
			}
			local = next
			if !batch.More {
				if local.Sequence < tip.Sequence {
					return errors.New("peer batch ended before its advertised frontier")
				}
				break
			}
		}
		if tip.Sequence > 0 {
			id, err := runtime.Authority.materialAtSequence(tip.KeyID, tip.Sequence)
			if err != nil {
				return err
			}
			if id != tip.TipMaterialID {
				if err := runtime.fetchMaterial(ctx, member, tip.TipMaterialID); err != nil {
					return err
				}
				return errors.New("peer batch does not match its advertised signed frontier")
			}
		}
	}
	if err := runtime.fillDependencies(ctx, member); err != nil {
		return err
	}
	return runtime.reconcileReports(ctx, member)
}
func (runtime *Runtime) fillDependencies(ctx context.Context, member Member) error {
	fetched := map[string]bool{}
	for {
		missing, err := runtime.Authority.PendingDependencies()
		if err != nil {
			return err
		}
		if len(missing) == 0 {
			return nil
		}
		progress := false
		for _, id := range missing {
			if fetched[id] {
				continue
			}
			fetched[id] = true
			if err := runtime.fetchMaterial(ctx, member, id); err != nil {
				return err
			}
			progress = true
		}
		if !progress {
			return errors.New("peer dependencies remain unresolved")
		}
	}
}
func (runtime *Runtime) fetchMaterial(ctx context.Context, member Member, id string) error {
	if ValidateDigest(id) != nil {
		return errors.New("invalid missing material ID")
	}
	body, err := runtime.peerBody(ctx, member, http.MethodGet, "/internal/materials/"+strings.TrimPrefix(id, "sha256:"), nil)
	if err != nil {
		return err
	}
	_, actual, err := EncodeMaterialFromBytes(body)
	if err != nil || actual != id {
		return errors.New("peer material does not match requested ID")
	}
	_, err = runtime.Authority.PutMaterial(body)
	return err
}
func (runtime *Runtime) peerJSON(ctx context.Context, member Member, method, path string, body []byte, result any) error {
	raw, err := runtime.peerBody(ctx, member, method, path, body)
	if err != nil {
		return err
	}
	if result == nil {
		return nil
	}
	parsed, err := parseContractJSON(raw, ContractDecodeLimits{MaxBytes: 64 << 20, MaxDepth: 256, MaxItems: 1 << 20})
	if err != nil || !bytes.Equal(appendContractJSON(nil, parsed), raw) {
		return errors.New("peer response is not canonical JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(result)
}
func (runtime *Runtime) peerBody(ctx context.Context, member Member, method, path string, body []byte) ([]byte, error) {
	if runtime.Channel == nil {
		return nil, errors.New("private member transport is unavailable")
	}
	current := false
	for _, candidate := range runtime.Authority.Snapshot().Config.Members {
		if candidate == member {
			current = true
			break
		}
	}
	if !current {
		return nil, errors.New("peer is no longer a control member")
	}
	client, err := runtime.Channel.peerClient(member.NodeID)
	if err != nil {
		return nil, err
	}
	// NodeID is an opaque domain ID, not a DNS name or a URL component. The
	// member is already fixed by peerClient and its authenticated dial closure.
	request, err := http.NewRequestWithContext(ctx, method, "https://control.loom"+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("private member request failed: HTTP %d", response.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, (64<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > 64<<20 {
		return nil, errors.New("peer response exceeds the current reader resource bound")
	}
	return raw, nil
}
