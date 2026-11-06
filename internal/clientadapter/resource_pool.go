package clientadapter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"loom/internal/clientmodel"
	"loom/internal/control"
	P "loom/protocol"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"sort"
)

// RuntimeApplication describes two independent confirmations from the existing
// native instance. Config is a disposable local projection, never authority.
type RuntimeApplication struct {
	Supported         bool   `json:"supported"`
	PermissionCurrent bool   `json:"permission_current"`
	ResourcesReady    bool   `json:"resources_ready"`
	Config            string `json:"config"`
}

type runtimeResourceSource struct {
	source     string
	base       map[string]any
	outbounds  map[string]map[string]any
	forwarding map[string]map[string]any
	wireguard  map[string]any
}

// A forwarding container has no independent grant. Its members and Policy
// references must be exactly derived from the same traversal descriptor.
func forwardingResource(entry map[string]any) (map[string]any, bool, error) {
	raw, exists := entry["hop"]
	if !exists {
		return nil, false, nil
	}
	hop, ok := raw.(map[string]any)
	if !ok || entry["type"] != "selector" || entry["default"] != "reject" || len(entry) != 6 || len(hop) != 4 {
		return nil, true, errors.New("invalid runtime forwarding container")
	}
	for field := range hop {
		if field != "policy" && field != "node_id" && field != "nodes" && field != "exit_choices" {
			return nil, true, errors.New("unknown forwarding descriptor field")
		}
	}
	policyBody, err := json.Marshal(hop["policy"])
	var policy P.HopPolicy
	if err != nil || json.Unmarshal(policyBody, &policy) != nil || policy.Validate() != nil || len(policy.Origins) != 0 || policy.EntryScope.Mode != "any" || len(policy.EntryScope.NodeIDs) != 0 {
		return nil, true, errors.New("invalid forwarding traversal Policy")
	}
	canonical, err := json.Marshal(policy)
	var normalized any
	if err != nil || json.Unmarshal(canonical, &normalized) != nil || !reflect.DeepEqual(normalized, hop["policy"]) {
		return nil, true, errors.New("noncanonical forwarding traversal Policy")
	}
	node, ok := hop["node_id"].(string)
	if !ok || !slices.Contains(policy.Nodes, node) {
		return nil, true, errors.New("forwarding node missing from traversal")
	}
	nodes, ok := hop["nodes"].(map[string]any)
	choices, choicesOK := hop["exit_choices"].(map[string]any)
	if !ok || !choicesOK || len(choices) != len(policy.Exits) {
		return nil, true, errors.New("incomplete forwarding traversal")
	}
	tags := make([]string, 0, len(nodes))
	bindings := map[string]any{}
	for tag, rawNode := range nodes {
		owner, ok := rawNode.(string)
		if tag == "" || tag == "reject" || !ok || owner == node || !slices.Contains(policy.Nodes, owner) || !slices.Contains(policy.Edges, P.DirectedHop{From: node, To: owner}) {
			return nil, true, errors.New("invalid forwarding segment reference")
		}
		tags = append(tags, tag)
		bindings[tag] = policy.PolicyID
	}
	for exit, rawChoices := range choices {
		values, ok := rawChoices.([]any)
		if !ok || !slices.Contains(policy.Exits, exit) {
			return nil, true, errors.New("invalid forwarding exit choices")
		}
		seen := map[string]bool{}
		for _, rawTag := range values {
			tag, ok := rawTag.(string)
			if !ok || nodes[tag] == nil || seen[tag] {
				return nil, true, errors.New("invalid forwarding choice reference")
			}
			seen[tag] = true
		}
	}
	sort.Strings(tags)
	members := []any{"reject"}
	for _, tag := range tags {
		members = append(members, tag)
	}
	if !reflect.DeepEqual(entry["outbounds"], members) || !reflect.DeepEqual(entry["candidate_policies"], bindings) {
		return nil, true, errors.New("forwarding references differ from traversal")
	}
	return hop, true, nil
}

func forwardingContainer(tag string, hop map[string]any) map[string]any {
	nodes := hop["nodes"].(map[string]any)
	tags := make([]string, 0, len(nodes))
	for tag := range nodes {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	members := []any{"reject"}
	bindings := map[string]any{}
	for _, tag := range tags {
		members = append(members, tag)
		bindings[tag] = hop["policy"].(map[string]any)["policy_id"]
	}
	return map[string]any{"type": "selector", "tag": tag, "default": "reject", "outbounds": members, "candidate_policies": bindings, "hop": hop}
}

// senderResource recognizes the actual native capability shape rather than a
// resource-name prefix. A physical direct, selector or receiving object is not
// a pool-owned sender.
func senderResource(value map[string]any) bool {
	if _, ok := value["execution"].(map[string]any); !ok {
		return false
	}
	if value["type"] == "hysteria2" {
		return true
	}
	return value["type"] == "direct" && value["detour"] == "wg-shared" && value["inet6_bind_address"] != nil && value["inet4_bind_address"] == nil
}

func decodeRuntimeResources(config string) (runtimeResourceSource, error) {
	var document map[string]any
	if json.Unmarshal([]byte(config), &document) != nil || document == nil {
		return runtimeResourceSource{}, errors.New("invalid runtime resource source")
	}
	value := runtimeResourceSource{source: config, base: document, outbounds: map[string]map[string]any{}, forwarding: map[string]map[string]any{}}
	outbounds, ok := document["outbounds"].([]any)
	if !ok {
		return value, errors.New("runtime outbounds missing")
	}
	kept := make([]any, 0, len(outbounds))
	for _, raw := range outbounds {
		entry, ok := raw.(map[string]any)
		if !ok {
			return value, errors.New("invalid runtime outbound")
		}
		hop, forward, err := forwardingResource(entry)
		if err != nil {
			return value, err
		}
		if forward {
			tag, _ := entry["tag"].(string)
			if tag == "" || value.forwarding[tag] != nil {
				return value, errors.New("ambiguous forwarding container")
			}
			value.forwarding[tag] = hop
			continue
		}
		if !senderResource(entry) {
			kept = append(kept, entry)
			continue
		}
		tag, _ := entry["tag"].(string)
		if tag == "" || value.outbounds[tag] != nil {
			return value, errors.New("ambiguous sender resource")
		}
		value.outbounds[tag] = entry
	}
	document["outbounds"] = kept
	endpoints, _ := document["endpoints"].([]any)
	for _, raw := range endpoints {
		entry, ok := raw.(map[string]any)
		if !ok {
			return value, errors.New("invalid runtime endpoint")
		}
		if entry["type"] != "wireguard" || entry["tag"] != "wg-shared" {
			continue
		}
		if value.wireguard != nil {
			return value, errors.New("ambiguous shared WG endpoint")
		}
		body, _ := json.Marshal(entry)
		_ = json.Unmarshal(body, &value.wireguard)
		entry["source_routes"] = []any{}
		entry["peers"] = wireGuardWorkingPeers(value.wireguard, nil)
	}
	return value, nil
}

func wireGuardWorkingPeers(wireguard map[string]any, sources map[string]bool) []any {
	routes, _ := wireguard["source_routes"].([]any)
	all, needed := map[string]bool{}, map[string]bool{}
	for _, raw := range routes {
		route, _ := raw.(map[string]any)
		destination, _ := route["destination"].(string)
		execution, _ := route["execution"].(string)
		source, _ := route["source"].(string)
		all[destination], all[execution+"/128"] = true, true
		if sources[source] {
			needed[destination], needed[execution+"/128"] = true, true
		}
	}
	result := []any{}
	peers, _ := wireguard["peers"].([]any)
	for _, raw := range peers {
		peer, _ := raw.(map[string]any)
		allowed, _ := peer["allowed_ips"].([]any)
		keep := []any{}
		for _, prefix := range allowed {
			text, _ := prefix.(string)
			if !all[text] || needed[text] {
				keep = append(keep, prefix)
			}
		}
		if len(keep) == 0 {
			continue
		}
		copy := make(map[string]any, len(peer))
		for key, item := range peer {
			copy[key] = item
		}
		copy["allowed_ips"] = keep
		if len(needed) == 0 {
			delete(copy, "persistent_keepalive_interval")
		}
		result = append(result, copy)
	}
	return result
}

// NativeResourceBase starts stable local facilities and complete permissions.
// Sender descriptions remain in the accepted source; native leases create
// their objects only when a selected connection or task needs them.
func NativeResourceBase(config string) (string, error) {
	value, err := decodeRuntimeResources(config)
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(value.base)
	return string(body), err
}

// A resource request installs constructor descriptions, not a live workset.
// Native connection/task leases alone decide which senders are materialized.
func resourceRequest(value runtimeResourceSource) (map[string]any, error) {
	tags := make([]string, 0, len(value.outbounds))
	for tag := range value.outbounds {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	outbounds := make([]any, 0, len(tags))
	for _, tag := range tags {
		outbounds = append(outbounds, value.outbounds[tag])
	}
	forwarding := map[string]any{}
	for tag, descriptor := range value.forwarding {
		forwarding[tag] = descriptor
	}
	request := map[string]any{"outbounds": outbounds, "forwarding": forwarding}
	if value.wireguard != nil {
		request["wireguard"] = map[string]any{"tag": "wg-shared", "source_routes": value.wireguard["source_routes"], "peers": value.wireguard["peers"]}
		// The definition is stable before and after the actual facility exists.
		// Existing receiving endpoints never acquire a sender initializer.
		if value.wireguard["execution"] == nil {
			initializer := map[string]any{}
			for key, item := range value.wireguard {
				if key != "tag" && key != "type" {
					initializer[key] = item
				}
			}
			initializer["source_routes"], initializer["peers"] = []any{}, []any{}
			request["wireguard"].(map[string]any)["initializer"] = initializer
		}
	}
	return request, nil
}

func currentResourceRequest(value runtimeResourceSource, auth map[string]string) (map[string]any, string, error) {
	request, err := resourceRequest(value)
	if err != nil {
		return nil, "", err
	}
	request["authorization_revisions"] = auth
	body, err := json.Marshal(request)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(body)
	return request, "sha256:" + hex.EncodeToString(sum[:]), nil
}

func describedResourceHashes(value runtimeResourceSource) (map[string]string, error) {
	result := make(map[string]string, len(value.outbounds))
	for tag, descriptor := range value.outbounds {
		hash, err := permissionProjectionHash(descriptor)
		if err != nil {
			return nil, err
		}
		result[tag] = hash
	}
	return result, nil
}

func forwardingResourceHashes(value runtimeResourceSource) (map[string]string, error) {
	result := make(map[string]string, len(value.forwarding))
	for tag, descriptor := range value.forwarding {
		hash, err := permissionProjectionHash(descriptor)
		if err != nil {
			return nil, err
		}
		result[tag] = hash
	}
	return result, nil
}

type resourceReadback struct {
	Revision               string            `json:"revision"`
	AuthorizationRevisions map[string]string `json:"authorization_revisions"`
	DesiredConfigHash      string            `json:"desired_config_hash"`
	ConfigHash             string            `json:"config_hash"`
	Outbounds              map[string]string `json:"outbounds"`
	DescribedOutbounds     map[string]string `json:"described_outbounds"`
	Forwarding             map[string]string `json:"forwarding"`
	WireGuard              bool              `json:"wireguard"`
}

func decodeResourceReadback(body []byte) (resourceReadback, error) {
	var value resourceReadback
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || decoder.Decode(new(any)) != io.EOF || !validSnapshotRevision(value.Revision) ||
		value.AuthorizationRevisions == nil || value.Outbounds == nil || value.DescribedOutbounds == nil || value.Forwarding == nil {
		return value, errors.New("incomplete native resource readback")
	}
	for _, hash := range []string{value.ConfigHash, value.DesiredConfigHash} {
		if hash != "" && control.ValidateDigest(hash) != nil {
			return value, errors.New("invalid native resource description hash")
		}
	}
	for _, hashes := range []map[string]string{value.Outbounds, value.DescribedOutbounds, value.Forwarding} {
		for tag, hash := range hashes {
			if tag == "" || control.ValidateDigest(hash) != nil {
				return value, errors.New("invalid native resource item hash")
			}
		}
	}
	for scope, revision := range value.AuthorizationRevisions {
		if scope == "" || !validSnapshotRevision(revision) {
			return value, errors.New("invalid native resource authorization revision")
		}
	}
	return value, nil
}

// ReconcileRuntimeResources installs the complete current legal descriptions.
// Missing unused objects are neither pending nor proof of a network failure.
func (selector *HTTPSelector) ReconcileRuntimeResources(ctx context.Context, source string) (bool, error) {
	value, err := decodeRuntimeResources(source)
	if err != nil {
		return false, err
	}
	return selector.reconcileRuntimeResources(ctx, value)
}

func (selector *HTTPSelector) reconcileRuntimeResources(ctx context.Context, value runtimeResourceSource) (bool, error) {
	body, err := selector.request(ctx, http.MethodGet, "/loom/resources", nil)
	if err != nil {
		return false, err
	}
	previous, err := decodeResourceReadback(body)
	if err != nil {
		return false, err
	}
	auth, err := selector.readRuntimePermissions(ctx, value.source)
	if err != nil {
		return false, err
	}
	request, hash, err := currentResourceRequest(value, auth)
	if err != nil {
		return false, err
	}
	forwarding, err := forwardingResourceHashes(value)
	if err != nil {
		return false, err
	}
	described, err := describedResourceHashes(value)
	if err != nil {
		return false, err
	}
	matches := func(state resourceReadback) bool {
		return state.ConfigHash == hash && state.DesiredConfigHash == hash && reflect.DeepEqual(state.AuthorizationRevisions, auth) &&
			reflect.DeepEqual(state.Forwarding, forwarding) && reflect.DeepEqual(state.DescribedOutbounds, described)
	}
	if matches(previous) {
		return true, nil
	}
	request["expected_revision"] = previous.Revision
	payload, err := json.Marshal(request)
	if err != nil {
		return false, err
	}
	body, err = selector.request(ctx, http.MethodPut, "/loom/resources", payload)
	if err != nil {
		return false, err
	}
	applied, err := decodeResourceReadback(body)
	if err != nil {
		return false, err
	}
	if !matches(applied) {
		return false, ErrSelectionSuperseded
	}
	body, err = selector.request(ctx, http.MethodGet, "/loom/resources", nil)
	if err != nil {
		return false, err
	}
	current, err := decodeResourceReadback(body)
	if err != nil {
		return false, err
	}
	return current.Revision == applied.Revision && matches(current), nil
}

// RuntimePermissionProjections are complete current authorization snapshots.
// WG peers/routes/listener are facilities and are not resent as authorization.
func RuntimePermissionProjections(config string) ([]ReceiverChange, error) {
	var document map[string]any
	if json.Unmarshal([]byte(config), &document) != nil {
		return nil, errors.New("invalid runtime authorization source")
	}
	result := []ReceiverChange{}
	seen := map[string]bool{}
	for _, section := range []string{"outbounds", "inbounds", "endpoints"} {
		entries, _ := document[section].([]any)
		for _, raw := range entries {
			entry, ok := raw.(map[string]any)
			if !ok {
				return nil, errors.New("invalid runtime permission entry")
			}
			tag, _ := entry["tag"].(string)
			projection := map[string]any{}
			if access, ok := entry["access"]; ok {
				if err := validateAccessMemberReferences(entry); err != nil {
					return nil, err
				}
				projection["access"] = access
			} else if execution, ok := entry["execution"]; ok && section != "outbounds" {
				projection["execution"] = execution
				if entry["type"] == "hysteria2" {
					users, ok := entry["users"].([]any)
					if !ok {
						return nil, errors.New("Hy2 receiving users missing")
					}
					projection["hysteria2_users"] = users
				} else if entry["type"] != "wireguard" {
					return nil, errors.New("unsupported native receiver")
				}
			} else {
				continue
			}
			if tag == "" || seen[tag] {
				return nil, errors.New("ambiguous native permission scope")
			}
			seen[tag] = true
			result = append(result, ReceiverChange{Tag: tag, Projection: projection})
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Tag < result[j].Tag })
	return result, nil
}

func stripPoolBase(value *runtimeResourceSource) (map[string]map[string]any, error) {
	pure := map[string]map[string]any{}
	endpoints, _ := value.base["endpoints"].([]any)
	kept := []any{}
	for _, raw := range endpoints {
		entry := raw.(map[string]any)
		if entry["type"] == "wireguard" && entry["execution"] == nil {
			tag, _ := entry["tag"].(string)
			if entry["system"] != false || entry["listen_port"] != nil || entry["name"] != nil || entry["host_sources"] != nil || entry["stack_address"] != nil {
				return nil, errors.New("pool cannot change a host or listening WG endpoint")
			}
			pure[tag] = entry
		} else {
			kept = append(kept, entry)
		}
	}
	if len(kept) == 0 {
		delete(value.base, "endpoints")
	} else {
		value.base["endpoints"] = kept
	}
	_, err := receiverProjections(value.base)
	return pure, err
}

// RuntimePermissionChanges permits sender additions/removals without treating
// them as a reason to replace the shared process. Real capture/listener/host
// changes remain explicit unsupported facility changes.
func RuntimePermissionChanges(before, after string) ([]ReceiverChange, bool, error) {
	a, err := decodeRuntimeResources(before)
	if err != nil {
		return nil, false, err
	}
	b, err := decodeRuntimeResources(after)
	if err != nil {
		return nil, false, err
	}
	old, err := RuntimePermissionProjections(before)
	if err != nil {
		return nil, false, err
	}
	next, err := RuntimePermissionProjections(after)
	if err != nil {
		return nil, false, err
	}
	pa, err := stripPoolBase(&a)
	if err != nil {
		return nil, false, err
	}
	pb, err := stripPoolBase(&b)
	if err != nil {
		return nil, false, err
	}
	for tag, previous := range pa {
		if current, ok := pb[tag]; ok && !reflect.DeepEqual(previous, current) {
			return nil, false, nil
		}
	}
	if !reflect.DeepEqual(a.base, b.base) || len(old) != len(next) {
		return nil, false, nil
	}
	byTag := map[string]map[string]any{}
	for _, item := range old {
		byTag[item.Tag] = item.Projection
	}
	changes := []ReceiverChange{}
	for _, item := range next {
		previous, exists := byTag[item.Tag]
		if !exists {
			return nil, false, nil
		}
		if !reflect.DeepEqual(previous, item.Projection) {
			changes = append(changes, item)
		}
	}
	return changes, true, nil
}

// WithRuntimePermissions updates only permission values in the prepared local
// configuration. A not-yet-created sender is never fabricated as running here.
func WithRuntimePermissions(config string, changes []ReceiverChange) (string, error) {
	var document map[string]any
	if json.Unmarshal([]byte(config), &document) != nil {
		return "", errors.New("invalid prepared runtime")
	}
	pending := map[string]map[string]any{}
	for _, change := range changes {
		if pending[change.Tag] != nil {
			return "", errors.New("duplicate permission scope")
		}
		pending[change.Tag] = change.Projection
	}
	for _, section := range []string{"outbounds", "inbounds", "endpoints"} {
		entries, _ := document[section].([]any)
		for _, raw := range entries {
			entry := raw.(map[string]any)
			tag, _ := entry["tag"].(string)
			p, ok := pending[tag]
			if !ok {
				continue
			}
			if access, ok := p["access"]; ok && entry["access"] != nil && len(p) == 1 {
				members, err := accessMemberReferences(access)
				if err != nil {
					return "", err
				}
				entry["access"], entry["outbounds"] = access, members
			} else if execution, ok := p["execution"]; ok && entry["execution"] != nil {
				entry["execution"] = execution
				if users, ok := p["hysteria2_users"]; ok && entry["type"] == "hysteria2" && len(p) == 2 {
					entry["users"] = users
				} else if entry["type"] != "wireguard" || len(p) != 1 {
					return "", errors.New("permission changed receiving facility")
				}
			} else {
				return "", errors.New("permission scope missing in prepared runtime")
			}
			delete(pending, tag)
		}
	}
	if len(pending) != 0 {
		return "", errors.New("permission scope missing in prepared runtime")
	}
	body, err := json.Marshal(document)
	return string(body), err
}

// ApplyRuntimeAuthorization always confirms the complete accepted permission
// first. A resource-only failure is represented independently by the caller.
func ApplyRuntimeAuthorization(ctx context.Context, before, after, running string) (RuntimeApplication, error) {
	selector, err := NewHTTPSelector(running)
	if err != nil {
		return RuntimeApplication{Config: running}, err
	}
	return selector.ApplyRuntimeAuthorization(ctx, before, after, running)
}

func (selector *HTTPSelector) ApplyRuntimeAuthorization(ctx context.Context, before, after, running string) (RuntimeApplication, error) {
	result := RuntimeApplication{Config: running}
	changes, hot, err := RuntimePermissionChanges(before, after)
	if err != nil || !hot {
		return result, err
	}
	result.Supported = true
	next, err := WithRuntimePermissions(running, changes)
	if err != nil {
		return result, err
	}
	next, err = WithRuntimeResourceDescriptions(next, after)
	if err != nil {
		return result, err
	}
	if err = selector.ApplyRuntimePermissions(ctx, after); err != nil {
		return result, err
	}
	result.PermissionCurrent = true
	result.Config = next
	body, err := selector.request(ctx, http.MethodGet, "/loom/resources", nil)
	if err == nil {
		state, decodeErr := decodeResourceReadback(body)
		if decodeErr == nil {
			value, sourceErr := decodeRuntimeResources(after)
			if sourceErr == nil {
				_, hash, requestErr := currentResourceRequest(value, state.AuthorizationRevisions)
				forwarding, hashErr := forwardingResourceHashes(value)
				described, describedErr := describedResourceHashes(value)
				result.ResourcesReady = requestErr == nil && hashErr == nil && describedErr == nil && state.ConfigHash == hash && state.DesiredConfigHash == hash && reflect.DeepEqual(state.Forwarding, forwarding) && reflect.DeepEqual(state.DescribedOutbounds, described)
			}
		}
	}
	return result, nil
}

func (selector *HTTPSelector) SetResourceSource(source string) error {
	value, err := decodeRuntimeResources(source)
	if err != nil {
		return err
	}
	selector.resourceSource.Store(&value)
	return nil
}

func (selector *HTTPSelector) confirmSelectionDescriptions(ctx context.Context, desired clientmodel.Selection) error {
	source := selector.resourceSource.Load()
	if source == nil || desired.CandidateID == "reject" {
		return nil
	}
	entries := map[string]any{}
	for _, raw := range source.base["outbounds"].([]any) {
		entry := raw.(map[string]any)
		if entry["tag"] == desired.Scope {
			access, _ := entry["access"].(map[string]any)
			entries, _ = access["entries"].(map[string]any)
			break
		}
	}
	ids := map[string]bool{desired.CandidateID: true}
	for _, id := range desired.Targets {
		ids[id] = true
	}
	for id := range ids {
		choice, ok := desired.Choices[id]
		if !ok {
			return errors.New("selected route choice missing")
		}
		if choice.FirstResourceID == "" {
			continue
		}
		entry, ok := entries[choice.FirstResourceID].(map[string]any)
		if !ok {
			return errors.New("selected resource missing current source permission")
		}
		tag, _ := entry["outbound"].(string)
		if source.outbounds[tag] == nil {
			return errors.New("selected sender description missing")
		}
	}
	ready, err := selector.reconcileRuntimeResources(ctx, *source)
	if err != nil {
		if ctx.Err() != nil || errors.Is(err, ErrSelectionSuperseded) {
			return err
		}
		return errors.Join(ErrResourcesNotReady, err)
	}
	if !ready {
		return ErrResourcesNotReady
	}
	return nil
}

var ErrResourcesNotReady = errors.New("current native resource descriptions are not confirmed")

// PrepareSelectionResources confirms the descriptions and permissions used by
// the existing Android preflight. Only native CAS confirms the actual selection.
func (selector *HTTPSelector) PrepareSelectionResources(ctx context.Context, desired clientmodel.Selection) (bool, error) {
	if err := clientmodel.ValidateAccessSelection(desired); err != nil {
		return false, err
	}
	err := selector.confirmSelectionDescriptions(ctx, desired)
	return err == nil, err
}

// WithRuntimeResourceDescriptions carries the current disposable sender input
// beside already-prepared host inputs. Descriptions do not prove materialized
// objects; the independent native pool readback remains the only completion.
func WithRuntimeResourceDescriptions(running, source string) (string, error) {
	current, err := decodeRuntimeResources(source)
	if err != nil {
		return "", err
	}
	var document map[string]any
	if json.Unmarshal([]byte(running), &document) != nil {
		return "", errors.New("invalid prepared runtime")
	}
	outbounds, _ := document["outbounds"].([]any)
	kept := make([]any, 0, len(outbounds)+len(current.outbounds))
	for _, raw := range outbounds {
		entry, ok := raw.(map[string]any)
		if !ok {
			return "", errors.New("invalid prepared outbound")
		}
		_, forward, err := forwardingResource(entry)
		if err != nil {
			return "", err
		}
		if !senderResource(entry) && !forward {
			kept = append(kept, entry)
		}
	}
	tags := make([]string, 0, len(current.outbounds))
	for tag := range current.outbounds {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	for _, tag := range tags {
		kept = append(kept, current.outbounds[tag])
	}
	tags = tags[:0]
	for tag := range current.forwarding {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	for _, tag := range tags {
		kept = append(kept, forwardingContainer(tag, current.forwarding[tag]))
	}
	document["outbounds"] = kept
	endpoints, _ := document["endpoints"].([]any)
	found := false
	for _, raw := range endpoints {
		entry := raw.(map[string]any)
		if entry["type"] != "wireguard" || entry["tag"] != "wg-shared" {
			continue
		}
		found = true
		if current.wireguard == nil {
			continue
		}
		entry["source_routes"], entry["peers"] = current.wireguard["source_routes"], current.wireguard["peers"]
	}
	if !found && current.wireguard != nil {
		endpoints = append(endpoints, current.wireguard)
		document["endpoints"] = endpoints
	}
	body, err := json.Marshal(document)
	return string(body), err
}

func permissionProjectionHash(value map[string]any) (string, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// Both hashes describe current operations on the same complete permission.
// A current WG listener operation includes its exact protected local port; no
// historical port or unrelated transport projection qualifies this authority.
func runtimePermissionHashes(source string, permission ReceiverChange) ([]string, error) {
	hash, err := permissionProjectionHash(permission.Projection)
	if err != nil {
		return nil, err
	}
	hashes := []string{hash}
	if permission.Projection["execution"] == nil || len(permission.Projection) != 1 {
		return hashes, nil
	}
	var document map[string]any
	if json.Unmarshal([]byte(source), &document) != nil {
		return nil, errors.New("invalid permission source")
	}
	endpoints, _ := document["endpoints"].([]any)
	for _, raw := range endpoints {
		entry := raw.(map[string]any)
		if entry["tag"] != permission.Tag || entry["type"] != "wireguard" {
			continue
		}
		port, ok := entry["listen_port"].(float64)
		if !ok || port < 1 || port > 65535 || port != float64(uint16(port)) {
			return nil, errors.New("managed WG listener port missing")
		}
		hash, err := permissionProjectionHash(map[string]any{"execution": permission.Projection["execution"], "wireguard_listener": map[string]any{"port": port}})
		if err != nil {
			return nil, err
		}
		hashes = append(hashes, hash)
	}
	return hashes, nil
}

func (selector *HTTPSelector) readRuntimePermissions(ctx context.Context, source string) (map[string]string, error) {
	permissions, err := RuntimePermissionProjections(source)
	if err != nil {
		return nil, err
	}
	result := map[string]string{}
	for _, permission := range permissions {
		prefix := "/loom/receivers/"
		if permission.Projection["access"] != nil {
			prefix = "/loom/access/"
		}
		body, err := selector.request(ctx, http.MethodGet, prefix+url.PathEscape(permission.Tag), nil)
		if err != nil {
			return nil, err
		}
		state, err := decodeReceiverReadback(body)
		if err != nil {
			return nil, err
		}
		allowed, err := runtimePermissionHashes(source, permission)
		if err != nil {
			return nil, err
		}
		if !slices.Contains(allowed, state.ConfigHash) {
			return nil, ErrSelectionSuperseded
		}
		result[permission.Tag] = state.Revision
	}
	return result, nil
}

func (selector *HTTPSelector) ConfirmRuntimePermissions(ctx context.Context, source string) error {
	_, err := selector.readRuntimePermissions(ctx, source)
	return err
}

func (selector *HTTPSelector) ApplyRuntimePermissions(ctx context.Context, source string) error {
	permissions, err := RuntimePermissionProjections(source)
	if err != nil {
		return err
	}
	for _, permission := range permissions {
		prefix := "/loom/receivers/"
		if permission.Projection["access"] != nil {
			prefix = "/loom/access/"
		}
		body, err := selector.request(ctx, http.MethodGet, prefix+url.PathEscape(permission.Tag), nil)
		if err != nil {
			return err
		}
		state, err := decodeReceiverReadback(body)
		if err != nil {
			return err
		}
		hashes, err := runtimePermissionHashes(source, permission)
		if err != nil {
			return err
		}
		if slices.Contains(hashes, state.ConfigHash) {
			continue
		}
		if err := selector.ApplyReceiverChanges(ctx, []ReceiverChange{permission}); err != nil {
			return err
		}
	}
	return selector.ConfirmRuntimePermissions(ctx, source)
}
