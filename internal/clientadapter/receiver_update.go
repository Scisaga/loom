package clientadapter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"sort"
)

// ReceiverChange is a disposable local-runtime projection from two already
// accepted configurations. It is never stored as another permission authority.
type ReceiverChange struct {
	Tag        string
	Projection map[string]any
}

// WithReceiverChanges keeps prepared host inputs (resolved website addresses,
// capture boundaries and local sockets). It applies the native permission and
// peer projections returned by ReceiverChanges, without performing I/O.
func WithReceiverChanges(config string, changes []ReceiverChange) (string, error) {
	var document map[string]any
	if err := json.Unmarshal([]byte(config), &document); err != nil {
		return "", err
	}
	pending := map[string]map[string]any{}
	for _, change := range changes {
		if change.Tag == "" || pending[change.Tag] != nil {
			return "", errors.New("ambiguous authorization update")
		}
		pending[change.Tag] = change.Projection
	}
	for _, section := range []string{"outbounds", "inbounds", "endpoints"} {
		entries, _ := document[section].([]any)
		for _, raw := range entries {
			entry, ok := raw.(map[string]any)
			if !ok {
				return "", errors.New("invalid runtime entry")
			}
			tag, _ := entry["tag"].(string)
			projection, found := pending[tag]
			if !found {
				continue
			}
			kind, _ := entry["type"].(string)
			if value, source := projection["access"]; source && section == "outbounds" && kind == "selector" && len(projection) == 1 && entry["access"] != nil {
				if err := validateAccessMemberReferences(entry); err != nil {
					return "", err
				}
				members, err := accessMemberReferences(value)
				if err != nil {
					return "", err
				}
				entry["access"] = value
				entry["outbounds"] = members
			} else if peers, wg := projection["wireguard_peers"]; wg && section == "endpoints" && kind == "wireguard" {
				execution, receiver := projection["execution"]
				fields := 1
				if receiver {
					fields++
					listener, ok := projection["wireguard_listener"].(map[string]any)
					if !ok || len(listener) != 1 || listener["port"] == nil {
						return "", errors.New("WG update omitted its local listener port")
					}
					entry["listen_port"] = listener["port"]
					fields++
				}
				if receiver != (entry["execution"] != nil) || len(projection) != fields {
					return "", errors.New("WG update changed its receiving scope")
				}
				entry["peers"] = peers
				if receiver {
					entry["execution"] = execution
				}
			} else if execution, receiver := projection["execution"]; receiver && entry["execution"] != nil && len(projection) == 2 && section == "inbounds" && kind == "hysteria2" {
				users, hy2 := projection["hysteria2_users"]
				if !hy2 {
					return "", errors.New("authorization update changed transport facility")
				}
				entry["users"], entry["execution"] = users, execution
			} else {
				return "", errors.New("authorization update does not match its native entry")
			}
			delete(pending, tag)
		}
	}
	if len(pending) != 0 {
		return "", errors.New("authorization update names an absent native entry")
	}
	body, err := json.Marshal(document)
	return string(body), err
}

// The member list is a reference table derived from the same source permission
// snapshot. It grants nothing and is not part of the native access update wire.
func accessMemberReferences(value any) ([]any, error) {
	access, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("invalid native access projection")
	}
	set := map[string]bool{"reject": true}
	for _, field := range []string{"entries", "egress_outbounds", "forward_outbounds"} {
		raw, exists := access[field]
		if !exists {
			return nil, errors.New("access outbound references are incomplete")
		}
		values, ok := raw.(map[string]any)
		if !ok {
			return nil, errors.New("invalid access outbound references")
		}
		for _, raw := range values {
			if field == "entries" {
				entry, ok := raw.(map[string]any)
				if !ok {
					return nil, errors.New("invalid access transport reference")
				}
				raw = entry["outbound"]
			}
			tag, ok := raw.(string)
			if !ok || tag == "" {
				return nil, errors.New("invalid access outbound reference")
			}
			set[tag] = true
		}
	}
	tags := make([]string, 0, len(set))
	for tag := range set {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	members := make([]any, len(tags))
	for index, tag := range tags {
		members[index] = tag
	}
	return members, nil
}

func validateAccessMemberReferences(entry map[string]any) error {
	members, err := accessMemberReferences(entry["access"])
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(entry["outbounds"], members) {
		return errors.New("access member references differ from its permission projection")
	}
	return nil
}

func receiverProjections(document map[string]any) (map[string]map[string]any, error) {
	projections := map[string]map[string]any{}
	for _, section := range []string{"endpoints", "inbounds"} {
		entries, _ := document[section].([]any)
		for _, raw := range entries {
			entry, ok := raw.(map[string]any)
			if !ok {
				return nil, errors.New("invalid runtime receiving entry")
			}
			execution, receiving := entry["execution"]
			kind, _ := entry["type"].(string)
			sourceRoutes, _ := entry["source_routes"].([]any)
			managedWG := section == "endpoints" && kind == "wireguard" && (receiving || len(sourceRoutes) > 0)
			if !receiving && !managedWG {
				continue
			}
			tag, _ := entry["tag"].(string)
			if tag == "" || projections[tag] != nil {
				return nil, errors.New("ambiguous receiving identity")
			}
			projection := map[string]any{}
			if receiving {
				projection["execution"] = execution
			}
			if managedWG {
				peers, ok := entry["peers"].([]any)
				if !ok {
					peers = []any{}
				}
				projection["wireguard_peers"] = peers
				delete(entry, "peers")
				if receiving {
					if entry["listen_port"] == nil {
						return nil, errors.New("WG receiver has no explicit local listener")
					}
					projection["wireguard_listener"] = map[string]any{"port": entry["listen_port"]}
					delete(entry, "listen_port")
				}
			} else if section == "inbounds" && kind == "hysteria2" {
				users, ok := entry["users"].([]any)
				if !ok {
					users = []any{}
				}
				projection["hysteria2_users"] = users
				delete(entry, "users")
			} else {
				return nil, errors.New("unsupported native receiver")
			}
			delete(entry, "execution")
			projections[tag] = projection
		}
	}
	outbounds, _ := document["outbounds"].([]any)
	for _, raw := range outbounds {
		entry, ok := raw.(map[string]any)
		if !ok {
			return nil, errors.New("invalid runtime outbound")
		}
		value, exists := entry["access"]
		if !exists {
			continue
		}
		tag, _ := entry["tag"].(string)
		if tag == "" || projections[tag] != nil {
			return nil, errors.New("ambiguous source authorization scope")
		}
		if err := validateAccessMemberReferences(entry); err != nil {
			return nil, err
		}
		projections[tag] = map[string]any{"access": value}
		delete(entry, "access")
		delete(entry, "outbounds")
	}
	return projections, nil
}

// ReceiverChanges derives semantic permission and WG peer updates. A sender-only
// WG endpoint needs no receiving grant. Unhandled component changes are reported
// to the caller, never disguised as admission or host ownership updates.
func ReceiverChanges(before, after string) ([]ReceiverChange, bool, error) {
	if before == "" || after == "" {
		return nil, before == after, nil
	}
	decode := func(config string) (map[string]any, error) {
		var v map[string]any
		err := json.Unmarshal([]byte(config), &v)
		return v, err
	}
	a, err := decode(before)
	if err != nil {
		return nil, false, err
	}
	b, err := decode(after)
	if err != nil {
		return nil, false, err
	}

	old, err := receiverProjections(a)
	if err != nil {
		return nil, false, err
	}
	next, err := receiverProjections(b)
	if err != nil {
		return nil, false, err
	}
	if !reflect.DeepEqual(a, b) || len(old) != len(next) {
		return nil, false, nil
	}
	changes := []ReceiverChange{}
	for tag, projection := range next {
		previous, exists := old[tag]
		if !exists {
			return nil, false, nil
		}
		if !reflect.DeepEqual(previous, projection) {
			changes = append(changes, ReceiverChange{tag, projection})
		}
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].Tag < changes[j].Tag })
	return changes, true, nil
}

type receiverReadback struct {
	Revision   string `json:"revision"`
	ConfigHash string `json:"config_hash"`
}

func decodeReceiverReadback(body []byte) (receiverReadback, error) {
	var value receiverReadback
	if json.Unmarshal(body, &value) != nil || !validSnapshotRevision(value.Revision) {
		return value, errors.New("incomplete receiving readback")
	}
	return value, nil
}
func (selector *HTTPSelector) ApplyReceiverChanges(ctx context.Context, changes []ReceiverChange) error {
	for _, change := range changes {
		prefix := "/loom/receivers/"
		if _, source := change.Projection["access"]; source {
			prefix = "/loom/access/"
		}
		path := prefix + url.PathEscape(change.Tag)
		body, err := selector.request(ctx, http.MethodGet, path, nil)
		if err != nil {
			return err
		}
		previous, err := decodeReceiverReadback(body)
		if err != nil {
			return err
		}
		projection, err := json.Marshal(change.Projection)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(projection)
		hash := "sha256:" + hex.EncodeToString(digest[:])
		if previous.ConfigHash == hash {
			continue
		}
		request := make(map[string]any, len(change.Projection)+1)
		for key, value := range change.Projection {
			request[key] = value
		}
		request["expected_revision"] = previous.Revision
		payload, err := json.Marshal(request)
		if err != nil {
			return err
		}
		body, err = selector.request(ctx, http.MethodPut, path, payload)
		if err != nil {
			return err
		}
		applied, err := decodeReceiverReadback(body)
		if err != nil {
			return err
		}
		if applied.Revision == previous.Revision || applied.ConfigHash != hash {
			return ErrSelectionSuperseded
		}
		body, err = selector.request(ctx, http.MethodGet, path, nil)
		if err != nil {
			return err
		}
		current, err := decodeReceiverReadback(body)
		if err != nil {
			return err
		}
		if current != applied {
			return ErrSelectionSuperseded
		}
	}
	return nil
}

// ReceivingProjections returns complete disposable native inputs for readback
// or a retry whose earlier write could not be confirmed. It adds no authority.
func ReceivingProjections(config string) ([]ReceiverChange, error) {
	var document map[string]any
	if err := json.Unmarshal([]byte(config), &document); err != nil {
		return nil, err
	}
	values, err := receiverProjections(document)
	if err != nil {
		return nil, err
	}
	changes := make([]ReceiverChange, 0, len(values))
	for tag, value := range values {
		changes = append(changes, ReceiverChange{Tag: tag, Projection: value})
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].Tag < changes[j].Tag })
	return changes, nil
}

// ConfirmReceiverChanges rereads the current native hashes. It never turns an
// interrupted PUT into success merely because the old snapshot is still known.
func (selector *HTTPSelector) ConfirmReceiverChanges(ctx context.Context, changes []ReceiverChange) error {
	for _, change := range changes {
		prefix := "/loom/receivers/"
		if _, source := change.Projection["access"]; source {
			prefix = "/loom/access/"
		}
		body, err := selector.request(ctx, http.MethodGet, prefix+url.PathEscape(change.Tag), nil)
		if err != nil {
			return err
		}
		current, err := decodeReceiverReadback(body)
		if err != nil {
			return err
		}
		projection, err := json.Marshal(change.Projection)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(projection)
		if current.ConfigHash != "sha256:"+hex.EncodeToString(digest[:]) {
			return ErrSelectionSuperseded
		}
	}
	return nil
}
