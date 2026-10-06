package control

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net"
	"sort"
	"strconv"
)

// LinkProbeCredential is a disposable private View projection. It authorizes
// Hy2 authentication only; it never supplies a forwarding ACL or an identity.
type LinkProbeCredential struct {
	LinkID     string `json:"link_id"`
	Credential string `json:"credential"`
}

func (value LinkProbeCredential) Validate() error {
	if ValidateID(value.LinkID) != nil || ValidatePublicKey(value.Credential) != nil {
		return errors.New("Link probe credential is invalid")
	}
	return nil
}

func LinkProbeUser(value LinkProbeCredential) (string, error) {
	if err := value.Validate(); err != nil {
		return "", err
	}
	return digestContractValue("loom-link-probe-user-v3\x00", map[string]string{"link_id": value.LinkID})
}

func deriveLinkProbeCredential(network string, source DeviceAuthorization, link NetworkLink, target TransportResource) (LinkProbeCredential, error) {
	root, err := base64.RawURLEncoding.DecodeString(source.RuntimeKey)
	if err != nil || len(root) != 32 || source.ID != link.FromNodeID || target.ID != link.ProbeTarget.ResourceID || target.OwnerNodeID != link.ToNodeID {
		clear(root)
		return LinkProbeCredential{}, errors.New("Link probe derivation has invalid identities or key")
	}
	defer clear(root)
	auth, err := digestContractValue("loom-resource-auth-v3\x00", target.Authentication)
	if err != nil {
		return LinkProbeCredential{}, err
	}
	info, err := CanonicalEncode(map[string]string{"network_id": network, "device_id": source.ID, "link_id": link.ID,
		"resource_id": target.ID, "resource_auth_digest": auth, "receiver_node_id": target.OwnerNodeID, "purpose": "link-probe-auth"})
	if err != nil {
		return LinkProbeCredential{}, err
	}
	key, err := hkdf.Key(sha256.New, root, []byte("loom-runtime-key-v3\x00"), string(info), 32)
	if err != nil {
		return LinkProbeCredential{}, err
	}
	defer clear(key)
	return LinkProbeCredential{LinkID: link.ID, Credential: base64.RawURLEncoding.EncodeToString(key)}, nil
}

// LinkSpecDigest binds all three resources, including the source WG identity.
// It does not modify stable Link IDs or existing Service candidate digests.
func LinkSpecDigest(view DeviceView, linkID string) (string, error) {
	resources := map[string]TransportResource{}
	for _, resource := range view.Resources {
		resources[resource.ID] = resource
	}
	for _, link := range view.Links {
		if link.ID != linkID {
			continue
		}
		from, to, target, err := linkResources(link, resources)
		if err != nil {
			return "", err
		}
		values := []TransportResource{from, to, target}
		sort.Slice(values, func(i, j int) bool { return values[i].ID < values[j].ID })
		return digestContractValue("loom-link-spec-v3\x00", map[string]any{"link": link, "resources": values})
	}
	return "", errors.New("Link observation has no current Link")
}

func validateLinkProbeCredentials(view DeviceView, passwords map[string]bool) error {
	if view.LinkProbeCredentials != nil && len(view.LinkProbeCredentials) == 0 {
		return errors.New("empty Link probe credentials must be omitted")
	}
	links := map[string]NetworkLink{}
	for _, link := range view.Links {
		links[link.ID] = link
	}
	for i, value := range view.LinkProbeCredentials {
		link, found := links[value.LinkID]
		if value.Validate() != nil || i > 0 && view.LinkProbeCredentials[i-1].LinkID >= value.LinkID || !found ||
			view.DeviceID != link.FromNodeID && view.DeviceID != link.ToNodeID {
			return errors.New("Link probe credential is outside this node's Link ownership")
		}
		key := link.ProbeTarget.ResourceID + "\x00" + value.Credential
		if passwords[key] {
			return errors.New("Link probe password duplicates another transport permission")
		}
		passwords[key] = true
	}
	return nil
}

func verifyLinkObservation(value Observation, view DeviceView) error {
	for _, permission := range view.LinkProbeCredentials {
		if permission.LinkID != value.LinkID {
			continue
		}
		for _, link := range view.Links {
			if link.ID != value.LinkID || link.FromNodeID != view.DeviceID {
				continue
			}
			digest, err := LinkSpecDigest(view, link.ID)
			if err == nil && value.ResourceID == link.ResourceID && value.SpecDigest == digest &&
				value.Target == net.JoinHostPort(link.ProbeTarget.Host, strconv.Itoa(link.ProbeTarget.Port)) && value.Action == link.ProbeTarget.Action {
				return nil
			}
		}
	}
	return errors.New("Link observation is outside the source's current probe specification")
}
