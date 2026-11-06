package control

import "errors"

// senderAuthenticationDigest fences an existing connection's authenticated
// resource identity. Dial coordinates and measurements do not revoke identity.
// This local projection never changes a signed View or measurement spec.
func senderAuthenticationDigest(view DeviceView, resource TransportResource, credential string) (string, error) {
	identity := map[string]any{"resource_id": resource.ID, "owner_node_id": resource.OwnerNodeID, "kind": resource.Kind, "sender_id": view.DeviceID}
	switch resource.Kind {
	case "wireguard":
		if resource.Authentication.PublicKey == nil || view.WireGuardPublicKey == "" {
			return "", errors.New("WG sender identity missing")
		}
		identity["receiver_public_key"], identity["sender_public_key"] = *resource.Authentication.PublicKey, view.WireGuardPublicKey
	case "hysteria2":
		if credential == "" {
			return "", errors.New("Hy2 sender credential missing")
		}
		digest, err := digestContractValue("loom-sender-credential-v3\x00", credential)
		if err != nil {
			return "", err
		}
		identity["credential_digest"] = digest
		identity["authentication"] = resource.Authentication
	default:
		return "", errors.New("unsupported sender identity")
	}
	return digestContractValue("loom-sender-authentication-v3\x00", identity)
}

func senderAuthenticationDigests(view DeviceExecution, credentials map[string]string) (map[string]string, error) {
	result := map[string]string{}
	self := viewNodes(view.DeviceView)[view.DeviceID]
	for _, resource := range view.Resources {
		if resource.OwnerNodeID == view.DeviceID || !senderMayAuthenticate(view, self, resource) {
			continue
		}
		tag, err := ForwardSegmentTag(resource.ID)
		if err != nil {
			return nil, err
		}
		digest, err := senderAuthenticationDigest(view.DeviceView, resource, credentials[resource.ID])
		if err != nil {
			return nil, err
		}
		result[tag] = digest
	}
	return result, nil
}
