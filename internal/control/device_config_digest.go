package control

const DeviceConfigDigestHeader = "Loom-Config-Digest"

// DeviceConfigurationDigest is a disposable transport comparison of an already
// verified envelope. Member signatures can differ for the same certified state;
// the complete proof, frontier and signed View digest must still match.
func DeviceConfigurationDigest(envelope DeviceViewEnvelope) (string, error) {
	return digestContractValue("loom-device-config-digest-v3\x00", map[string]any{
		"schema": envelope.Schema, "network_id": envelope.NetworkID, "genesis_digest": envelope.GenesisDigest,
		"control_proof": envelope.ControlProof, "fact_frontier": envelope.FactFrontier, "view_digest": envelope.ViewDigest,
	})
}
