package control

// A missing field in a management command means preserve the recorded key.
// Its signed result contains the complete value. Retrying the same request
// compares that meaning without storing a second command/receipt authority.
func withRequestedWireGuardRegistration(previous, requested Operation) Operation {
	want, ok := effectiveOperation(requested).Payload.(DevicePut)
	if !ok || want.WireGuardPublicKey != "" {
		return previous
	}
	have, ok := effectiveOperation(previous).Payload.(DevicePut)
	if !ok {
		return previous
	}
	have.WireGuardPublicKey = ""
	if value, ok := previous.Payload.(ConflictResolution); ok {
		value.Value = have
		previous.Payload = value
	} else {
		previous.Payload = have
	}
	return previous
}
