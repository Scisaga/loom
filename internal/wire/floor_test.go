package wire

import "testing"

func floorAt(recovery, control, revision, device int64) ClientFloorsV2 {
	hash := HashRaw("floor-test", []byte("same"))
	return ClientFloorsV2{Schema: 2, ClusterID: "cluster", AcceptedRecoveryEpoch: recovery, RecoveryStatementHash: hash, RecoveryPolicyHash: hash, AcceptedControlEpoch: control, ControlSetHash: hash, AcceptedControlRevision: revision, HeadHash: hash, DeviceGeneration: device, DeviceLeafHash: hash, DeviceViewHash: hash, BootstrapTransitionHash: hash, V2Latched: true}
}

func TestFloorsRejectRollbackForkAndRecoverySkip(t *testing.T) {
	current := floorAt(1, 2, 3, 4)
	for name, mutate := range map[string]func(*ClientFloorsV2){
		"recovery rollback": func(f *ClientFloorsV2) { f.AcceptedRecoveryEpoch = 0 },
		"recovery skip":     func(f *ClientFloorsV2) { f.AcceptedRecoveryEpoch = 3 },
		"control rollback":  func(f *ClientFloorsV2) { f.AcceptedControlEpoch = 1 },
		"revision fork":     func(f *ClientFloorsV2) { f.HeadHash = EmptyHashV1 },
		"device rollback":   func(f *ClientFloorsV2) { f.DeviceGeneration = 3 },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := current
			mutate(&candidate)
			if _, err := AdvanceFloors(current, candidate); err == nil {
				t.Fatal("invalid floor accepted")
			}
		})
	}
}
