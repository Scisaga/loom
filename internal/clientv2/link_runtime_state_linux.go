//go:build linux

package clientv2

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"loom/internal/wire"
)

const (
	maximumLinuxLinkRuntimeStateBytes = 16 << 20
	domainLinuxLinkRuntimePlan        = "loom-linux-link-runtime-plan-v1"
)

type LinuxEndpointGenerationFloorV1 struct {
	EndpointID                string `json:"endpoint_id"`
	MinimumListenerGeneration int64  `json:"minimum_listener_generation"`
}

type LinuxLinkRuntimeStateV1 struct {
	Schema           int                              `json:"schema"`
	ClusterID        string                           `json:"cluster_id"`
	DeviceID         string                           `json:"device_id"`
	AuthorityFloors  wire.ClientFloorsV2              `json:"authority_floors"`
	PlanHash         string                           `json:"plan_hash"`
	Plan             LinuxLinkRuntimePlanV1           `json:"plan"`
	GenerationFloors []LinuxEndpointGenerationFloorV1 `json:"generation_floors"`
}

// AcceptLinuxLinkRuntimePlan 要求输入 envelope 已经是 durable Device LKG 的
// exact 当前值，然后在同一独占锁内以旧 generation floors 生成并
// 原子提交新 runtime LKG。失败时旧 plan/floors 完全不变（D106、D120、D131）。
func AcceptLinuxLinkRuntimePlan(runtimeStatePath, deviceStatePath string,
	envelope *wire.DeviceViewEnvelopeV2, set, previousSet *wire.ControlSetV1,
	peerDirectory *wire.ControlPeerDirectoryPrivateObjectV1, artifactRaw []byte,
	now time.Time) (*LinuxLinkRuntimeStateV1, error) {
	if runtimeStatePath == "" || deviceStatePath == "" || runtimeStatePath == deviceStatePath ||
		!filepath.IsAbs(runtimeStatePath) || filepath.Clean(runtimeStatePath) != runtimeStatePath {
		return nil, errors.New("[D131 Linux runtime] runtime/device state path 无效")
	}
	if err := secureEnrollmentDirectory(filepath.Dir(runtimeStatePath)); err != nil {
		return nil, err
	}
	lock, err := openPrivateLock(runtimeStatePath + ".lock")
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		return nil, err
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)

	deviceStore, err := Open(deviceStatePath)
	if err != nil {
		return nil, err
	}
	trustedEnvelope := deviceStore.Envelope()
	if envelope == nil || trustedEnvelope == nil || !wire.EqualCanonical(*envelope, *trustedEnvelope) {
		return nil, errors.New("[D131 Linux runtime] candidate view 不是 durable Device LKG exact 当前值")
	}
	trustedSet, trustedPreviousSet := deviceStore.ControlSets()
	if trustedSet == nil {
		// 仅兼容旧 LKG；新 installation/sync 已把 authority 与 view 原子持久化。
		trustedSet, trustedPreviousSet = set, previousSet
	}
	if trustedSet == nil {
		return nil, errors.New("[D131 Linux runtime] durable ControlSet 缺失")
	}
	verifiedFloors, err := wire.VerifyDeviceViewEnvelopeWithPrevious(envelope, trustedSet, trustedPreviousSet)
	if err != nil || !wire.EqualCanonical(verifiedFloors, deviceStore.Floors()) {
		return nil, errors.New("[D131 Linux runtime] candidate authority/floors 与 durable Device LKG 不一致")
	}
	installation := deviceStore.Enrollment()
	if installation == nil {
		return nil, errors.New("[D124 Linux runtime] durable Device LKG 缺正式 enrollment installation")
	}

	current, err := readLinuxLinkRuntimeState(runtimeStatePath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	minimums := make(map[string]int64)
	if current != nil {
		for _, floor := range current.GenerationFloors {
			minimums[floor.EndpointID] = floor.MinimumListenerGeneration
		}
	}
	plan, err := BuildLinuxLinkRuntimePlan(envelope, trustedSet, trustedPreviousSet, peerDirectory, artifactRaw,
		installation.Credentials, now, minimums)
	if err != nil {
		return nil, err
	}
	mergeLinuxEndpointGenerationFloors(minimums, envelope.Payload.Active.EndpointBundle)
	generationFloors := make([]LinuxEndpointGenerationFloorV1, 0, len(minimums))
	for endpointID, generation := range minimums {
		generationFloors = append(generationFloors, LinuxEndpointGenerationFloorV1{
			EndpointID: endpointID, MinimumListenerGeneration: generation,
		})
	}
	sort.Slice(generationFloors, func(i, j int) bool {
		return generationFloors[i].EndpointID < generationFloors[j].EndpointID
	})
	planHash, err := wire.HashObject(domainLinuxLinkRuntimePlan, &plan)
	if err != nil {
		return nil, err
	}
	candidate := &LinuxLinkRuntimeStateV1{
		Schema: 1, ClusterID: envelope.Payload.ClusterID, DeviceID: envelope.Payload.DeviceID,
		AuthorityFloors: verifiedFloors, PlanHash: planHash, Plan: plan, GenerationFloors: generationFloors,
	}
	if current != nil {
		if err := validateLinuxRuntimeAuthorityAdvance(current.AuthorityFloors, candidate.AuthorityFloors); err != nil {
			return nil, err
		}
		for _, floor := range current.GenerationFloors {
			if minimums[floor.EndpointID] < floor.MinimumListenerGeneration {
				return nil, errors.New("[D120 Linux runtime] listener generation floor 回退")
			}
		}
		if wire.EqualCanonical(*current, *candidate) {
			return current, nil
		}
	}
	if err := validateLinuxLinkRuntimeState(candidate); err != nil {
		return nil, err
	}
	if err := persistProtectedCanonical(runtimeStatePath, candidate); err != nil {
		return nil, err
	}
	return readLinuxLinkRuntimeState(runtimeStatePath)
}

func LoadLinuxLinkRuntimeState(path string) (*LinuxLinkRuntimeStateV1, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("[D131 Linux runtime] runtime state path 无效")
	}
	if err := secureEnrollmentDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	lock, err := openPrivateLock(path + ".lock")
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_SH); err != nil {
		return nil, err
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	return readLinuxLinkRuntimeState(path)
}

func readLinuxLinkRuntimeState(path string) (*LinuxLinkRuntimeStateV1, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 ||
		info.Size() < 1 || info.Size() > maximumLinuxLinkRuntimeStateBytes {
		return nil, errors.New("[D131 Linux runtime] runtime LKG 必须是 0600 有界普通文件")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || int(stat.Uid) != os.Geteuid() {
		return nil, errors.New("[D131 Linux runtime] runtime LKG owner 不是当前服务账号")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var state LinuxLinkRuntimeStateV1
	canonical, err := wire.DecodeStrict(body, maximumLinuxLinkRuntimeStateBytes, &state)
	if err != nil || !bytes.Equal(canonical, body) {
		return nil, errors.New("[D131 Linux runtime] runtime LKG 不是 exact canonical wire")
	}
	if err := validateLinuxLinkRuntimeState(&state); err != nil {
		return nil, err
	}
	return &state, nil
}

func validateLinuxLinkRuntimeState(state *LinuxLinkRuntimeStateV1) error {
	if state == nil || state.Schema != 1 || state.ClusterID == "" || state.DeviceID == "" ||
		state.Plan.Schema != 1 || state.Plan.ClusterID != state.ClusterID || state.Plan.DeviceID != state.DeviceID ||
		state.Plan.Actions == nil || state.GenerationFloors == nil {
		return errors.New("[D131 Linux runtime] runtime LKG header/plan 无效")
	}
	planHash, err := wire.HashObject(domainLinuxLinkRuntimePlan, &state.Plan)
	if err != nil || planHash != state.PlanHash {
		return errors.New("[D131 Linux runtime] runtime plan hash 不匹配")
	}
	for index, floor := range state.GenerationFloors {
		if floor.EndpointID == "" || floor.MinimumListenerGeneration < 1 ||
			(index > 0 && state.GenerationFloors[index-1].EndpointID >= floor.EndpointID) {
			return errors.New("[D120 Linux runtime] generation floors 无效/未排序")
		}
	}
	if state.AuthorityFloors.ClusterID != state.ClusterID || !state.AuthorityFloors.V2Latched {
		return errors.New("[D106 Linux runtime] runtime authority floors 无效")
	}
	if _, err := wire.AdvanceFloors(wire.ClientFloorsV2{}, state.AuthorityFloors); err != nil {
		return errors.New("[D106 Linux runtime] runtime authority floors wire 无效")
	}
	return nil
}

func mergeLinuxEndpointGenerationFloors(floors map[string]int64, bundle wire.DeviceEndpointBundleV1) {
	for _, binding := range bundle.DataIngressSets {
		for _, endpoint := range binding.EndpointSet.Endpoints {
			maximum := floors[endpoint.EndpointID]
			for _, generation := range endpoint.ListenerGenerations {
				if generation.ListenerGeneration > maximum {
					maximum = generation.ListenerGeneration
				}
			}
			for _, tombstone := range endpoint.ListenerTombstones {
				if tombstone.ListenerGeneration > maximum {
					maximum = tombstone.ListenerGeneration
				}
			}
			if maximum > 0 {
				floors[endpoint.EndpointID] = maximum
			}
		}
	}
}

func validateLinuxRuntimeAuthorityAdvance(current, candidate wire.ClientFloorsV2) error {
	if current.ClusterID != candidate.ClusterID || current.BootstrapTransitionHash != candidate.BootstrapTransitionHash ||
		candidate.AcceptedRecoveryEpoch < current.AcceptedRecoveryEpoch ||
		candidate.DeviceGeneration < current.DeviceGeneration {
		return errors.New("[D106 Linux runtime] runtime authority/device floor 回退")
	}
	if candidate.AcceptedRecoveryEpoch == current.AcceptedRecoveryEpoch {
		if candidate.RecoveryStatementHash != current.RecoveryStatementHash ||
			candidate.RecoveryPolicyHash != current.RecoveryPolicyHash ||
			candidate.AcceptedControlEpoch < current.AcceptedControlEpoch {
			return errors.New("[D106 Linux runtime] runtime recovery/control authority 分叉或回退")
		}
		if candidate.AcceptedControlEpoch == current.AcceptedControlEpoch {
			if candidate.ControlSetHash != current.ControlSetHash ||
				candidate.AcceptedControlRevision < current.AcceptedControlRevision ||
				candidate.AcceptedControlRevision == current.AcceptedControlRevision && candidate.HeadHash != current.HeadHash {
				return errors.New("[D106 Linux runtime] runtime control Head 分叉或回退")
			}
		}
	}
	if candidate.DeviceGeneration == current.DeviceGeneration &&
		candidate.DeviceViewHash != current.DeviceViewHash {
		return errors.New("[D106 Linux runtime] runtime Device generation 同序号分叉")
	}
	return nil
}
