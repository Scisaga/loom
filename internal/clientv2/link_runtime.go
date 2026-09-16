package clientv2

import (
	"bytes"
	"errors"
	"time"

	"loom/internal/wire"
)

const LinuxLinkIntentArtifactID = wire.LinuxLinkIntentArtifactID

type LinuxLinkIntentArtifactV1 = wire.LinuxLinkIntentArtifactV1

type LinuxLinkDialCandidateV1 struct {
	EndpointID         string `json:"endpoint_id"`
	LogicalServerID    string `json:"logical_server_id"`
	Transport          string `json:"transport"`
	ListenerGeneration int64  `json:"listener_generation"`
	DialTargetFQDN     string `json:"dial_target_fqdn"`
	PeerAddress        string `json:"peer_address,omitempty"`
	PublicPort         int64  `json:"public_port"`
	PublishedState     string `json:"published_state"`
}

type LinuxLinkRuntimeActionV1 struct {
	LinkID               string                         `json:"link_id"`
	Generation           int64                          `json:"generation"`
	Purpose              string                         `json:"purpose"`
	Mode                 string                         `json:"mode"`
	Peer                 wire.LinkIntentDestinationV1   `json:"peer"`
	AllowedTransports    []string                       `json:"allowed_transports"`
	ListenerResourceRefs []string                       `json:"listener_resource_refs"`
	CredentialRefs       []string                       `json:"credential_refs"`
	RouteScope           string                         `json:"route_scope"`
	ResolveAtFinalEgress bool                           `json:"resolve_at_final_egress"`
	DialCandidates       []LinuxLinkDialCandidateV1     `json:"dial_candidates"`
	WireGuardPeer        *wire.LinuxWireGuardResourceV1 `json:"wireguard_peer,omitempty"`
}

type LinuxLinkRuntimePlanV1 struct {
	Schema              int                            `json:"schema"`
	ClusterID           string                         `json:"cluster_id"`
	DeviceID            string                         `json:"device_id"`
	DeviceGeneration    int64                          `json:"device_generation"`
	ArtifactGeneration  int64                          `json:"artifact_generation"`
	EnableTUN           bool                           `json:"enable_tun"`
	EnableMixed         bool                           `json:"enable_mixed"`
	ServeForward        bool                           `json:"serve_forward"`
	ServeInternetEgress bool                           `json:"serve_internet_egress"`
	CertifiedControl    bool                           `json:"certified_control"`
	ControlMemberID     string                         `json:"control_member_id,omitempty"`
	Actions             []LinuxLinkRuntimeActionV1     `json:"actions"`
	LocalWireGuardKey   *wire.LinuxLocalWireGuardKeyV1 `json:"local_wireguard_key,omitempty"`
}

// BuildLinuxLinkRuntimePlan 只把 current Device view 承诺的 exact artifact
// 转为本机运行计划。LinkIntent 不能通过本地参数、可拨端口或
// Device 自报职责产生；control 还必须存在于 Head 绑定的 private peer directory。
func BuildLinuxLinkRuntimePlan(envelope *wire.DeviceViewEnvelopeV2, set, previousSet *wire.ControlSetV1,
	peerDirectory *wire.ControlPeerDirectoryPrivateObjectV1, artifactRaw []byte,
	credentials []InstalledSecretV1, now time.Time,
	minimumGenerations map[string]int64) (LinuxLinkRuntimePlanV1, error) {
	if envelope == nil || set == nil || now.IsZero() {
		return LinuxLinkRuntimePlanV1{}, errors.New("[Linux runtime] view/ControlSet/time 缺失")
	}
	if _, err := wire.VerifyDeviceViewEnvelopeWithPrevious(envelope, set, previousSet); err != nil {
		return LinuxLinkRuntimePlanV1{}, err
	}
	if envelope.Payload.State != "active" || envelope.Payload.Active == nil {
		return LinuxLinkRuntimePlanV1{}, errors.New("[Linux runtime] tombstone Device 禁止生成新运行计划")
	}
	var artifact LinuxLinkIntentArtifactV1
	canonical, err := wire.DecodeStrict(artifactRaw, 4<<20, &artifact)
	if err != nil || !bytes.Equal(canonical, artifactRaw) {
		return LinuxLinkRuntimePlanV1{}, errors.New("[Linux runtime] LinkIntent artifact 不是 exact canonical wire")
	}
	if err := validateLinuxLinkIntentArtifact(&artifact, envelope); err != nil {
		return LinuxLinkRuntimePlanV1{}, err
	}
	if err := wire.VerifyConfigQCAuthority(artifact.AuthorityHeadHash, artifact.Authority.QC,
		&artifact.Authority.Head, set, previousSet); err != nil {
		return LinuxLinkRuntimePlanV1{}, err
	}
	if err := bindLinuxLinkIntentArtifactRef(&artifact, artifactRaw, envelope.Payload.Active.ConfigArtifactRefs); err != nil {
		return LinuxLinkRuntimePlanV1{}, err
	}

	responsibilities := envelope.Payload.Active.Responsibilities.Values
	plan := LinuxLinkRuntimePlanV1{
		Schema: 1, ClusterID: artifact.ClusterID, DeviceID: artifact.DeviceID,
		DeviceGeneration: artifact.DeviceGeneration, ArtifactGeneration: artifact.Generation,
		EnableTUN:           containsString(responsibilities, "use_loom"),
		EnableMixed:         containsString(responsibilities, "use_loom"),
		ServeForward:        containsString(responsibilities, "forward"),
		ServeInternetEgress: containsString(responsibilities, "internet_egress"),
		Actions:             []LinuxLinkRuntimeActionV1{},
		LocalWireGuardKey:   artifact.LocalWireGuardKey,
	}
	memberIDs, err := linuxCertifiedControlMembers(set, peerDirectory,
		envelope.SignedCurrent.Head.Body.Payload.ControlPeerDirectoryHash)
	if err != nil {
		return LinuxLinkRuntimePlanV1{}, err
	}
	if memberID, found := memberIDs[artifact.DeviceID]; found {
		plan.CertifiedControl, plan.ControlMemberID = true, memberID
	}
	credentialIDs := make(map[string]struct{}, len(credentials))
	if artifact.LocalWireGuardKey != nil {
		credentialIDs[artifact.LocalWireGuardKey.SecretID] = struct{}{}
	}
	for _, credential := range credentials {
		if credential.SecretID == "" {
			return LinuxLinkRuntimePlanV1{}, errors.New("[Linux runtime] installed credential ID 无效")
		}
		if _, duplicate := credentialIDs[credential.SecretID]; duplicate {
			return LinuxLinkRuntimePlanV1{}, errors.New("[Linux runtime] installed credential ID 重复")
		}
		credentialIDs[credential.SecretID] = struct{}{}
	}
	endpoints, err := linuxAuthorizedDataEndpoints(&envelope.Payload.Active.EndpointBundle)
	if err != nil {
		return LinuxLinkRuntimePlanV1{}, err
	}
	wireguard := make(map[string]wire.LinuxWireGuardResourceV1, len(artifact.WireGuardResources))
	for _, resource := range artifact.WireGuardResources {
		if _, collision := endpoints[resource.ResourceID]; collision {
			return LinuxLinkRuntimePlanV1{}, errors.New("[Linux runtime] private peer 资源与公开 endpoint ID 冲突")
		}
		wireguard[resource.ResourceID] = resource
	}
	for _, intent := range artifact.LinkIntents {
		for _, credentialRef := range intent.CredentialRefs {
			if _, found := credentialIDs[credentialRef]; !found {
				return LinuxLinkRuntimePlanV1{}, errors.New("[Linux runtime] LinkIntent 引用未安装 credential")
			}
		}
		touchesFrom := intent.FromDeviceID == artifact.DeviceID
		touchesTo := intent.To.DeviceID == artifact.DeviceID
		if !touchesFrom && !touchesTo {
			return LinuxLinkRuntimePlanV1{}, errors.New("[Linux runtime] artifact 含与本 Device 无关 LinkIntent")
		}
		mode := "listen"
		if intent.Initiator == "from" && touchesFrom || intent.Initiator == "to" && touchesTo {
			mode = "dial"
		}
		peer := intent.To
		if touchesTo {
			peer = wire.LinkIntentDestinationV1{DeviceID: intent.FromDeviceID}
		}
		action := LinuxLinkRuntimeActionV1{
			LinkID: intent.LinkID, Generation: intent.Generation, Purpose: intent.Purpose, Mode: mode,
			Peer: peer, AllowedTransports: append([]string(nil), intent.AllowedTransports...),
			ListenerResourceRefs: append([]string(nil), intent.ListenerResourceRefs...),
			CredentialRefs:       append([]string(nil), intent.CredentialRefs...), RouteScope: intent.RouteScope,
			DialCandidates: []LinuxLinkDialCandidateV1{},
		}
		if len(intent.ListenerResourceRefs) == 1 {
			if resource, found := wireguard[intent.ListenerResourceRefs[0]]; found {
				if resource.ListenerGeneration < minimumGenerations[resource.ResourceID] {
					return LinuxLinkRuntimePlanV1{}, errors.New("[Linux runtime] peer WireGuard listener 低于已见 generation")
				}
				action.WireGuardPeer = &resource
				if mode == "dial" {
					action.DialCandidates = append(action.DialCandidates, LinuxLinkDialCandidateV1{
						EndpointID: resource.ResourceID, LogicalServerID: resource.ListenerDeviceID, Transport: "wireguard",
						ListenerGeneration: resource.ListenerGeneration, PeerAddress: resource.EndpointAddress,
						PublicPort: resource.EndpointPort, PublishedState: "preferred"})
				}
			}
		}
		switch intent.Purpose {
		case "bootstrap":
			return LinuxLinkRuntimePlanV1{}, errors.New("[Linux runtime] active Device 禁止恢复 bootstrap LinkIntent")
		case "control_overlay":
			if !plan.CertifiedControl {
				return LinuxLinkRuntimePlanV1{}, errors.New("[Linux runtime] 非 certified ControlSet Device 不得运行 control LinkIntent")
			}
			_, fromFound := memberIDs[intent.FromDeviceID]
			_, toFound := memberIDs[intent.To.DeviceID]
			if !fromFound || !toFound {
				return LinuxLinkRuntimePlanV1{}, errors.New("[Linux runtime] control LinkIntent peer 不在 exact ControlSet directory")
			}
		case "data_forward":
			if touchesTo && !plan.ServeForward {
				return LinuxLinkRuntimePlanV1{}, errors.New("[Linux runtime] 未授权 forward 的 Device 不得监听 data edge")
			}
			if touchesFrom && !plan.ServeForward {
				if !plan.EnableTUN || !linuxDestinationGranted(envelope.Payload.Active.Grants, intent.To) {
					return LinuxLinkRuntimePlanV1{}, errors.New("[Linux runtime] use_loom data edge 缺 exact destination grant")
				}
			}
			action.ResolveAtFinalEgress = touchesFrom && linuxEgressGranted(envelope.Payload.Active.Grants, intent.To)
			if action.WireGuardPeer != nil {
				break
			}
			for _, endpointID := range intent.ListenerResourceRefs {
				endpoint, found := endpoints[endpointID]
				if !found || !containsString(intent.AllowedTransports, endpoint.Transport) {
					return LinuxLinkRuntimePlanV1{}, errors.New("[Linux runtime] LinkIntent listener 未绑定 Device view endpoint/transport")
				}
				if mode != "dial" {
					continue
				}
				floor := minimumGenerations[endpointID]
				if floor < 1 {
					floor = 1
				}
				ordered, err := DialOrder(endpoint, now, floor)
				if err != nil {
					return LinuxLinkRuntimePlanV1{}, err
				}
				for _, generation := range ordered {
					action.DialCandidates = append(action.DialCandidates, LinuxLinkDialCandidateV1{
						EndpointID: endpoint.EndpointID, LogicalServerID: endpoint.LogicalServerID,
						Transport: endpoint.Transport, ListenerGeneration: generation.ListenerGeneration,
						DialTargetFQDN: generation.DialTargetFQDN, PublicPort: generation.PublicPort,
						PublishedState: generation.PublishedState,
					})
				}
			}
			if mode == "dial" && len(action.DialCandidates) == 0 {
				return LinuxLinkRuntimePlanV1{}, errors.New("[Linux runtime] dial LinkIntent 没有当前可拨 certified generation")
			}
		}
		plan.Actions = append(plan.Actions, action)
	}
	return plan, nil
}

func validateLinuxLinkIntentArtifact(artifact *LinuxLinkIntentArtifactV1,
	envelope *wire.DeviceViewEnvelopeV2) error {
	if artifact == nil || envelope == nil || artifact.ClusterID != envelope.Payload.ClusterID ||
		artifact.DeviceID != envelope.Payload.DeviceID || artifact.DeviceGeneration != envelope.Payload.DeviceGeneration {
		return errors.New("[D131 Linux runtime] LinkIntent artifact header/view binding 无效")
	}
	base := artifact.Authority.Head.Body.Payload
	current := envelope.SignedCurrent.Head.Body.Payload
	if base.RecoveryEpoch != current.RecoveryEpoch || base.RecoveryStatementHash != current.RecoveryStatementHash ||
		base.RecoveryPolicyHash != current.RecoveryPolicyHash || base.ControlEpoch != current.ControlEpoch ||
		base.ControlSetHash != current.ControlSetHash || base.ControlRevision > current.ControlRevision ||
		base.RaftTerm > current.RaftTerm || base.CommittedLogicalTime > current.CommittedLogicalTime ||
		(base.ControlRevision == current.ControlRevision && artifact.AuthorityHeadHash != envelope.SignedCurrent.Head.HeadHash) {
		return errors.New("[D131 Linux runtime] LinkIntent base 超出当前 certified authority 或同坐标分叉")
	}
	return wire.ValidateLinuxLinkIntentArtifact(artifact)
}

func bindLinuxLinkIntentArtifactRef(artifact *LinuxLinkIntentArtifactV1, raw []byte,
	refs []wire.DeviceConfigArtifactRefV1) error {
	contentHash, err := wire.DeviceConfigArtifactContentHash(raw)
	if err != nil {
		return err
	}
	matches := 0
	for _, ref := range refs {
		if ref.ArtifactID != LinuxLinkIntentArtifactID {
			continue
		}
		if ref.Generation > artifact.Generation {
			return errors.New("[Linux runtime] 禁止选择低于 Device view 最新代的 LinkIntent artifact")
		}
		if ref.Generation == artifact.Generation && ref.Platform == "linux-server" &&
			ref.MediaType == "application/vnd.loom.config+json" && ref.RenderContractID == artifact.RenderContractID &&
			ref.SizeBytes == int64(len(raw)) && ref.ContentHash == contentHash {
			matches++
		}
	}
	if matches != 1 {
		return errors.New("[Linux runtime] LinkIntent artifact 未被 current Device view exact ref 承诺")
	}
	return nil
}

func linuxCertifiedControlMembers(set *wire.ControlSetV1,
	object *wire.ControlPeerDirectoryPrivateObjectV1, expectedHash string) (map[string]string, error) {
	result := make(map[string]string)
	if object == nil {
		return result, nil
	}
	if err := wire.ValidateControlPeerDirectoryPrivateObject(set, object); err != nil ||
		object.ControlPeerDirectoryHash != expectedHash {
		return nil, errors.New("[Linux runtime] private control directory 未绑定 current Head")
	}
	for _, member := range object.Directory.Members {
		result[member.DeviceID] = member.MemberID
	}
	return result, nil
}

func linuxAuthorizedDataEndpoints(bundle *wire.DeviceEndpointBundleV1) (map[string]wire.DataIngressEndpointV2, error) {
	result := make(map[string]wire.DataIngressEndpointV2)
	for _, binding := range bundle.DataIngressSets {
		for _, endpoint := range binding.EndpointSet.Endpoints {
			if _, duplicate := result[endpoint.EndpointID]; duplicate {
				return nil, errors.New("[Linux runtime] Device endpoint bundle 跨 set 重复 endpoint ID")
			}
			result[endpoint.EndpointID] = endpoint
		}
	}
	return result, nil
}

func linuxDestinationGranted(grants wire.EnrollmentDestinationGrantsV1,
	destination wire.LinkIntentDestinationV1) bool {
	for _, grant := range grants.Values {
		if destination.ServiceID != "" && grant.Kind == "service" && grant.TargetID == destination.ServiceID ||
			destination.DeviceID != "" && grant.Kind == "egress" && grant.TargetID == destination.DeviceID {
			return true
		}
	}
	return false
}

func linuxEgressGranted(grants wire.EnrollmentDestinationGrantsV1,
	destination wire.LinkIntentDestinationV1) bool {
	for _, grant := range grants.Values {
		if grant.Kind == "egress" && grant.TargetID == destination.DeviceID {
			return true
		}
	}
	return false
}
