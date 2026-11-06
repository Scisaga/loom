package protocol

import (
	"errors"
	"slices"
)

// HopPolicy and HopPermission are projections of existing signed values into
// one receiver. They are compiled once per accepted runtime update, never from
// an incoming request. Requests contain neither of these permission values.
type HopPolicy struct {
	PolicyID   string        `json:"policy_id"`
	ServiceID  string        `json:"service_id"`
	Kind       string        `json:"kind"`
	Origins    []string      `json:"origins"`
	Exits      []string      `json:"exits"`
	Nodes      []string      `json:"nodes"`
	EntryScope PolicyScope   `json:"entry_scope"`
	RelayScope PolicyScope   `json:"relay_scope"`
	MaxHops    int           `json:"max_hops"`
	Edges      []DirectedHop `json:"edges"`
}
type DirectedHop struct {
	From string `json:"from"`
	To   string `json:"to"`
}
type HopPermission struct {
	SenderID       string
	ReceiverID     string
	Purpose        string
	Forward        bool
	InternetEgress bool
	LANGateway     bool
}

func orderedIDs(values []string) bool {
	if values == nil {
		return false
	}
	for index, value := range values {
		if ValidateID(value) != nil || value == "direct" || index > 0 && values[index-1] >= value {
			return false
		}
	}
	return true
}
func (policy HopPolicy) Validate() error {
	if ValidateID(policy.PolicyID) != nil || ValidateID(policy.ServiceID) != nil || policy.Kind != "internet" && policy.Kind != "local_network" || !orderedIDs(policy.Origins) || !orderedIDs(policy.Exits) || !orderedIDs(policy.Nodes) || policy.EntryScope.Validate() != nil || policy.RelayScope.Validate() != nil || policy.MaxHops < 0 || policy.Edges == nil {
		return errors.New("invalid receiving Policy projection")
	}
	if policy.Kind == "local_network" && len(policy.Exits) > 1 {
		return errors.New("LAN requires its one fixed gateway")
	}
	nodes := idSet(policy.Nodes)
	for _, exit := range policy.Exits {
		if !member(nodes, exit) {
			return errors.New("exit is outside the qualified node graph")
		}
	}
	previous := ""
	for index, edge := range policy.Edges {
		key := edge.From + "\x00" + edge.To
		if edge.From == edge.To || !member(nodes, edge.From) || !member(nodes, edge.To) || index > 0 && previous >= key {
			return errors.New("invalid qualified directed hop")
		}
		previous = key
	}
	return nil
}
func (permission HopPermission) Validate() error {
	if ValidateID(permission.SenderID) != nil || ValidateID(permission.ReceiverID) != nil || permission.SenderID == permission.ReceiverID || permission.Purpose != "access" && permission.Purpose != "forward" {
		return errors.New("invalid authenticated hop permission")
	}
	return nil
}

// CompiledPolicy is an immutable membership index of one accepted projection.
// It is discarded with that runtime projection and carries no authority.
type CompiledPolicy struct {
	policyID, serviceID, kind string
	origins, exits, nodes     map[string]struct{}
	entries, relays           PolicyScope
	entrySet, relaySet        map[string]struct{}
	edges                     map[DirectedHop]struct{}
	maxHops                   int
}

func idSet(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}
func member(values map[string]struct{}, value string) bool { _, ok := values[value]; return ok }
func (policy HopPolicy) Compile() (*CompiledPolicy, error) {
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	result := &CompiledPolicy{policyID: policy.PolicyID, serviceID: policy.ServiceID, kind: policy.Kind,
		origins: idSet(policy.Origins), exits: idSet(policy.Exits), nodes: idSet(policy.Nodes),
		entries: PolicyScope{Mode: policy.EntryScope.Mode}, relays: PolicyScope{Mode: policy.RelayScope.Mode},
		entrySet: idSet(policy.EntryScope.NodeIDs), relaySet: idSet(policy.RelayScope.NodeIDs),
		edges: make(map[DirectedHop]struct{}, len(policy.Edges)), maxHops: policy.MaxHops}
	for _, edge := range policy.Edges {
		result.edges[edge] = struct{}{}
	}
	return result, nil
}
func scopeMember(mode string, values map[string]struct{}, node string) bool {
	return mode == "any" || mode == "only" && member(values, node)
}
func (policy *CompiledPolicy) MaxNodes() int {
	if policy == nil {
		return 0
	}
	return len(policy.nodes)
}
func (policy *CompiledPolicy) PolicyID() string {
	if policy == nil {
		return ""
	}
	return policy.policyID
}
func (policy *CompiledPolicy) ServiceID() string {
	if policy == nil {
		return ""
	}
	return policy.serviceID
}

// Admit appends this receiver exactly once, after checking the actual transport
// sender, original access grant, chosen exit, responsibilities, scopes and loop
// constraints. Work per request is proportional to its visited nodes, not to the
// number of devices, exits, resources, graph edges or permitted complete paths.
func (policy *CompiledPolicy) Admit(value PathContext, permission HopPermission) (PathContext, error) {
	if policy == nil || permission.Validate() != nil || value.Validate(policy.MaxNodes()) != nil {
		return PathContext{}, errors.New("invalid authenticated hop input")
	}
	if !member(policy.origins, value.OriginID) || !member(policy.exits, value.FinalExitID) || !member(policy.nodes, permission.ReceiverID) {
		return PathContext{}, errors.New("origin, exit or receiver is not allowed")
	}
	if policy.maxHops > 0 && len(value.Visited)+1 > policy.maxHops {
		return PathContext{}, errors.New("path exceeds its explicit hop limit")
	}
	if permission.Purpose == "access" {
		if permission.SenderID != value.OriginID || len(value.Visited) != 0 {
			return PathContext{}, errors.New("access cannot impersonate an origin or skip its entry")
		}
	} else if len(value.Visited) == 0 || value.Visited[len(value.Visited)-1] != permission.SenderID {
		return PathContext{}, errors.New("forward does not match the actual predecessor")
	}
	path := append(slices.Clone(value.Visited), permission.ReceiverID)
	if !scopeMember(policy.entries.Mode, policy.entrySet, path[0]) {
		return PathContext{}, errors.New("entry is outside the Policy")
	}
	for index, node := range path {
		if index < len(path)-1 && (node == permission.ReceiverID || node == value.FinalExitID) {
			return PathContext{}, errors.New("path repeats its receiver or continues past its final exit")
		}
		if !member(policy.nodes, node) || index > 0 && node != value.FinalExitID && !scopeMember(policy.relays.Mode, policy.relaySet, node) {
			return PathContext{}, errors.New("relay is outside the Policy")
		}
		if index > 0 {
			if _, ok := policy.edges[DirectedHop{path[index-1], node}]; !ok {
				return PathContext{}, errors.New("path has no qualified directed segment")
			}
		}
	}
	if permission.ReceiverID == value.FinalExitID {
		if policy.kind == "internet" && !permission.InternetEgress || policy.kind == "local_network" && !permission.LANGateway {
			return PathContext{}, errors.New("receiver cannot provide this final egress")
		}
	} else if !permission.Forward {
		return PathContext{}, errors.New("receiver has no forwarding responsibility")
	}
	value.Visited = path
	return value, nil
}

// VerifyCurrent rechecks an already admitted registration/connection against a
// replacement permission snapshot. It does not append the same receiver twice.
func (policy *CompiledPolicy) VerifyCurrent(value PathContext, permission HopPermission) error {
	if len(value.Visited) == 0 || value.Visited[len(value.Visited)-1] != permission.ReceiverID {
		return errors.New("restored context does not end at this receiver")
	}
	prior := value
	prior.Visited = value.Visited[:len(value.Visited)-1]
	_, err := policy.Admit(prior, permission)
	return err
}
func (policy HopPolicy) Admit(value PathContext, permission HopPermission) (PathContext, error) {
	compiled, err := policy.Compile()
	if err != nil {
		return PathContext{}, err
	}
	return compiled.Admit(value, permission)
}

// AdmitEntry tests admission without choosing an exit or requesting a target.
// It is stronger than physical transport echo and weaker than business success.
func (policy *CompiledPolicy) AdmitEntry(sender, receiver string, forward, egress bool) error {
	if policy == nil || !member(policy.origins, sender) || !member(policy.nodes, receiver) || !scopeMember(policy.entries.Mode, policy.entrySet, receiver) || !forward && (!egress || policy.kind != "internet" || !member(policy.exits, receiver)) {
		return errors.New("principal has no current access admission at this entry")
	}
	return nil
}

func (policy *CompiledPolicy) AllowsOrigin(id string) bool {
	return policy != nil && member(policy.origins, id)
}
func (policy *CompiledPolicy) AllowsExit(id string) bool {
	return policy != nil && member(policy.exits, id)
}
