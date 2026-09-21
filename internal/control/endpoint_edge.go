package control

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

const endpointEdgePlanSchema = 1

// EndpointEdgePlan is an owner-only runtime projection of one certified
// EndpointGeneration. It carries no authority or TLS key: the edge forwards
// opaque TCP bytes and the control listener performs every authentication
// decision.
type EndpointEdgePlan struct {
	Schema           int                      `json:"schema"`
	CertifiedHead    string                   `json:"certified_head"`
	ProjectionDigest string                   `json:"projection_digest"`
	EdgeNode         string                   `json:"edge_node"`
	Listen           string                   `json:"listen"`
	Target           string                   `json:"target"`
	Generations      []EndpointEdgeGeneration `json:"generations"`
}

type EndpointEdgeGeneration struct {
	EndpointID string `json:"endpoint_id"`
	Generation uint64 `json:"generation"`
}

func (plan EndpointEdgePlan) Validate(node string) error {
	if plan.Schema != endpointEdgePlanSchema || !validDigest(plan.CertifiedHead) || !validDigest(plan.ProjectionDigest) ||
		!validName(plan.EdgeNode) || plan.EdgeNode != node || len(plan.Generations) == 0 ||
		!validAddress(plan.Listen) || !validAddress(plan.Target) {
		return errors.New("endpoint edge plan is invalid")
	}
	for index, generation := range plan.Generations {
		if !validName(generation.EndpointID) || generation.Generation == 0 || index > 0 &&
			(plan.Generations[index-1].EndpointID > generation.EndpointID ||
				plan.Generations[index-1].EndpointID == generation.EndpointID && plan.Generations[index-1].Generation >= generation.Generation) {
			return errors.New("endpoint edge generations are not uniquely sorted")
		}
	}
	host, _, _ := net.SplitHostPort(plan.Target)
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsPrivate() && !ip.IsLoopback() {
		return errors.New("endpoint edge target is not private")
	}
	return nil
}

// ProjectEndpointEdge derives the entire edge runtime value from the current
// certified state. It never accepts an operator-supplied listener or target.
func ProjectEndpointEdge(certified CertifiedState, edgeNode string) (EndpointEdgePlan, error) {
	if !validName(edgeNode) {
		return EndpointEdgePlan{}, errors.New("endpoint edge node is invalid")
	}
	var selected *EndpointGeneration
	generations := []EndpointEdgeGeneration{}
	for index := range certified.Projection.EndpointGenerations {
		generation := &certified.Projection.EndpointGenerations[index]
		if generation.EdgeNode != edgeNode || generation.State == "retired" {
			continue
		}
		if selected != nil && (selected.EdgeListen != generation.EdgeListen || selected.Listen != generation.Listen) {
			return EndpointEdgePlan{}, errors.New("endpoint edge node has conflicting active listeners")
		}
		if selected == nil {
			selected = generation
		}
		generations = append(generations, EndpointEdgeGeneration{EndpointID: generation.EndpointID, Generation: generation.Generation})
	}
	if selected == nil {
		return EndpointEdgePlan{}, errors.New("endpoint edge node has no active generation")
	}
	plan := EndpointEdgePlan{Schema: endpointEdgePlanSchema, CertifiedHead: HeadID(certified.Head),
		ProjectionDigest: certified.Head.ProjectionDigest, EdgeNode: selected.EdgeNode,
		Listen: selected.EdgeListen, Target: selected.Listen, Generations: generations}
	return plan, plan.Validate(edgeNode)
}

func SaveEndpointEdgePlan(path string, plan EndpointEdgePlan) error {
	if err := plan.Validate(plan.EdgeNode); err != nil {
		return err
	}
	return atomicJSON(path, plan)
}

func LoadEndpointEdgePlan(path, node string) (EndpointEdgePlan, error) {
	var plan EndpointEdgePlan
	if err := readStrict(path, &plan); err != nil {
		return plan, err
	}
	return plan, plan.Validate(node)
}

type EndpointEdgeRuntime struct {
	listener net.Listener
	target   string
	done     chan struct{}
	once     sync.Once
}

func OpenEndpointEdge(plan EndpointEdgePlan, node string) (*EndpointEdgeRuntime, error) {
	if err := plan.Validate(node); err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", plan.Listen)
	if err != nil {
		return nil, err
	}
	runtime := &EndpointEdgeRuntime{listener: listener, target: plan.Target, done: make(chan struct{})}
	go runtime.accept()
	return runtime, nil
}

func (runtime *EndpointEdgeRuntime) accept() {
	defer close(runtime.done)
	for {
		incoming, err := runtime.listener.Accept()
		if err != nil {
			return
		}
		go runtime.forward(incoming)
	}
}

func (runtime *EndpointEdgeRuntime) forward(incoming net.Conn) {
	defer incoming.Close()
	dialer := net.Dialer{Timeout: 10 * time.Second}
	target, err := dialer.DialContext(context.Background(), "tcp", runtime.target)
	if err != nil {
		return
	}
	defer target.Close()
	_ = incoming.SetDeadline(time.Time{})
	_ = target.SetDeadline(time.Time{})
	finished := make(chan struct{})
	go func() {
		_, _ = io.Copy(target, incoming)
		if tcp, ok := target.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		close(finished)
	}()
	_, _ = io.Copy(incoming, target)
	_ = incoming.Close()
	<-finished
}

func (runtime *EndpointEdgeRuntime) Close() error {
	var err error
	runtime.once.Do(func() { err = runtime.listener.Close() })
	<-runtime.done
	return err
}

func loadOptionalEndpointEdge(path, node string) (EndpointEdgePlan, bool, error) {
	plan, err := LoadEndpointEdgePlan(path, node)
	if errors.Is(err, os.ErrNotExist) {
		return EndpointEdgePlan{}, false, nil
	}
	return plan, err == nil, err
}
