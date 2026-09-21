package control

import (
	"bytes"
	"io"
	"net"
	"testing"
)

func TestEndpointEdgeProjectsCertifiedGenerationAndForwardsOpaqueBytes(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		connection, acceptErr := target.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		_, _ = io.Copy(connection, connection)
	}()

	reserved, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	edgeAddress := reserved.Addr().String()
	_ = reserved.Close()
	digest := "sha256:" + SHA256([]byte("demo"))
	certified := CertifiedState{Head: GovernanceHead{Schema: HeadSchema, Index: 4, LogDigest: digest,
		ProjectionDigest: digest, ConfigMaterial: digest}, Projection: Projection{EndpointGenerations: []EndpointGeneration{{
		Schema: endpointSchema, EndpointID: "demo-entry", Generation: 3, Node: "demo-control", EdgeNode: "demo-edge",
		EdgeListen: edgeAddress, Transport: "tls_tunnel", Listen: target.Addr().String(), Address: "entry.example:443",
		ServerName: "entry.example", TLSCertificateFile: "/demo/cert.pem", TLSPrivateKeyFile: "/demo/key.pem",
		SPKISHA256: SHA256([]byte("spki")), State: "prepared",
	}}}}
	plan, err := ProjectEndpointEdge(certified, "demo-edge")
	if err != nil {
		t.Fatal(err)
	}
	if plan.CertifiedHead != HeadID(certified.Head) || plan.Target != target.Addr().String() || plan.Listen != edgeAddress ||
		len(plan.Generations) != 1 || plan.Generations[0].Generation != 3 {
		t.Fatalf("edge projection changed certified coordinates: %+v", plan)
	}
	edge, err := OpenEndpointEdge(plan, "demo-edge")
	if err != nil {
		t.Fatal(err)
	}
	defer edge.Close()
	connection, err := net.Dial("tcp", edgeAddress)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("opaque tls bytes")
	if _, err := connection.Write(payload); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(connection, response); err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	if !bytes.Equal(response, payload) {
		t.Fatalf("edge changed bytes: got %q", response)
	}
}

func TestEndpointEdgeRejectsAuthorityAndPublicTargetConfusion(t *testing.T) {
	digest := "sha256:" + SHA256([]byte("demo"))
	plan := EndpointEdgePlan{Schema: endpointEdgePlanSchema, CertifiedHead: digest, ProjectionDigest: digest,
		EdgeNode: "demo-edge", Listen: "127.0.0.1:10001", Target: "192.0.2.10:10002",
		Generations: []EndpointEdgeGeneration{{EndpointID: "demo-entry", Generation: 1}}}
	if err := plan.Validate("demo-edge"); err == nil {
		t.Fatal("endpoint edge accepted a public target instead of a private control listener")
	}
	plan.Target = "127.0.0.1:10002"
	if err := plan.Validate("demo-control"); err == nil {
		t.Fatal("endpoint edge plan was accepted by a different node")
	}
}
