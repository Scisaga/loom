package control

import (
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"
)

func localWebsiteExpectation(node NodeConfig, projection Projection, id string, generation U64) WebsiteRequestExpectation {
	return WebsiteRequestExpectation{node.NetworkID, node.GenesisID, projection.ControlConfigID, node.ControlID, node.NodeID, id, generation}
}

func localWebsiteRequest(root string, node NodeConfig, projection Projection, id string, generation U64) (WebsiteRequest, error) {
	if ValidateID(id) != nil || generation == 0 {
		return WebsiteRequest{}, errors.New("invalid website coordinates")
	}
	if _, err := activeLocalMember(node, projection.Config); err != nil {
		return WebsiteRequest{}, err
	}
	return readWebsiteRequest(websiteRequestDirectory(root, id, generation), localWebsiteExpectation(node, projection, id, generation))
}

func localWebsiteRequests(root string, node NodeConfig, projection Projection) ([]WebsiteRequestSummary, error) {
	result := []WebsiteRequestSummary{}
	parent := filepath.Join(root, "website-requests")
	entries, err := os.ReadDir(parent)
	if errors.Is(err, os.ErrNotExist) {
		return result, nil
	}
	if err != nil {
		return result, err
	}
	if err := ownedWebsiteDirectory(parent); err != nil {
		return result, err
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		directory := filepath.Join(parent, entry.Name())
		if err := ownedWebsiteDirectory(directory); err != nil {
			return result, err
		}
		body, err := readProtectedControlFile(filepath.Join(directory, "request.json"))
		if err != nil {
			return result, err
		}
		var request WebsiteRequest
		if DecodeCanonical(body, &request, ContractDecodeLimits{MaxBytes: 8 << 20, MaxDepth: 128, MaxItems: 1 << 20}) != nil || request.Validate() != nil ||
			websiteRequestDirectory(root, request.EndpointID, request.Generation) != directory {
			return result, errors.New("local website request cannot be read back")
		}
		_, verifyErr := localWebsiteRequest(root, node, projection, request.EndpointID, request.Generation)
		result = append(result, WebsiteRequestSummary{request.EndpointID, request.Generation, verifyErr == nil})
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].EndpointID < result[j].EndpointID || result[i].EndpointID == result[j].EndpointID && result[i].Generation < result[j].Generation
	})
	return result, nil
}

func installWebsiteCertificate(root string, node NodeConfig, projection Projection, input websiteInstallInput, now time.Time) (EndpointGeneration, error) {
	var empty EndpointGeneration
	request, err := localWebsiteRequest(root, node, projection, input.EndpointID, input.Generation)
	if err != nil {
		return empty, err
	}
	endpoint := EndpointGeneration{ID: input.EndpointID, Generation: input.Generation, OwnerControlID: node.ControlID,
		Host: input.Host, Port: input.Port, ServerName: "control.loom", WebsiteTrustID: input.WebsiteTrustID, Modes: []string{"web"}, State: "prepared"}
	var previous *EndpointGeneration
	for _, current := range projection.EndpointGenerations {
		if current.ID != input.EndpointID {
			continue
		}
		if current.OwnerControlID != node.ControlID || current.WebsiteTrustID == "" || current.Generation > input.Generation {
			return empty, errors.New("website request does not match the current owned endpoint")
		}
		if previous == nil || current.Generation > previous.Generation {
			copy := current
			previous = &copy
		}
	}
	if previous != nil {
		endpoint.Modes = append([]string{}, previous.Modes...)
		endpoint.Preference = previous.Preference
	}
	trust, err := endpointWebsiteTrust(projection, endpoint)
	if err != nil {
		return empty, err
	}
	leafDER, err := websiteReturnedLeaf(input.CertificatePEM, trust)
	if err != nil {
		return empty, err
	}
	rootDER, _ := base64.RawURLEncoding.DecodeString(trust.CertificateDER)
	leaf, err := VerifyWebsiteCertificate(request, localWebsiteExpectation(node, projection, input.EndpointID, input.Generation), leafDER, rootDER, now)
	if err != nil {
		return empty, err
	}
	endpoint.SPKISHA256 = endpointByteDigest(leaf.RawSubjectPublicKeyInfo)
	endpoint.CertificateDigest = endpointByteDigest(leaf.Raw)
	if err := endpoint.Validate(); err != nil {
		return empty, err
	}
	if previous != nil && previous.Generation == endpoint.Generation && !reflect.DeepEqual(*previous, endpoint) {
		return empty, errors.New("this endpoint generation already has different coordinates or has advanced beyond prepared")
	}
	inputs := EndpointLocalInputs{Listen: input.Listen,
		CertificateFile: filepath.Join(root, "endpoint-inputs", endpoint.CertificateDigest[7:]+".pem"),
		KeyFile:         filepath.Join(websiteRequestDirectory(root, input.EndpointID, input.Generation), "key.pem")}
	if err := inputs.Validate(); err != nil {
		return empty, err
	}
	for _, current := range projection.EndpointGenerations {
		if current.WebsiteTrustID != "" && current.State == "serving" && current.Port != input.Port {
			return empty, errors.New("website candidates must retain the common advertised port while existing entries are serving")
		}
		if current.OwnerControlID != node.ControlID || current.ServerName != endpoint.ServerName || current.State != "serving" || current.CertificateDigest == endpoint.CertificateDigest {
			continue
		}
		existing, err := loadEndpointInputs(root, current)
		if err != nil {
			return empty, errors.New("existing serving input cannot be verified")
		}
		if existing.Listen == inputs.Listen || current.Host == endpoint.Host && current.Port == endpoint.Port {
			return empty, errors.New("renewal needs another operator-provided address and listener; the existing serving certificate is retained")
		}
	}
	parent := filepath.Dir(inputs.CertificateFile)
	if err := os.Mkdir(parent, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return empty, err
	}
	if err := ownedWebsiteDirectory(parent); err != nil {
		return empty, err
	}
	if err := putControlBytes(inputs.CertificateFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})); err != nil {
		return empty, err
	}
	if err := installEndpointInputsAt(root, endpoint, inputs, now); err != nil {
		return empty, err
	}
	return endpoint, nil
}
