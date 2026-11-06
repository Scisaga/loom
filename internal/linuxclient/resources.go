package linuxclient

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"loom/internal/control"
)

// ResourceInputs only locates this node's execution material. An unused entry
// cannot create a listener or restore any permission absent from the View.
type ResourceInputs struct {
	Schema    int                     `json:"schema"`
	Listeners []ResourceListenerInput `json:"listeners"`
}

type ResourceListenerInput struct {
	ResourceID      string `json:"resource_id"`
	Listen          string `json:"listen,omitempty"`
	ListenPort      int    `json:"listen_port,omitempty"`
	CertificateFile string `json:"certificate_file,omitempty"`
	KeyFile         string `json:"key_file,omitempty"`
}

func (inputs ResourceInputs) Validate() error {
	if inputs.Schema != 3 || inputs.Listeners == nil {
		return errors.New("resource execution inputs are incomplete")
	}
	for index, value := range inputs.Listeners {
		if control.ValidateID(value.ResourceID) != nil || index > 0 && inputs.Listeners[index-1].ResourceID >= value.ResourceID {
			return errors.New("resource listener identities are invalid")
		}
		if value.Listen != "" {
			host, port, err := net.SplitHostPort(value.Listen)
			ip, ipErr := netip.ParseAddr(host)
			number, portErr := strconv.Atoi(port)
			if value.ListenPort != 0 || err != nil || ipErr != nil || ip.Zone() != "" || ip.String() != host || portErr != nil || number < 1 || number > 65535 || net.JoinHostPort(host, strconv.Itoa(number)) != value.Listen {
				return errors.New("resource listener address is invalid")
			}
		} else if value.ListenPort < 1 || value.ListenPort > 65535 {
			return errors.New("resource WG listener port is invalid")
		}

		if value.Listen != "" {
			if value.CertificateFile == "" || value.KeyFile == "" {
				return errors.New("local Hy2 input requires both certificate and key references")
			}
		} else if value.CertificateFile != "" || value.KeyFile != "" {
			return errors.New("local WG port input cannot contain TLS references")
		}
		for _, path := range []string{value.CertificateFile, value.KeyFile} {
			if path != "" && (!filepath.IsAbs(path) || filepath.Clean(path) != path) {
				return errors.New("resource TLS inputs require canonical absolute file references")
			}
		}
	}
	return nil
}

type resourceExecution struct {
	resource control.TransportResource
	input    ResourceListenerInput
	roots    *x509.CertPool
	password string
	acl      string
}

func resourceListenerInputs(view control.DeviceView, inputPath string) ([]ResourceListenerInput, error) {
	owned := []control.TransportResource{}
	for _, resource := range view.Resources {
		if resource.OwnerNodeID == view.DeviceID && (resource.Kind == "hysteria2" || resource.Kind == "wireguard") {
			owned = append(owned, resource)
		}
	}
	if len(owned) == 0 {
		return []ResourceListenerInput{}, nil
	}
	if inputPath == "" {
		return nil, errors.New("owned resources require explicit local execution inputs")
	}
	var inputs ResourceInputs
	if err := readStrict(inputPath, 1<<20, &inputs); err != nil {
		return nil, err
	}
	byID := map[string]ResourceListenerInput{}
	for _, input := range inputs.Listeners {
		byID[input.ResourceID] = input
	}
	result := make([]ResourceListenerInput, 0, len(owned))
	active := []ResourceListenerInput{}
	for _, resource := range owned {
		input, found := byID[resource.ID]
		if !found {
			return nil, errors.New("resource execution input is missing")
		}
		if resource.Kind == "wireguard" {
			if input.Listen != "" || input.ListenPort < 1 || input.ListenPort > 65535 || input.CertificateFile != "" || input.KeyFile != "" {
				return nil, errors.New("WG requires only its explicit local listen_port")
			}
		} else if input.ListenPort != 0 || input.Listen == "" || input.CertificateFile == "" || input.KeyFile == "" {
			return nil, errors.New("Hy2 requires listen and its certificate/key, without a WG port")
		}
		for _, previous := range active {
			port := input.ListenPort
			if port == 0 {
				port = int(netip.MustParseAddrPort(input.Listen).Port())
			}
			oldPort := previous.ListenPort
			if oldPort == 0 {
				oldPort = int(netip.MustParseAddrPort(previous.Listen).Port())
			}
			if port != oldPort {
				continue
			}
			if input.ListenPort != 0 || previous.ListenPort != 0 {
				return nil, errors.New("WG wildcard UDP port conflicts with another owned resource")
			}
			left, right := netip.MustParseAddrPort(input.Listen).Addr(), netip.MustParseAddrPort(previous.Listen).Addr()
			if left.Is4() == right.Is4() && (left == right || left.IsUnspecified() || right.IsUnspecified()) {
				return nil, errors.New("owned Hy2 UDP listeners overlap")
			}
		}
		active = append(active, input)
		result = append(result, input)
	}
	return result, nil
}

func resourceInputsDigest(inputs []ResourceListenerInput) (string, error) {
	body, err := control.CanonicalEncode(append([]ResourceListenerInput{}, inputs...))
	if err != nil {
		return "", err
	}
	return control.ReleaseDigest(body), nil
}
func appliedResourceInputs(executions []resourceExecution) []ResourceListenerInput {
	inputs := make([]ResourceListenerInput, 0, len(executions))
	for _, execution := range executions {
		inputs = append(inputs, execution.input)
	}
	return inputs
}

func prepareResourceExecutions(view control.DeviceView, inputPath string, now time.Time) ([]resourceExecution, error) {
	inputs, err := resourceListenerInputs(view, inputPath)
	if err != nil {
		return nil, err
	}
	owned := map[string]control.TransportResource{}
	for _, resource := range view.Resources {
		if resource.OwnerNodeID == view.DeviceID {
			owned[resource.ID] = resource
		}
	}
	result := make([]resourceExecution, 0, len(inputs))
	for _, input := range inputs {
		resource := owned[input.ResourceID]
		acl, err := control.InboundACLDigest(view, resource.ID)
		if err != nil {
			return nil, err
		}
		if resource.Kind == "wireguard" {
			if input.CertificateFile != "" || input.KeyFile != "" {
				return nil, errors.New("WG listener cannot consume TLS material")
			}
			result = append(result, resourceExecution{resource: resource, input: input, acl: acl})
			continue
		}
		if input.CertificateFile == "" || input.KeyFile == "" {
			return nil, errors.New("Hy2 listener requires its certificate and key")
		}
		pair, err := control.LoadTLSCertificate(input.CertificateFile, input.KeyFile)
		if err != nil {
			return nil, err
		}
		certificates, err := control.HY2TrustPEM(resource)
		if err != nil {
			return nil, err
		}
		roots := x509.NewCertPool()
		for _, certificate := range certificates {
			if !roots.AppendCertsFromPEM([]byte(certificate)) {
				return nil, errors.New("resource CA input is invalid")
			}
		}
		intermediates := x509.NewCertPool()
		for _, der := range pair.Certificate[1:] {
			certificate, err := x509.ParseCertificate(der)
			if err != nil {
				return nil, errors.New("resource certificate chain is invalid")
			}
			intermediates.AddCert(certificate)
		}
		if pair.Leaf.IsCA {
			return nil, errors.New("resource identity is a CA")
		}
		if _, err := pair.Leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: *resource.Authentication.ServerName, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
			return nil, errors.New("resource certificate does not match its certified trust, name, purpose or validity")
		}
		password := ""
		for _, credential := range view.TransportCredentials {
			if credential.ResourceID == resource.ID {
				password = credential.Credential
				break
			}
		}

		result = append(result, resourceExecution{resource: resource, input: input, roots: roots, password: password, acl: acl})
	}
	return result, nil
}

func resourceMatcher(matcher control.ServiceMatcher) map[string]any {
	switch matcher.Kind {
	case "dns_exact":
		return map[string]any{"domain": []string{matcher.Value}}
	case "dns_suffix":
		return map[string]any{"domain_suffix": []string{matcher.Value}}
	default:
		return map[string]any{"ip_cidr": []string{matcher.Value}}
	}
}

// appendHY2Runtime is pure: local material is validated before rendering, and
// clock, randomness, filesystem and network state cannot change this output.
func appendHY2Runtime(config string, view control.DeviceView, executions []resourceExecution) (string, error) {
	if len(executions) == 0 {
		return config, nil
	}
	var document map[string]any
	if err := json.Unmarshal([]byte(config), &document); err != nil {
		return "", err
	}
	inbounds, _ := document["inbounds"].([]any)

	for _, execution := range executions {
		if execution.resource.Kind != "hysteria2" {
			continue
		}
		resource, input := execution.resource, execution.input
		host, port, _ := net.SplitHostPort(input.Listen)
		number, _ := strconv.Atoi(port)
		tag := "resource:" + resource.ID
		users := []any{}
		for _, permission := range view.TransportCredentials {
			if permission.ResourceID != resource.ID {
				continue
			}
			user, err := control.TransportCredentialUser(view.NetworkID, permission)
			if err != nil {
				return "", err
			}
			users = append(users, map[string]any{"name": user, "password": permission.Credential})
		}

		projection, err := control.ReceiverExecutionOptions(view, resource.ID)
		if err != nil {
			return "", err
		}
		inbounds = append(inbounds, map[string]any{"execution": projection, "type": "hysteria2", "tag": tag, "listen": host, "listen_port": number, "users": users,
			"tls": map[string]any{"enabled": true, "certificate_path": input.CertificateFile, "key_path": input.KeyFile}})
	}
	document["inbounds"] = inbounds
	body, err := json.Marshal(document)
	return string(body), err
}

func processOwnsUDP(pid int, listen string) bool {
	host, port, err := net.SplitHostPort(listen)
	ip, ipErr := netip.ParseAddr(host)
	number, portErr := strconv.Atoi(port)
	if err != nil || ipErr != nil || portErr != nil {
		return false
	}
	var encoded strings.Builder
	for offset := 0; offset < len(ip.AsSlice()); offset += 4 {
		fmt.Fprintf(&encoded, "%08X", binary.NativeEndian.Uint32(ip.AsSlice()[offset:offset+4]))
	}
	fmt.Fprintf(&encoded, ":%04X", number)
	base := filepath.Join("/proc", strconv.Itoa(pid))
	fds, err := os.ReadDir(filepath.Join(base, "fd"))
	if err != nil {
		return false
	}
	owned := map[string]bool{}
	for _, fd := range fds {
		link, err := os.Readlink(filepath.Join(base, "fd", fd.Name()))
		if err == nil && strings.HasPrefix(link, "socket:[") && strings.HasSuffix(link, "]") {
			owned[strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")] = true
		}
	}
	name := "udp"
	if ip.Is6() {
		name = "udp6"
	}
	file, err := os.Open(filepath.Join(base, "net", name))
	if err != nil {
		return false
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) > 9 && fields[1] == encoded.String() && fields[2] == strings.Repeat("0", len(ip.AsSlice())*2)+":0000" && fields[3] == "07" && owned[fields[9]] {
			return true
		}
	}
	return false
}

func (execution resourceExecution) readback(ctx context.Context, pid int, now time.Time) (control.ResourceReadback, error) {
	if !processOwnsUDP(pid, execution.input.Listen) {
		return control.ResourceReadback{}, executionFailure("resource_ownership", "unverified", ErrWireGuardOwnership)
	}
	host, port, _ := net.SplitHostPort(execution.input.Listen)
	ip, _ := netip.ParseAddr(host)
	if ip.IsUnspecified() {
		if ip.Is4() {
			host = "127.0.0.1"
		} else {
			host = "::1"
		}
	}
	destination := net.JoinHostPort(host, port)
	transport := &http3.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: execution.roots,
		ServerName: *execution.resource.Authentication.ServerName, Time: func() time.Time { return now }},
		Dial: func(ctx context.Context, _ string, tlsConfig *tls.Config, config *quic.Config) (quic.EarlyConnection, error) {
			return quic.DialAddrEarly(ctx, destination, tlsConfig, config)
		}}
	defer transport.Close()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://hysteria/auth", nil)
	if err != nil {
		return control.ResourceReadback{}, err
	}
	request.Header.Set("Hysteria-Auth", execution.password)
	request.Header.Set("Hysteria-CC-RX", "0")
	response, err := transport.RoundTrip(request)
	if err != nil {
		return control.ResourceReadback{}, resourceProbeFailure(err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	wanted := 233
	if execution.password == "" {
		wanted = http.StatusNotFound
	}
	if response.StatusCode != wanted || response.TLS == nil || len(response.TLS.VerifiedChains) == 0 || len(response.TLS.PeerCertificates) == 0 {
		return control.ResourceReadback{}, executionFailure("resource_readback", "identity_rejected", errors.New("resource authentication rejected"))
	}
	digest := sha256.Sum256(response.TLS.PeerCertificates[0].Raw)
	return control.ResourceReadback{ResourceID: execution.resource.ID, ListenerID: execution.resource.ListenerID, Listen: execution.input.Listen,
		CertificateDigest: "sha256:" + hex.EncodeToString(digest[:]), ACLDigest: execution.acl}, nil
}

func readHY2Resources(ctx context.Context, executions []resourceExecution, pid int, now time.Time) ([]control.ResourceReadback, error) {
	values := make([]control.ResourceReadback, 0, len(executions))
	for _, execution := range executions {
		if execution.resource.Kind != "hysteria2" {
			continue
		}
		pending, cancel := context.WithTimeout(ctx, 3*time.Second)
		value, err := execution.readback(pending, pid, now)
		cancel()
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, nil
}

func waitTransportResources(ctx context.Context, view control.DeviceView, executions []resourceExecution, pid int, now func() time.Time, done <-chan error) error {
	pending, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		_, err := readTransportResources(pending, view, executions, pid, now())
		if err == nil {
			return nil
		}
		select {
		case <-pending.Done():
			return fmt.Errorf("resource runtime did not become ready: %w", err)
		case err := <-done:
			return processFailure("resource_process", err)
		case <-ticker.C:
		}
	}
}

// WG listener readback proves local execution ownership, not path health. The
// receiver key was matched before starting this exact process. Only native DNS
// and business observations assert remote transport or Service availability.
func readTransportResources(ctx context.Context, view control.DeviceView, executions []resourceExecution, pid int, now time.Time) ([]control.ResourceReadback, error) {
	values, err := readTransportOwnership(view, executions, pid)
	if err != nil {
		return nil, err
	}
	hy2, err := readHY2Resources(ctx, executions, pid, now)
	if err != nil {
		// A probe took time. Before treating a timeout as missing evidence,
		// check every owned listener again, including the independent WG one.
		if errors.Is(err, errResourceReadbackTimeout) {
			if _, ownershipErr := readTransportOwnership(view, executions, pid); ownershipErr != nil {
				return nil, ownershipErr
			}
		}
		return nil, err
	}
	values = append(values, hy2...)
	sort.Slice(values, func(i, j int) bool { return values[i].ResourceID < values[j].ResourceID })
	return values, nil
}

func readTransportOwnership(view control.DeviceView, executions []resourceExecution, pid int) ([]control.ResourceReadback, error) {
	owned := map[string]control.TransportResource{}
	for _, resource := range view.Resources {
		if resource.OwnerNodeID == view.DeviceID && (resource.Kind == "hysteria2" || resource.Kind == "wireguard") {
			owned[resource.ID] = resource
		}
	}
	if len(executions) != len(owned) {
		return nil, executionFailure("resource_acl", "rejected", errors.New("resource execution set differs from the applied configuration"))
	}
	values := []control.ResourceReadback{}
	for _, execution := range executions {
		resource, found := owned[execution.resource.ID]
		if !found || !reflect.DeepEqual(resource, execution.resource) {
			return nil, executionFailure("resource_acl", "rejected", errors.New("resource execution differs from the applied configuration"))
		}
		delete(owned, resource.ID)
		listen := execution.input.Listen
		if resource.Kind == "wireguard" {
			listen = ""
			for _, host := range []string{"::", "0.0.0.0"} {
				candidate := net.JoinHostPort(host, strconv.Itoa(execution.input.ListenPort))
				if processOwnsUDP(pid, candidate) {
					listen = candidate
					break
				}
			}
		}
		if listen == "" || !processOwnsUDP(pid, listen) {
			return nil, executionFailure("resource_ownership", "unverified", ErrWireGuardOwnership)
		}
		acl, err := control.InboundACLDigest(view, resource.ID)
		if err != nil || acl != execution.acl {
			if err == nil {
				err = errors.New("resource ACL differs from the applied configuration")
			}
			return nil, executionFailure("resource_acl", "rejected", err)
		}
		if resource.Kind == "wireguard" {
			values = append(values, control.ResourceReadback{ResourceID: resource.ID, ListenerID: resource.ListenerID, Listen: listen, PublicKey: *resource.Authentication.PublicKey, ACLDigest: acl})
		}
	}
	sort.Slice(values, func(i, j int) bool { return values[i].ResourceID < values[j].ResourceID })
	return values, nil
}
