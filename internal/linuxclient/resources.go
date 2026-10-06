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
	Listen          string `json:"listen"`
	CertificateFile string `json:"certificate_file"`
	KeyFile         string `json:"key_file"`
}

func (inputs ResourceInputs) Validate() error {
	if inputs.Schema != 3 || inputs.Listeners == nil {
		return errors.New("resource execution inputs are incomplete")
	}
	for index, value := range inputs.Listeners {
		host, port, err := net.SplitHostPort(value.Listen)
		ip, ipErr := netip.ParseAddr(host)
		number, portErr := strconv.Atoi(port)
		if control.ValidateID(value.ResourceID) != nil || index > 0 && inputs.Listeners[index-1].ResourceID >= value.ResourceID ||
			err != nil || ipErr != nil || ip.Zone() != "" || ip.String() != host || portErr != nil || number < 1 || number > 65535 || net.JoinHostPort(host, strconv.Itoa(number)) != value.Listen {
			return errors.New("resource listener identities or addresses are invalid")
		}
		for _, path := range []string{value.CertificateFile, value.KeyFile} {
			if !filepath.IsAbs(path) || filepath.Clean(path) != path {
				return errors.New("resource TLS inputs require canonical absolute file references")
			}
		}
	}
	return nil
}

type hy2Execution struct {
	resource control.TransportResource
	input    ResourceListenerInput
	roots    *x509.CertPool
	password string
	acl      string
}

func prepareHY2Executions(view control.DeviceView, inputPath string, now time.Time) ([]hy2Execution, error) {
	owned := []control.TransportResource{}
	for _, resource := range view.Resources {
		if resource.OwnerNodeID == view.DeviceID && resource.Kind == "hysteria2" {
			owned = append(owned, resource)
		}
	}
	if len(owned) == 0 {
		return nil, nil
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
	result := make([]hy2Execution, 0, len(owned))
	listeners := map[string]bool{}
	for _, resource := range owned {
		input, found := byID[resource.ID]
		if !found || listeners[input.Listen] {
			return nil, errors.New("resource execution input is missing or a listener is duplicated")
		}
		listeners[input.Listen] = true
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
		acl, err := control.InboundACLDigest(view, resource.ID)
		if err != nil {
			return nil, err
		}
		password := ""
		for _, credential := range view.InboundCredentials {
			if credential.ResourceID == resource.ID {
				password = credential.Credential
				break
			}
		}
		if password == "" {
			for _, credential := range view.LinkProbeCredentials {
				for _, link := range view.Links {
					if link.ID == credential.LinkID && link.ToNodeID == view.DeviceID && link.ProbeTarget.ResourceID == resource.ID {
						password = credential.Credential
						break
					}
				}
			}
		}
		result = append(result, hy2Execution{resource: resource, input: input, roots: roots, password: password, acl: acl})
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
func appendHY2Runtime(config string, view control.DeviceView, executions []hy2Execution) (string, error) {
	if len(executions) == 0 {
		return config, nil
	}
	var document map[string]any
	if err := json.Unmarshal([]byte(config), &document); err != nil {
		return "", err
	}
	route, ok := document["route"].(map[string]any)
	if !ok {
		return "", errors.New("resource runtime has no route policy")
	}
	previousRules, ok := route["rules"].([]any)
	if !ok {
		return "", errors.New("resource runtime rules are invalid")
	}
	inbounds, _ := document["inbounds"].([]any)
	outbounds, _ := document["outbounds"].([]any)
	outbounds = append(outbounds, map[string]any{"type": "direct", "tag": "resource-egress"})
	rules := []any{}
	relayOutbounds := map[string]bool{}
	for _, execution := range executions {
		resource, input := execution.resource, execution.input
		host, port, _ := net.SplitHostPort(input.Listen)
		number, _ := strconv.Atoi(port)
		tag := "resource:" + resource.ID
		users := []any{}
		for _, permission := range view.InboundCredentials {
			if permission.ResourceID != resource.ID {
				continue
			}
			user, err := control.InboundCredentialUser(permission)
			if err != nil {
				return "", err
			}
			users = append(users, map[string]any{"name": user, "password": permission.Credential})
			if permission.RelayTarget != nil {
				host, port, err := control.RelayDialTarget(view, *permission.RelayTarget, view.DeviceID)
				if err != nil {
					return "", err
				}
				address, err := netip.ParseAddr(host)
				if err != nil {
					return "", err
				}
				outboundTag, iface := "relay:"+permission.RelayTarget.LinkID, ""
				for _, link := range view.Links {
					if link.ID != permission.RelayTarget.LinkID {
						continue
					}
					for _, local := range view.Resources {
						if local.ID == link.FromResourceID {
							iface = local.ListenerID
						}
					}
				}
				if iface == "" {
					return "", errors.New("relay has no owned WireGuard interface")
				}
				if !relayOutbounds[outboundTag] {
					outbounds = append(outbounds, map[string]any{"type": "direct", "tag": outboundTag, "bind_interface": iface})
					relayOutbounds[outboundTag] = true
				}
				rules = append(rules, map[string]any{"inbound": []string{tag}, "auth_user": []string{user}, "network": "udp", "ip_cidr": []string{netip.PrefixFrom(address, address.BitLen()).String()}, "port": []int{port}, "outbound": outboundTag})
				continue
			}
			for _, set := range []struct {
				matchers []control.ServiceMatcher
				outbound string
			}{{permission.ExcludedTargets, "reject"}, {permission.AllowedTargets, "resource-egress"}} {
				for _, matcher := range set.matchers {
					rule := resourceMatcher(matcher)
					rule["inbound"], rule["auth_user"], rule["outbound"] = []string{tag}, []string{user}, set.outbound
					rules = append(rules, rule)
				}
			}
		}
		// Reject before reaching access rules. The receiver never sniffs SNI to
		// reinterpret an arbitrary IP target as a permitted domain request.
		for _, permission := range view.LinkProbeCredentials {
			for _, link := range view.Links {
				if link.ID != permission.LinkID || link.ToNodeID != view.DeviceID || link.ProbeTarget.ResourceID != resource.ID {
					continue
				}
				user, err := control.LinkProbeUser(permission)
				if err != nil {
					return "", err
				}
				// Authentication only: no matching forwarding rule is added.
				users = append(users, map[string]any{"name": user, "password": permission.Credential})
			}
		}
		rules = append(rules, map[string]any{"inbound": []string{tag}, "outbound": "reject"})
		inbounds = append(inbounds, map[string]any{"type": "hysteria2", "tag": tag, "listen": host, "listen_port": number, "users": users,
			"tls": map[string]any{"enabled": true, "certificate_path": input.CertificateFile, "key_path": input.KeyFile}})
	}
	route["rules"] = append(rules, previousRules...)
	document["outbounds"], document["inbounds"] = outbounds, inbounds
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
		if len(fields) > 9 && fields[1] == encoded.String() && owned[fields[9]] {
			return true
		}
	}
	return false
}

func (execution hy2Execution) readback(ctx context.Context, pid int, now time.Time) (control.ResourceReadback, error) {
	if !processOwnsUDP(pid, execution.input.Listen) {
		return control.ResourceReadback{}, errors.New("resource UDP listener is not owned by this execution process")
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
		return control.ResourceReadback{}, errors.New("resource QUIC/TLS readback failed")
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	wanted := 233
	if execution.password == "" {
		wanted = http.StatusNotFound
	}
	if response.StatusCode != wanted || response.TLS == nil || len(response.TLS.VerifiedChains) == 0 || len(response.TLS.PeerCertificates) == 0 {
		return control.ResourceReadback{}, errors.New("resource identity or Hy2 authentication readback failed")
	}
	digest := sha256.Sum256(response.TLS.PeerCertificates[0].Raw)
	return control.ResourceReadback{ResourceID: execution.resource.ID, ListenerID: execution.resource.ListenerID, Listen: execution.input.Listen,
		CertificateDigest: "sha256:" + hex.EncodeToString(digest[:]), ACLDigest: execution.acl}, nil
}

func readHY2Resources(ctx context.Context, executions []hy2Execution, pid int, now time.Time) ([]control.ResourceReadback, error) {
	values := make([]control.ResourceReadback, 0, len(executions))
	for _, execution := range executions {
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

func waitHY2Resources(ctx context.Context, executions []hy2Execution, pid int, now func() time.Time, done <-chan error) error {
	if len(executions) == 0 {
		return nil
	}
	pending, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		_, err := readHY2Resources(pending, executions, pid, now())
		if err == nil {
			return nil
		}
		select {
		case <-pending.Done():
			return fmt.Errorf("resource runtime did not become ready: %w", err)
		case <-done:
			return errors.New("resource runtime exited before readback")
		case <-ticker.C:
		}
	}
}
