package linuxclient

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"loom/internal/clientmodel"
	"loom/internal/clientruntime"
	"loom/internal/control"
	"loom/internal/deviceclient"
	"loom/internal/releasefloor"
	"loom/internal/rollout"
	"loom/internal/version"
)

const legacySingBoxConfig = "/etc/loom/sing-box/v2/config.json"

type Options struct {
	DeviceState         string
	LocalState          string
	Status              string
	Config              string
	SingBox             string
	WireGuard           string
	IP                  string
	SS                  string
	Ping                string
	WireGuardPrivateKey string
	DataPlaneCA         string
	ServerCert          string
	ServerKey           string
	ReleaseFloor        string
	AppliedSnapshot     string
	RolloutState        string
	MigrationOverlay    string
	Log                 io.Writer
	Now                 func() time.Time
	Generation          func() (string, error)
	Probe               Probe
	RefreshPoll         time.Duration
	defaultProbe        bool
}

func (options *Options) defaults() {
	if options.Log == nil {
		options.Log = io.Discard
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Generation == nil {
		options.Generation = NetworkGeneration
	}
	if options.Probe == nil {
		options.Probe = BusinessProbe
		options.defaultProbe = true
	}
	if options.WireGuard == "" {
		options.WireGuard = "/usr/bin/wg"
	}
	if options.IP == "" {
		options.IP = "/usr/sbin/ip"
	}
	if options.SS == "" {
		options.SS = "/usr/bin/ss"
	}
	if options.Ping == "" {
		options.Ping = "/usr/bin/ping"
	}
	if options.WireGuardPrivateKey == "" {
		options.WireGuardPrivateKey = "/etc/wireguard/node.key"
	}
	if options.DataPlaneCA == "" {
		options.DataPlaneCA = "/run/loom-client/data-plane-ca.crt"
	}
	if options.ServerCert == "" {
		options.ServerCert = "/etc/loom/tls/node.crt"
	}
	if options.ServerKey == "" {
		options.ServerKey = "/etc/loom/tls/node.key"
	}
	if options.ReleaseFloor == "" {
		options.ReleaseFloor = releasefloor.Path
	}
	if options.AppliedSnapshot == "" {
		options.AppliedSnapshot = "/var/lib/loom/applied"
	}
	if options.RolloutState == "" {
		options.RolloutState = rollout.Path
	}
	if options.MigrationOverlay == "" {
		options.MigrationOverlay = DefaultMigrationOverlay
	}
	if options.RefreshPoll <= 0 {
		options.RefreshPoll = 30 * time.Second
	}
}

func (options Options) probeForView(view control.DeviceView) Probe {
	if !options.defaultProbe || view.RuntimeContract == 0 || len(view.DNS) == 0 {
		return options.Probe
	}
	dns := view.DNS[0]
	target := "https://www.baidu.com/"
	if len(view.BusinessProbeTargets) != 0 {
		target = view.BusinessProbeTargets[0]
	}
	return func(ctx context.Context) ProbeResult { return businessProbe(ctx, dns, target) }
}

func linuxDeploymentReadback(options Options) (*control.DeploymentReadback, error) {
	floor, err := releasefloor.Read(options.ReleaseFloor)
	if err != nil || floor == nil {
		return nil, err
	}
	appliedBody, err := os.ReadFile(options.AppliedSnapshot)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil || len(appliedBody) == 0 || len(appliedBody) > 128 {
		if err != nil {
			return nil, err
		}
		return nil, errors.New("applied snapshot readback is invalid")
	}
	applied := strings.TrimSpace(string(appliedBody))
	if len(applied) != 12 {
		return nil, errors.New("applied snapshot readback is invalid")
	}
	if _, err := hex.DecodeString(applied); err != nil {
		return nil, errors.New("applied snapshot readback is invalid")
	}
	record, err := rollout.Read(options.RolloutState)
	if err != nil {
		return nil, err
	}
	coordinate := version.Self()
	actualVersion := coordinate.Tag
	if actualVersion == "" {
		actualVersion = coordinate.Commit
	}
	if actualVersion == "" {
		actualVersion = coordinate.Binary
	}
	if actualVersion == "" {
		return nil, nil
	}
	verified := record != nil && record.Stage == rollout.Verified && record.Snapshot == floor.SelectedSnapshot &&
		record.LastGood == floor.SelectedSnapshot && applied == floor.SelectedSnapshot
	return &control.DeploymentReadback{Generation: floor.Generation, PayloadSHA256: floor.PayloadSHA256,
		SelectedSnapshot: floor.SelectedSnapshot, AppliedSnapshot: applied, Version: actualVersion,
		RolloutVerified: verified}, nil
}

func runtimeView(store *deviceclient.Store) (*control.DeviceViewEnvelope, error) {
	return accessView(store.LKG())
}

func accessView(lkg *control.DeviceViewEnvelope) (*control.DeviceViewEnvelope, error) {
	if lkg == nil || lkg.View.Platform != "linux" || lkg.View.Runtime == nil {
		return nil, errors.New("Linux device has no certified runtime profile")
	}
	if err := lkg.View.Runtime.Validate(lkg.View.Routes); err != nil {
		return nil, fmt.Errorf("certified runtime profile: %w", err)
	}
	return lkg, nil
}

func hasRole(roles []string, wanted string) bool {
	index := sort.SearchStrings(roles, wanted)
	return index < len(roles) && roles[index] == wanted
}

func serverOnlyView(store *deviceclient.Store) (*control.DeviceViewEnvelope, bool) {
	return serverOnlyEnvelope(store.LKG())
}

func serverOnlyEnvelope(lkg *control.DeviceViewEnvelope) (*control.DeviceViewEnvelope, bool) {
	return lkg, lkg != nil && lkg.View.Platform == "linux" && hasRole(lkg.View.Roles, "server") &&
		!hasRole(lkg.View.Roles, "access") && lkg.View.ServerRuntime != nil
}

func renderServerRuntime(profile control.ServerRuntimeProfile, certificatePath, keyPath string, identifyDomains bool) (string, error) {
	if err := profile.Validate(); err != nil {
		return "", err
	}
	if certificatePath == "" || keyPath == "" {
		return "", errors.New("server TLS paths are required")
	}
	users := make([]map[string]any, 0, len(profile.Users))
	for _, user := range profile.Users {
		users = append(users, map[string]any{"name": user.Name, "password": user.Password})
	}
	tls := map[string]any{"enabled": true, "certificate_path": certificatePath, "key_path": keyPath}
	if profile.Protocol == "hysteria2" {
		tls["alpn"] = []string{"h3"}
	}
	rules := make([]map[string]any, 0, len(profile.ACL)+2)
	if identifyDomains {
		rules = append(rules, map[string]any{"inbound": []string{"loom-server-in"}, "action": "sniff"})
	}
	outbounds := []any{map[string]any{"type": "direct", "tag": "loom-server-egress"},
		map[string]any{"type": "block", "tag": "loom-server-block"}}
	nextOutbounds := map[string]bool{}
	for _, acl := range profile.ACL {
		rule := map[string]any{"auth_user": []string{acl.User}}
		switch acl.Action {
		case "egress":
			rule["outbound"] = "loom-server-egress"
			exact, suffix := []string{}, []string{}
			for _, matcher := range acl.DestinationMatchers {
				if strings.HasPrefix(matcher, ".") {
					suffix = append(suffix, strings.TrimPrefix(matcher, "."))
				} else {
					exact = append(exact, matcher)
				}
			}
			if len(exact) != 0 {
				rule["domain"] = exact
			}
			if len(suffix) != 0 {
				rule["domain_suffix"] = suffix
			}
			if len(acl.DNSAddresses) != 0 {
				prefixes := make([]string, 0, len(acl.DNSAddresses))
				for _, value := range acl.DNSAddresses {
					address := net.ParseIP(value)
					suffix := "/32"
					if address.To4() == nil {
						suffix = "/128"
					}
					prefixes = append(prefixes, address.String()+suffix)
				}
				rule["ip_cidr"] = prefixes
				rule["port"] = []int{53}
			}
		case "next_hop":
			sum := sha256.Sum256([]byte(acl.BindInterface + "\x00" + acl.NextHost + "\x00" + strconv.Itoa(acl.NextPort)))
			tag := "loom-next-" + hex.EncodeToString(sum[:6])
			rule["outbound"] = tag
			if !nextOutbounds[tag] {
				outbounds = append(outbounds, map[string]any{"type": "direct", "tag": tag, "bind_interface": acl.BindInterface})
				nextOutbounds[tag] = true
			}
			if address := net.ParseIP(acl.NextHost); address != nil {
				suffix := "/32"
				if address.To4() == nil {
					suffix = "/128"
				}
				rule["ip_cidr"] = []string{address.String() + suffix}
			} else {
				rule["domain"] = []string{acl.NextHost}
			}
			rule["port"] = []int{acl.NextPort}
		default:
			return "", errors.New("server runtime ACL action is invalid")
		}
		rules = append(rules, rule)
	}
	// A valid inbound user must still fail closed outside its certified ACL.
	rules = append(rules, map[string]any{"inbound": []string{"loom-server-in"}, "outbound": "loom-server-block"})
	document := map[string]any{
		"inbounds": []any{map[string]any{"type": profile.Protocol, "tag": "loom-server-in", "listen": "::",
			"listen_port": profile.ListenPort, "users": users, "tls": tls}},
		"outbounds": outbounds,
		"route":     map[string]any{"rules": rules, "final": "loom-server-block"},
	}
	body, err := json.Marshal(document)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func mergeServerRuntime(accessConfig string, profile control.ServerRuntimeProfile, certificatePath, keyPath string, identifyDomains bool) (string, error) {
	serverConfig, err := renderServerRuntime(profile, certificatePath, keyPath, identifyDomains)
	if err != nil {
		return "", err
	}
	var access, server map[string]any
	if err := json.Unmarshal([]byte(accessConfig), &access); err != nil {
		return "", errors.New("access runtime config is invalid")
	}
	if err := json.Unmarshal([]byte(serverConfig), &server); err != nil {
		return "", err
	}
	for _, field := range []string{"inbounds", "outbounds"} {
		left, leftOK := access[field].([]any)
		right, rightOK := server[field].([]any)
		if !leftOK || !rightOK {
			return "", errors.New("runtime config collection is invalid")
		}
		access[field] = append(left, right...)
	}
	accessRoute, ok := access["route"].(map[string]any)
	if !ok {
		accessRoute = map[string]any{}
		access["route"] = accessRoute
	}
	serverRoute, ok := server["route"].(map[string]any)
	if !ok {
		return "", errors.New("server runtime route is invalid")
	}
	serverRules, ok := serverRoute["rules"].([]any)
	if !ok {
		return "", errors.New("server runtime rules are invalid")
	}
	accessRules, _ := accessRoute["rules"].([]any)
	accessRoute["rules"] = append(serverRules, accessRules...)
	body, err := json.Marshal(access)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func attachDataPlaneCA(config, path string) (string, error) {
	var document map[string]any
	if err := json.Unmarshal([]byte(config), &document); err != nil {
		return "", errors.New("access runtime config is invalid")
	}
	outbounds, ok := document["outbounds"].([]any)
	if !ok {
		return "", errors.New("access runtime outbounds are invalid")
	}
	for _, raw := range outbounds {
		outbound, ok := raw.(map[string]any)
		if !ok {
			return "", errors.New("access runtime outbound is invalid")
		}
		kind, _ := outbound["type"].(string)
		if kind != "hysteria2" && kind != "trojan" {
			continue
		}
		tls, ok := outbound["tls"].(map[string]any)
		if !ok {
			return "", errors.New("data-plane TLS outbound is incomplete")
		}
		tls["certificate_path"] = path
	}
	body, err := json.Marshal(document)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func accessRuntimeConfig(view control.DeviceView, caPath string, endpointExclusions []string) (string, error) {
	if view.Runtime == nil {
		return "", errors.New("access device has no runtime profile")
	}
	if err := deviceclient.SavePublicDataPlaneCA(caPath, view.PublicDataPlaneCA); err != nil {
		return "", err
	}
	config, err := attachDataPlaneCA(view.Runtime.Config, caPath)
	if err != nil {
		return "", err
	}
	return deriveLinuxAccessRuntime(config, endpointExclusions)
}

func deriveLinuxAccessRuntime(config string, endpointExclusions []string) (string, error) {
	var document map[string]any
	if err := json.Unmarshal([]byte(config), &document); err != nil {
		return "", errors.New("access runtime is invalid")
	}
	inbounds, ok := document["inbounds"].([]any)
	if !ok {
		return "", errors.New("access runtime inbounds are invalid")
	}
	managed := 0
	for _, raw := range inbounds {
		inbound, ok := raw.(map[string]any)
		if !ok || inbound["type"] != "tun" {
			continue
		}
		if inbound["tag"] != "tun-in" || inbound["auto_route"] != true {
			return "", errors.New("access runtime TUN contract is invalid")
		}
		if existing, found := inbound["address"]; found {
			values, ok := existing.([]any)
			if !ok || len(values) != 1 || values[0] != "172.19.0.1/30" {
				return "", errors.New("access runtime TUN address conflicts with the Linux platform boundary")
			}
		}
		if existing, found := inbound["stack"]; found && existing != "system" {
			return "", errors.New("access runtime TUN stack conflicts with the Linux platform boundary")
		}
		if _, found := inbound["route_exclude_address"]; found {
			return "", errors.New("signed access runtime cannot define local endpoint route exclusions")
		}
		inbound["address"] = []string{"172.19.0.1/30"}
		inbound["stack"] = "system"
		if len(endpointExclusions) != 0 {
			inbound["route_exclude_address"] = append([]string(nil), endpointExclusions...)
		}
		managed++
	}
	if managed != 1 {
		return "", errors.New("access runtime must contain exactly one managed TUN")
	}
	route, found := document["route"].(map[string]any)
	if document["route"] != nil && !found {
		return "", errors.New("access runtime route is invalid")
	}
	if !found {
		route = map[string]any{}
		document["route"] = route
	}
	if existing, found := route["auto_detect_interface"]; found && existing != true {
		return "", errors.New("access runtime interface detection conflicts with the Linux platform boundary")
	}
	route["auto_detect_interface"] = true
	body, err := json.Marshal(document)
	return string(body), err
}

func linuxComponentReadbacks(view control.DeviceView, singBox string) ([]control.ComponentReadback, error) {
	wanted := map[string]bool{}
	for _, expected := range view.ExpectedComponents {
		wanted[expected.Name] = true
	}
	actual := map[string]control.ComponentReadback{}
	if wanted["agent"] {
		coordinate := version.Self()
		value := control.ComponentReadback{Name: "agent", Version: version.AgentProtocolVersion}
		if coordinate.Binary != "" {
			value.Digest = "sha256:" + coordinate.Binary
		}
		actual[value.Name] = value
	}
	if wanted["sing-box"] || wanted["sing_box"] {
		output, err := exec.Command(singBox, "version").Output()
		if err != nil || len(output) == 0 || len(output) > 64<<10 {
			return nil, errors.New("sing-box version readback failed")
		}
		fields := strings.Fields(string(output))
		componentVersion := ""
		for index, field := range fields {
			if strings.EqualFold(field, "version") && index+1 < len(fields) {
				componentVersion = strings.TrimPrefix(fields[index+1], "v")
				break
			}
		}
		if componentVersion == "" {
			return nil, errors.New("sing-box version output is not recognized")
		}
		file, err := os.Open(singBox)
		if err != nil {
			return nil, err
		}
		info, statErr := file.Stat()
		if statErr != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 256<<20 {
			_ = file.Close()
			return nil, errors.New("sing-box digest target is not a bounded regular file")
		}
		hash := sha256.New()
		copied, copyErr := io.Copy(hash, io.LimitReader(file, info.Size()+1))
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil || copied != info.Size() {
			return nil, errors.New("sing-box digest readback failed")
		}
		digest := "sha256:" + hex.EncodeToString(hash.Sum(nil))
		for _, name := range []string{"sing-box", "sing_box"} {
			if wanted[name] {
				actual[name] = control.ComponentReadback{Name: name, Version: componentVersion, Digest: digest}
			}
		}
	}
	result := make([]control.ComponentReadback, 0, len(actual))
	for _, expected := range view.ExpectedComponents {
		if value, found := actual[expected.Name]; found {
			result = append(result, value)
		}
	}
	return result, nil
}

type wireGuardPeerCounters struct {
	Interface string
	Handshake int64
	RXBytes   uint64
	TXBytes   uint64
}

func parseWireGuardDump(body []byte) (map[string]wireGuardPeerCounters, error) {
	if len(body) == 0 || len(body) > 8<<20 {
		return nil, errors.New("WireGuard dump is empty or too large")
	}
	peers := map[string]wireGuardPeerCounters{}
	for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) == 5 { // interface row
			continue
		}
		if len(fields) != 9 {
			return nil, errors.New("WireGuard dump row is invalid")
		}
		handshake, handshakeErr := strconv.ParseInt(fields[5], 10, 64)
		rx, rxErr := strconv.ParseUint(fields[6], 10, 64)
		tx, txErr := strconv.ParseUint(fields[7], 10, 64)
		if fields[0] == "" || fields[1] == "" || handshakeErr != nil || rxErr != nil || txErr != nil {
			return nil, errors.New("WireGuard counter row is invalid")
		}
		if _, duplicate := peers[fields[1]]; duplicate {
			return nil, errors.New("WireGuard peer appears on multiple interfaces")
		}
		peers[fields[1]] = wireGuardPeerCounters{Interface: fields[0], Handshake: handshake, RXBytes: rx, TXBytes: tx}
	}
	return peers, nil
}

func probeWireGuardTarget(ping string, peer wireGuardPeerCounters, target string) (string, int64, error) {
	context, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	started := time.Now()
	command := exec.CommandContext(context, ping, "-n", "-I", peer.Interface, "-c", "1", "-W", "2", target)
	if err := command.Start(); err != nil {
		return "unknown", 0, errors.New("WireGuard probe executable is unavailable")
	}
	err := command.Wait()
	latency := time.Since(started).Milliseconds()
	if latency < 1 {
		latency = 1
	}
	if err != nil {
		return "unavailable", latency, nil
	}
	return "available", latency, nil
}

func linuxLinkReadbacks(view control.DeviceView, wireGuard, ping, epochBase string) ([]control.LinkReadback, error) {
	wanted := false
	for _, target := range view.LinkProbeTargets {
		wanted = wanted || target.Transport == "wireguard" && target.PeerWGPublicKey != ""
	}
	if !wanted {
		return nil, nil
	}
	body, err := exec.Command(wireGuard, "show", "all", "dump").Output()
	if err != nil {
		return nil, errors.New("WireGuard counter readback failed")
	}
	peers, err := parseWireGuardDump(body)
	if err != nil {
		return nil, err
	}
	result := make([]control.LinkReadback, 0, len(view.LinkProbeTargets))
	for _, target := range view.LinkProbeTargets {
		if target.Transport != "wireguard" || target.PeerWGPublicKey == "" {
			continue
		}
		peer, found := peers[target.PeerWGPublicKey]
		if !found {
			continue
		}
		state, latency, probeErr := probeWireGuardTarget(ping, peer, target.Target)
		if probeErr != nil {
			return nil, probeErr
		}
		epochHash := sha256.Sum256([]byte(epochBase + "\x00" + peer.Interface))
		readback := control.LinkReadback{LinkID: target.LinkID, Peer: target.Peer, Interface: peer.Interface,
			Epoch: hex.EncodeToString(epochHash[:8]), ProbeTarget: target.Target, Result: state,
			LatencyMS: latency, RXBytes: peer.RXBytes, TXBytes: peer.TXBytes}
		if peer.Handshake > 0 {
			readback.LatestHandshakeAt = time.Unix(peer.Handshake, 0).UTC().Format(time.RFC3339)
		}
		result = append(result, readback)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].LinkID < result[j].LinkID })
	return result, nil
}

var errCertifiedViewChanged = errors.New("a newer certified device view is available")

type fetchedActivationError struct{ cause error }

func (err *fetchedActivationError) Error() string {
	return "activate fetched certified view: " + err.cause.Error()
}
func (err *fetchedActivationError) Unwrap() error { return err.cause }

// certifiedViewChanged only detects a new authority coordinate. It never
// persists the fetched envelope: the next runtime generation must prepare,
// apply and read back the real runtime before it may promote the LKG.
func certifiedViewChanged(ctx context.Context, store *deviceclient.Store, log io.Writer) bool {
	refreshContext, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	envelope, err := deviceclient.Fetch(refreshContext, store)
	if err != nil {
		fmt.Fprintf(log, "control view refresh unavailable; keeping certified LKG: %v\n", err)
		return false
	}
	current := store.LKG()
	return current == nil || envelope.Head.Index != current.Head.Index || control.HeadID(envelope.Head) != control.HeadID(current.Head)
}

// observeServer is the evidence-only HostAdapter for a Linux server-only
// authorization. It owns no listener and never reads legacy status/gossip;
// missing component or link evidence remains absent/unknown.
func observeServer(ctx context.Context, store *deviceclient.Store, options Options, done <-chan error, exact bool) error {
	lkg, ok := serverOnlyView(store)
	if !ok {
		return errors.New("Linux device is not server-only")
	}
	generation, err := options.Generation()
	if err != nil {
		return err
	}
	status := func(reported bool) Status {
		return Status{Schema: 1, DeviceID: lkg.View.DeviceID, Head: control.HeadID(lkg.Head), Floor: lkg.Head.Index,
			Preference: clientmodel.Preference{Schema: 1, Mode: clientmodel.ModeAuto}, NetworkGeneration: generation,
			Selections: []SelectionStatus{}, Observations: []clientmodel.Observation{}, Runtime: "running", Reported: reported}
	}
	// Listener and WireGuard readback already succeeded before this function is
	// entered. Expose that fact before a possibly slow report attempt so install
	// and supervision do not mistake a healthy server-only runtime for failure.
	if err := WriteStatus(options.Status, status(false)); err != nil {
		return err
	}
	components, componentErr := linuxComponentReadbacks(lkg.View, options.SingBox)
	if componentErr != nil {
		fmt.Fprintf(options.Log, "server component observation unavailable: %v\n", componentErr)
	}
	startedAt := options.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
	lastFacts := ""
	lastReportedAt := time.Time{}
	report := func(force bool) bool {
		digest, err := control.DeviceViewDigest(lkg.View)
		if err != nil {
			fmt.Fprintf(options.Log, "server observation view is invalid: %v\n", err)
			return false
		}
		links, linkErr := linuxLinkReadbacks(lkg.View, options.WireGuard, options.Ping, startedAt)
		if linkErr != nil {
			fmt.Fprintf(options.Log, "server link observation unavailable: %v\n", linkErr)
		}
		nextComponents, componentErr := linuxComponentReadbacks(lkg.View, options.SingBox)
		if componentErr != nil {
			fmt.Fprintf(options.Log, "server component observation unavailable: %v\n", componentErr)
			nextComponents = components
		}
		deployment, deploymentErr := linuxDeploymentReadback(options)
		if deploymentErr != nil {
			fmt.Fprintf(options.Log, "server deployment observation unavailable: %v\n", deploymentErr)
		}
		facts := runtimeFactsDigest(Activation{}, nextComponents, links, deployment)
		if !force && facts == lastFacts && options.Now().Sub(lastReportedAt) < 60*time.Second {
			return !lastReportedAt.IsZero()
		}
		value := control.DeviceReport{ReportedAt: options.Now().UTC().Truncate(time.Second).Format(time.RFC3339),
			Runtime:    &control.RuntimeReadback{State: "running", AppliedViewDigest: digest, Exact: exact, StartedAt: startedAt},
			Components: append([]control.ComponentReadback(nil), nextComponents...), Links: links, Deployment: deployment}
		reportContext, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		if err := deviceclient.Report(reportContext, store, value); err != nil {
			fmt.Fprintf(options.Log, "private server observation unavailable: %v\n", err)
			return false
		} else {
			lastFacts, lastReportedAt, components = facts, options.Now(), nextComponents
		}
		return true
	}
	if reported := report(true); WriteStatus(options.Status, status(reported)) != nil {
		return errors.New("write Linux server runtime status")
	}
	ticker := time.NewTicker(options.RefreshPoll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-done:
			if err == nil {
				return errors.New("server sing-box exited unexpectedly")
			}
			return fmt.Errorf("server sing-box exited: %w", err)
		case <-ticker.C:
			if certifiedViewChanged(ctx, store, options.Log) {
				return errCertifiedViewChanged
			}
			if reported := report(false); WriteStatus(options.Status, status(reported)) != nil {
				return errors.New("write Linux server runtime status")
			}
		}
	}
}

func writeConfig(path, config string) error {
	return atomicJSONBytes(path, []byte(config))
}

func atomicJSONBytes(path string, body []byte) (retErr error) {
	if len(body) == 0 {
		return errors.New("runtime config is empty")
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(directory, ".runtime-config-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer func() {
		_ = file.Close()
		if retErr != nil {
			_ = os.Remove(temporary)
		}
	}()
	if err = file.Chmod(0o600); err == nil {
		_, err = file.Write(body)
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

func checkRuntime(singBox, config string) error {
	command := exec.Command(singBox, "check", "-c", config)
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("sing-box preflight failed: %w: %s", err, string(output))
	}
	return nil
}

func preflightRuntimeConfig(singBox, config string) error {
	directory, err := os.MkdirTemp("", "loom-runtime-preflight-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(directory)
	if err := os.Chmod(directory, 0o700); err != nil {
		return err
	}
	path := filepath.Join(directory, "config.json")
	if err := writeConfig(path, config); err != nil {
		return err
	}
	return checkRuntime(singBox, path)
}

func Preflight(deviceState, singBox string) error {
	store, err := deviceclient.Load(deviceState)
	if err != nil {
		return err
	}
	lkg, serverOnly := serverOnlyView(store)
	if !serverOnly {
		lkg, err = runtimeView(store)
		if err != nil {
			return err
		}
	}
	if err := protectLegacyServerRuntime(legacySingBoxConfig); err != nil {
		if overlay, overlayErr := loadMigrationOverlay(DefaultMigrationOverlay); overlayErr != nil || overlay == nil {
			return err
		}
	}
	directory, err := os.MkdirTemp("", "loom-linux-preflight-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(directory)
	path := filepath.Join(directory, "config.json")
	config := ""
	if serverOnly {
		config, err = renderServerRuntime(*lkg.View.ServerRuntime, "/etc/loom/tls/node.crt", "/etc/loom/tls/node.key",
			lkg.View.RequiresServerDomainIdentification())
	} else {
		caPath := filepath.Join(directory, "data-plane-ca.crt")
		config, err = accessRuntimeConfig(lkg.View, caPath, nil)
		if lkg.View.ServerRuntime != nil {
			config, err = mergeServerRuntime(config, *lkg.View.ServerRuntime, "/etc/loom/tls/node.crt", "/etc/loom/tls/node.key",
				lkg.View.RequiresServerDomainIdentification())
		}
	}
	if err != nil {
		return err
	}
	if lkg.View.ServerRuntime == nil {
		if overlay, overlayErr := loadMigrationOverlay(DefaultMigrationOverlay); overlayErr != nil {
			return overlayErr
		} else if overlay != nil {
			return errors.New("migration overlay exists without a certified ServerRuntime")
		}
	}
	if lkg.View.ServerRuntime != nil {
		config, _, err = applyMigrationOverlay(config, controlServerProfile{
			Protocol: lkg.View.ServerRuntime.Protocol, ListenPort: lkg.View.ServerRuntime.ListenPort}, DefaultMigrationOverlay)
		if err != nil {
			return err
		}
	}
	if err := writeConfig(path, config); err != nil {
		return err
	}
	return checkRuntime(singBox, path)
}

func protectLegacyServerRuntime(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect existing server runtime: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > 16<<20 {
		return errors.New("existing sing-box config is not a bounded regular file")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read existing server runtime: %w", err)
	}
	server, err := clientruntime.HasServerInbound(body)
	if err != nil {
		return fmt.Errorf("inspect existing server runtime: %w", err)
	}
	if server {
		return errors.New("refusing to replace a server data-plane with the client-only runtime")
	}
	return nil
}

func tryFetch(store *deviceclient.Store, log io.Writer) *control.DeviceViewEnvelope {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	envelope, err := deviceclient.Fetch(ctx, store)
	if err != nil {
		fmt.Fprintf(log, "control sync unavailable; continuing from certified LKG: %v\n", err)
		return nil
	}
	return &envelope
}

func listenerOutputContainsPort(body []byte, port int) bool {
	suffix := ":" + strconv.Itoa(port)
	for _, field := range strings.Fields(string(body)) {
		if strings.HasSuffix(field, suffix) {
			return true
		}
	}
	return false
}

func waitServerListener(ctx context.Context, options Options, profile control.ServerRuntimeProfile, done <-chan error) error {
	arguments := []string{"-H", "-ltn"}
	if profile.Protocol == "hysteria2" {
		arguments = []string{"-H", "-lun"}
	}
	timeout := time.NewTimer(10 * time.Second)
	defer timeout.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-done:
			if err == nil {
				return errors.New("sing-box exited before listener readback")
			}
			return fmt.Errorf("sing-box exited before listener readback: %w", err)
		case <-timeout.C:
			return errors.New("sing-box listener readback timed out")
		case <-ticker.C:
			body, err := exec.Command(options.SS, arguments...).Output()
			if err == nil && listenerOutputContainsPort(body, profile.ListenPort) {
				return nil
			}
		}
	}
}

type configRollback struct {
	path    string
	body    []byte
	existed bool
}

func captureConfigRollback(path string) (configRollback, error) {
	rollback := configRollback{path: path}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return rollback, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > 16<<20 {
		return rollback, errors.New("existing runtime config is not a bounded regular file")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return rollback, err
	}
	rollback.body, rollback.existed = body, true
	return rollback, nil
}

func (rollback configRollback) restore() {
	if rollback.existed {
		_ = atomicJSONBytes(rollback.path, rollback.body)
	} else {
		_ = os.Remove(rollback.path)
	}
}

func reportSelection(ctx context.Context, store *deviceclient.Store, activation Activation, now time.Time,
	components []control.ComponentReadback, links []control.LinkReadback, deployment *control.DeploymentReadback,
	startedAt string, options Options, exact bool) error {
	selected := ""
	if len(activation.Selections) > 0 {
		selected = activation.Selections[0].CandidateID
	}
	report := control.DeviceReport{ReportedAt: now.UTC().Truncate(time.Second).Format(time.RFC3339),
		Observations: append([]control.Observation(nil), activation.State.Observations...)}
	if lkg := store.LKG(); lkg != nil && lkg.View.Schema == 2 {
		for _, selection := range activation.Selections {
			report.Selections = append(report.Selections, control.ReportSelection{Scope: selection.Scope, CandidateID: selection.CandidateID})
		}
		sort.Slice(report.Selections, func(i, j int) bool { return report.Selections[i].Scope < report.Selections[j].Scope })
		digest, err := control.DeviceViewDigest(lkg.View)
		if err != nil {
			return err
		}
		report.Runtime = &control.RuntimeReadback{State: "running", AppliedViewDigest: digest, Exact: exact, StartedAt: startedAt}
		report.Components = append([]control.ComponentReadback(nil), components...)
		report.Links = append([]control.LinkReadback(nil), links...)
		report.Deployment = deployment
	} else {
		report.Selection = selected
	}
	sort.Slice(report.Observations, func(i, j int) bool { return report.Observations[i].CandidateID < report.Observations[j].CandidateID })
	return deviceclient.Report(ctx, store, report)
}

func runtimeFactsDigest(activation Activation, components []control.ComponentReadback, links []control.LinkReadback,
	deployment *control.DeploymentReadback) string {
	body, _ := json.Marshal(struct {
		Selections   []SelectionStatus           `json:"selections"`
		Observations []control.Observation       `json:"observations"`
		Components   []control.ComponentReadback `json:"components"`
		Links        []control.LinkReadback      `json:"links"`
		Deployment   *control.DeploymentReadback `json:"deployment,omitempty"`
	}{activation.Selections, activation.State.Observations, components, links, deployment})
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func stopProcess(command *exec.Cmd, done <-chan error) error {
	if command.Process != nil {
		_ = command.Process.Signal(os.Interrupt)
	}
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.C:
		if command.Process != nil {
			_ = command.Process.Kill()
		}
		return <-done
	}
}

func activationFresh(activation Activation, now time.Time) bool {
	for _, selection := range activation.Selections {
		if observationState(activation.State.Observations, selection.CandidateID,
			activation.State.NetworkGeneration, now) == "unknown" {
			return false
		}
	}
	return len(activation.Selections) > 0
}

func runtimeStatus(lkg *control.DeviceViewEnvelope, activation Activation, reported bool) Status {
	return Status{Schema: 1, DeviceID: lkg.View.DeviceID, Head: control.HeadID(lkg.Head), Floor: lkg.Head.Index,
		Preference: activation.State.Preference, NetworkGeneration: activation.State.NetworkGeneration,
		Selections: activation.Selections, Observations: activation.State.Observations, Runtime: "running", Reported: reported}
}

// runGeneration owns one applied certified view. A refresh is deliberately a
// generation boundary because sing-box cannot bind both old and new server
// listeners simultaneously.
func runGeneration(ctx context.Context, options Options, allowFetch bool) (retErr error) {
	options.defaults()
	if err := os.Remove(options.Status); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove stale runtime status: %w", err)
	}
	store, err := deviceclient.Load(options.DeviceState)
	if err != nil {
		return err
	}
	previous := store.LKG()
	selected := previous
	var fetched *control.DeviceViewEnvelope
	if allowFetch && store.LKG() != nil {
		fetched = tryFetch(store, options.Log)
		if fetched != nil {
			selected = fetched
		}
	}
	promoted := fetched == nil
	defer func() {
		if fetched != nil && !promoted && retErr != nil && !errors.Is(retErr, errCertifiedViewChanged) && ctx.Err() == nil {
			retErr = &fetchedActivationError{cause: retErr}
		}
	}()
	configPrevious, err := captureConfigRollback(options.Config)
	if err != nil {
		return err
	}
	if lkg, ok := serverOnlyEnvelope(selected); ok {
		config, renderErr := renderServerRuntime(*lkg.View.ServerRuntime, options.ServerCert, options.ServerKey,
			lkg.View.RequiresServerDomainIdentification())
		if renderErr != nil {
			return renderErr
		}
		config, exact, overlayErr := applyMigrationOverlay(config, controlServerProfile{
			Protocol: lkg.View.ServerRuntime.Protocol, ListenPort: lkg.View.ServerRuntime.ListenPort}, options.MigrationOverlay)
		if overlayErr != nil {
			return overlayErr
		}
		if err := preflightRuntimeConfig(options.SingBox, config); err != nil {
			return err
		}
		var previousServer *control.ServerRuntimeProfile
		if previous != nil {
			previousServer = previous.View.ServerRuntime
		}
		wireGuard, wireGuardErr := applyWireGuard(lkg.View.ServerRuntime, previousServer, lkg.View.Server, options)
		if wireGuardErr != nil {
			return wireGuardErr
		}
		activated := false
		defer func() {
			if !activated {
				wireGuard.Rollback()
				configPrevious.restore()
			}
		}()
		if err := writeConfig(options.Config, config); err != nil {
			return err
		}
		command := exec.Command(options.SingBox, "run", "-c", options.Config)
		command.Stdout, command.Stderr = options.Log, options.Log
		if err := command.Start(); err != nil {
			return err
		}
		done := make(chan error, 1)
		go func() { done <- command.Wait() }()
		stopped := false
		defer func() {
			if !stopped {
				_ = stopProcess(command, done)
			}
		}()
		if err := waitServerListener(ctx, options, *lkg.View.ServerRuntime, done); err != nil {
			return err
		}
		if err := readbackWireGuard(*lkg.View.ServerRuntime, options); err != nil {
			return err
		}
		if fetched != nil {
			if err := store.SaveLKG(*fetched); err != nil {
				return err
			}
		}
		wireGuard.Commit()
		activated = true
		promoted = true
		err := observeServer(ctx, store, options, done, exact)
		if ctx.Err() != nil {
			stopped = true
			_ = stopProcess(command, done)
		}
		return err
	}
	lkg, err := accessView(selected)
	if err != nil {
		return err
	}
	if lkg.View.ServerRuntime == nil {
		if overlay, overlayErr := loadMigrationOverlay(options.MigrationOverlay); overlayErr != nil {
			return overlayErr
		} else if overlay != nil {
			return errors.New("migration overlay exists without a certified ServerRuntime")
		}
	}
	caPrevious, err := captureConfigRollback(options.DataPlaneCA)
	if err != nil {
		return err
	}
	caPromoted := false
	defer func() {
		if !caPromoted {
			caPrevious.restore()
		}
	}()
	endpointExclusions := []string(nil)
	if lkg.View.RequiresServerDomainIdentification() {
		endpointExclusions, err = deviceclient.EndpointRouteExclusions(ctx, lkg.View.Endpoints, lkg.View.DNS)
		if err != nil {
			return err
		}
	}
	runtimeConfig, err := accessRuntimeConfig(lkg.View, options.DataPlaneCA, endpointExclusions)
	if err != nil {
		return err
	}
	if lkg.View.ServerRuntime != nil {
		runtimeConfig, err = mergeServerRuntime(runtimeConfig, *lkg.View.ServerRuntime, options.ServerCert, options.ServerKey,
			lkg.View.RequiresServerDomainIdentification())
		if err != nil {
			return err
		}
	}
	exact := true
	if lkg.View.ServerRuntime != nil {
		runtimeConfig, exact, err = applyMigrationOverlay(runtimeConfig, controlServerProfile{
			Protocol: lkg.View.ServerRuntime.Protocol, ListenPort: lkg.View.ServerRuntime.ListenPort}, options.MigrationOverlay)
		if err != nil {
			return err
		}
	}
	if err := preflightRuntimeConfig(options.SingBox, runtimeConfig); err != nil {
		return err
	}
	var previousServer *control.ServerRuntimeProfile
	if previous != nil {
		previousServer = previous.View.ServerRuntime
	}
	wireGuard, err := applyWireGuard(lkg.View.ServerRuntime, previousServer, lkg.View.Server, options)
	if err != nil {
		return err
	}
	activated := false
	defer func() {
		if !activated {
			wireGuard.Rollback()
			configPrevious.restore()
		}
	}()
	if err := writeConfig(options.Config, runtimeConfig); err != nil {
		return err
	}
	command := exec.Command(options.SingBox, "run", "-c", options.Config)
	command.Stdout, command.Stderr = options.Log, options.Log
	if err := command.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	stopped := false
	defer func() {
		if !stopped {
			_ = stopProcess(command, done)
		}
	}()
	selector, err := NewHTTPSelector(runtimeConfig)
	if err != nil {
		return err
	}
	scopes, _, err := scopesFor(lkg.View.Routes)
	if err != nil {
		return err
	}
	if err := waitSelector(ctx, selector, scopes); err != nil {
		return err
	}
	if lkg.View.ServerRuntime != nil {
		if err := waitServerListener(ctx, options, *lkg.View.ServerRuntime, done); err != nil {
			return err
		}
		if err := readbackWireGuard(*lkg.View.ServerRuntime, options); err != nil {
			return err
		}
	}
	if fetched != nil {
		if err := store.SaveLKG(*fetched); err != nil {
			return err
		}
	}
	wireGuard.Commit()
	activated = true
	caPromoted = true
	promoted = true
	startedAt := options.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
	components, componentErr := linuxComponentReadbacks(lkg.View, options.SingBox)
	if componentErr != nil {
		fmt.Fprintf(options.Log, "component observation unavailable: %v\n", componentErr)
	}
	generation, err := options.Generation()
	if err != nil {
		return err
	}
	local, err := LoadLocalState(options.LocalState, generation)
	if err != nil {
		return err
	}
	probe := options.probeForView(lkg.View)
	activation, activateErr := Activate(ctx, selector, lkg.View.Routes, local, probe, options.Now)
	if activation.State.Schema == 0 {
		return activateErr
	}
	saved, err := SaveObservations(options.LocalState, activation.State)
	if err != nil {
		return err
	}
	activation.State = saved
	reported := false
	lastReportedAt := time.Time{}
	reportContext, cancel := context.WithTimeout(ctx, 20*time.Second)
	links, linkErr := linuxLinkReadbacks(lkg.View, options.WireGuard, options.Ping, startedAt)
	if linkErr != nil {
		fmt.Fprintf(options.Log, "link observation unavailable: %v\n", linkErr)
	}
	deployment, deploymentErr := linuxDeploymentReadback(options)
	if deploymentErr != nil {
		fmt.Fprintf(options.Log, "deployment observation unavailable: %v\n", deploymentErr)
	}
	lastFacts := runtimeFactsDigest(activation, components, links, deployment)
	// Runtime/selector readback and private report delivery are distinct facts.
	// Publish the former immediately so an unavailable control tunnel cannot
	// make a running data plane look as if it never started. A successful report
	// below atomically replaces this projection with Reported=true.
	if err := WriteStatus(options.Status, runtimeStatus(lkg, activation, false)); err != nil {
		cancel()
		return err
	}
	if err := reportSelection(reportContext, store, activation, options.Now(), components, links, deployment, startedAt, options, exact); err != nil {
		fmt.Fprintf(options.Log, "private report unavailable; data plane remains on certified LKG: %v\n", err)
	} else {
		reported = true
		lastReportedAt = options.Now()
	}
	cancel()
	if err := WriteStatus(options.Status, runtimeStatus(lkg, activation, reported)); err != nil {
		return err
	}
	if activateErr != nil {
		fmt.Fprintf(options.Log, "all currently eligible candidates are unavailable: %v\n", activateErr)
	}
	ticker := time.NewTicker(options.RefreshPoll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			stopped = true
			_ = stopProcess(command, done)
			return nil
		case err := <-done:
			stopped = true
			if err == nil {
				return errors.New("sing-box exited unexpectedly")
			}
			return fmt.Errorf("sing-box exited: %w", err)
		case <-ticker.C:
			if certifiedViewChanged(ctx, store, options.Log) {
				return errCertifiedViewChanged
			}
			generation, generationErr := options.Generation()
			if generationErr != nil {
				fmt.Fprintf(options.Log, "network generation refresh unavailable: %v\n", generationErr)
				continue
			}
			at := options.Now().UTC().Truncate(time.Second)
			local, loadErr := LoadLocalState(options.LocalState, generation)
			if loadErr != nil {
				fmt.Fprintf(options.Log, "runtime refresh state unavailable: %v\n", loadErr)
				continue
			}
			next, nextErr := Activate(ctx, selector, lkg.View.Routes, local, probe, options.Now)
			if next.State.Schema == 0 {
				fmt.Fprintf(options.Log, "runtime refresh unavailable: %v\n", nextErr)
				continue
			}
			saved, saveErr := SaveObservations(options.LocalState, next.State)
			if saveErr != nil {
				fmt.Fprintf(options.Log, "runtime refresh was not saved: %v\n", saveErr)
				continue
			}
			next.State = saved
			nextComponents, componentErr := linuxComponentReadbacks(lkg.View, options.SingBox)
			if componentErr != nil {
				fmt.Fprintf(options.Log, "component observation unavailable: %v\n", componentErr)
				nextComponents = components
			}
			links, linkErr := linuxLinkReadbacks(lkg.View, options.WireGuard, options.Ping, startedAt)
			if linkErr != nil {
				fmt.Fprintf(options.Log, "link observation unavailable: %v\n", linkErr)
			}
			deployment, deploymentErr := linuxDeploymentReadback(options)
			if deploymentErr != nil {
				fmt.Fprintf(options.Log, "deployment observation unavailable: %v\n", deploymentErr)
			}
			facts := runtimeFactsDigest(next, nextComponents, links, deployment)
			if reported && at.Sub(lastReportedAt) < 60*time.Second && generation == activation.State.NetworkGeneration &&
				activationFresh(next, at) && facts == lastFacts {
				activation = next
				continue
			}
			reportContext, reportCancel := context.WithTimeout(ctx, 20*time.Second)
			reportErr := reportSelection(reportContext, store, next, options.Now(), nextComponents, links, deployment, startedAt, options, exact)
			reportCancel()
			reported = reportErr == nil
			if reported {
				lastReportedAt = options.Now()
				lastFacts = facts
				components = nextComponents
			}
			if reportErr != nil {
				fmt.Fprintf(options.Log, "private report unavailable; data plane remains on certified LKG: %v\n", reportErr)
			}
			activation = next
			if err := WriteStatus(options.Status, runtimeStatus(lkg, activation, reported)); err != nil {
				return err
			}
			if nextErr != nil {
				fmt.Fprintf(options.Log, "all currently eligible candidates are unavailable: %v\n", nextErr)
			}
		}
	}
}

// Run supervises certified runtime generations. A rejected fetched generation
// is never promoted; its config and WireGuard transaction roll back, then the
// previous certified LKG is restarted before the next bounded retry.
func Run(ctx context.Context, options Options) error {
	allowFetch := true
	for {
		err := runGeneration(ctx, options, allowFetch)
		if ctx.Err() != nil {
			return nil
		}
		if errors.Is(err, errCertifiedViewChanged) {
			allowFetch = true
			continue
		}
		var activationError *fetchedActivationError
		if errors.As(err, &activationError) {
			options.defaults()
			fmt.Fprintf(options.Log, "fetched certified view was not activated; restoring prior runtime: %v\n", activationError.cause)
			allowFetch = false
			continue
		}
		return err
	}
}
