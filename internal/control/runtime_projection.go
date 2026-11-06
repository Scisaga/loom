package control

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
)

func digestContractValue(domain string, value any) (string, error) {
	body, err := CanonicalEncode(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte(domain), body...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func localCandidate(service Service, policy NetworkPolicy, finalExit string, records ...DNSRecord) (RouteCandidate, error) {
	entry := finalExit
	if finalExit == "direct" {
		entry = ""
	}
	return candidateForEntry(service, policy, entry, TransportResource{}, finalExit, records...)
}

// servicePermissionValues verifies the selected current values without requiring
// a deleted Policy or Service to reappear. Missing references grant nothing.
func servicePermissionValues(view DeviceView) (map[string]Service, map[string]NetworkPolicy, error) {
	if validateIDSet(view.PolicyIDs) != nil || view.Services == nil || view.Policies == nil {
		return nil, nil, errors.New("service permission values are incomplete")
	}
	services := map[string]Service{}
	for index, service := range view.Services {
		if service.ValidateCurrent() != nil || index > 0 && view.Services[index-1].ID >= service.ID {
			return nil, nil, errors.New("view Services are invalid or not uniquely sorted")
		}
		services[service.ID] = service
	}
	byPolicy := map[string]NetworkPolicy{}
	for index, policy := range view.Policies {
		selected := containsString(view.PolicyIDs, policy.ID)
		service, present := services[policy.ServiceID]
		measuringExit := present && policy.Action == "allow" && policy.permitsEndpoint(service, view.DeviceID) &&
			(service.Kind == "internet" && containsString(view.Responsibilities, "internet_egress") || service.Kind == "local_network" && containsString(view.Responsibilities, "forward"))
		servingForward := containsString(view.Responsibilities, "forward") && policy.Action == "allow" && (policy.EntryScope.Allows(view.DeviceID) || policy.RelayScope.Allows(view.DeviceID))
		if policy.Validate() != nil || index > 0 && view.Policies[index-1].ID >= policy.ID || !selected && !measuringExit && !servingForward {
			return nil, nil, errors.New("view Policies are invalid, unassigned or not uniquely sorted")
		}
		if service, found := services[policy.ServiceID]; found && policy.ValidateForService(service) != nil {
			return nil, nil, errors.New("view Policy does not match its Service kind")
		}
		if !selected {
			continue
		}
		byPolicy[policy.ID] = policy
	}
	return services, byPolicy, nil
}

func matcherRule(matcher ServiceMatcher) map[string]any {
	if matcher.Port != 0 {
		port := matcher.Port
		matcher.Port = 0
		rule := matcherRule(matcher)
		rule["port"] = []int{port}
		return rule
	}
	switch matcher.Kind {
	case "public_internet":
		return map[string]any{"public_internet": true}
	case "dns_exact":
		return map[string]any{"domain": []string{matcher.Value}}
	case "dns_suffix":
		return map[string]any{"domain_suffix": []string{matcher.Value}}
	case "ip_prefix":
		return map[string]any{"ip_cidr": []string{matcher.Value}}
	default:
		panic("validated Service matcher has an unknown kind")
	}
}

// Capture routes the complete independently authorized scope to its selector.
// Current target restrictions are enforced there, rather than bypassing capture.
func captureServiceRule(service Service, records ...DNSRecord) map[string]any {
	rules := make([]any, 0, len(service.baseTargetMatchers(records...)))
	for _, matcher := range service.baseTargetMatchers(records...) {
		rules = append(rules, matcherRule(matcher))
	}
	return map[string]any{"type": "logical", "mode": "or", "rules": rules}
}

// ProjectAccessRuntime derives from stable authorization and explicit intent.
func ProjectAccessRuntime(view DeviceView, selected []string) ([]RouteCandidate, *RuntimeProfile, error) {
	value, err := ProjectDeviceExecution(view, selected)
	if err != nil {
		return nil, nil, err
	}
	return value.Routes, value.RuntimeProfile, nil
}

func targetMatchesService(target string, service Service, records ...DNSRecord) bool {
	if service.ValidateCurrent() != nil || ValidateHTTPSURL(target) != nil {
		return false
	}
	parsed, _ := url.Parse(target)
	port := 443
	if parsed.Port() != "" {
		port, _ = strconv.Atoi(parsed.Port())
	}
	base := false
	for _, matcher := range service.baseTargetMatchers(records...) {
		base = base || matcher.Matches(parsed.Hostname())
	}
	if !base {
		return false
	}
	for _, matcher := range service.TargetMatchers(records...) {
		if matcher.MatchesEndpoint(parsed.Hostname(), port) {
			return true
		}
	}
	return false
}

func validateDeviceViewAuthorization(view DeviceView) error { return validateStableView(view) }

// ProjectDeviceView consumes authenticated facts and independently verified
// immutable release sets. It performs no I/O; the envelope signer attaches the
// actual member proof and verified fact frontier.
func ProjectDeviceView(projection Projection, deviceID string, releases ...ReleaseSet) (DeviceView, error) {
	for _, service := range projection.NetworkIntent.Services {
		if err := service.ValidateCurrent(); err != nil {
			return DeviceView{}, errors.New("historical Service requires explicit forward facts before current View projection")
		}
	}
	view, err := projectDeviceView(projection, deviceID, releases...)
	if err != nil {
		return DeviceView{}, err
	}
	if err := view.Validate(); err != nil {
		return DeviceView{}, err
	}
	return view, nil
}

// Only the private configuration builder may defer validation to its strict encoder.
func projectDeviceView(projection Projection, deviceID string, releases ...ReleaseSet) (DeviceView, error) {
	if len(projection.NetworkIntent.BusinessProbeTargets) != 0 {
		return DeviceView{}, errors.New("historical probe pool requires explicit Service forward replacement and retirement")
	}
	var authorization DeviceAuthorization
	found := false
	for _, value := range projection.DeviceAuthorizations {
		if value.ID == deviceID {
			if found {
				return DeviceView{}, errors.New("device authorization is ambiguous")
			}
			authorization, found = value, true
		}
	}
	identity, identityFound := identityFor(projection, deviceID)
	if !identityFound || found && authorization.Validate() != nil {
		return DeviceView{}, errors.New("device identity or authorization is unavailable")
	}
	view := DeviceView{NetworkID: projection.NetworkID, DNSRecords: projectDNSRecords(projection.NetworkIntent.DNSRecords), Schema: 3, DeviceID: identity.ID, Name: identity.Name, Platform: identity.Platform, DevicePublicKey: identity.DevicePublicKey,
		WireGuardPublicKey: authorization.WireGuardPublicKey,
		Responsibilities:   append([]string{}, authorization.Responsibilities...), PolicyIDs: append([]string{}, authorization.PolicyIDs...),
		Services: []Service{}, Policies: []NetworkPolicy{}, Resources: []TransportResource{}, Nodes: []ViewNode{}, TransportCredentials: []TransportCredential{}, Endpoints: []EndpointGeneration{},
		DNSServers: append([]string{}, authorization.DNSServers...), ExpectedComponents: []ComponentReadback{}}
	view.PublicTrust = append([]PublicTrust(nil), projection.NetworkIntent.PublicTrust...)
	var componentErr error
	view.ExpectedComponents, componentErr = deviceExpectedComponents(projection, deviceID, releases)
	if componentErr != nil {
		return DeviceView{}, componentErr
	}
	for _, member := range projection.Config.Members {
		if member.NodeID == deviceID {
			view.Responsibilities = append(view.Responsibilities, "control")
			break
		}
	}
	sort.Strings(view.Responsibilities)
	usable := executableServices(projection)
	serviceIDs := map[string]bool{}
	for _, policy := range projection.NetworkIntent.Policies {
		if !containsString(view.PolicyIDs, policy.ID) {
			continue
		}
		for _, service := range projection.NetworkIntent.Services {
			if _, active := usable[service.ID]; active && service.ID == policy.ServiceID && policy.ValidateForService(service) == nil {
				view.Policies = append(view.Policies, policy)
				serviceIDs[service.ID] = true
				break
			}
		}
	}
	for _, service := range projection.NetworkIntent.Services {
		if serviceIDs[service.ID] {
			view.Services = append(view.Services, service)
		}
	}
	sort.Slice(view.Policies, func(i, j int) bool { return view.Policies[i].ID < view.Policies[j].ID })
	sort.Slice(view.Services, func(i, j int) bool { return view.Services[i].ID < view.Services[j].ID })
	err := projectViewResources(projection, &view)
	if err != nil {
		return DeviceView{}, err
	}
	view.DNSRecords = projectViewDNS(view)
	for _, endpoint := range projection.EndpointGenerations {
		if endpoint.State != "serving" && endpoint.State != "draining" || !containsString(endpoint.Modes, "device") {
			continue
		}
		if _, member := proofMember(projection.Config, endpoint.OwnerControlID); member {
			view.Endpoints = append(view.Endpoints, endpoint)
		}
	}
	sort.Slice(view.Endpoints, func(i, j int) bool {
		return view.Endpoints[i].ID < view.Endpoints[j].ID || view.Endpoints[i].ID == view.Endpoints[j].ID && view.Endpoints[i].Generation < view.Endpoints[j].Generation
	})
	// An unrepresentable concurrent website port conflict removes only the
	// reserved website projection. The management snapshot exposes the conflict.
	view.WebEndpoints, _ = WebsiteEndpoints(projection)
	return view, nil
}

// ServicesOverlap proves overlaps available from the certified matcher values;
// it never resolves DNS to invent a relation between a name and an IP prefix.
func ServicesOverlap(left, right Service) bool {
	if left.IsPublicInternet() || right.IsPublicInternet() {
		return left.IsPublicInternet() && right.IsPublicInternet()
	}
	for _, a := range left.TargetMatchers() {
		for _, b := range right.TargetMatchers() {
			if a.Kind == "ip_prefix" && b.Kind == "ip_prefix" {
				pa, ea := netip.ParsePrefix(a.Value)
				pb, eb := netip.ParsePrefix(b.Value)
				if ea == nil && eb == nil && (pa.Contains(pb.Addr()) || pb.Contains(pa.Addr())) {
					return true
				}
			}
			if a.Kind == "dns_exact" && b.Matches(a.Value) || b.Kind == "dns_exact" && a.Matches(b.Value) || a.Kind == "dns_suffix" && b.Kind == "dns_suffix" && (a.Matches(b.Value) || b.Matches(a.Value)) {
				return true
			}
		}
	}
	return false
}
