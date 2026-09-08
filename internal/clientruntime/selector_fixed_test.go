package clientruntime

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"loom/internal/agent"
	"loom/internal/attest"
	"loom/internal/clientcore"
	"loom/internal/clientreport"
)

func multipleInternetServicesFixture(t *testing.T) ([]byte, []byte) {
	t.Helper()
	body, plan := pathPlanFixture(t)
	var sb singBoxConfig
	var cfg agent.Config
	_ = json.Unmarshal(body, &sb)
	_ = json.Unmarshal(plan, &cfg)
	previous := cfg.Declarations[0].Selector
	const internetSelector = "opaque:route@internet"
	cfg.Declarations[0].Selector = internetSelector
	for i := range sb.Outbounds {
		if sb.Outbounds[i].Tag == previous {
			sb.Outbounds[i].Tag = internetSelector
		}
	}
	for i := range sb.Route.Rules {
		if sb.Route.Rules[i].Outbound == previous {
			sb.Route.Rules[i].Outbound = internetSelector
		}
	}
	for _, name := range []string{"demo-web", "demo-api"} {
		d := cfg.Declarations[0]
		d.ID, d.Selector, d.Targets = name, "opaque:"+name, []string{"https://" + name + ".example/health"}
		candidate := agent.Cand{Tag: name + "-candidate", Chain: []string{"demo-other"}, ProbeUser: name + "-probe"}
		d.Candidates = []agent.Cand{candidate}
		cfg.Declarations = append(cfg.Declarations, d)
		proxy := sb.Outbounds[3]
		proxy.Tag = candidate.Tag
		sb.Outbounds = append(sb.Outbounds, proxy, singBoxOutbound{Type: "selector", Tag: d.Selector, Outbounds: []string{candidate.Tag}, Default: candidate.Tag})
		sb.Inbounds[0].Users = append(sb.Inbounds[0].Users, singBoxUser{Username: candidate.ProbeUser, Password: cfg.ProbeSecret})
		sb.Route.Rules = append([]singBoxRule{
			{Inbound: []string{"probe-in"}, AuthUser: []string{candidate.ProbeUser}, Outbound: candidate.Tag},
			{Inbound: []string{"tun-in", "in-1080"}, Domain: []string{name + ".example"}, Outbound: d.Selector},
		}, sb.Route.Rules...)
	}
	// §7.3：必要运行规则不是业务分流，统一上网路径时必须逐字保留。
	sb.Route.Rules = append([]singBoxRule{
		windowsTUNDNSRule(),
		{Inbound: []string{"tun-in", "in-1080"}, IPCIDR: []string{"10.0.0.0/8"}, Outbound: "dns-out"},
		{Inbound: []string{"tun-in", "in-1080"}, Domain: []string{"bootstrap.example"}, Outbound: "dns-out"},
	}, sb.Route.Rules...)
	for _, d := range cfg.Declarations {
		cfg.Selectors = append(cfg.Selectors, agent.SelectorPlan{Selector: d.Selector, Default: d.Candidates[0].Tag, Candidates: d.Candidates})
	}
	body, _ = json.Marshal(sb)
	plan, _ = json.Marshal(cfg)
	return body, plan
}

func TestWindowsFixedInternetDoesNotTreatBroadOrMixedPrefixesAsPrivate(t *testing.T) {
	for _, test := range []struct {
		prefixes []string
		touches  bool
		private  bool
	}{
		{[]string{"10.0.0.0/8", "192.168.0.0/16"}, true, true},
		{[]string{"10.0.0.0/4"}, true, false},
		{[]string{"10.0.0.0/8", "192.0.2.0/24"}, true, false},
		{[]string{"192.0.2.0/24"}, false, false},
		{[]string{"fc00::/7", "fe80::/10"}, true, true},
		{[]string{"fc00::/1"}, true, false},
	} {
		if touches, private, err := windowsPrivateRouteScope(singBoxRule{IPCIDR: test.prefixes}); err != nil || touches != test.touches || private != test.private {
			t.Fatalf("[§7.3] private 运行规则识别=%v/%v，预期=%v/%v: %v", touches, private, test.touches, test.private, err)
		}
	}
}

func TestWindowsFixedExitRejectsIndependentPrivateRoutingWithoutChangingAuto(t *testing.T) {
	for _, name := range []string{"private", "mixed-domain", "mixed-suffix", "mixed-prefix", "broad-prefix", "invalid-prefix"} {
		t.Run(name, func(t *testing.T) {
			body, planBody := multipleInternetServicesFixture(t)
			var sb singBoxConfig
			var cfg agent.Config
			_ = json.Unmarshal(body, &sb)
			_ = json.Unmarshal(planBody, &cfg)
			rule := singBoxRule{Inbound: []string{"tun-in", "in-1080"}, IPCIDR: []string{"10.0.0.0/8"}, Outbound: cfg.Declarations[1].Selector}
			switch name {
			case "mixed-domain":
				rule.Domain = []string{"public.example"}
			case "mixed-suffix":
				rule.DomainSuffix = []string{"public.example"}
			case "mixed-prefix":
				rule.IPCIDR = append(rule.IPCIDR, "192.0.2.0/24")
			case "broad-prefix":
				rule.IPCIDR = []string{"10.0.0.0/4"}
			case "invalid-prefix":
				rule.IPCIDR = []string{"demo-invalid"}
			}
			sb.Route.Rules = append([]singBoxRule{rule}, sb.Route.Rules...)
			body, _ = json.Marshal(sb)
			originalBody := slices.Clone(body)
			plan, err := validateWindowsAgentPair(body, planBody, "")
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := plan.Derive(body, clientcore.Preference{Schema: 1, Mode: clientcore.FixedExit, Exit: "demo-exit"}); err == nil {
				t.Fatal("[§7.3] 固定模式静默停用了必要私网决策或改写了混合规则")
			}
			autoBody, auto, err := plan.Derive(body, clientcore.Preference{Schema: 1, Mode: clientcore.Auto})
			var restored singBoxConfig
			_ = json.Unmarshal(autoBody, &restored)
			if err != nil || !slices.Equal(originalBody, body) || !reflect.DeepEqual(auto, &cfg) || !reflect.DeepEqual(restored, sb) {
				t.Fatal("[§7.3] 被拒绝的偏好改变了签名配置或原 Auto 的私网 Agent", err)
			}
		})
	}
}

func TestWindowsFixedExitUnifiesServicesAndAutoRestoresSignedRouting(t *testing.T) {
	body, planBody := multipleInternetServicesFixture(t)
	plan, err := validateWindowsAgentPair(body, planBody, "")
	if err != nil {
		t.Fatal(err)
	}
	var source singBoxConfig
	_ = json.Unmarshal(body, &source)
	fixedBody, fixed, err := plan.Derive(body, clientcore.Preference{Schema: 1, Mode: clientcore.FixedExit, Exit: "demo-exit"})
	if err != nil {
		t.Fatal(err)
	}
	if len(fixed.Declarations) != 1 || len(fixed.Selectors) != 1 || len(fixed.Declarations[0].Candidates) != 2 || !reflect.DeepEqual(fixed.Declarations[0].Targets, plan.config.Declarations[0].Targets) || fixed.Declarations[0].Objective != plan.config.Declarations[0].Objective {
		t.Fatal("[§7.3] 固定出口仍存在多 Service 决策，或改变了默认上网的真实探测策略")
	}
	var derived singBoxConfig
	_ = json.Unmarshal(fixedBody, &derived)
	if !reflect.DeepEqual(source.Inbounds, derived.Inbounds) || !reflect.DeepEqual(source.DNS, derived.DNS) || len(source.Route.Rules) != len(derived.Route.Rules) || derived.Route.Final != source.Route.Final {
		t.Fatal("[§7.3] 统一路径删除了必要的入口、DNS、探测或 fail-closed 边界")
	}
	serviceRules := 0
	for i, original := range source.Route.Rules {
		rule := derived.Route.Rules[i]
		if slices.Contains(original.Domain, "demo-web.example") || slices.Contains(original.Domain, "demo-api.example") {
			serviceRules++
			if rule.Outbound != fixed.Declarations[0].Selector {
				t.Fatal("[§7.3] 不同 Service 请求仍指向独立 selector")
			}
			original.Outbound = rule.Outbound
		}
		if !reflect.DeepEqual(original, rule) {
			t.Fatal("[§7.3] 业务引用以外的 DNS、private、bootstrap 或 probe 规则被改写")
		}
	}
	if serviceRules != 2 || len(plan.ObservationDeclarations(clientcore.Preference{Mode: clientcore.FixedExit})) != 1 {
		t.Fatal("[§7.3] 固定路径观测仍暴露已停用的 Service 行")
	}
	autoBody, auto, err := plan.Derive(body, clientcore.Preference{Schema: 1, Mode: clientcore.Auto})
	if err != nil {
		t.Fatal(err)
	}
	var restored singBoxConfig
	_ = json.Unmarshal(autoBody, &restored)
	if !reflect.DeepEqual(restored, source) || len(auto.Declarations) != 3 || !reflect.DeepEqual(auto, &plan.config) {
		t.Fatal("[§7.3] 返回 Auto 未恢复完整签名 Service 规则和策略")
	}
}

func TestWindowsFixedExitRejectsAmbiguousOrMissingInternetBoundary(t *testing.T) {
	for _, name := range []string{"missing", "duplicate", "partial", "unbounded", "probe"} {
		t.Run(name, func(t *testing.T) {
			body, planBody := multipleInternetServicesFixture(t)
			var sb singBoxConfig
			_ = json.Unmarshal(body, &sb)
			last := len(sb.Route.Rules) - 1
			switch name {
			case "missing":
				sb.Route.Rules = sb.Route.Rules[:last]
			case "duplicate":
				sb.Route.Rules = append(sb.Route.Rules, sb.Route.Rules[last])
			case "partial":
				sb.Route.Rules[last].Inbound = []string{"in-1080"}
			case "unbounded":
				sb.Route.Rules[last].Inbound = nil
			case "probe":
				sb.Route.Rules[last].Inbound = []string{"in-1080", "probe-in"}
			}
			body, _ = json.Marshal(sb)
			plan, err := validateWindowsAgentPair(body, planBody, "")
			if err != nil {
				if name == "missing" {
					t.Fatal("[§5.8] 缺少默认上网策略仍应允许 Auto 按原规则 fail closed", err)
				}
				return
			}
			if _, _, err := plan.Derive(body, clientcore.Preference{Schema: 1, Mode: clientcore.FixedExit, Exit: "demo-exit"}); err == nil {
				t.Fatal("[§7.3] 接受了无法唯一界定上网范围的固定出口")
			}
		})
	}
}

func TestWindowsFixedInternetAgentChoosesOneActualPrefixForAllServices(t *testing.T) {
	body, planBody := multipleInternetServicesFixture(t)
	network, cfg := agentNetworkFixturePlan(t, body, planBody)
	opts := agentTestOptions(t)
	runRound(t, cfg, opts)
	network.mu.Lock()
	current, puts := network.current, slices.Clone(network.puts)
	network.mu.Unlock()
	if len(cfg.Declarations) != 1 || current != "opaque:z@fast" || !slices.Equal(puts, []string{current}) {
		t.Fatal("[§7.3] 统一上网路径没有根据单次入口探测选择较快入口")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runtime := &WindowsAgent{ctx: ctx, done: make(chan struct{}), config: cfg, statePath: opts.StatePath}
	report, err := runtime.Report(ctx, time.Now())
	if err != nil || len(report.Selections) != 1 || report.Selections[0].Declaration != cfg.Declarations[0].ID || report.Selections[0].Candidate != current || !slices.Equal(report.Selections[0].Chain, []string{"demo-prefix-b", "demo-exit"}) || report.Selections[0].Health == nil || !strings.Contains(report.Selections[0].Reason, "decision_scope=") {
		t.Fatal("[§16.1] 固定出口报告没有唯一实际路径、质量和切换原因", err)
	}
	health := report.Selections[0].Health
	if health.SelectedState != "unknown" || health.SelectedP50MS != nil || health.SelectedP95MS != nil || health.BestP50MS != nil {
		t.Fatal("[§16.1] 入口探测冒充完整路径质量")
	}
	key, cert, ca := fixedInternetReportIdentity(t, cfg.Node)
	defer clear(key)
	now := time.Now()
	observation, err := clientreport.BuildWithAgent(cfg.Node, "0123456789ab", nil, report, now, key, cert, ca)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := attest.VerifyFresh(observation.Attest, ca, now, time.Minute)
	if err != nil || claim.CanonicalVersion != 5 || claim.Agent == nil || len(claim.Agent.Selections) != 1 {
		t.Fatal("[§16.1] 真实统一路径没有通过 canonical v5 验签", err)
	}
	signed, _ := json.Marshal(claim.Agent)
	actual, _ := json.Marshal(report)
	if string(signed) != string(actual) {
		t.Fatal("[§16.1] 签名没有完整绑定实际单路径、质量、原因和 decision_scope")
	}
	observation.Attest.Agent.Selections[0].Candidate = "opaque:forged"
	if _, err := attest.VerifyFresh(observation.Attest, ca, now, time.Minute); err == nil {
		t.Fatal("[§16.1] 统一路径签名接受了篡改的候选")
	}
}

func fixedInternetReportIdentity(t *testing.T, node string) (keyPEM, certPEM, caPEM []byte) {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "demo-fixed-report-ca"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: node + ".node.internal"}, DNSNames: []string{node + ".node.internal"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, root, &key.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
}
