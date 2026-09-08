package clientruntime

import (
	"errors"
	"net/netip"
	"slices"

	"loom/internal/agent"
	"loom/internal/clientcore"
)

// §7.3：默认上网声明来自签名业务规则的结构，不能从 opaque selector 或 Service 名称猜测。
func windowsInternetSelector(sb *singBoxConfig) (string, []string, error) {
	var business []string
	selectors := map[string]bool{}
	for _, inbound := range sb.Inbounds {
		if inbound.Type == "tun" || inbound.Type == "mixed" && inbound.ListenPort == 1080 {
			business = append(business, inbound.Tag)
		}
	}
	for _, outbound := range sb.Outbounds {
		selectors[outbound.Tag] = outbound.Type == "selector"
	}
	selector := ""
	for _, rule := range sb.Route.Rules {
		if rule.Action != "" || !selectors[rule.Outbound] || len(rule.AuthUser)+len(rule.Domain)+len(rule.DomainSuffix)+len(rule.IPCIDR)+len(rule.Port) != 0 {
			continue
		}
		matches := len(rule.Inbound) == 0
		for _, inbound := range rule.Inbound {
			matches = matches || slices.Contains(business, inbound)
		}
		if !matches {
			continue
		}
		// §13.5：完整且唯一的受管入口边界才能扩大 Service 路由，不能波及探测或其他本地入口。
		if selector != "" || len(business) == 0 || len(rule.Inbound) != len(business) {
			return "", nil, errors.New("[§7.3] 无法唯一识别完整业务入口的默认上网 selector")
		}
		for _, inbound := range business {
			if !slices.Contains(rule.Inbound, inbound) {
				return "", nil, errors.New("[§7.3] 默认上网规则混合了业务和非业务入口")
			}
		}
		selector = rule.Outbound
	}
	return selector, business, nil
}

// §7.3：domain / domain_suffix / ip_cidr 是 OR，不能把域名误当作私网前缀的附加限制。
// hasPrivate 也包含横跨公网和私网的宽前缀，防止改写时破坏其原有私网分支。
func windowsPrivateRouteScope(rule singBoxRule) (hasPrivate, onlyPrivate bool, err error) {
	onlyPrivate = len(rule.IPCIDR) > 0 && len(rule.Domain)+len(rule.DomainSuffix) == 0
	for _, value := range rule.IPCIDR {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return false, false, errors.New("[§7.3] 上网规则的 IP 前缀无效，不能安全合并")
		}
		private := false
		for _, block := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10", "::1/128", "fc00::/7", "fe80::/10"} {
			allowed := netip.MustParsePrefix(block)
			private = private || prefix.Bits() >= allowed.Bits() && allowed.Contains(prefix.Addr())
			hasPrivate = hasPrivate || prefix.Overlaps(allowed)
		}
		onlyPrivate = onlyPrivate && private
	}
	return hasPrivate, onlyPrivate, nil
}

// §7.3：只把受管上网规则引用统一到同一 selector；DNS、探测认证及必要内网/引导规则保持原样。
func (p *WindowsSelectorPlan) fixedInternetConfig(sb *singBoxConfig, preference clientcore.Preference) (*agent.Config, error) {
	selector, business, err := windowsInternetSelector(sb)
	if err != nil {
		return nil, err
	}
	if selector == "" || selector != p.internetSelector {
		return nil, errors.New("[§7.3] 当前签名配置没有唯一的默认上网 selector，不能统一固定出口")
	}
	index := slices.IndexFunc(p.config.Declarations, func(d agent.Decl) bool { return d.Selector == selector })
	if index < 0 {
		return nil, errors.New("[§7.3] 默认上网 selector 缺少可执行的完整路径测量声明")
	}
	d := p.config.Declarations[index]
	d.Candidates = slices.DeleteFunc(slices.Clone(d.Candidates), func(c agent.Cand) bool {
		return len(c.Chain) == 0 || c.Chain[len(c.Chain)-1] != preference.Exit
	})
	if len(d.Candidates) == 0 {
		return nil, errors.New("[§5.8] 默认上网声明没有到所选出口的授权候选")
	}
	selectors := map[string]bool{}
	for i := range sb.Outbounds {
		o := &sb.Outbounds[i]
		selectors[o.Tag] = o.Type == "selector"
		if o.Tag == selector {
			o.Outbounds = nil
			for _, candidate := range d.Candidates {
				o.Outbounds = append(o.Outbounds, candidate.Tag)
			}
			if !slices.Contains(o.Outbounds, o.Default) {
				o.Default = o.Outbounds[0]
			}
		}
	}
	for i := range sb.Route.Rules {
		rule := &sb.Route.Rules[i]
		if rule.Action != "" || !selectors[rule.Outbound] {
			continue
		}
		matches := len(rule.Inbound) == 0
		for _, inbound := range rule.Inbound {
			matches = matches || slices.Contains(business, inbound)
		}
		if !matches {
			continue
		}
		private, onlyPrivate, err := windowsPrivateRouteScope(*rule)
		if err != nil {
			return nil, err
		}
		if private && rule.Outbound != selector {
			if !onlyPrivate {
				return nil, errors.New("[§7.3] 私网与公网条件混合的独立 selector 规则无法安全合并到统一上网模式")
			}
			return nil, errors.New("[§7.3] 独立私网 selector 无法合并到统一上网模式")
		}
		if len(rule.Inbound) == 0 {
			return nil, errors.New("[§7.3] 上网 selector 规则缺少明确入口边界")
		}
		for _, inbound := range rule.Inbound {
			if !slices.Contains(business, inbound) {
				return nil, errors.New("[§7.3] 上网 selector 规则混合了业务和非业务入口")
			}
		}
		rule.Outbound = selector
	}
	cfg := p.config
	cfg.Declarations = []agent.Decl{d}
	cfg.Selectors = slices.DeleteFunc(slices.Clone(p.config.Selectors), func(s agent.SelectorPlan) bool { return s.Selector != selector })
	restrictWindowsAgentSelectors(&cfg)
	return &cfg, nil
}

// §7.3 / §16.1：读取失败时也只显示当前模式实际参与决策的声明，不能复活已停用的 Service 行。
func (p *WindowsSelectorPlan) ObservationDeclarations(preference clientcore.Preference) []string {
	var ids []string
	if p != nil {
		for _, d := range p.config.Declarations {
			if preference.Mode != clientcore.FixedExit || d.Selector == p.internetSelector {
				ids = append(ids, d.ID)
			}
		}
	}
	return ids
}
