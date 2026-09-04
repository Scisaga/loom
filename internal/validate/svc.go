package validate

import (
	"net"
	"sort"
	"strings"

	"loom/internal/model"
)

// checkServices 校验服务定义(§4.5)。
//
// 服务是接入端能选择的单位,也是选路的单位。它出错的后果都很安静:
// 地址被两个服务同时认领 → 路由取决于规则顺序;地址清单为空 → 这个服务
// 永远匹配不到任何流量。所以这里挡得比较死。
func checkServices(fs *findings, s *model.SSOT) {
	decls := s.DeclarationByID()

	seenID := map[string]bool{}
	// owner 记每个地址被谁认领,用来发现重叠。
	owner := map[string]string{}

	svcs := append([]model.Service(nil), s.Services...)
	sort.Slice(svcs, func(i, j int) bool { return svcs[i].ID < svcs[j].ID })

	for i := range svcs {
		svc := &svcs[i]
		where := "service:" + svc.ID
		concrete := 0
		validAddresses := 0
		if svc.ID == "" {
			fs.add("§4.5 服务", "service:(无 id)", "服务缺少 id")
			continue
		}
		if seenID[svc.ID] {
			fs.add("§4.5 服务", where, "服务 id 重复")
			continue
		}
		seenID[svc.ID] = true

		if len(svc.Addresses) == 0 {
			fs.add("§4.5 服务", where,
				"没有地址 —— 这个服务永远匹配不到任何流量,而不会有任何报错")
		}
		for _, a := range svc.Addresses {
			canonical, suffix, reason := canonicalServiceHost(a)
			if reason != "" {
				fs.add("§4.5 服务", where,
					"地址 %q 不是合法 hostname/suffix(%s) —— 这里要的是 host,"+
						"不是 wildcard、URL/path 或 host:port", a, reason)
				continue
			}
			if !suffix {
				concrete++
			}
			validAddresses++
			// 同一个地址被两个服务认领,路由结果就取决于规则顺序 ——
			// 而规则顺序是渲染细节,不该决定流量走哪。
			if prev, dup := owner[canonical]; dup {
				fs.add("§4.5 服务", where,
					"地址 %q 已被服务 %q 认领 —— 两个服务抢同一个地址时,"+
						"走哪条路取决于渲染出的规则顺序,那不该是策略", a, prev)
				continue
			}
			owner[canonical] = svc.ID
		}

		// 后缀地址探不了 —— `.baidu.com` 不是一个具体主机。一个服务如果
		// 全是后缀,它就无法被度量,selector 只能停在默认候选上,而这在
		// 渲染产物里看不出任何异常。
		if validAddresses > 0 && concrete == 0 {
			fs.add("§4.5 服务", where,
				"只有后缀地址,没有一个具体主机 —— 探测无从下手,这个服务的 selector "+
					"会一直停在默认候选上。至少给一个具体地址(它同时充当探测目标)")
		}

		d, ok := decls[svc.Declaration]
		if !ok {
			fs.add("§4.5 服务", where, "declaration 引用了不存在的声明 %q", svc.Declaration)
			continue
		}
		// 服务把一组地址**归到一起**,等价类从一组地址里**挑一个**。两者叠加
		// 是有意义的(先归组再挑),但还没实现 —— 明说,别让它悄悄按其中
		// 一种行为跑。
		if !d.AddressFromRequest() {
			fs.add("§4.5 服务", where,
				"声明 %q 的 address_axis 是 %q(从等价类里选地址),"+
					"而服务是把地址归到一起走同一条路 —— 两者叠加尚未实现",
				d.ID, d.AddressAxis)
		}
	}

	// 后缀与具体地址的重叠:`.openai.com` 和 `api.openai.com` 分属两个服务时,
	// 后者应当优先。这是能表达的,但必须是有意的。
	for addr, o := range owner {
		if model.IsSuffix(addr) {
			continue
		}
		for suf, so := range owner {
			if model.IsSuffix(suf) && so != o &&
				(addr == strings.TrimPrefix(suf, ".") || strings.HasSuffix(addr, suf)) {
				fs.add("§4.5 服务", "service:"+o,
					"地址 %q 落在服务 %q 的后缀 %q 之内 —— 渲染时具体地址优先,"+
						"但这需要是有意的安排", addr, so, suf)
			}
		}
	}
}

// canonicalServiceHost 把服务地址收敛到两种语法:
//
//	example.com   精确 hostname
//	.example.com  hostname suffix
//
// DNS 不区分大小写,因此返回的 key 统一为小写,用于检测重复和重叠。
// 这里故意不接受 IP。Service 的数据面是按 HTTP hostname 分流,
// IP 规则不应该偷偷落入 sing-box 的 domain 规则。
func canonicalServiceHost(addr string) (key string, suffix bool, reason string) {
	if addr == "" || addr == "." {
		return "", false, "地址为空"
	}
	if strings.Contains(addr, "*") {
		return "", false, "不接受 wildcard *"
	}
	if strings.Contains(addr, "://") || strings.ContainsAny(addr, "/?#") {
		return "", false, "不接受 URL 或 path"
	}
	if strings.Contains(addr, ":") {
		return "", false, "不接受 host:port"
	}

	host := addr
	if strings.HasPrefix(host, ".") {
		suffix = true
		host = host[1:]
	}
	if len(host) > 253 {
		return "", false, "hostname 超过 253 字节"
	}
	if net.ParseIP(host) != nil {
		return "", false, "不接受 IP 地址"
	}

	for _, label := range strings.Split(host, ".") {
		if label == "" {
			return "", false, "hostname 包含空 label"
		}
		if len(label) > 63 {
			return "", false, "hostname label 超过 63 字节"
		}
		if !asciiAlphaNum(label[0]) || !asciiAlphaNum(label[len(label)-1]) {
			return "", false, "hostname label 必须以字母或数字开头和结尾"
		}
		for i := 1; i < len(label)-1; i++ {
			if !asciiAlphaNum(label[i]) && label[i] != '-' {
				return "", false, "hostname label 只能包含 ASCII 字母、数字和连字号"
			}
		}
	}

	key = strings.ToLower(host)
	if suffix {
		key = "." + key
	}
	return key, suffix, ""
}

func asciiAlphaNum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// checkServicePorts 校验接入节点的入口语义(§4.5)。正常形态是一条中控托管
// 的 service-aware mixed 主入口;声明绑定端口只是显式 override/兼容入口。
func checkServicePorts(fs *findings, s *model.SSOT) {
	for _, n := range s.AccessNodes() {
		var automaticPorts []int
		for _, mp := range n.Access.MixedPorts {
			where := "access:" + n.ID
			if mp.ManagedAutomatic() {
				automaticPorts = append(automaticPorts, mp.Port)
			}
			switch {
			case mp.ManagedAutomatic() && mp.ExplicitOverride():
				fs.add("§4.5 服务", where,
					"端口 %d 同时设了 services 和 declaration —— 一个端口要么按 host "+
						"反查服务,要么钉在一条声明上,不能既是又是", mp.Port)
			case !mp.ManagedAutomatic() && !mp.ExplicitOverride():
				fs.add("§4.5 服务", where,
					"端口 %d 既没绑声明也没开 services —— 它不会路由任何流量", mp.Port)
			}
		}
		if len(automaticPorts) > 1 {
			sort.Ints(automaticPorts)
			fs.add("§4.5 服务", "access:"+n.ID,
				"中控托管的 service-aware mixed 主入口只能有一个,当前声明了端口 %v —— "+
					"多个入口语义相同,会迫使应用做无意义的端口选择", automaticPorts)
		}
	}
}

// checkCredentialRotation 检查凭据轮换的两步(§13.4)。
//
// 轮换最容易出的错不是配错,是**忘了第二步** —— 过渡窗口一直开着,旧凭据
// 永远有效,而轮换的全部意义就是让旧的失效。校验器挡不住"忘了"(那要看
// 时间,是事件历史的活),但能挡住几种一看就不对的配法。
func checkCredentialRotation(fs *findings, s *model.SSOT) {
	for i := range s.Credentials {
		c := &s.Credentials[i]
		where := "credential:" + c.ID
		if c.Generation < 0 {
			fs.add("§13.4 轮换", where, "generation 不能为负:%d", c.Generation)
		}
		if c.AcceptPrevious && c.Gen() <= 1 {
			fs.add("§13.4 轮换", where,
				"accept_previous 为真,但 generation=%d 是第一代,没有上一代可接受 —— "+
					"轮换要先把 generation 加一", c.Generation)
		}
		if c.Revoked() && c.AcceptPrevious {
			// 已吊销还开着过渡窗口,等于把吊销掉的那一代继续放行。
			fs.add("§13.4 轮换", where,
				"已吊销(revoked_at=%s)却还开着 accept_previous —— "+
					"这会让旧凭据继续可用,吊销就白做了", c.RevokedAt)
		}
	}
}
