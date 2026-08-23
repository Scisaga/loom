package validate

import (
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
			if a == "" || a == "." {
				fs.add("§4.5 服务", where, "地址为空")
				continue
			}
			if strings.ContainsAny(a, "/: ") {
				fs.add("§4.5 服务", where,
					"地址 %q 看起来不是主机名 —— 这里要的是 host,不是 URL 也不是 host:port", a)
				continue
			}
			// 同一个地址被两个服务认领,路由结果就取决于规则顺序 ——
			// 而规则顺序是渲染细节,不该决定流量走哪。
			if prev, dup := owner[a]; dup {
				fs.add("§4.5 服务", where,
					"地址 %q 已被服务 %q 认领 —— 两个服务抢同一个地址时,"+
						"走哪条路取决于渲染出的规则顺序,那不该是策略", a, prev)
				continue
			}
			owner[a] = svc.ID
		}

		// 后缀地址探不了 —— `.baidu.com` 不是一个具体主机。一个服务如果
		// 全是后缀,它就无法被度量,selector 只能停在默认候选上,而这在
		// 渲染产物里看不出任何异常。
		concrete := 0
		for _, a := range svc.Addresses {
			if !model.IsSuffix(a) {
				concrete++
			}
		}
		if len(svc.Addresses) > 0 && concrete == 0 {
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
			if model.IsSuffix(suf) && so != o && strings.HasSuffix(addr, suf) {
				fs.add("§4.5 服务", "service:"+o,
					"地址 %q 落在服务 %q 的后缀 %q 之内 —— 渲染时具体地址优先,"+
						"但这需要是有意的安排", addr, so, suf)
			}
		}
	}
}

// checkServicePorts 校验接入节点的端口模式(§4.5)。
func checkServicePorts(fs *findings, s *model.SSOT) {
	for _, n := range s.AccessNodes() {
		for _, mp := range n.Access.MixedPorts {
			where := "access:" + n.ID
			switch {
			case mp.ByService() && mp.Declaration != "":
				fs.add("§4.5 服务", where,
					"端口 %d 同时设了 services 和 declaration —— 一个端口要么按 host "+
						"反查服务,要么钉在一条声明上,不能既是又是", mp.Port)
			case !mp.ByService() && mp.Declaration == "":
				fs.add("§4.5 服务", where,
					"端口 %d 既没绑声明也没开 services —— 它不会路由任何流量", mp.Port)
			case mp.ByService() && len(s.Services) == 0:
				fs.add("§4.5 服务", where,
					"端口 %d 按服务分流,但一个服务都没声明 —— 所有流量都会落到兜底", mp.Port)
			}
		}
	}
}
