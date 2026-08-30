package model

import (
	"sort"
	"strings"
)

// Service 是**接入端能选择的单位**(§4.5)。
//
// 它把一组地址和一条访问声明绑在一起:这些地址都属于同一个服务,因此走同一
// 条路;而走哪条路由那条声明的 objective 与约束决定。
//
// 为什么接入端不能直接指定地址,见 §4.5。三条理由里最硬的一条:能指定任意
// 地址,一份泄露的接入凭据就能把服务器变成开放代理。
//
// **和等价类别混**(§4.3):
//
//	等价类        N 个地址**可互换**,数据平面挑一个 → 度量单位是 (链, 地址)
//	服务地址清单  N 个地址**都要用**,只是归组     → 度量单位是 (链, 服务)
type Service struct {
	ID   string `yaml:"id"`
	Name string `yaml:"name,omitempty"`

	// Addresses 是这个服务用到的主机名。
	//
	// 以 `.` 开头表示后缀匹配(`.openai.com` 匹配 `api.openai.com`)——
	// 服务的地址清单几乎一定会不全,后缀匹配是最省事的补救。漏掉的那些
	// 会落到兜底并被上报者记下来(§4.5)。
	Addresses []string `yaml:"addresses"`

	// Declaration 是治理这个服务的访问声明:objective、约束、允许的出口。
	// 多个服务可以共用一条声明(同样的策略),但**各自独立选路** ——
	// 这正是 D43 修正的那一点。
	Declaration string `yaml:"declaration"`
}

// Tag 是这个服务在 sing-box 配置与上报里的稳定标识。
func (s *Service) Tag() string { return "svc:" + s.ID }

// Suffix 报告一条地址是不是后缀匹配。
func IsSuffix(addr string) bool { return strings.HasPrefix(addr, ".") }

// SortedAddresses 返回排序后的地址,渲染必须是纯函数(§12)。
func (s *Service) SortedAddresses() []string {
	out := append([]string(nil), s.Addresses...)
	sort.Strings(out)
	return out
}

// ServiceByID 建索引。
func (s *SSOT) ServiceByID() map[string]*Service {
	m := make(map[string]*Service, len(s.Services))
	for i := range s.Services {
		m[s.Services[i].ID] = &s.Services[i]
	}
	return m
}

// ServicesFor 返回由某条声明治理的全部服务,按 id 排序。
func (s *SSOT) ServicesFor(declID string) []*Service {
	var out []*Service
	for i := range s.Services {
		if s.Services[i].Declaration == declID {
			out = append(out, &s.Services[i])
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// EffectiveDefaultDeclaration 返回接入端显式声明的设备默认策略。这里刻意不从
// 凭据数量推断：即使设备只有一条声明，“未匹配即放行”也必须是中控的明确决定。
func (a *AccessRole) EffectiveDefaultDeclaration() string {
	if a == nil {
		return ""
	}
	return a.DefaultDeclaration
}
