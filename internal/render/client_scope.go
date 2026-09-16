package render

import (
	"errors"
	"sort"

	"loom/internal/model"
	"loom/internal/wire"
)

// v2 的 Device 授权是当前权限边界，旧声明仅提供路由策略。出口授权只约束
// 链的最后一台服务器，不能顺便删掉转发节点；本机 Direct 不消耗 Loom 授权。
type clientAccessScope struct {
	services map[string]bool
	egress   map[string]bool
}

func (scope *clientAccessScope) serverCandidates(ssot *model.SSOT, node *model.Node, declaration *model.AccessDeclaration) []model.RouteCandidate {
	byTag := map[string]model.RouteCandidate{}
	candidates, _ := scope.candidates(ssot, node, declaration)
	for _, candidate := range candidates {
		byTag[candidate.Tag()] = candidate
	}
	for _, service := range ssot.Services {
		if service.Declaration != declaration.ID {
			continue
		}
		candidates, _ := scope.serviceCandidates(ssot, node, declaration, &service)
		for _, candidate := range candidates {
			byTag[candidate.Tag()] = candidate
		}
	}
	result := make([]model.RouteCandidate, 0, len(byTag))
	for _, candidate := range byTag {
		result = append(result, candidate)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Tag() < result[j].Tag() })
	return result
}

func newClientAccessScope(ssot *model.SSOT, grants *wire.EnrollmentDestinationGrantsV1) (*clientAccessScope, error) {
	if err := wire.ValidateEnrollmentDestinationGrants(grants); err != nil {
		return nil, err
	}
	scope := &clientAccessScope{services: map[string]bool{}, egress: map[string]bool{}}
	nodes := ssot.NodeByID()
	services := map[string]bool{}
	for _, service := range ssot.Services {
		services[service.ID] = true
	}
	for _, grant := range grants.Values {
		switch grant.Kind {
		case "service":
			if !services[grant.TargetID] {
				return nil, errors.New("[v2 客户端配置] 授权服务缺少路由策略")
			}
			scope.services[grant.TargetID] = true
		case "egress":
			node := nodes[grant.TargetID]
			if node == nil || node.Server == nil || !node.Server.EgressCapable || node.Decommission {
				return nil, errors.New("[v2 客户端配置] 授权出口缺少有效服务器")
			}
			scope.egress[grant.TargetID] = true
		}
	}
	return scope, nil
}

func (scope *clientAccessScope) allowsDeclaration(declaration *model.AccessDeclaration) bool {
	return scope == nil || declaration != nil && declaration.AddressFromRequest() &&
		(declaration.PinnedEgress() == "" || scope.egress[declaration.PinnedEgress()])
}

func (scope *clientAccessScope) allowsService(id string) bool {
	return scope == nil || scope.services[id]
}

func (scope *clientAccessScope) candidates(ssot *model.SSOT, node *model.Node,
	declaration *model.AccessDeclaration) ([]model.RouteCandidate, []model.CandidateSkip) {
	if !scope.allowsDeclaration(declaration) {
		return nil, nil
	}
	candidates, skipped := ssot.EnumerateCandidates(node, declaration)
	if scope == nil {
		return candidates, skipped
	}
	allowed := make([]model.RouteCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.Egress() == "" || scope.egress[candidate.Egress()] {
			allowed = append(allowed, candidate)
		}
	}
	return allowed, skipped
}

func (scope *clientAccessScope) serviceCandidates(ssot *model.SSOT, node *model.Node,
	declaration *model.AccessDeclaration, service *model.Service) ([]model.RouteCandidate, []model.CandidateSkip) {
	if !scope.allowsService(service.ID) {
		return nil, nil
	}
	return ssot.EnumerateServiceCandidates(node, declaration, service)
}
