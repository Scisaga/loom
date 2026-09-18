package report

import (
	"sort"

	"loom/internal/model"
)

// AndroidBundleSecretRefs is the narrow render helper retained for the Android
// product asset. It derives placeholders only; enrollment and delivery are not
// report-daemon responsibilities.
func AndroidBundleSecretRefs(s *model.SSOT, node *model.Node) []string {
	if s == nil || node == nil || node.Decommission || node.Access == nil ||
		node.Access.Platform != model.Android || node.IsServer() {
		return nil
	}
	seen := map[string]bool{"api/" + node.ID: true}
	credentials := s.CredentialByID()
	credentialByDeclaration := map[string]*model.Credential{}
	var declarationIDs []string
	for _, credentialID := range node.Access.Credentials {
		credential := credentials[credentialID]
		if credential == nil || credential.Revoked() {
			continue
		}
		if credentialByDeclaration[credential.Declaration] == nil {
			declarationIDs = append(declarationIDs, credential.Declaration)
		}
		credentialByDeclaration[credential.Declaration] = credential
	}
	sort.Strings(declarationIDs)
	pinned := map[string]bool{}
	for _, mixed := range node.Access.MixedPorts {
		if !mixed.ManagedAutomatic() && mixed.ExplicitOverride() {
			pinned[mixed.Declaration] = true
		}
	}
	if declaration := node.Access.EffectiveDefaultDeclaration(); declaration != "" {
		pinned[declaration] = true
	}
	declarations := s.DeclarationByID()
	usesProbe := false
	include := func(credential *model.Credential, candidates []model.RouteCandidate) {
		if credential == nil || len(candidates) == 0 {
			return
		}
		usesProbe = true
		for _, candidate := range candidates {
			if len(candidate.ServerChain) > 0 {
				seen[credential.Ref()] = true
				break
			}
		}
	}
	for _, declarationID := range declarationIDs {
		credential := credentialByDeclaration[declarationID]
		declaration := declarations[declarationID]
		if declaration == nil {
			continue
		}
		if pinned[declarationID] {
			candidates, _ := s.EnumerateCandidates(node, declaration)
			include(credential, candidates)
		}
		for _, service := range s.ServicesFor(declarationID) {
			candidates, _ := s.EnumerateServiceCandidates(node, declaration, service)
			include(credential, candidates)
		}
	}
	if usesProbe {
		seen["probe/"+node.ID] = true
	}
	refs := make([]string, 0, len(seen))
	for ref := range seen {
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	return refs
}
