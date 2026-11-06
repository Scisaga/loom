package clientmodel

import (
	"errors"
	"loom/internal/control"
	"loom/protocol"
)

func BindSelectionChoices(value Selection, routes []RouteCandidate) (Selection, error) {
	value.Choices = map[string]protocol.RouteChoice{}
	if value.CandidateID == "reject" {
		value.PolicyID = ""
		return value, ValidateAccessSelection(value)
	}
	wanted := map[string]bool{value.CandidateID: true}
	for _, id := range value.Targets {
		wanted[id] = true
	}
	for _, route := range routes {
		if !wanted[route.ID] {
			continue
		}
		if CandidateSelectorScope(route) != value.Scope || value.PolicyID != "" && value.PolicyID != route.PolicyID {
			return Selection{}, errors.New("selection spans independent Policies or scopes")
		}
		value.PolicyID = route.PolicyID
		value.Choices[route.ID] = protocol.RouteChoice{EntryNodeID: route.EntryNodeID, FirstResourceID: route.FirstResourceID, FinalExit: route.FinalExit}
	}
	if len(value.Choices) != len(wanted) {
		return Selection{}, errors.New("selection contains an unknown route")
	}
	return value, nil
}

// Complete snapshots compare both choices and the Policy. A candidate digest
// alone cannot be used to initialize a shared transport's connection context.
func ValidateAccessSelection(value Selection) error {
	if !ValidSelectorScope(value.Scope) || value.Targets == nil || value.Choices == nil {
		return errors.New("incomplete source selection")
	}
	if value.CandidateID == "reject" {
		if value.PolicyID != "" || len(value.Targets) != 0 || len(value.Choices) != 0 {
			return errors.New("reject selection grants nothing")
		}
		return nil
	}
	if control.ValidateID(value.PolicyID) != nil {
		return errors.New("source selection lacks its Policy")
	}
	used := map[string]bool{value.CandidateID: true}
	for target, id := range value.Targets {
		if _, _, _, err := protocol.ParseConnectionTargetKey(target); err != nil {
			return errors.New("invalid connection target")
		}
		used[id] = true
	}
	if len(used) != len(value.Choices) {
		return errors.New("selection has missing or extraneous route choices")
	}
	for id := range used {
		choice, ok := value.Choices[id]
		if !ok || control.ValidateDigest(id) != nil || choice.Validate() != nil {
			return errors.New("invalid route choice")
		}
	}
	return nil
}
