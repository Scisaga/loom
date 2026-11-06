package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// RouteChoice is an execution decision, never a credential or grant. Policy is
// carried once by its atomic selector snapshot and each connection context.
type RouteChoice struct {
	EntryNodeID     string `json:"entry_node_id"`
	FirstResourceID string `json:"first_resource_id"`
	FinalExit       string `json:"final_exit"`
}

func (choice RouteChoice) Validate() error {
	if ValidateID(choice.FinalExit) != nil {
		return errors.New("invalid selected exit")
	}
	if choice.FinalExit == "direct" {
		if choice.EntryNodeID != "" || choice.FirstResourceID != "" {
			return errors.New("Direct cannot use a managed entry")
		}
		return nil
	}
	if ValidateID(choice.EntryNodeID) != nil || choice.EntryNodeID == "direct" || choice.FirstResourceID != "" && ValidateID(choice.FirstResourceID) != nil {
		return errors.New("invalid selected entry")
	}
	return nil
}

// CandidateID is the same canonical string-only identity in every adapter and
// the native selector. Unicode stays UTF-8; only quote/backslash need escaping
// because IDs already reject control characters.
func CandidateID(serviceID, policyID string, choice RouteChoice) (string, error) {
	if ValidateID(serviceID) != nil || ValidateID(policyID) != nil || choice.Validate() != nil {
		return "", errors.New("invalid route identity")
	}
	body := []byte("loom-candidate-id-v3\x00{")
	fields := [][2]string{{"entry_node_id", choice.EntryNodeID}, {"final_exit", choice.FinalExit}, {"first_resource_id", choice.FirstResourceID}, {"policy_id", policyID}, {"service_id", serviceID}}
	quote := func(value string) {
		body = append(body, '"')
		for _, c := range []byte(value) {
			if c == '"' || c == '\\' {
				body = append(body, '\\')
			}
			body = append(body, c)
		}
		body = append(body, '"')
	}
	for i, field := range fields {
		if i > 0 {
			body = append(body, ',')
		}
		quote(field[0])
		body = append(body, ':')
		quote(field[1])
	}
	body = append(body, '}')
	digest := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}
