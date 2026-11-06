package protocol

import (
	"encoding/base64"
	"errors"
	"strings"
)

// TargetRegistration is a deletable synthetic-target cache value. Principals
// and Policy IDs must be rechecked at actual use; storing it grants nothing.
type TargetRegistration struct {
	Principal  string
	Connection Connection
	Host       string
	Port       uint16
}

const registrationPrefix = "!loom-exec3!"

func (value TargetRegistration) Marshal(maxNodes int) (string, error) {
	if ValidateID(value.Principal) != nil || ValidateID(value.Connection.PolicyID) != nil {
		return "", errors.New("invalid registered transport binding")
	}
	request := Request{Operation: ResolveTarget, PolicyID: value.Connection.PolicyID, Context: &value.Connection.Path, Host: value.Host, Port: value.Port}
	body, err := request.Marshal(maxNodes)
	if err != nil {
		return "", err
	}
	header := appendText(nil, value.Principal)
	header = append(header, body...)
	return registrationPrefix + base64.RawURLEncoding.EncodeToString(header), nil
}
func UnmarshalRegistration(key string, maxNodes int) (TargetRegistration, error) {
	if !strings.HasPrefix(key, registrationPrefix) || len(key) > 2*MaxFrameBytes {
		return TargetRegistration{}, errors.New("target is not a native execution registration")
	}
	encoded := strings.TrimPrefix(key, registrationPrefix)
	body, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(body) != encoded {
		return TargetRegistration{}, errors.New("noncanonical registered target")
	}
	r := reader{body: body}
	principal, err := r.text(MaxIDBytes)
	if err != nil || ValidateID(principal) != nil {
		return TargetRegistration{}, errors.New("invalid registered principal")
	}
	request, err := UnmarshalRequest(body[r.offset:], maxNodes)
	if err != nil {
		return TargetRegistration{}, err
	}
	if request.Operation != ResolveTarget || request.Nonce != [16]byte{} {
		return TargetRegistration{}, errors.New("registered target has an invalid execution purpose")
	}
	return TargetRegistration{Principal: principal, Connection: Connection{PolicyID: request.PolicyID, Path: *request.Context}, Host: request.Host, Port: request.Port}, nil
}
