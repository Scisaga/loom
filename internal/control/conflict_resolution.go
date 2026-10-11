package control

import (
	"errors"
	"reflect"
)

// ConflictResolution is the payload of the existing ordinary Material. Its
// value is selected by target kind, never an arbitrary JSON command or store.
type ConflictResolution struct {
	Conflicts []string        `json:"conflicts"`
	Action    string          `json:"action"`
	Value     MaterialPayload `json:"value,omitempty"`
}

func (ConflictResolution) materialPayload() {}

func (value ConflictResolution) contractObject() map[string]any {
	result := map[string]any{"conflicts": value.Conflicts, "action": value.Action}
	if value.Value != nil {
		result["value"] = value.Value
	}
	return result
}

func resolvableTarget(kind string) bool {
	switch kind {
	case "service", "policy", "device", "resource", "link", "probe_target", "expected_component", "dns_record", "public_trust", "admin_certificate":
		return true
	}
	return false
}

func validateResolution(kind, id string, payload MaterialPayload, public bool) error {
	value, ok := payload.(ConflictResolution)
	if !ok || !resolvableTarget(kind) || ValidateID(id) != nil || len(value.Conflicts) < 2 || validateDigests(value.Conflicts) != nil {
		return errors.New("conflict resolution requires a supported target and all sorted conflict references")
	}
	switch value.Action {
	case "delete":
		if value.Value != nil {
			return errors.New("deletion resolution cannot contain a value")
		}
		return nil
	case "put":
		if err := validateCurrentTransportPayload(value.Value); err != nil {
			return err
		}
		if public && kind == "device" {
			device, ok := value.Value.(DevicePut)
			if !ok || device.ID != id {
				return errors.New("device resolution accepts only public management fields")
			}
			return device.Validate()
		}
		return validateMaterialPayload(kind+".put", kind, id, value.Value)
	}
	return errors.New("conflict resolution action must be put or delete")
}

func decodeResolution(kind string, raw any, public bool) (MaterialPayload, error) {
	object, ok := raw.(map[string]any)
	if !ok || !resolvableTarget(kind) {
		return nil, errors.New("unsupported conflict resolution target or payload")
	}
	var value ConflictResolution
	fields := map[string]any{"conflicts": &value.Conflicts, "action": &value.Action}
	copy := make(map[string]any, len(object))
	for key, entry := range object {
		if key != "value" {
			copy[key] = entry
		}
	}
	if err := decodeContractObjectFields(copy, fields); err != nil {
		return nil, err
	}
	entry, present := object["value"]
	if value.Action == "delete" {
		if present {
			return nil, errors.New("deletion resolution cannot contain a value")
		}
		return value, nil
	}
	if value.Action != "put" || !present {
		return nil, errors.New("put resolution requires a complete typed value")
	}
	if public && kind == "device" {
		var device DevicePut
		if err := assignContractJSON(entry, reflect.ValueOf(&device).Elem()); err != nil {
			return nil, err
		}
		value.Value = device
	} else {
		decoded, err := decodeMaterialPayload(kind+".put", kind, entry)
		if err != nil {
			return nil, err
		}
		value.Value = decoded
	}
	return value, nil
}

// Only the new resolution fact has this projection. Original ordinary signed
// bytes and their interpretation remain unchanged; this copy is never signed.
func effectiveMaterial(material Material) Material {
	if value, ok := material.Payload.(ConflictResolution); ok {
		material.Operation = material.TargetKind + "." + value.Action
		material.Payload = value.Value
		if value.Action == "delete" {
			material.Payload = DeleteTarget{ID: material.TargetID}
		}
	}
	return material
}

func effectiveOperation(operation Operation) Operation {
	if value, ok := operation.Payload.(ConflictResolution); ok {
		operation.Operation = operation.TargetKind + "." + value.Action
		operation.Payload = value.Value
		if value.Action == "delete" {
			operation.Payload = DeleteTarget{ID: operation.TargetID}
		}
	}
	return operation
}

func resolutionReferences(payload MaterialPayload, dependencies []string) error {
	if value, ok := payload.(ConflictResolution); ok {
		for _, id := range value.Conflicts {
			if !contains(dependencies, id) {
				return errors.New("every conflict must be an explicit reviewed dependency")
			}
		}
	}
	return nil
}

func publicDeviceValue(value DeviceAuthorization) DevicePut {
	return DevicePut{ID: value.ID, Name: value.Name, Responsibilities: append([]string{}, value.Responsibilities...), PolicyIDs: append([]string{}, value.PolicyIDs...), DistributionURLs: append([]string{}, value.DistributionURLs...), DNSServers: append([]string(nil), value.DNSServers...)}
}

func validateResolutionTarget(material Material, view Projection) error {
	value := material.Payload.(ConflictResolution)
	target, found := view.CurrentTarget(material.TargetKind, material.TargetID)
	if !found || !target.Conflicted || target.Deleted || !reflect.DeepEqual(target.MaterialIDs, value.Conflicts) {
		return errors.New("current conflict sources changed; review all sources again")
	}
	return nil
}
