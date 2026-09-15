package main

import (
	"bytes"
	"encoding/json"
	"errors"

	"loom/internal/dnsprovider"
	"loom/internal/wire"
)

func validateControlPayload(operation wire.ControlOperationV1, payload json.RawMessage) error {
	switch operation.Body.Kind {
	case controlPingKind:
		if len(payload) != 0 {
			return errors.New("control_ping 不接受 payload")
		}
		return nil
	case dnsprovider.BindingOperationKind:
		var binding dnsprovider.BindingV1
		canonical, err := wire.DecodeStrict(payload, 64<<10, &binding)
		if err != nil || !bytes.Equal(canonical, payload) || binding.ClusterID != operation.Body.ClusterID {
			return errors.New("[DNS] payload 不规范或 cluster 不匹配")
		}
		hash, err := dnsprovider.BindingHash(binding)
		if err != nil || hash != operation.Body.PayloadHash || operation.Body.PayloadSchema != 1 {
			return errors.New("[DNS] 签名未绑定 exact DNS payload")
		}
		return nil
	default:
		return errors.New("operation reducer 未登记")
	}
}

func (runtime *controlRuntime) validateDNSBindingUpdateLocked(payload json.RawMessage) error {
	var binding dnsprovider.BindingV1
	if _, err := wire.DecodeStrict(payload, 64<<10, &binding); err != nil {
		return err
	}
	var previous *dnsprovider.BindingV1
	for _, record := range runtime.journal.Records {
		if record.Operation.Body.Kind != dnsprovider.BindingOperationKind {
			continue
		}
		var stored dnsprovider.BindingV1
		if err := validateControlPayload(record.Operation, record.Payload); err != nil {
			return err
		}
		if _, err := wire.DecodeStrict(record.Payload, 64<<10, &stored); err != nil {
			return err
		}
		if stored.ServerID == binding.ServerID {
			previous = &stored
		} else if stored.Zone == binding.Zone && stored.Name == binding.Name {
			return errors.New("[DNS] 该域名已由其他 Device 占用")
		}
	}
	if previous == nil {
		if binding.Generation != 1 || binding.PreviousBindingHash != wire.EmptyHashV1 {
			return errors.New("[DNS] 首次绑定必须从 generation 1 开始")
		}
		return nil
	}
	hash, err := dnsprovider.BindingHash(*previous)
	if err != nil || binding.PreviousBindingHash != hash || binding.Generation != previous.Generation+1 ||
		binding.Name != previous.Name || binding.Zone != previous.Zone {
		return errors.New("[DNS] 更新未引用前代绑定或改变了稳定域名")
	}
	oldSets, _ := previous.RRSets()
	newSets, _ := binding.RRSets()
	for _, old := range oldSets {
		found := false
		for _, next := range newSets {
			found = found || old.Type == next.Type
		}
		if !found {
			return errors.New("[DNS] 删除地址族需要独立的退役操作")
		}
	}
	return nil
}
