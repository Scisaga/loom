package clientv2

import (
	"errors"
	"sort"
	"time"

	"loom/internal/wire"
)

// DialOrder 返回新连接唯一允许尝试的签名 generations：preferred 优先，
// advertised 仅作有界回退，draining 不用于新连接且绝不扫描相邻端口。
func DialOrder(endpoint wire.DataIngressEndpointV2, now time.Time, minimumGeneration int64) ([]wire.ListenerGenerationV2, error) {
	if !oneOf(endpoint.Transport, "hysteria2", "trojan_tls", "wireguard") {
		return nil, errors.New("[D107 Linux] endpoint transport 无效")
	}
	var preferred, fallback []wire.ListenerGenerationV2
	for _, generation := range endpoint.ListenerGenerations {
		if err := wire.ValidateListenerGeneration(&generation, endpoint.Transport); err != nil {
			return nil, err
		}
		if generation.ListenerGeneration < minimumGeneration {
			continue
		}
		from, _ := wire.ParseTimeZ(generation.ValidFrom)
		until, _ := wire.ParseTimeZ(generation.ValidUntil)
		if now.UTC().Before(from) || !now.UTC().Before(until) || generation.PublishedState == "draining" {
			continue
		}
		if generation.PublishedState == "preferred" {
			preferred = append(preferred, generation)
		} else {
			fallback = append(fallback, generation)
		}
	}
	if len(preferred) != 1 {
		return nil, errors.New("[D120 Linux] 当前可拨 endpoint 必须恰有一个 preferred generation")
	}
	sort.Slice(fallback, func(i, j int) bool { return fallback[i].ListenerGeneration > fallback[j].ListenerGeneration })
	return append(preferred, fallback...), nil
}

type Mode string

const (
	ModeDirect Mode = "direct"
	ModeAuto   Mode = "auto"
	ModeFixed  Mode = "fixed"
)

func ValidateMode(mode Mode, fixedEgressID string, authorizedEgressIDs []string) error {
	switch mode {
	case ModeDirect, ModeAuto:
		if fixedEgressID != "" {
			return errors.New("[D97 Linux] Direct/Auto 禁止 fixed egress")
		}
	case ModeFixed:
		found := false
		for _, id := range authorizedEgressIDs {
			if id == fixedEgressID {
				found = true
			}
		}
		if !found {
			return errors.New("[D97 Linux] 指定出口已移除或未授权；必须阻断，不能静默切 Auto")
		}
	default:
		return errors.New("[D97 Linux] route mode 无效")
	}
	return nil
}

func oneOf(value string, allowed ...string) bool {
	for _, item := range allowed {
		if value == item {
			return true
		}
	}
	return false
}
