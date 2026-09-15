package webui

import (
	"fmt"
	"strings"
	"time"

	"loom/internal/nodepresence"
)

func deviceControl(d Deps) *ClientControlDeps {
	if d.Control == nil {
		return nil
	}
	if d.Control.Devices != nil {
		return d.Control.Devices
	}
	return d.Control.Clients
}

// 设备 API 与浏览器使用相同可信投影；registry 不能独自证明运行态在线。
func loadDeviceInventory(d Deps) (ClientInventory, error) {
	control := deviceControl(d)
	if control == nil || control.List == nil {
		return ClientInventory{}, fmt.Errorf("device registry is unavailable on this machine")
	}
	inventory, err := control.List()
	if err != nil || d.Snapshot == nil && d.TrafficSnapshot == nil {
		return inventory, err
	}
	now := time.Now().UTC()
	if d.Now != nil {
		now = d.Now().UTC()
	}
	return mergeClientRuntime(inventory, browserView(d), now), nil
}

func loadClientInventory(d Deps) (ClientInventory, error) { return loadDeviceInventory(d) }

func deviceEnrollmentOptions(d Deps) (DeviceEnrollmentOptions, error) {
	control := deviceControl(d)
	if control == nil || control.EnrollmentOptions == nil {
		return DeviceEnrollmentOptions{}, fmt.Errorf("Device enrollment options are unavailable")
	}
	return control.EnrollmentOptions()
}

func deviceListContains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

const (
	// 完整 Observation 保持原一分钟采集/同步语义；它过期后即使仍有心跳，
	// 也不能把旧健康和配置证据继续展示为 Online。
	clientRuntimeStaleAfter = 2 * time.Minute
	// Windows、Android 与 Linux 每五秒发送独立最小心跳；漏掉三次后在线租约失效。
	// 它不刷新上面的完整 Observation 时钟。
	clientPresenceStaleAfter = nodepresence.Lease
)

// mergeClientRuntime 只改页面使用的切片副本。registry/SSOT 仍分别保存身份与
// 期望态；Online 必须来自当前 View 中直连或验签后的健康证据。
func mergeClientRuntime(inventory ClientInventory, view View, now time.Time) ClientInventory {
	out := inventory
	out.Clients = append([]ClientView(nil), inventory.Clients...)
	nodes := make(map[string]NodeView, len(view.Nodes))
	ambiguous := make(map[string]bool)
	for _, node := range view.Nodes {
		if node.ID == "" {
			continue
		}
		if _, exists := nodes[node.ID]; exists {
			ambiguous[node.ID] = true
			continue
		}
		nodes[node.ID] = node
	}
	for i := range out.Clients {
		client := &out.Clients[i]
		// registry 中即使残留 online 字样，也不能绕过本次运行态证据。
		if client.Status == "online" {
			client.Status = "unknown"
		}
		node, found := nodes[client.ID]
		if !found || ambiguous[client.ID] {
			continue
		}
		mergeClientNodeRuntime(client, node, now)
	}
	return out
}

func mergeClientNodeRuntime(client *ClientView, node NodeView, now time.Time) {
	client.RuntimeProblems = nil
	heartbeat, heartbeatOK := parseClientObservedAt(node.PresenceAt)
	if heartbeatOK {
		client.HeartbeatAt = heartbeat.Format(time.RFC3339Nano)
	} else {
		client.HeartbeatAt = ""
	}
	requiresPresence := clientRequiresPresence(*client)
	// Windows、Android 与 Linux 的完整 Observation 都不能充当心跳兼容层；
	// 从未提交 loom-presence-v1 的客户端不能沿用旧报告 lease。
	heartbeatStale := requiresPresence && (!heartbeatOK || now.Sub(heartbeat) > clientPresenceStaleAfter ||
		heartbeat.After(now.Add(time.Minute)))
	if !requiresPresence {
		client.PresenceStatus = "not used"
		client.HeartbeatAt = ""
	} else if !heartbeatOK {
		client.PresenceStatus = "not yet reported"
	} else if heartbeatStale {
		client.PresenceStatus = "stale"
	} else {
		client.PresenceStatus = "live"
	}
	if node.IdentityError != "" {
		client.DataPlaneStatus = "problem"
		client.RuntimeProblems = []string{node.IdentityError}
		client.ConfigState = "not reported"
		client.LastSeenAt = ""
		overrideClientRuntimeStatus(client, "problem")
		return
	}
	direct := node.Reached || node.Source == "直连 /status"
	trusted := direct || node.Source == "签名转述" || node.Source == "签名健康转述"
	if !trusted {
		if strings.TrimSpace(node.ObservedAt) == "" {
			client.DataPlaneStatus = "not observed"
		} else {
			client.DataPlaneStatus = "untrusted observation"
		}
		client.ConfigState = "not reported"
		client.LastSeenAt = ""
		return
	}

	observed, observedOK := parseClientObservedAt(node.ObservedAt)
	if observedOK {
		client.LastSeenAt = observed.Format(time.RFC3339)
	} else {
		client.LastSeenAt = ""
	}
	if strings.TrimSpace(node.Applied) == "" {
		client.ConfigState = "not reported"
	} else {
		client.ConfigState = "applied " + short(node.Applied)
	}
	client.RuntimeProblems = append([]string(nil), node.Problems...)

	observationStale := !observedOK || node.AgeSec > int(clientRuntimeStaleAfter.Seconds()) ||
		now.Sub(observed) > clientRuntimeStaleAfter || observed.After(now.Add(time.Minute))
	stale := observationStale || heartbeatStale
	switch {
	case !node.Declared:
		client.DataPlaneStatus = "undeclared"
		overrideClientRuntimeStatus(client, "undeclared")
	case node.Decommission:
		client.DataPlaneStatus = "decommissioned"
		overrideClientRuntimeStatus(client, "decommissioned")
	case stale:
		client.DataPlaneStatus = "stale"
		overrideClientRuntimeStatus(client, "stale")
	case node.Health == "problem":
		client.DataPlaneStatus = "problem"
		overrideClientRuntimeStatus(client, "problem")
	case node.Health == "healthy":
		client.DataPlaneStatus = "online"
		overrideClientRuntimeStatus(client, "online")
	default:
		client.DataPlaneStatus = "unknown"
		if client.Status == "online" {
			client.Status = "unknown"
		}
	}
}

func clientRequiresPresence(client ClientView) bool {
	switch strings.ToLower(strings.TrimSpace(client.Platform)) {
	case "android", "linux-server", "windows-desktop":
		return true
	default:
		return false
	}
}

func parseClientObservedAt(value string) (time.Time, bool) {
	observed, err := time.Parse(time.RFC3339, strings.TrimSpace(value))
	if err != nil {
		return time.Time{}, false
	}
	return observed.UTC(), true
}

func overrideClientRuntimeStatus(client *ClientView, status string) {
	switch client.Status {
	case "revoked", "pending", "invite_expired", "provisioning":
		return
	default:
		client.Status = status
	}
}
