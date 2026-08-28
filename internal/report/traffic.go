package report

import (
	"crypto/sha256"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"loom/internal/attest"
	"loom/internal/model"
)

const bootIDPath = "/proc/sys/kernel/random/boot_id"

// collectTrafficAttestationFromDump signs counters from the exact WireGuard
// snapshot already used for this round's carrier status.
func collectTrafficAttestationFromDump(cfg *Config, now time.Time, dump []byte) *attest.TrafficAttest {
	if cfg == nil || len(cfg.Interfaces) == 0 || len(dump) == 0 {
		return nil
	}
	boot, err := os.ReadFile(bootIDPath)
	if err != nil || strings.TrimSpace(string(boot)) == "" {
		return nil
	}
	claim, err := trafficClaimFromDump(cfg, now, dump, strings.TrimSpace(string(boot)),
		func(iface string) (string, error) {
			// iface is constrained to wg-<valid node id> before this callback, so
			// it cannot escape /sys/class/net.
			b, err := os.ReadFile("/sys/class/net/" + iface + "/ifindex")
			if err != nil {
				return "", err
			}
			index := strings.TrimSpace(string(b))
			if _, err := strconv.ParseUint(index, 10, 32); err != nil {
				return "", fmt.Errorf("ifindex %q 无效:%w", index, err)
			}
			return index, nil
		})
	if err != nil {
		return nil
	}
	key, err := os.ReadFile(nodeKeyPath)
	if err != nil {
		return nil
	}
	crt, err := os.ReadFile(nodeCertPath)
	if err != nil {
		return nil
	}
	signed, err := attest.SignTraffic(claim, key, crt)
	if err != nil {
		return nil
	}
	return signed
}

// trafficClaimFromDump is the pure parser behind collection. PeerNode and the
// normalized LinkID come from the rendered topology (Neighbor / wg-<peer>), not
// from a key string. PeerPublicKey remains diagnostic only.
func trafficClaimFromDump(cfg *Config, now time.Time, dump []byte, bootID string,
	interfaceIndex func(string) (string, error)) (attest.TrafficClaim, error) {
	claim := attest.TrafficClaim{
		Version: attest.TrafficClaimVersion,
		Node:    cfg.Node,
		TS:      now.UTC().Format(time.RFC3339),
	}
	if bootID == "" || strings.ContainsAny(bootID, "\r\n\t") {
		return claim, fmt.Errorf("boot id 无效")
	}
	peerByInterface := make(map[string]string, len(cfg.Interfaces))
	for _, neighbor := range cfg.Neighbors {
		if model.ValidNodeID(neighbor.Node) {
			peerByInterface[model.IfaceName(neighbor.Node)] = neighbor.Node
		}
	}
	for _, iface := range cfg.Interfaces {
		// The renderer guarantees this form. The suffix fallback makes old
		// rendered configs usable even if their Neighbor address was omitted.
		if !strings.HasPrefix(iface, "wg-") {
			continue
		}
		peer := strings.TrimPrefix(iface, "wg-")
		if model.ValidNodeID(peer) && iface == model.IfaceName(peer) {
			if _, ok := peerByInterface[iface]; !ok {
				peerByInterface[iface] = peer
			}
		}
	}
	seenManagedInterface := map[string]bool{}
	for _, line := range strings.Split(string(dump), "\n") {
		fields := strings.Split(line, "\t")
		// WireGuard dump peer row:
		// iface pubkey psk endpoint allowed-ips handshake rx tx keepalive
		if len(fields) < 9 {
			continue
		}
		iface := fields[0]
		peerNode, managed := peerByInterface[iface]
		if !managed {
			continue
		}
		if seenManagedInterface[iface] {
			return claim, fmt.Errorf("managed interface %s 出现多个 WireGuard peers", iface)
		}
		seenManagedInterface[iface] = true
		rx, errRX := strconv.ParseInt(fields[6], 10, 64)
		tx, errTX := strconv.ParseInt(fields[7], 10, 64)
		if errRX != nil || errTX != nil || rx < 0 || tx < 0 {
			return claim, fmt.Errorf("无法解析 %s 的 WireGuard counter", iface)
		}
		index, err := interfaceIndex(iface)
		if err != nil {
			return claim, fmt.Errorf("读取 %s counter reset boundary:%w", iface, err)
		}
		// A peer-key replacement resets WireGuard's per-peer counters even when
		// the host and interface index stay unchanged. Bind a non-secret key
		// fingerprint into the epoch so that transition is rejected as a reset.
		peerKeyFingerprint := sha256.Sum256([]byte(fields[1]))
		epoch := fmt.Sprintf("%s/%s/%x", bootID, index, peerKeyFingerprint[:16])
		claim.Counters = append(claim.Counters, attest.TrafficCounter{
			Interface: iface, PeerNode: peerNode,
			LinkID:        attest.CanonicalTrafficLinkID(cfg.Node, peerNode),
			PeerPublicKey: fields[1], CounterEpoch: epoch,
			RXBytes: rx, TXBytes: tx,
		})
	}
	sort.Slice(claim.Counters, func(i, j int) bool {
		a, b := claim.Counters[i], claim.Counters[j]
		if a.Interface != b.Interface {
			return a.Interface < b.Interface
		}
		return a.PeerPublicKey < b.PeerPublicKey
	})
	return claim, nil
}

// verifyTrafficAttachment binds the independently verified claim back to its
// containing Observation. Without both comparisons a relay could attach B's
// valid counter snapshot to A's otherwise valid observation.
func verifyTrafficAttachment(o *Observation, ca []byte, now time.Time,
	maxAge time.Duration) (*attest.TrafficClaim, error) {
	if o == nil || o.Traffic == nil {
		return nil, nil
	}
	claim, err := attest.VerifyTrafficFresh(o.Traffic, ca, now, maxAge)
	if err != nil {
		return nil, err
	}
	if claim.Node != o.Node {
		return nil, fmt.Errorf("流量签名节点 %q 与外层观测节点 %q 不一致", claim.Node, o.Node)
	}
	if claim.TS != o.TS {
		return nil, fmt.Errorf("流量签名时间 %q 与外层观测时间 %q 不一致", claim.TS, o.TS)
	}
	return claim, nil
}

func trafficPeerNode(iface string) string {
	if !strings.HasPrefix(iface, "wg-") {
		return ""
	}
	peer := strings.TrimPrefix(iface, "wg-")
	if !model.ValidNodeID(peer) || model.IfaceName(peer) != iface {
		return ""
	}
	return peer
}
