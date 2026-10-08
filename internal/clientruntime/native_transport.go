package clientruntime

import (
	"encoding/base64"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"strconv"
	"strings"

	"loom/internal/control"
)

type singBoxEndpoint struct {
	Type              string                `json:"type"`
	Tag               string                `json:"tag"`
	System            bool                  `json:"system"`
	Address           []string              `json:"address"`
	PrivateKey        string                `json:"private_key"`
	Inet4MappedPrefix string                `json:"inet4_mapped_prefix"`
	Peers             []singBoxEndpointPeer `json:"peers"`
}
type singBoxEndpointPeer struct {
	Address    string   `json:"address"`
	Port       int      `json:"port"`
	PublicKey  string   `json:"public_key"`
	AllowedIPs []string `json:"allowed_ips"`
}

func validateWindowsNativeEndpoints(c singBoxConfig, tags map[string]string) error {
	for _, endpoint := range c.Endpoints {
		if endpoint.Type != "wireguard" || endpoint.System || !strings.HasPrefix(endpoint.Tag, "wg-send.") || control.ValidateID(strings.TrimPrefix(endpoint.Tag, "wg-send.")) != nil || tags[endpoint.Tag] != "" || len(endpoint.Address) == 0 || len(endpoint.Peers) != 1 {
			return errors.New("invalid native userspace WG endpoint")
		}
		key, err := base64.StdEncoding.DecodeString(endpoint.PrivateKey)
		if err != nil || len(key) != 32 || base64.StdEncoding.EncodeToString(key) != endpoint.PrivateKey || key[0]&7 != 0 || key[31]&192 != 64 {
			return errors.New("invalid native WG sender key")
		}
		clear(key)
		prefix, err := netip.ParsePrefix(endpoint.Inet4MappedPrefix)
		if err != nil || prefix.String() != endpoint.Inet4MappedPrefix || prefix != prefix.Masked() || !prefix.Addr().Is6() || !prefix.Addr().IsPrivate() || prefix.Bits() != 96 {
			return errors.New("invalid resource IPv4 mapping")
		}
		for i, text := range endpoint.Address {
			address, err := netip.ParsePrefix(text)
			if err != nil || address.String() != text || !address.Addr().Is6() || !address.Addr().IsPrivate() || address.Bits() != 128 || i > 0 && endpoint.Address[i-1] >= text {
				return errors.New("invalid exact WG packet source")
			}
		}
		peer := endpoint.Peers[0]
		public, err := base64.StdEncoding.DecodeString(peer.PublicKey)
		if err != nil || len(public) != 32 || base64.StdEncoding.EncodeToString(public) != peer.PublicKey || peer.Address == "" || peer.Port < 1 || peer.Port > 65535 || !reflect.DeepEqual(peer.AllowedIPs, []string{"::/0"}) {
			return errors.New("invalid native WG receiver")
		}
		tags[endpoint.Tag] = "wireguard"
	}
	return nil
}

func validateNativeProbeRule(rule singBoxRule, tags map[string]string) error {
	if rule.Outbound == "reject" {
		if !reflect.DeepEqual(rule, singBoxRule{Inbound: []string{control.LinkProbeInbound}, Outbound: "reject"}) {
			return errors.New("native diagnostic reject was broadened")
		}
		return nil
	}
	if len(rule.AuthUser) != 1 || len(rule.IPCIDR) != 1 || !reflect.DeepEqual(rule.Port, []int{53}) || rule.Outbound != control.WireGuardBaseTag(rule.AuthUser[0]) || tags[rule.Outbound] != "direct" {
		return errors.New("invalid native diagnostic boundary")
	}
	address, err := netip.ParsePrefix(rule.IPCIDR[0])
	if err != nil || !address.Addr().Is6() || !address.Addr().IsPrivate() || address.Bits() != 128 {
		return errors.New("invalid native diagnostic address")
	}
	want := singBoxRule{Inbound: []string{control.LinkProbeInbound}, AuthUser: rule.AuthUser, IPCIDR: rule.IPCIDR, Port: []int{53}, Outbound: rule.Outbound}
	if !reflect.DeepEqual(want, rule) {
		return errors.New("native diagnostic contains unrelated capture")
	}
	return nil
}

func validateWindowsDNS(c singBoxConfig, tags map[string]string) error {
	if c.DNS == nil {
		return nil
	}
	dns := c.DNS
	if len(dns.Servers) == 0 || dns.ReverseMapping || dns.FakeIP != nil || dns.Strategy != "" && dns.Strategy != "prefer_ipv4" {
		return errors.New("invalid managed DNS facilities")
	}
	servers := map[string]bool{}
	for _, server := range dns.Servers {
		if server.Tag == "" || servers[server.Tag] {
			return errors.New("DNS server tag is duplicated")
		}
		servers[server.Tag] = true
		switch {
		case server.Tag == "loom-overlay-dns":
			if server.Detour != "" || server.Strategy != "" || server.Address != "loom-static" && server.Address != "rcode://name_error" || (server.Address == "loom-static") != (len(server.StaticRecords) > 0) {
				return errors.New("invalid overlay DNS")
			}
			for name, addresses := range server.StaticRecords {
				if name == "control.loom" {
					continue
				}
				if (control.DNSRecord{ID: "demo-record", Name: name, Addresses: addresses}).Validate() != nil {
					return errors.New("invalid overlay DNS record")
				}
			}
		case server.Tag == "loom-runtime-deny-dns":
			if !reflect.DeepEqual(server, singBoxDNSServer{Tag: server.Tag, Address: "rcode://refused"}) {
				return errors.New("invalid DNS refusal")
			}
		case strings.HasPrefix(server.Tag, "loom-resolver-"):
			index, err := strconv.Atoi(strings.TrimPrefix(server.Tag, "loom-resolver-"))
			host, port, e := net.SplitHostPort(strings.TrimPrefix(server.Address, "udp://"))
			ip, pe := netip.ParseAddr(host)
			if err != nil || index < 0 || e != nil || pe != nil || ip.String() != host || port != "53" || server.Address != "udp://"+net.JoinHostPort(host, "53") || server.Detour != "loom-underlay-dns" || tags[server.Detour] != "direct" || server.StaticRecords != nil || server.Strategy != "" {
				return errors.New("invalid authenticated resolver")
			}
		case strings.HasPrefix(server.Tag, "wg-dns."):
			id := strings.TrimPrefix(server.Tag, "wg-dns.")
			host, port, err := net.SplitHostPort(strings.TrimPrefix(server.Address, "udp://"))
			ip, e := netip.ParseAddr(host)
			if err != nil || e != nil || !ip.Is6() || !ip.IsPrivate() || ip.String() != host || port != "53" || server.Address != "udp://"+net.JoinHostPort(host, "53") || server.Detour != control.WireGuardBaseTag(id) || tags[server.Detour] != "direct" || server.Strategy != "ipv6_only" || server.StaticRecords != nil {
				return errors.New("invalid native receiver DNS")
			}
		default:
			return errors.New("unsupported DNS server")
		}
	}
	if !servers[dns.Final] {
		return errors.New("unknown final DNS resolver")
	}
	for _, rule := range dns.Rules {
		if !servers[rule.Server] || len(rule.Inbound) > 0 || len(rule.QueryType) > 0 || len(rule.Domain) > 0 {
			return errors.New("unsupported authorization DNS rule")
		}
		for _, tag := range rule.Outbound {
			if tags[tag] != "direct" && tags[tag] != "hysteria2" {
				return errors.New("DNS rule references an unknown sender")
			}
		}
		if len(rule.DomainSuffix) > 0 && !reflect.DeepEqual(rule.DomainSuffix, []string{"loom"}) || len(rule.Outbound) == 0 && rule.Server != "loom-overlay-dns" || rule.Server == "loom-overlay-dns" && !reflect.DeepEqual(rule.DomainSuffix, []string{"loom"}) {
			return errors.New("DNS rule was broadened")
		}
	}
	return nil
}
