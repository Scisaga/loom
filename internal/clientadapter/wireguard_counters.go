package clientadapter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"loom/internal/control"
)

// ObserveWireGuardCounters reads the already running WG owner through its
// authenticated local API. This request creates no network traffic in WG.
func ObserveWireGuardCounters(ctx context.Context, view control.DeviceView, now func() time.Time) (*control.WireGuardCounters, error) {
	tag, expected, err := control.WireGuardCounterBindings(view)
	if err != nil {
		return nil, err
	}
	if tag == "" {
		return nil, nil
	}
	return observeWireGuardCounters(ctx, tag, expected, now)
}
func observeWireGuardCounters(ctx context.Context, tag string, expected []control.WireGuardPeerCounter, now func() time.Time) (*control.WireGuardCounters, error) {
	source, ok := ctx.Value(nativeDiagnosticKey{}).(nativeDiagnostic)
	if !ok {
		return nil, errors.New("WG counter owner is unavailable")
	}
	timeout, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return source.dial(ctx, "tcp", "127.0.0.1:61800")
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(timeout, http.MethodGet, "http://127.0.0.1:61800/loom/wireguard-counters", nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+source.secret)
	response, err := client.Do(request)
	if err != nil {
		return nil, errors.New("WG counter read unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("WG counter source refused the read")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, (4<<20)+1))
	if err != nil || len(body) > 4<<20 {
		return nil, errors.New("WG counter response exceeds boundary")
	}
	var value struct {
		Endpoints []struct {
			Interface string `json:"interface"`
			Epoch     string `json:"epoch"`
			Peers     []struct {
				PublicKey string       `json:"public_key"`
				RXBytes   *control.U64 `json:"rx_bytes"`
				TXBytes   *control.U64 `json:"tx_bytes"`
			} `json:"peers"`
		} `json:"endpoints"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || decoder.Decode(new(any)) != io.EOF || len(value.Endpoints) != 1 {
		return nil, errors.New("WG counter response is invalid")
	}
	endpoint := value.Endpoints[0]
	if endpoint.Interface != tag || endpoint.Peers == nil {
		return nil, errors.New("WG counters are not from the applied shared endpoint")
	}
	observed := &control.WireGuardCounters{Interface: tag, Epoch: endpoint.Epoch, ObservedAt: now().UnixMilli(), Peers: []control.WireGuardPeerCounter{}}
	for _, peer := range endpoint.Peers {
		if peer.RXBytes == nil || peer.TXBytes == nil {
			return nil, errors.New("WG counter peer has incomplete counts")
		}
		observed.Peers = append(observed.Peers, control.WireGuardPeerCounter{PublicKey: peer.PublicKey, RXBytes: *peer.RXBytes, TXBytes: *peer.TXBytes, Links: []control.WireGuardCounterLink{}})
	}
	// Validate every native slot, including retired or no longer authorized keys,
	// before projecting the real observations onto the current View.
	if err := observed.Validate(); err != nil {
		return nil, err
	}
	allowed := make(map[string]control.WireGuardPeerCounter, len(expected))
	for _, peer := range expected {
		allowed[peer.PublicKey] = peer
	}
	result := &control.WireGuardCounters{Interface: tag, Epoch: observed.Epoch, ObservedAt: observed.ObservedAt, Peers: []control.WireGuardPeerCounter{}}
	for _, peer := range observed.Peers {
		if binding, ok := allowed[peer.PublicKey]; ok {
			peer.Links = append([]control.WireGuardCounterLink{}, binding.Links...)
			result.Peers = append(result.Peers, peer)
		}
	}
	return result, nil
}
