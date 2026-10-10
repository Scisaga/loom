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
	if endpoint.Interface != tag || endpoint.Peers == nil || len(endpoint.Peers) != len(expected) {
		return nil, errors.New("WG counters are not from the applied shared endpoint")
	}
	result := &control.WireGuardCounters{Interface: tag, Epoch: endpoint.Epoch, ObservedAt: now().UnixMilli(), Peers: expected}
	for i, peer := range endpoint.Peers {
		if peer.RXBytes == nil || peer.TXBytes == nil || peer.PublicKey != expected[i].PublicKey {
			return nil, errors.New("WG counter peer differs from applied configuration")
		}
		result.Peers[i].RXBytes, result.Peers[i].TXBytes = *peer.RXBytes, *peer.TXBytes
	}
	if err := result.Validate(); err != nil {
		return nil, err
	}
	return result, nil
}
