package clientadapter

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

func BusinessProbe(ctx context.Context) ProbeResult {
	started := time.Now()
	probeContext, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	if err := probeTCP(probeContext); err != nil {
		return ProbeResult{Metric: time.Since(started), Description: "TCP/TLS: " + err.Error()}
	}
	if err := probeDNS(probeContext); err != nil {
		return ProbeResult{Metric: time.Since(started), Description: "UDP/DNS: " + err.Error()}
	}
	return ProbeResult{Available: true, Metric: time.Since(started), Description: "TCP/TLS and UDP/DNS succeeded"}
}

func probeTCP(ctx context.Context) error {
	dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second},
		Config: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "www.baidu.com"}}
	connection, err := dialer.DialContext(ctx, "tcp", "www.baidu.com:443")
	if err != nil {
		return err
	}
	return connection.Close()
}

func probeDNS(ctx context.Context) error {
	idBytes := make([]byte, 2)
	if _, err := io.ReadFull(rand.Reader, idBytes); err != nil {
		return err
	}
	id := binary.BigEndian.Uint16(idBytes)
	body := make([]byte, 12)
	binary.BigEndian.PutUint16(body[0:2], id)
	binary.BigEndian.PutUint16(body[2:4], 0x0100)
	binary.BigEndian.PutUint16(body[4:6], 1)
	for _, label := range []string{"example", "com"} {
		body = append(body, byte(len(label)))
		body = append(body, label...)
	}
	body = append(body, 0, 0, 1, 0, 1)
	connection, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "udp", "1.1.1.1:53")
	if err != nil {
		return err
	}
	defer connection.Close()
	if deadline, found := ctx.Deadline(); found {
		_ = connection.SetDeadline(deadline)
	}
	if _, err := connection.Write(body); err != nil {
		return err
	}
	response := make([]byte, 1500)
	read, err := connection.Read(response)
	if err != nil {
		return err
	}
	if read < 12 || binary.BigEndian.Uint16(response[0:2]) != id || binary.BigEndian.Uint16(response[2:4])&0x8000 == 0 ||
		binary.BigEndian.Uint16(response[2:4])&0x000f != 0 || binary.BigEndian.Uint16(response[6:8]) == 0 {
		return fmt.Errorf("DNS response is not a successful answer")
	}
	return nil
}
