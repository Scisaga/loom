//go:build windows

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"testing"
	"testing/synctest"
	"time"

	"loom/internal/clientenroll"
	"loom/internal/clientreport"
	"loom/internal/nodepresence"
)

func TestWindowsPresenceWorkerStartsImmediatelyAndKeepsFiveSecondPeriod(t *testing.T) {
	identity, err := clientenroll.GeneratePreparedIdentity(clientenroll.PlatformWindowsDesktop,
		"https://control.example/loom-client/enroll", rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clearPreparedIdentity(&identity)
	block, _ := pem.Decode(identity.CSRPEM)
	if block == nil {
		t.Fatal("Windows identity CSR 缺失")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("Windows identity 不是 ECDSA")
	}

	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		sent := make(chan nodepresence.Heartbeat, 8)
		worker := newWindowsPresenceWorker("demo-windows", identity.PrivateKeyPEM,
			func(ctx context.Context, heartbeat *nodepresence.Heartbeat) clientreport.Result {
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) != windowsPresenceSendTimeout {
					t.Fatal("Windows 心跳没有独立的四秒发送预算")
				}
				sent <- *heartbeat
				return clientreport.Result{Status: http.StatusNoContent}
			}, nil)
		if worker.interval != nodepresence.Period || nodepresence.Period != 5*time.Second ||
			nodepresence.Lease != 15*time.Second || clientreport.Period != time.Minute {
			t.Fatalf("独立周期错误:heartbeat=%s lease=%s observation=%s",
				worker.interval, nodepresence.Lease, clientreport.Period)
		}
		go worker.Run(ctx)
		synctest.Wait()
		first := nextWindowsHeartbeat(t, sent)
		firstAt, err := nodepresence.Verify(first, publicKey, time.Now(), nodepresence.MaximumTransit)
		if err != nil {
			t.Fatal(err)
		}

		time.Sleep(nodepresence.Period - time.Nanosecond)
		synctest.Wait()
		select {
		case <-sent:
			t.Fatal("Windows 心跳早于五秒发送")
		default:
		}
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		second := nextWindowsHeartbeat(t, sent)
		secondAt, err := nodepresence.Verify(second, publicKey, time.Now(), nodepresence.MaximumTransit)
		if err != nil || secondAt.Sub(firstAt) != nodepresence.Period {
			t.Fatalf("Windows 心跳未保持五秒签名节拍:first=%s second=%s err=%v", firstAt, secondAt, err)
		}

		cancel()
		synctest.Wait()
		time.Sleep(nodepresence.Period)
		synctest.Wait()
		select {
		case <-sent:
			t.Fatal("Windows 进程停止后仍发送心跳")
		default:
		}
	})
}

func TestWindowsPresenceTimestampSurvivesClockRollback(t *testing.T) {
	now := time.Date(2026, 9, 15, 8, 0, 0, 0, time.FixedZone("test", 8*60*60))
	first := nextWindowsPresenceTimestamp(now, time.Time{})
	second := nextWindowsPresenceTimestamp(now.Add(-time.Hour), first)
	if first.Location() != time.UTC || !second.After(first) || second.Sub(first) != time.Nanosecond {
		t.Fatalf("Windows 心跳时间没有单调推进:first=%s second=%s", first, second)
	}
}

func nextWindowsHeartbeat(t *testing.T, sent <-chan nodepresence.Heartbeat) nodepresence.Heartbeat {
	t.Helper()
	select {
	case heartbeat := <-sent:
		return heartbeat
	default:
		t.Fatal("Windows 心跳未发送")
		return nodepresence.Heartbeat{}
	}
}
