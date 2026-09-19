//go:build windows

package main

import "testing"

func TestWindowsObservationDisplayUsesBusinessOutcomes(t *testing.T) {
	for _, test := range []struct {
		result, health, summary string
	}{
		{"available", "可用", "TCP/TLS 与 UDP/DNS 已验证"},
		{"unavailable", "不可用", "TCP/TLS 或 UDP/DNS 失败"},
		{"unknown", "未知", "尚无真实业务结果"},
	} {
		health, summary, _ := windowsObservationDisplay(test.result)
		if health != test.health || summary != test.summary {
			t.Fatalf("result %q projected as health=%q summary=%q", test.result, health, summary)
		}
	}
}
