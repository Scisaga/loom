//go:build linux

package clientv2

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"loom/internal/wire"
)

func TestLinuxInviteCarrierMatchesExactDescriptorHash(t *testing.T) {
	descriptor := linuxInviteCarrierFixture(t)
	raw, err := wire.MarshalCanonical(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	wantHash, _ := wire.HashObject(wire.DomainInviteDescriptor, descriptor)
	fromStdin, err := ReadLinuxInviteDescriptor("-", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	stdinHash, _ := wire.HashObject(wire.DomainInviteDescriptor, fromStdin)
	uri, err := EncodeInviteURI(&descriptor)
	if err != nil {
		t.Fatal(err)
	}
	fromURI, err := DecodeInviteURI(uri)
	if err != nil {
		t.Fatal(err)
	}
	uriHash, _ := wire.HashObject(wire.DomainInviteDescriptor, fromURI)
	if stdinHash != wantHash || uriHash != wantHash {
		t.Fatalf("file/URI descriptor hash 分叉: want=%s file=%s uri=%s", wantHash, stdinHash, uriHash)
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "device.loom-invite")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadLinuxInviteDescriptor(path, nil); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "linked.loom-invite")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadLinuxInviteDescriptor(link, nil); err == nil {
		t.Fatal("接受了 symlink Invite carrier")
	}
}

func TestLinuxInviteCarrierRejectsUnknownAndTrailingBytes(t *testing.T) {
	descriptor := linuxInviteCarrierFixture(t)
	raw, _ := wire.MarshalCanonical(descriptor)
	if _, err := DecodeLinuxInviteDescriptor(append(raw, '\n')); err == nil {
		t.Fatal("接受了带尾随空白的 .loom-invite")
	}
	unknown := bytes.Replace(raw, []byte(`"schema":2`), []byte(`"extra":true,"schema":2`), 1)
	if _, err := DecodeLinuxInviteDescriptor(unknown); err == nil {
		t.Fatal("接受了含未知字段的 .loom-invite")
	}
}

func linuxInviteCarrierFixture(t *testing.T) wire.InviteBootstrapDescriptorV2 {
	t.Helper()
	// Carrier 解码刻意不建立 authority；完整字段/签名由 proof verifier 测试覆盖。
	// 这里用最小对象只隔离验证 file 与 URI 的 canonical bytes 完全相同。
	return wire.InviteBootstrapDescriptorV2{Schema: 2}
}
