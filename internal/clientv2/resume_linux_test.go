//go:build linux

package clientv2

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"loom/internal/wire"
)

func TestLinuxResumeCarrierRequiresExactCanonicalRegularFile(t *testing.T) {
	descriptor := wire.EnrollmentResumeDescriptorV1{Schema: 1}
	raw, err := wire.MarshalCanonical(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := ReadLinuxResumeDescriptor("-", bytes.NewReader(raw))
	if err != nil || decoded.Schema != 1 {
		t.Fatalf("stdin canonical resume 未解码: descriptor=%#v err=%v", decoded, err)
	}
	if _, err := ReadLinuxResumeDescriptor("-", bytes.NewReader(append(raw, '\n'))); err == nil {
		t.Fatal("resume carrier 接受了非 exact canonical 尾随换行")
	}
	unknown := []byte(`{"schema":1,"token":"forbidden"}`)
	if _, err := ReadLinuxResumeDescriptor("-", bytes.NewReader(unknown)); err == nil {
		t.Fatal("resume carrier 接受了 token/unknown field")
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "device.loom-resume")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadLinuxResumeDescriptor(path, nil); err != nil {
		t.Fatalf("普通 resume 文件未解码: %v", err)
	}
	link := filepath.Join(directory, "linked.loom-resume")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadLinuxResumeDescriptor(link, nil); err == nil {
		t.Fatal("resume carrier 接受了 symlink")
	}
}

func TestLinuxResumeNeverCreatesReplacementIdentity(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "identity.json")
	if _, err := LoadEnrollmentIdentityForResume(path); err == nil {
		t.Fatal("缺失 identity 的 resume 未失败")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("resume 路径生成了替代 identity: %v", err)
	}
}
