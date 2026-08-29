package publish

import (
	"errors"
	"strings"
	"testing"
)

type mirrorTargetStub struct {
	name       string
	files      map[string][]byte
	blobs      map[string]bool
	current    string
	pushes     int
	pushErr    error
	readErr    error
	currentErr error
}

func (s *mirrorTargetStub) String() string { return s.name }
func (s *mirrorTargetStub) Push(*Tree) error {
	s.pushes++
	return s.pushErr
}
func (s *mirrorTargetStub) ReadFile(path string) ([]byte, bool, error) {
	if s.readErr != nil {
		return nil, false, s.readErr
	}
	body, ok := s.files[path]
	return body, ok, nil
}
func (s *mirrorTargetStub) HasBlob(path string) (bool, error) { return s.blobs[path], nil }
func (s *mirrorTargetStub) Current() (string, error)          { return s.current, s.currentErr }

func TestMirrorSetPushesEveryTargetAndReportsPartialFailure(t *testing.T) {
	a := &mirrorTargetStub{name: "a"}
	b := &mirrorTargetStub{name: "b", pushErr: errors.New("down")}
	target, err := NewMirrorSet(a, b)
	if err != nil {
		t.Fatal(err)
	}
	if err := target.Push(&Tree{}); err == nil || !strings.Contains(err.Error(), "1/2") {
		t.Fatalf("部分镜像失败没有让发布保持非绿:%v", err)
	}
	if a.pushes != 1 || b.pushes != 1 {
		t.Fatalf("应尝试每个镜像:a=%d b=%d", a.pushes, b.pushes)
	}
}

func TestMirrorSetRequiresExactSmallFilesOnEveryMirror(t *testing.T) {
	a := &mirrorTargetStub{name: "a", files: map[string][]byte{"current.json": []byte("one")}}
	b := &mirrorTargetStub{name: "b", files: map[string][]byte{"current.json": []byte("one")}}
	target, err := NewMirrorSet(a, b)
	if err != nil {
		t.Fatal(err)
	}
	body, found, err := target.ReadFile("current.json")
	if err != nil || !found || string(body) != "one" {
		t.Fatalf("一致镜像读取失败:found=%v body=%q err=%v", found, body, err)
	}
	b.files["current.json"] = []byte("two")
	if _, _, err := target.ReadFile("current.json"); err == nil || !strings.Contains(err.Error(), "不同字节") {
		t.Fatalf("镜像分叉未被识别:%v", err)
	}
	delete(b.files, "current.json")
	if _, found, err := target.ReadFile("current.json"); err != nil || found {
		t.Fatalf("缺一份时应报告不完整而不是假装收敛:found=%v err=%v", found, err)
	}
}

func TestMirrorSetRejectsDuplicateTarget(t *testing.T) {
	if _, err := NewMirrorSet(&mirrorTargetStub{name: "same"}, &mirrorTargetStub{name: "same"}); err == nil {
		t.Fatal("重复镜像应被拒绝")
	}
}
