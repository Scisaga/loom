// Package crdt 保存只增、内容寻址的复制材料。
// 这里的对象永远不能直接改变权限或渲染输入；effective SSOT 仍只由
// controlplane 的 committed + certified head 决定（D101、D104）。
package crdt

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"loom/internal/wire"
)

const objectDomain = "loom-crdt-immutable-object-v1"

type Object struct {
	Schema   int             `json:"schema"`
	ID       string          `json:"id"`
	Kind     string          `json:"kind"`
	Payload  json.RawMessage `json:"payload"`
	ObjectID string          `json:"object_id"`
}

type objectHashInput struct {
	Schema  int             `json:"schema"`
	ID      string          `json:"id"`
	Kind    string          `json:"kind"`
	Payload json.RawMessage `json:"payload"`
}

type diskState struct {
	Schema  int      `json:"schema"`
	Objects []Object `json:"objects"`
}

type Store struct {
	mu      sync.Mutex
	path    string
	objects map[string]Object
}

func NewObject(id, kind string, payload []byte) (Object, error) {
	if !validToken(id, 256) || !validToken(kind, 128) {
		return Object{}, errors.New("[D101 CRDT] immutable object id/kind 无效")
	}
	canonical, err := wire.CanonicalizeStrict(payload)
	if err != nil {
		return Object{}, err
	}
	input := objectHashInput{Schema: 1, ID: id, Kind: kind, Payload: json.RawMessage(canonical)}
	hash, err := wire.HashObject(objectDomain, input)
	if err != nil {
		return Object{}, err
	}
	return Object{Schema: 1, ID: id, Kind: kind, Payload: json.RawMessage(canonical), ObjectID: hash}, nil
}

func Open(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("[D101 CRDT] store path 不能为空")
	}
	store := &Store{path: path, objects: make(map[string]Object)}
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, err
	}
	var state diskState
	if _, err := wire.DecodeStrict(body, 64<<20, &state); err != nil {
		return nil, fmt.Errorf("[D101 CRDT] store 无效: %w", err)
	}
	if state.Schema != 1 || !sort.SliceIsSorted(state.Objects, func(i, j int) bool { return state.Objects[i].ID < state.Objects[j].ID }) {
		return nil, errors.New("[D101 CRDT] store schema/order 无效")
	}
	for _, object := range state.Objects {
		if err := validateObject(object); err != nil {
			return nil, err
		}
		if _, exists := store.objects[object.ID]; exists {
			return nil, errors.New("[D101 CRDT] store 含重复 logical ID")
		}
		store.objects[object.ID] = cloneObject(object)
	}
	return store, nil
}

func (s *Store) Add(object Object) error {
	if err := validateObject(object); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.objects[object.ID]; ok {
		if existing.ObjectID == object.ObjectID && bytes.Equal(existing.Payload, object.Payload) && existing.Kind == object.Kind {
			return nil
		}
		return errors.New("[D101 CRDT] 同一 logical ID 出现不同 bytes，副本已损坏")
	}
	s.objects[object.ID] = cloneObject(object)
	if err := s.persistLocked(); err != nil {
		delete(s.objects, object.ID)
		return err
	}
	return nil
}

// Merge 是交换律、结合律、幂等的 add-only union；冲突不会由 LWW 静默覆盖。
func (s *Store) Merge(objects []Object) error {
	ordered := append([]Object(nil), objects...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
	for i := range ordered {
		if err := s.Add(ordered[i]); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) Snapshot() []Object {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshotLocked()
}

func (s *Store) Missing(peerObjectIDs []string) []Object {
	known := make(map[string]struct{}, len(peerObjectIDs))
	for _, id := range peerObjectIDs {
		known[id] = struct{}{}
	}
	objects := s.Snapshot()
	missing := objects[:0]
	for _, object := range objects {
		if _, exists := known[object.ObjectID]; !exists {
			missing = append(missing, object)
		}
	}
	return missing
}

// Root 仅用于 anti-entropy 完整性比较，不代表任何对象已获授权。
func (s *Store) Root() (string, error) {
	objects := s.Snapshot()
	leaves := make([][]byte, len(objects))
	for i, object := range objects {
		canonical, err := wire.MarshalCanonical(object)
		if err != nil {
			return "", err
		}
		leaves[i] = canonical
	}
	return "sha256:" + hex.EncodeToString(wire.MerkleRoot(leaves)), nil
}

func validateObject(object Object) error {
	if object.Schema != 1 || !validToken(object.ID, 256) || !validToken(object.Kind, 128) {
		return errors.New("[D101 CRDT] immutable object schema/id/kind 无效")
	}
	canonical, err := wire.CanonicalizeStrict(object.Payload)
	if err != nil || !bytes.Equal(canonical, object.Payload) {
		return errors.New("[D101 CRDT] payload 必须已经是 canonical JSON")
	}
	want, err := wire.HashObject(objectDomain, objectHashInput{Schema: 1, ID: object.ID, Kind: object.Kind, Payload: object.Payload})
	if err != nil {
		return err
	}
	if object.ObjectID != want {
		return errors.New("[D101 CRDT] object_id 与 exact bytes 不匹配")
	}
	return nil
}

func (s *Store) snapshotLocked() []Object {
	objects := make([]Object, 0, len(s.objects))
	for _, object := range s.objects {
		objects = append(objects, cloneObject(object))
	}
	sort.Slice(objects, func(i, j int) bool { return objects[i].ID < objects[j].ID })
	return objects
}

func (s *Store) persistLocked() error {
	body, err := wire.MarshalCanonical(diskState{Schema: 1, Objects: s.snapshotLocked()})
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	temp, err := os.CreateTemp(dir, ".crdt-*")
	if err != nil {
		return err
	}
	name := temp.Name()
	defer os.Remove(name)
	if err := temp.Chmod(0600); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(body); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, s.path); err != nil {
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func cloneObject(object Object) Object {
	object.Payload = append(json.RawMessage(nil), object.Payload...)
	return object
}

func validToken(value string, maximum int) bool {
	if value == "" || len(value) > maximum {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') && r != '-' && r != '_' && r != ':' && r != '.' {
			return false
		}
	}
	return true
}
