package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"loom/internal/wire"
)

const domainAcceptedDeviceReport = "loom-accepted-device-report-v2"

type StoredDeviceReportV1 struct {
	DeviceID        string                  `json:"device_id"`
	CertificateHash string                  `json:"certificate_hash"`
	Body            wire.DeviceReportBodyV2 `json:"body"`
	Payload         json.RawMessage         `json:"payload"`
	ReportHash      string                  `json:"report_hash"`
}

type DeviceReportStoreStateV1 struct {
	Schema  int                    `json:"schema"`
	Reports []StoredDeviceReportV1 `json:"reports"`
}

// DeviceReportStore 是 report sink 的 durable latest/CAS 实现；报告先完整 fsync，
// 才对 private handler 返回 204，进程崩溃不能使同一 sequence 接受冲突内容。
type DeviceReportStore struct {
	mu      sync.Mutex
	path    string
	schemas wire.DeviceReportSchemaRegistry
	state   DeviceReportStoreStateV1
}

func OpenDeviceReportStore(path string, schemas wire.DeviceReportSchemaRegistry) (*DeviceReportStore, error) {
	if path == "" || len(schemas) == 0 {
		return nil, errors.New("[device_report] store path/reader contract 无效")
	}
	copySchemas := make(wire.DeviceReportSchemaRegistry, len(schemas))
	for kind, schema := range schemas {
		if kind == "" || schema < 1 {
			return nil, errors.New("[device_report] store reader contract 无效")
		}
		copySchemas[kind] = schema
	}
	store := &DeviceReportStore{path: path, schemas: copySchemas,
		state: DeviceReportStoreStateV1{Schema: 1, Reports: []StoredDeviceReportV1{}}}
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return nil, errors.New("[device_report] store 必须是 0600 普通文件")
	}
	canonical, err := wire.CanonicalizeStrict(body)
	if err != nil || !bytes.Equal(canonical, body) {
		return nil, errors.New("[device_report] store 不是 exact canonical JSON")
	}
	var state DeviceReportStoreStateV1
	if _, err := wire.DecodeStrict(body, 64<<20, &state); err != nil {
		return nil, err
	}
	if err := validateDeviceReportStoreState(&state, copySchemas); err != nil {
		return nil, err
	}
	store.state = state
	return store, nil
}

func (store *DeviceReportStore) Commit(ctx context.Context, verified VerifiedDeviceReportV2) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	record, err := storedDeviceReport(verified, store.schemas)
	if err != nil {
		return err
	}
	key := deviceReportStoreKey(record.DeviceID, record.CertificateHash)
	position := sort.Search(len(store.state.Reports), func(i int) bool {
		current := store.state.Reports[i]
		return deviceReportStoreKey(current.DeviceID, current.CertificateHash) >= key
	})
	next := cloneDeviceReportStoreState(store.state)
	if position < len(next.Reports) && deviceReportStoreKey(next.Reports[position].DeviceID, next.Reports[position].CertificateHash) == key {
		current := next.Reports[position]
		if record.Body.ReportSequence < current.Body.ReportSequence ||
			record.Body.ReportSequence == current.Body.ReportSequence && record.ReportHash != current.ReportHash {
			return ErrDeviceReportSequence
		}
		if record.Body.ReportSequence == current.Body.ReportSequence {
			return nil
		}
		next.Reports[position] = record
	} else {
		next.Reports = append(next.Reports, StoredDeviceReportV1{})
		copy(next.Reports[position+1:], next.Reports[position:])
		next.Reports[position] = record
	}
	if err := store.persistLocked(next); err != nil {
		return err
	}
	store.state = next
	return nil
}

func (store *DeviceReportStore) Snapshot() DeviceReportStoreStateV1 {
	store.mu.Lock()
	defer store.mu.Unlock()
	return cloneDeviceReportStoreState(store.state)
}

func storedDeviceReport(verified VerifiedDeviceReportV2,
	schemas wire.DeviceReportSchemaRegistry) (StoredDeviceReportV1, error) {
	body := verified.Body()
	payload := verified.Payload()
	if verified.DeviceID() == "" || body.DeviceID != verified.DeviceID() {
		return StoredDeviceReportV1{}, errors.New("[device_report] opaque identity/report Device 不一致")
	}
	if err := wire.ValidateDeviceReportBody(&body, schemas); err != nil {
		return StoredDeviceReportV1{}, err
	}
	payloadHash, err := wire.DeviceReportPayloadHash(payload)
	if err != nil || payloadHash != body.PayloadHash {
		return StoredDeviceReportV1{}, errors.New("[device_report] stored payload hash 不匹配")
	}
	certificateHash := verified.identity.CertificateHash()
	if _, err := wire.ParseHash(certificateHash); err != nil {
		return StoredDeviceReportV1{}, err
	}
	reportHash, err := wire.HashObject(domainAcceptedDeviceReport, struct {
		Body    wire.DeviceReportBodyV2 `json:"body"`
		Payload json.RawMessage         `json:"payload"`
	}{Body: body, Payload: payload})
	if err != nil {
		return StoredDeviceReportV1{}, err
	}
	return StoredDeviceReportV1{DeviceID: body.DeviceID, CertificateHash: certificateHash,
		Body: body, Payload: payload, ReportHash: reportHash}, nil
}

func validateDeviceReportStoreState(state *DeviceReportStoreStateV1, schemas wire.DeviceReportSchemaRegistry) error {
	if state == nil || state.Schema != 1 || state.Reports == nil {
		return errors.New("[device_report] store state header 无效")
	}
	previousKey := ""
	for i := range state.Reports {
		record := &state.Reports[i]
		key := deviceReportStoreKey(record.DeviceID, record.CertificateHash)
		if key == "\x00" || i > 0 && previousKey >= key || record.Body.DeviceID != record.DeviceID {
			return errors.New("[device_report] stored reports 未排序、重复或 identity 不一致")
		}
		if _, err := wire.ParseHash(record.CertificateHash); err != nil {
			return err
		}
		payloadHash, err := wire.DeviceReportPayloadHash(record.Payload)
		if err != nil || payloadHash != record.Body.PayloadHash || wire.ValidateDeviceReportBody(&record.Body, schemas) != nil {
			return errors.New("[device_report] stored report body/payload 无效")
		}
		wantHash, err := wire.HashObject(domainAcceptedDeviceReport, struct {
			Body    wire.DeviceReportBodyV2 `json:"body"`
			Payload json.RawMessage         `json:"payload"`
		}{Body: record.Body, Payload: record.Payload})
		if err != nil || wantHash != record.ReportHash {
			return errors.New("[device_report] stored report hash 不匹配")
		}
		previousKey = key
	}
	return nil
}

func (store *DeviceReportStore) persistLocked(state DeviceReportStoreStateV1) error {
	if err := validateDeviceReportStoreState(&state, store.schemas); err != nil {
		return err
	}
	body, err := wire.MarshalCanonical(state)
	if err != nil {
		return err
	}
	directory := filepath.Dir(store.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, filepath.Base(store.path)+".tmp-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err == nil {
		_, err = temporary.Write(body)
	}
	if err == nil {
		err = temporary.Sync()
	}
	closeErr := temporary.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, store.path); err != nil {
		return err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	err = dir.Sync()
	closeErr = dir.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func deviceReportStoreKey(deviceID, certificateHash string) string {
	return deviceID + "\x00" + certificateHash
}

func cloneDeviceReportStoreState(state DeviceReportStoreStateV1) DeviceReportStoreStateV1 {
	body, _ := wire.MarshalCanonical(state)
	var clone DeviceReportStoreStateV1
	_, _ = wire.DecodeStrict(body, 64<<20, &clone)
	return clone
}
