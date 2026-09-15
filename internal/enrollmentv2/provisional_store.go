package enrollmentv2

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"loom/internal/wire"
)

const DomainProvisionalPreparationRequest = "loom-enrollment-provisional-preparation-request-v1"

type ProvisionalMaterialGenerator func(context.Context, string, VerifiedClaimAttemptV2,
	DurableRecord, EnrollmentCommitCoordinateV1) (PreparedProvisionalV1, error)

type provisionalFirstResultRecordV1 struct {
	OperationID string                       `json:"operation_id"`
	RequestHash string                       `json:"request_hash"`
	Reservation DurableRecord                `json:"reservation"`
	Coordinate  EnrollmentCommitCoordinateV1 `json:"coordinate"`
	Prepared    PreparedProvisionalV1        `json:"prepared"`
}

type provisionalFirstResultStateV1 struct {
	Schema  int                              `json:"schema"`
	Records []provisionalFirstResultRecordV1 `json:"records"`
}

// DurableProvisionalService 把 CA/result generator 的第一次合法输出原子保存。
// 文件只位于 control-private 存储，绝不能进入 public distribution。
type DurableProvisionalService struct {
	mu       sync.Mutex
	path     string
	generate ProvisionalMaterialGenerator
	state    provisionalFirstResultStateV1
}

func OpenDurableProvisionalService(path string,
	generate ProvisionalMaterialGenerator) (*DurableProvisionalService, error) {
	if path == "" || generate == nil {
		return nil, errors.New("[Enrollment] provisional store path/generator 不能为空")
	}
	service := &DurableProvisionalService{path: path, generate: generate,
		state: provisionalFirstResultStateV1{Schema: 2, Records: []provisionalFirstResultRecordV1{}}}
	state, err := readProvisionalFirstResults(path)
	if errors.Is(err, os.ErrNotExist) {
		return service, nil
	}
	if err != nil {
		return nil, err
	}
	service.state = state
	return service, nil
}

func (service *DurableProvisionalService) PrepareProvisional(ctx context.Context,
	operationID string, attempt VerifiedClaimAttemptV2, record DurableRecord,
	coordinate EnrollmentCommitCoordinateV1) (PreparedProvisionalV1, error) {
	if service == nil || operationID == "" {
		return PreparedProvisionalV1{}, errors.New("[Enrollment] provisional request identity 无效")
	}
	if err := ctx.Err(); err != nil {
		return PreparedProvisionalV1{}, err
	}
	if err := validateCommitCoordinate(&coordinate, record.State.ClusterID); err != nil {
		return PreparedProvisionalV1{}, err
	}
	wantOperationID, err := ProvisionalOperationID(&record)
	if err != nil || operationID != wantOperationID {
		return PreparedProvisionalV1{}, errors.New("[Enrollment] provisional request operation ID 无效")
	}
	requestHash, err := provisionalPreparationRequestHash(operationID, &record, &coordinate)
	if err != nil {
		return PreparedProvisionalV1{}, err
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	index := sort.Search(len(service.state.Records), func(index int) bool {
		return service.state.Records[index].OperationID >= operationID
	})
	if index < len(service.state.Records) && service.state.Records[index].OperationID == operationID {
		existing := service.state.Records[index]
		if existing.RequestHash != requestHash || !wire.EqualCanonical(existing.Coordinate, coordinate) {
			return PreparedProvisionalV1{},
				errors.New("[Enrollment] provisional operation ID 已绑定不同 request/coordinate")
		}
		if err := validatePreparedProvisional(&existing.Prepared, operationID, &record, &coordinate); err != nil {
			return PreparedProvisionalV1{}, err
		}
		return clonePreparedProvisional(existing.Prepared), nil
	}
	prepared, err := service.generate(ctx, operationID, attempt, cloneDurableRecord(record), coordinate)
	if err != nil {
		return PreparedProvisionalV1{}, err
	}
	if err := validatePreparedProvisional(&prepared, operationID, &record, &coordinate); err != nil {
		return PreparedProvisionalV1{}, err
	}
	firstResult := provisionalFirstResultRecordV1{OperationID: operationID,
		RequestHash: requestHash, Reservation: cloneDurableRecord(record), Coordinate: coordinate, Prepared: clonePreparedProvisional(prepared)}
	candidate := cloneProvisionalFirstResultState(service.state)
	candidate.Records = append(candidate.Records, provisionalFirstResultRecordV1{})
	copy(candidate.Records[index+1:], candidate.Records[index:])
	candidate.Records[index] = firstResult
	if err := service.persistLocked(candidate); err != nil {
		return PreparedProvisionalV1{}, err
	}
	service.state = candidate
	return clonePreparedProvisional(prepared), nil
}

func (service *DurableProvisionalService) persistLocked(candidate provisionalFirstResultStateV1) error {
	if err := validateProvisionalFirstResultState(&candidate); err != nil {
		return err
	}
	body, err := wire.MarshalCanonical(candidate)
	if err != nil {
		return err
	}
	directory := filepath.Dir(service.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(directory, filepath.Base(service.path)+".tmp-")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err = file.Chmod(0o600); err == nil {
		_, err = file.Write(body)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := replaceDurableFile(temporary, service.path); err != nil {
		return err
	}
	return syncDurableDirectory(directory)
}

func provisionalPreparationRequestHash(operationID string, record *DurableRecord,
	coordinate *EnrollmentCommitCoordinateV1) (string, error) {
	if record == nil || coordinate == nil {
		return "", errors.New("[Enrollment] provisional request hash input 不完整")
	}
	return wire.HashObject(DomainProvisionalPreparationRequest, struct {
		Schema      int                          `json:"schema"`
		OperationID string                       `json:"operation_id"`
		Record      DurableRecord                `json:"record"`
		Coordinate  EnrollmentCommitCoordinateV1 `json:"coordinate"`
	}{Schema: 1, OperationID: operationID, Record: *record, Coordinate: *coordinate})
}

func validateProvisionalFirstResultState(state *provisionalFirstResultStateV1) error {
	if state == nil || state.Schema != 2 || state.Records == nil {
		return errors.New("[D130 Enrollment] provisional first-result store schema 无效")
	}
	for index := range state.Records {
		record := &state.Records[index]
		if record.OperationID == "" || index > 0 && state.Records[index-1].OperationID >= record.OperationID {
			return errors.New("[Enrollment] provisional first-results 未按 operation ID 严格排序")
		}
		if _, err := wire.ParseHash(record.RequestHash); err != nil {
			return err
		}
		if err := validateStoredPreparedProvisional(&record.Prepared, record.OperationID,
			&record.Coordinate); err != nil {
			return err
		}
		if err := validateDurableRecord(&record.Reservation); err != nil {
			return err
		}
		requestHash, err := provisionalPreparationRequestHash(record.OperationID, &record.Reservation, &record.Coordinate)
		operationID, idErr := ProvisionalOperationID(&record.Reservation)
		if err != nil || idErr != nil || requestHash != record.RequestHash || operationID != record.OperationID {
			return errors.New("[D130 Enrollment] stored first-result reservation/request binding 无效")
		}
		if err := validatePreparedProvisional(&record.Prepared, record.OperationID, &record.Reservation, &record.Coordinate); err != nil {
			return err
		}
	}
	return nil
}

// ProvisionalRecoveryV1 保留首次签发时已经认证的 reservation 和冻结日志坐标。
// daemon 在选举 barrier 之前恢复尚未写入 operation journal 的 first-result；
// 不需要再持有 claim token/CSR，也不得再次调用 CA（D102、D130）。
type ProvisionalRecoveryV1 struct {
	Reservation DurableRecord
	Coordinate  EnrollmentCommitCoordinateV1
	Prepared    PreparedProvisionalV1
}

func ReadDurableProvisionalResults(path string) ([]ProvisionalRecoveryV1, error) {
	state, err := readProvisionalFirstResults(path)
	if errors.Is(err, os.ErrNotExist) {
		return []ProvisionalRecoveryV1{}, nil
	}
	if err != nil {
		return nil, err
	}
	results := make([]ProvisionalRecoveryV1, len(state.Records))
	for i, record := range state.Records {
		results[i] = ProvisionalRecoveryV1{Reservation: record.Reservation, Coordinate: record.Coordinate, Prepared: record.Prepared}
	}
	return results, nil
}

func readProvisionalFirstResults(path string) (provisionalFirstResultStateV1, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return provisionalFirstResultStateV1{}, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() < 1 || info.Size() > 64<<20 {
		return provisionalFirstResultStateV1{}, errors.New("[D130 Enrollment] first-result store 必须是 0600 有界普通文件")
	}
	file, err := os.Open(path)
	if err != nil {
		return provisionalFirstResultStateV1{}, err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		_ = file.Close()
		return provisionalFirstResultStateV1{}, errors.New("[D130 Enrollment] first-result store 在读取时被替换")
	}
	body, err := io.ReadAll(io.LimitReader(file, (64<<20)+1))
	closeErr := file.Close()
	if err != nil {
		return provisionalFirstResultStateV1{}, err
	}
	if closeErr != nil {
		return provisionalFirstResultStateV1{}, closeErr
	}
	var state provisionalFirstResultStateV1
	canonical, err := wire.DecodeStrict(body, 64<<20, &state)
	if err != nil || len(body) > 64<<20 || !bytes.Equal(body, canonical) {
		return provisionalFirstResultStateV1{}, fmt.Errorf("[D130 Enrollment] first-result store 非规范或损坏: %v", err)
	}
	if err := validateProvisionalFirstResultState(&state); err != nil {
		return provisionalFirstResultStateV1{}, err
	}
	return state, nil
}

func validateStoredPreparedProvisional(prepared *PreparedProvisionalV1, operationID string,
	coordinate *EnrollmentCommitCoordinateV1) error {
	if prepared == nil || coordinate == nil || prepared.Operation.OperationID != operationID ||
		prepared.Operation.IssuedAt != coordinate.CommittedLogicalTime ||
		prepared.Operation.ClusterID != coordinate.ClusterID ||
		prepared.Issuance.Body.IssuanceLogCoordinate.RecoveryEpoch != coordinate.RecoveryEpoch ||
		prepared.Issuance.Body.IssuanceLogCoordinate.RaftIndex != coordinate.RaftIndex {
		return errors.New("[Enrollment] stored provisional first-result coordinate 无效")
	}
	if err := validateCommitCoordinate(coordinate, prepared.Operation.ClusterID); err != nil {
		return err
	}
	return validateProvisionalEvidence(&prepared.Operation, &prepared.Issuance,
		&prepared.Profile, &prepared.Result)
}

func clonePreparedProvisional(value PreparedProvisionalV1) PreparedProvisionalV1 {
	body, err := wire.MarshalCanonical(value)
	if err != nil {
		return PreparedProvisionalV1{}
	}
	var result PreparedProvisionalV1
	if _, err := wire.DecodeStrict(body, 32<<20, &result); err != nil {
		return PreparedProvisionalV1{}
	}
	return result
}

func cloneProvisionalFirstResultState(value provisionalFirstResultStateV1) provisionalFirstResultStateV1 {
	body, err := wire.MarshalCanonical(value)
	if err != nil {
		return provisionalFirstResultStateV1{}
	}
	var result provisionalFirstResultStateV1
	if _, err := wire.DecodeStrict(body, 64<<20, &result); err != nil {
		return provisionalFirstResultStateV1{}
	}
	return result
}
