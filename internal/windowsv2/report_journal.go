package windowsv2

import (
	"bytes"
	"context"
	"errors"
	"os"
	"sync"

	"loom/internal/clientsecret"
	"loom/internal/wire"
)

const (
	ReportJournalPurpose      = "windows-v2-report-v1"
	maximumReportJournalBytes = 8 << 20
	reportEnvelopeHashDomain  = "loom-windows-device-report-envelope-v1"
)

type DeviceReportJournalV1 struct {
	Schema                   int                          `json:"schema"`
	DeviceID                 string                       `json:"device_id"`
	LastAcceptedSequence     int64                        `json:"last_accepted_sequence"`
	LastAcceptedEnvelopeHash string                       `json:"last_accepted_envelope_hash,omitempty"`
	NextSequence             int64                        `json:"next_sequence"`
	Pending                  *wire.DeviceReportEnvelopeV2 `json:"pending,omitempty"`
}

var reportJournalMutex sync.Mutex

// SendDeviceReportDurable 先原子保存 exact signed envelope，再发送；响应前后崩溃
// 都只会重放相同 report_id/sequence/bytes，成功后才推进 sequence（D131）。
func SendDeviceReportDurable(ctx context.Context, journalPath string,
	options DeviceReportOptions) (wire.DeviceReportEnvelopeV2, error) {
	_, envelope, err := sendDeviceReportDurable(ctx, journalPath, options, true)
	return envelope, err
}

// RetryPendingDeviceReportDurable 只重放已经 durable 的 exact envelope；没有
// pending 时不创建新报告。宿主在接受新 Device view 前先调用它，避免 floors
// 前移后把已占用 sequence 变成无法重放的旧签名（D131）。
func RetryPendingDeviceReportDurable(ctx context.Context, journalPath string,
	options DeviceReportOptions) (bool, wire.DeviceReportEnvelopeV2, error) {
	return sendDeviceReportDurable(ctx, journalPath, options, false)
}

func sendDeviceReportDurable(ctx context.Context, journalPath string,
	options DeviceReportOptions, create bool,
) (bool, wire.DeviceReportEnvelopeV2, error) {
	if ctx == nil || options.Protector == nil || options.ReportID != "" ||
		options.ReportSequence != 0 || validateProtectedPath(journalPath) != nil {
		return false, wire.DeviceReportEnvelopeV2{}, errors.New("[D131 Windows report] durable journal 输入无效")
	}
	reportJournalMutex.Lock()
	defer reportJournalMutex.Unlock()
	store, err := OpenState(options.StatePath, options.Protector)
	if err != nil {
		return false, wire.DeviceReportEnvelopeV2{}, err
	}
	state := store.Snapshot()
	if state == nil || state.Envelope.Payload.State != "active" || state.Envelope.Payload.Active == nil {
		return false, wire.DeviceReportEnvelopeV2{}, errors.New("[D131 Windows report] tombstone/inactive Device 禁止 durable report")
	}
	journal, err := readDeviceReportJournal(journalPath, options.Protector)
	if errors.Is(err, os.ErrNotExist) {
		if !create {
			return false, wire.DeviceReportEnvelopeV2{}, nil
		}
		journal = &DeviceReportJournalV1{Schema: 1,
			DeviceID: state.Envelope.Payload.DeviceID, NextSequence: 1}
	} else if err != nil {
		return false, wire.DeviceReportEnvelopeV2{}, err
	}
	if journal.DeviceID != state.Envelope.Payload.DeviceID {
		return false, wire.DeviceReportEnvelopeV2{}, errors.New("[D131 Windows report] journal 属于另一 Device")
	}
	var envelope wire.DeviceReportEnvelopeV2
	if journal.Pending == nil {
		if !create {
			return false, wire.DeviceReportEnvelopeV2{}, nil
		}
		options.ReportSequence = journal.NextSequence
		envelope, err = PrepareDeviceReport(options)
		if err != nil {
			return false, wire.DeviceReportEnvelopeV2{}, err
		}
		journal.Pending = &envelope
		if err := writeDeviceReportJournal(journalPath, journal, options.Protector); err != nil {
			return false, wire.DeviceReportEnvelopeV2{}, err
		}
	} else {
		envelope = cloneValue(*journal.Pending)
	}
	if err := SubmitDeviceReport(ctx, options, &envelope); err != nil {
		return true, envelope, err
	}
	envelopeHash, err := wire.HashObject(reportEnvelopeHashDomain, &envelope)
	if err != nil {
		return true, envelope, err
	}
	next, err := wire.CheckedAdd(journal.NextSequence, 1)
	if err != nil {
		return true, envelope, errors.New("[D131 Windows report] report sequence 溢出")
	}
	journal.LastAcceptedSequence = journal.NextSequence
	journal.LastAcceptedEnvelopeHash = envelopeHash
	journal.NextSequence = next
	journal.Pending = nil
	if err := writeDeviceReportJournal(journalPath, journal, options.Protector); err != nil {
		return true, envelope, err
	}
	return true, envelope, nil
}

func readDeviceReportJournal(path string,
	protector clientsecret.Protector) (*DeviceReportJournalV1, error) {
	body, err := clientsecret.ReadLargeProtected(path, ReportJournalPurpose, protector)
	if err != nil {
		return nil, err
	}
	defer clear(body)
	if len(body) > maximumReportJournalBytes {
		return nil, errors.New("[D131 Windows report] journal 超过大小边界")
	}
	var journal DeviceReportJournalV1
	canonical, err := wire.DecodeStrict(body, maximumReportJournalBytes, &journal)
	if err != nil || !bytes.Equal(canonical, body) {
		return nil, errors.New("[D131 Windows report] journal 不是 exact canonical wire")
	}
	if err := validateDeviceReportJournal(&journal); err != nil {
		return nil, err
	}
	return &journal, nil
}

func writeDeviceReportJournal(path string, journal *DeviceReportJournalV1,
	protector clientsecret.Protector) error {
	if err := validateDeviceReportJournal(journal); err != nil {
		return err
	}
	body, err := wire.MarshalCanonical(journal)
	if err != nil {
		return err
	}
	defer clear(body)
	if len(body) > maximumReportJournalBytes {
		return errors.New("[D131 Windows report] journal 超过大小边界")
	}
	if err := clientsecret.WriteLargeProtected(path, ReportJournalPurpose, body, protector); err != nil {
		return err
	}
	replayed, err := readDeviceReportJournal(path, protector)
	if err != nil {
		return err
	}
	if !wire.EqualCanonical(*journal, *replayed) {
		return errors.New("[D131 Windows report] journal 写后回读分叉")
	}
	return nil
}

func validateDeviceReportJournal(journal *DeviceReportJournalV1) error {
	if journal == nil || journal.Schema != 1 || journal.DeviceID == "" ||
		journal.LastAcceptedSequence < 0 || journal.NextSequence < 1 {
		return errors.New("[D131 Windows report] journal header/sequence 无效")
	}
	wanted, err := wire.CheckedAdd(journal.LastAcceptedSequence, 1)
	if err != nil || wanted != journal.NextSequence {
		return errors.New("[D131 Windows report] journal sequence 不连续")
	}
	if journal.LastAcceptedSequence == 0 {
		if journal.LastAcceptedEnvelopeHash != "" {
			return errors.New("[D131 Windows report] 初始 journal 禁止 last hash")
		}
	} else if _, err := wire.ParseHash(journal.LastAcceptedEnvelopeHash); err != nil {
		return errors.New("[D131 Windows report] journal last hash 无效")
	}
	if journal.Pending != nil && (journal.Pending.Schema != 2 ||
		journal.Pending.Body.DeviceID != journal.DeviceID ||
		journal.Pending.Body.ReportSequence != journal.NextSequence) {
		return errors.New("[D131 Windows report] pending envelope 与 journal 序号/Device 不一致")
	}
	return nil
}
