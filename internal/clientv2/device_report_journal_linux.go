//go:build linux

package clientv2

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
	"loom/internal/wire"
)

const maximumLinuxDeviceReportJournalBytes = 8 << 20

type LinuxDeviceReportJournalV1 struct {
	Schema                   int                          `json:"schema"`
	DeviceID                 string                       `json:"device_id"`
	LastAcceptedSequence     int64                        `json:"last_accepted_sequence"`
	LastAcceptedEnvelopeHash string                       `json:"last_accepted_envelope_hash,omitempty"`
	NextSequence             int64                        `json:"next_sequence"`
	Pending                  *wire.DeviceReportEnvelopeV2 `json:"pending,omitempty"`
}

// SendLinuxDeviceReportDurable 在发送前先持久化 exact signed envelope。
// 进程在 HTTP 响应前后崩溃都只会重放同一 sequence/bytes；
// 只有 204 成功后才原子推进 next sequence（D131）。
func SendLinuxDeviceReportDurable(ctx context.Context, journalPath string,
	options LinuxDeviceReportOptions) (wire.DeviceReportEnvelopeV2, error) {
	if ctx == nil || journalPath == "" || filepath.Clean(journalPath) != journalPath ||
		!filepath.IsAbs(journalPath) || options.ReportID != "" || options.ReportSequence != 0 ||
		options.RetryEnvelope != nil {
		return wire.DeviceReportEnvelopeV2{}, errors.New("[D131 Linux report] durable journal 输入无效")
	}
	if err := secureEnrollmentDirectory(filepath.Dir(journalPath)); err != nil {
		return wire.DeviceReportEnvelopeV2{}, err
	}
	lock, err := openPrivateLock(journalPath + ".lock")
	if err != nil {
		return wire.DeviceReportEnvelopeV2{}, err
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		return wire.DeviceReportEnvelopeV2{}, err
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)

	store, err := Open(options.StatePath)
	if err != nil {
		return wire.DeviceReportEnvelopeV2{}, err
	}
	current := store.Envelope()
	if current == nil || current.Payload.Active == nil {
		return wire.DeviceReportEnvelopeV2{}, errors.New("[D131 Linux report] durable journal 缺 active LKG")
	}
	journal, err := readLinuxDeviceReportJournal(journalPath)
	if errors.Is(err, os.ErrNotExist) {
		journal = &LinuxDeviceReportJournalV1{
			Schema: 1, DeviceID: current.Payload.DeviceID, NextSequence: 1,
		}
	} else if err != nil {
		return wire.DeviceReportEnvelopeV2{}, err
	}
	if journal.DeviceID != current.Payload.DeviceID {
		return wire.DeviceReportEnvelopeV2{}, errors.New("[D131 Linux report] journal 属于另一 Device")
	}

	var envelope wire.DeviceReportEnvelopeV2
	if journal.Pending == nil {
		payloadHash, err := wire.DeviceReportPayloadHash(options.Payload)
		if err != nil {
			return wire.DeviceReportEnvelopeV2{}, err
		}
		options.ReportSequence = journal.NextSequence
		options.ReportID = linuxDeviceReportID(journal.NextSequence, payloadHash)
		envelope, err = PrepareLinuxDeviceReport(options)
		if err != nil {
			return wire.DeviceReportEnvelopeV2{}, err
		}
		journal.Pending = &envelope
		if err := persistProtectedCanonical(journalPath, journal); err != nil {
			return wire.DeviceReportEnvelopeV2{}, err
		}
	} else {
		options.RetryEnvelope = journal.Pending
		envelope, err = PrepareLinuxDeviceReport(options)
		if err != nil {
			return wire.DeviceReportEnvelopeV2{}, err
		}
	}
	if err := SubmitLinuxDeviceReport(ctx, options, &envelope); err != nil {
		return envelope, err
	}
	envelopeHash, err := wire.HashObject("loom-linux-device-report-envelope-v1", &envelope)
	if err != nil {
		return envelope, err
	}
	next, err := wire.CheckedAdd(journal.NextSequence, 1)
	if err != nil {
		return envelope, errors.New("[D131 Linux report] report sequence 溢出")
	}
	journal.LastAcceptedSequence = journal.NextSequence
	journal.LastAcceptedEnvelopeHash = envelopeHash
	journal.NextSequence = next
	journal.Pending = nil
	if err := persistProtectedCanonical(journalPath, journal); err != nil {
		// 服务端可能已接收；保留原文并报错，不在内存里猜测推进。
		return envelope, err
	}
	return envelope, nil
}

func linuxDeviceReportID(sequence int64, payloadHash string) string {
	digest := strings.TrimPrefix(payloadHash, "sha256:")
	if len(digest) > 16 {
		digest = digest[:16]
	}
	return fmt.Sprintf("report-%020d-%s", sequence, digest)
}

func readLinuxDeviceReportJournal(path string) (*LinuxDeviceReportJournalV1, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 ||
		info.Size() < 1 || info.Size() > maximumLinuxDeviceReportJournalBytes {
		return nil, errors.New("[D131 Linux report] journal 必须是 0600 小型普通文件")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || int(stat.Uid) != os.Geteuid() {
		return nil, errors.New("[D131 Linux report] journal owner 不是当前服务账号")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var journal LinuxDeviceReportJournalV1
	canonical, err := wire.DecodeStrict(body, maximumLinuxDeviceReportJournalBytes, &journal)
	if err != nil || !bytes.Equal(canonical, body) {
		return nil, errors.New("[D131 Linux report] journal 不是 exact canonical wire")
	}
	if err := validateLinuxDeviceReportJournal(&journal); err != nil {
		return nil, err
	}
	return &journal, nil
}

func validateLinuxDeviceReportJournal(journal *LinuxDeviceReportJournalV1) error {
	if journal == nil || journal.Schema != 1 || journal.DeviceID == "" ||
		journal.LastAcceptedSequence < 0 || journal.NextSequence < 1 {
		return errors.New("[D131 Linux report] journal header/sequence 无效")
	}
	wantNext, err := wire.CheckedAdd(journal.LastAcceptedSequence, 1)
	if err != nil || journal.NextSequence != wantNext {
		return errors.New("[D131 Linux report] journal sequence 不连续")
	}
	if journal.LastAcceptedSequence == 0 {
		if journal.LastAcceptedEnvelopeHash != "" {
			return errors.New("[D131 Linux report] 初始 journal 禁止 last hash")
		}
	} else if _, err := wire.ParseHash(journal.LastAcceptedEnvelopeHash); err != nil {
		return errors.New("[D131 Linux report] journal last hash 无效")
	}
	if journal.Pending != nil && (journal.Pending.Schema != 2 ||
		journal.Pending.Body.DeviceID != journal.DeviceID ||
		journal.Pending.Body.ReportSequence != journal.NextSequence) {
		return errors.New("[D131 Linux report] pending envelope 与 journal 序号/Device 不一致")
	}
	return nil
}
