package linuxclient

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// A root-only, disposable execution handle records intent before link creation.
// It contains public configuration and the random kernel ownership token, never
// private keys or permission facts. It cannot restore a runtime or grant access.
type wireGuardCleanupEntry struct {
	Link         wireGuardExecutionLink `json:"link"`
	Alias        string                 `json:"alias"`
	CreationName string                 `json:"creation_name"`
	Index        int                    `json:"index"`
	PublicKey    string                 `json:"public_key"`
	Configured   bool                   `json:"configured"`
}

func runtimeNetworkLock(options Options) (*os.File, error) {
	if options.Config == "" {
		return nil, nil
	}
	if err := os.MkdirAll(filepath.Dir(options.Config), 0o700); err != nil {
		return nil, err
	}
	fd, err := syscall.Open(options.Config+".wg-lock", syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "runtime network lock")
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, errors.New("another process owns this runtime network generation")
	}
	return file, nil
}

func (transaction *wireGuardTransaction) saveOwnership() error {
	if transaction.options.Config == "" {
		return nil
	}
	entries := []wireGuardCleanupEntry{}
	for _, value := range transaction.owned {
		if value.alias != "" {
			entries = append(entries, wireGuardCleanupEntry{Link: value.link, Alias: value.alias, CreationName: value.creationName, Index: value.index, PublicKey: value.publicKey, Configured: value.configured})
		}
	}
	if len(entries) == 0 {
		err := os.Remove(transaction.options.Config + ".wg-ownership")
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	return atomicJSON(transaction.options.Config+".wg-ownership", entries)
}

func cleanupRecordedWireGuard(options Options) error {
	if options.Config == "" {
		return nil
	}
	var entries []wireGuardCleanupEntry
	if err := readStrict(options.Config+".wg-ownership", 1<<20, &entries); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return errors.Join(ErrWireGuardCleanup, err)
	}
	transaction := &wireGuardTransaction{options: options}
	for _, value := range entries {
		token, err := hex.DecodeString(strings.TrimPrefix(value.Alias, "loom-runtime:"))
		if err != nil || len(token) != 16 || value.Alias != "loom-runtime:"+hex.EncodeToString(token) || value.CreationName != "lm"+hex.EncodeToString(token)[:13] || value.Index < 0 || value.Link.Interface == "" {
			return errors.Join(ErrWireGuardCleanup, ErrWireGuardOwnership)
		}
		transaction.owned = append(transaction.owned, wireGuardOwnedLink{link: value.Link, alias: value.Alias, creationName: value.CreationName, index: value.Index, publicKey: value.PublicKey, configured: value.Configured})
	}
	return transaction.Cleanup()
}

// CleanupWireGuard is the systemd ExecStopPost entry after the runtime exits.
// Concurrent live execution is rejected; cleanup still compares kernel token,
// ifindex, peer, address and exact routes before removing each owned interface.
func CleanupWireGuard(options Options) error {
	options.defaults()
	lock, err := runtimeNetworkLock(options)
	if err != nil {
		return err
	}
	if lock != nil {
		defer lock.Close()
	}
	return cleanupRecordedWireGuard(options)
}
