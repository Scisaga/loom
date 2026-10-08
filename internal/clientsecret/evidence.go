package clientsecret

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
)

// PreserveProtected keeps the exact existing sealed file, including its
// original ciphertext. It cannot overwrite evidence or re-encrypt history.
// The caller holds the source identity's write lock throughout migration.
func PreserveProtected(source, target, purpose string, expected []byte, protector Protector) error {
	if source == target || protector == nil || validateProtectedPath(source) != nil || validateProtectedPath(target) != nil || validatePurpose(purpose) != nil {
		return errors.New("invalid protected evidence paths or protection")
	}
	body, err := readRegular(source, maxCiphertext*2)
	if err != nil {
		return err
	}
	defer clear(body)
	plain, err := decodeProtected(body, purpose, protector)
	defer clear(plain)
	if err != nil || !bytes.Equal(plain, expected) {
		return errors.New("protected source changed before evidence preservation")
	}
	if saved, err := readRegular(target, maxCiphertext*2); err == nil {
		defer clear(saved)
		if !bytes.Equal(saved, body) {
			return errors.New("protected evidence already contains different sealed bytes")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = file.Write(body)
	if err == nil {
		err = file.Sync()
	}
	err = errors.Join(err, file.Close())
	if err != nil {
		return err
	}
	if err := syncDirectory(filepath.Dir(target)); err != nil {
		return err
	}
	saved, err := readRegular(target, maxCiphertext*2)
	defer clear(saved)
	if err != nil || !bytes.Equal(saved, body) {
		return errors.New("protected evidence readback differs")
	}
	return nil
}
