package clientdist

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
)

func installPackageFile(ctx context.Context, destination string, source *packageFileInput) error {
	if source == nil || source.file == nil || source.digest == "" {
		return errors.New("verified package source unavailable")
	}
	if err := source.stable(); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(destination), ".loom-install-")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	hash := sha256.New()
	buffer := make([]byte, packageCopyBuffer)
	n, copyErr := io.CopyBuffer(io.MultiWriter(file, hash), packageContextReader{ctx, io.NewSectionReader(source.file, 0, source.size)}, buffer)
	if copyErr == nil && (n != source.size || hex.EncodeToString(hash.Sum(nil)) != source.digest) {
		copyErr = errors.New("verified source changed while copying")
	}
	if copyErr == nil {
		copyErr = source.stable()
	}
	if copyErr == nil {
		copyErr = file.Chmod(source.mode)
	}
	if copyErr == nil {
		copyErr = file.Sync()
	}
	copyErr = errors.Join(copyErr, file.Close())
	if copyErr != nil {
		return copyErr
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Rename(name, destination); err != nil {
		return err
	}
	if err := syncDirectory(filepath.Dir(destination)); err != nil {
		return err
	}
	actual, err := openPackageInput(destination, source.name, true)
	if err != nil {
		return err
	}
	digest, readErr := hashPackageInput(ctx, actual, buffer)
	closeErr := actual.file.Close()
	if readErr != nil || closeErr != nil || actual.size != source.size || digest != source.digest {
		return errors.Join(errors.New("installed file readback differs"), readErr, closeErr)
	}
	return nil
}

func verifyInstalledProgram(ctx context.Context, directory string, component Component) error {
	actual, err := openPackageInput(filepath.Join(directory, component.Path), component.Path, true)
	if err != nil {
		return err
	}
	digest, readErr := hashPackageInput(ctx, actual, make([]byte, packageCopyBuffer))
	closeErr := actual.file.Close()
	if readErr != nil || closeErr != nil || digest != component.SHA256 || component.Size > 0 && int64(component.Size) != actual.size {
		return errors.Join(errors.New("accepted executable bytes differ"), readErr, closeErr)
	}
	return nil
}
