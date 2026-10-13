package clientrelease

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"loom/internal/clientdist"
	"loom/internal/control"
)

// The private copy makes verification and use consume the same bytes even if
// the public input is subsequently rewritten in place. Only metadata is cached.
type capturedArtifact struct {
	file   *os.File
	entry  os.FileInfo
	reader *io.SectionReader
	once   sync.Once
	err    error
}

func (input *capturedArtifact) Read(body []byte) (int, error) { return input.reader.Read(body) }

func (input *capturedArtifact) Close() error {
	input.once.Do(func() {
		current, err := os.Lstat(input.file.Name())
		if err == nil && (!current.Mode().IsRegular() || !os.SameFile(input.entry, current)) {
			input.err = errors.New("release capture was replaced before cleanup")
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			input.err = err
		} else if err == nil {
			input.err = os.Remove(input.file.Name())
		}
		input.err = errors.Join(input.err, input.file.Close())
	})
	return input.err
}

type captureReader struct {
	ctx    context.Context
	source io.Reader
}

func (reader captureReader) Read(body []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.source.Read(body)
}

func (store *Store) captureArtifact(ctx context.Context, root *os.Root, artifact control.ReleaseArtifact) (_ *capturedArtifact, resultErr error) {
	if artifact.Validate() != nil || artifact.Size == 0 || artifact.Size > maxPackageBytes {
		return nil, errors.New("release capture coordinates are invalid")
	}
	source, err := openFile(root, digestPath("bin", artifact.Digest, ""), int64(artifact.Size))
	if err != nil {
		return nil, err
	}
	defer source.Close()
	if err := prepareDownloadWork(store.workRoot); err != nil {
		return nil, err
	}
	file, err := os.CreateTemp(store.workRoot, "archive-*")
	if err != nil {
		return nil, err
	}
	entry, err := file.Stat()
	if err != nil {
		file.Close()
		os.Remove(file.Name())
		return nil, err
	}
	input := &capturedArtifact{file: file, entry: entry}
	failed := true
	defer func() {
		if failed {
			resultErr = errors.Join(resultErr, input.Close())
		}
	}()
	hash := sha256.New()
	n, err := io.CopyBuffer(io.MultiWriter(file, hash), captureReader{ctx, io.LimitReader(source, int64(artifact.Size)+1)}, make([]byte, 64<<10))
	if err != nil {
		return nil, err
	}
	if n != int64(artifact.Size) || fmt.Sprintf("sha256:%x", hash.Sum(nil)) != artifact.Digest {
		return nil, errors.New("release package differs from its signed digest or size")
	}
	input.reader = io.NewSectionReader(file, 0, n)
	failed = false
	return input, nil
}

func (store *Store) inspectCaptured(ctx context.Context, input *capturedArtifact, pkg control.ReleasePackage) (control.ReleasePackage, error) {
	if pkg.Entry.ComponentID == "linux-client-bootstrap" {
		verified, err := clientdist.VerifyArchiveFile(ctx, input.file, store.key, store.workRoot)
		if err != nil {
			return control.ReleasePackage{}, err
		}
		if !bytes.Equal(verified.ManifestBody, pkg.ManifestBody) || !bytes.Equal(verified.Signature, pkg.Signature) {
			err = errors.New("release archive differs from its original signed manifest")
		}
		err = errors.Join(err, verified.Close())
		return pkg, err
	}
	// Other platform package validators retain their original archive contracts.
	// Only the selected artifact is parsed; the returned download is still disk-backed.
	body, err := io.ReadAll(io.NewSectionReader(input.file, 0, int64(pkg.Entry.Artifact.Size)))
	if err != nil {
		return control.ReleasePackage{}, err
	}
	return InspectInput(pkg.Entry.Artifact.Name, Input{Body: body, Manifest: pkg.ManifestBody, Signature: pkg.Signature}, store.key)
}
