package publish

import (
	"archive/tar"
	"io"
)

type tarWriter struct{ w *tar.Writer }

func newTar(w io.Writer) *tarWriter { return &tarWriter{w: tar.NewWriter(w)} }

func (t *tarWriter) add(name string, body []byte) error {
	if err := t.w.WriteHeader(&tar.Header{
		Name: name, Mode: 0o644, Size: int64(len(body)),
	}); err != nil {
		return err
	}
	_, err := t.w.Write(body)
	return err
}

func (t *tarWriter) close() error { return t.w.Close() }
