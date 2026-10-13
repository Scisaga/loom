package clientrelease

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"loom/internal/control"
)

type transferHookWriter struct {
	bytes.Buffer
	hook func() error
}

func (writer *transferHookWriter) Write(body []byte) (int, error) {
	if writer.hook != nil {
		hook := writer.hook
		writer.hook = nil
		if err := hook(); err != nil {
			return 0, err
		}
	}
	return writer.Buffer.Write(body)
}

func TestTransferStreamsOriginalUSTARAndKeepsVerifiedDescriptor(t *testing.T) {
	body := bytes.Repeat([]byte("demo-stream-payload"), 9000)
	file := TransferFile{Name: digestPath("bin", control.ReleaseDigest(body), ""), Size: int64(len(body)), Digest: control.ReleaseDigest(body)}
	var expected bytes.Buffer
	original := tar.NewWriter(&expected)
	if err := original.WriteHeader(&tar.Header{Name: file.Name, Mode: 0644, Size: file.Size, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); err != nil {
		t.Fatal(err)
	}
	if _, err := original.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}
	for _, replace := range []bool{false, true} {
		t.Run(map[bool]string{false: "unchanged", true: "path-replaced"}[replace], func(t *testing.T) {
			directory := t.TempDir()
			writeProjectionFile(t, directory, file.Name, body)
			root, err := os.OpenRoot(directory)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			var output transferHookWriter
			if replace {
				output.hook = func() error {
					path := filepath.Join(directory, file.Name)
					if err := os.WriteFile(path+".replacement", bytes.Repeat([]byte{'x'}, len(body)), 0600); err != nil {
						return err
					}
					return os.Rename(path+".replacement", path)
				}
			}
			writer := tar.NewWriter(&output)
			if err := writeTransferFile(root, writer, file, make([]byte, 32<<10)); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(output.Bytes(), expected.Bytes()) {
				t.Fatal("streaming changed USTAR bytes or read a replacement input")
			}
			reader := tar.NewReader(bytes.NewReader(output.Bytes()))
			if _, err := reader.Next(); err != nil {
				t.Fatal(err)
			}
			if n, err := io.Copy(io.Discard, reader); err != nil || n != file.Size {
				t.Fatal("streamed payload boundary changed", n, err)
			}
			if _, err := reader.Next(); err != io.EOF {
				t.Fatal("streamed archive footer changed", err)
			}
		})
	}
}

func TestTransferRejectsInPlaceMutationDuringStreaming(t *testing.T) {
	body := bytes.Repeat([]byte("demo-stream-payload"), 9000)
	file := TransferFile{Name: digestPath("bin", control.ReleaseDigest(body), ""), Size: int64(len(body)), Digest: control.ReleaseDigest(body)}
	for _, mutation := range []string{"digest", "truncate", "grow"} {
		t.Run(mutation, func(t *testing.T) {
			directory := t.TempDir()
			writeProjectionFile(t, directory, file.Name, body)
			root, err := os.OpenRoot(directory)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			output := &transferHookWriter{hook: func() error {
				path := filepath.Join(directory, file.Name)
				switch mutation {
				case "digest":
					return os.WriteFile(path, bytes.Repeat([]byte{'x'}, len(body)), 0600)
				case "truncate":
					return os.Truncate(path, int64(len(body)-1))
				default:
					return os.Truncate(path, int64(len(body)+1))
				}
			}}
			if err := writeTransferFile(root, tar.NewWriter(output), file, make([]byte, 32<<10)); err == nil {
				t.Fatal("in-place source mutation completed an authenticated transfer")
			}
		})
	}
}
