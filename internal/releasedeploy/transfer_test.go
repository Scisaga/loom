package releasedeploy

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"loom/internal/clientrelease"
	"loom/internal/control"
)

func TestFileReuseTransportsOnlyMissingBytesThroughStrictTar(t *testing.T) {
	root := filepath.Join(t.TempDir(), "demo root's contents")
	if err := os.MkdirAll(filepath.Join(root, "bin"), 0700); err != nil {
		t.Fatal(err)
	}
	files := []clientrelease.TransferFile{}
	content := map[string][]byte{}
	for _, text := range []string{"demo one", "demo two", "demo three"} {
		body := []byte(text)
		digest := control.ReleaseDigest(body)
		name := "bin/" + strings.TrimPrefix(digest, "sha256:")
		files = append(files, clientrelease.TransferFile{Name: name, Size: int64(len(body)), Digest: digest})
		content[name] = body
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	for _, count := range []int{0, 1, len(files)} {
		for _, file := range files[:count] {
			if err := os.WriteFile(filepath.Join(root, file.Name), content[file.Name], 0600); err != nil {
				t.Fatal(err)
			}
		}
		body, err := exec.Command("sh", "-c", reuseQueryScript(root, files)).Output()
		if err != nil {
			t.Fatal(err)
		}
		reuse, err := reuseReadback(body, files)
		if err != nil || !reflect.DeepEqual(reuse, files[:count]) {
			t.Fatal("file presence was guessed instead of verified", err, reuse)
		}
		var network bytes.Buffer
		writer := tar.NewWriter(&network)
		for _, file := range files[count:] {
			if err := writer.WriteHeader(&tar.Header{Name: file.Name, Mode: 0644, Size: file.Size, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); err != nil {
				t.Fatal(err)
			}
			writer.Write(content[file.Name])
		}
		writer.Close()
		if count == len(files) && network.Len() != 1024 {
			t.Fatal("full reuse transferred file payloads")
		}
		script := "set -eu\numask 077\nrelease_tmp=" + literal(t.TempDir()) + "\n" + assembleArchiveScript(root, reuse) + "cat \"$release_tmp/incoming.tar\"\n"
		command := exec.Command("sh", "-c", script)
		networkBytes := append([]byte{}, network.Bytes()...)
		command.Stdin = bytes.NewReader(networkBytes)
		merged, err := command.Output()
		if err != nil {
			t.Fatal("target assembly failed", err)
		}
		buffer := bytes.NewReader(merged)
		reader := tar.NewReader(buffer)
		seen := map[string]bool{}
		for {
			header, err := reader.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(reader)
			if err != nil || seen[header.Name] || header.Mode != 0644 || header.Typeflag != tar.TypeReg || len(header.PAXRecords) != 0 || !bytes.Equal(body, content[header.Name]) {
				t.Fatal("reused or received public bytes changed", header.Name, err)
			}
			seen[header.Name] = true
		}
		if len(seen) != len(files) || buffer.Len() != 0 {
			t.Fatal("incomplete archive or trailing bytes", len(seen), buffer.Len())
		}
		if count == 1 {
			// Assembly must not turn a trailing network byte into an accepted
			// archive by discarding it together with GNU tar's own padding.
			command := exec.Command("sh", "-c", script)
			command.Stdin = bytes.NewReader(append(networkBytes, 'x'))
			if combined, err := command.Output(); err == nil {
				buffer := bytes.NewReader(combined)
				reader := tar.NewReader(buffer)
				for {
					_, err = reader.Next()
					if err != nil {
						break
					}
				}
				if err == io.EOF && buffer.Len() == 0 {
					t.Fatal("assembly hid trailing network content")
				}
			}
		}
	}
	file := files[0]
	if err := os.WriteFile(filepath.Join(root, file.Name), bytes.Repeat([]byte("x"), int(file.Size)), 0600); err != nil {
		t.Fatal(err)
	}
	for _, script := range []string{reuseQueryScript(root, files), "set -eu\nrelease_tmp=" + literal(t.TempDir()) + "\n" + assembleArchiveScript(root, files)} {
		if err := exec.Command("sh", "-c", script).Run(); err == nil {
			t.Fatal("changed reusable bytes passed a fresh query or upload-time recheck")
		}
	}
	if err := os.Remove(filepath.Join(root, file.Name)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, files[1].Name), filepath.Join(root, file.Name)); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("sh", "-c", reuseQueryScript(root, files)).Run(); err == nil {
		t.Fatal("symlink acquired a reusable file identity")
	}
}

func TestReuseReadbackRejectsUnknownOrAmbiguousIndexes(t *testing.T) {
	files := []clientrelease.TransferFile{{Name: "demo"}}
	for _, value := range []string{"0", "1\n", "-1\n", "+0\n", "00\n", "0\n0\n", "\n"} {
		if _, err := reuseReadback([]byte(value), files); err == nil {
			t.Fatal("invalid transfer scope accepted", value)
		}
	}
}
