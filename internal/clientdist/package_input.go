package clientdist

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"debug/buildinfo"
	"debug/elf"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"loom/internal/clientcomponent"
)

const packageCopyBuffer = 64 << 10

// Metadata and fixed handles only. Root is private temporary storage, not an
// accepted package record. Every successful caller must Close after consumption.
type VerifiedDirectory struct {
	Manifest                Manifest
	ID, Root                string
	ManifestBody, Signature []byte
	input                   *packageInput
}

func (v VerifiedDirectory) Close() error {
	if v.input == nil {
		return nil
	}
	return v.input.close()
}

type packageFileInput struct {
	name, path, digest string
	mode               os.FileMode
	size               int64
	file               *os.File
	entry              os.FileInfo
}
type packageInput struct {
	root   string
	entry  os.FileInfo
	files  map[string]*packageFileInput
	remove bool
	once   sync.Once
	err    error
}

func packageInputNames() []string {
	names := append(payloadNames(), "manifest.json", "manifest.sig", "checksums.txt")
	sort.Strings(names)
	return names
}
func packageExpectedMode(name string) os.FileMode {
	if name == "loom" || name == "sing-box" || name == "install.sh" {
		return 0755
	}
	return 0644
}
func (input *packageInput) close() error {
	input.once.Do(func() {
		for _, v := range input.files {
			if v.file != nil {
				input.err = errors.Join(input.err, v.file.Close())
			}
		}
		if input.remove {
			current, err := os.Lstat(input.root)
			if errors.Is(err, os.ErrNotExist) {
				return
			}
			if err != nil || !os.SameFile(current, input.entry) || !packageDirectoryPrivate(current) || !packageFileOwnerMatches(current, input.entry) {
				input.err = errors.Join(input.err, errors.New("private package capture was replaced"), err)
				return
			}
			input.err = errors.Join(input.err, os.RemoveAll(input.root))
		}
	})
	return input.err
}
func (v *packageFileInput) stable() error {
	actual, err := v.file.Stat()
	current, pathErr := os.Lstat(v.path)
	if err != nil || pathErr != nil || !os.SameFile(v.entry, actual) || !os.SameFile(v.entry, current) ||
		!actual.Mode().IsRegular() || !current.Mode().IsRegular() || actual.Size() != v.size || current.Size() != v.size ||
		!actual.ModTime().Equal(v.entry.ModTime()) || !current.ModTime().Equal(v.entry.ModTime()) ||
		actual.Mode() != v.entry.Mode() || current.Mode() != v.entry.Mode() || !packageFileLinks(actual) || !packageFileLinks(current) ||
		!packageFileOwnerMatches(actual, v.entry) || !packageFileOwnerMatches(current, v.entry) {
		return errors.New("package file changed during consumption")
	}
	return nil
}

type packageContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (v packageContextReader) Read(b []byte) (int, error) {
	if err := v.ctx.Err(); err != nil {
		return 0, err
	}
	return v.reader.Read(b)
}
func hashPackageInput(ctx context.Context, v *packageFileInput, buffer []byte) (string, error) {
	if err := v.stable(); err != nil {
		return "", err
	}
	hash := sha256.New()
	n, err := io.CopyBuffer(hash, packageContextReader{ctx, io.NewSectionReader(v.file, 0, v.size)}, buffer)
	if err != nil || n != v.size {
		return "", errors.Join(errors.New("package file length changed"), err)
	}
	if err := v.stable(); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
func smallPackageInput(ctx context.Context, v *packageFileInput, limit int64) ([]byte, error) {
	if v == nil || v.size <= 0 || v.size > limit {
		return nil, errors.New("package metadata exceeds its boundary")
	}
	if err := v.stable(); err != nil {
		return nil, err
	}
	body := make([]byte, int(v.size))
	if _, err := io.ReadFull(packageContextReader{ctx, io.NewSectionReader(v.file, 0, v.size)}, body); err != nil {
		return nil, err
	}
	return body, v.stable()
}
func openPackageInput(filePath, name string, installed bool) (*packageFileInput, error) {
	before, err := os.Lstat(filePath)
	if err != nil || !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > maxArchiveBytes || !packageFileLinks(before) ||
		!packageFileModeMatches(before, packageExpectedMode(name)) || installed && !packageFileOwned(before) {
		return nil, errors.Join(errors.New("package file ownership, mode, length or type differs"), err)
	}
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	v := &packageFileInput{name: name, path: filePath, mode: packageExpectedMode(name), size: before.Size(), file: file, entry: before}
	if err := v.stable(); err != nil {
		file.Close()
		return nil, err
	}
	return v, nil
}
func openPackageDirectory(ctx context.Context, directory string, installed bool) (*packageInput, error) {
	entry, err := os.Lstat(directory)
	if err != nil || !entry.IsDir() || entry.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("package directory must be a real directory")
	}
	input := &packageInput{root: directory, entry: entry, files: map[string]*packageFileInput{}}
	wanted := map[string]bool{}
	for _, name := range packageInputNames() {
		wanted[name] = true
	}
	var total int64
	err = filepath.WalkDir(directory, func(filePath string, item os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if filePath == directory {
			return nil
		}
		name, err := filepath.Rel(directory, filePath)
		if err != nil {
			return err
		}
		if item.IsDir() {
			if name != "systemd" && name != "source" && name != "licenses" {
				return errors.New("package contains an unexpected directory")
			}
			if installed {
				info, err := item.Info()
				if err != nil || !packageDirectoryOwned(info) {
					return errors.New("installed package directory protection differs")
				}
			}
			return nil
		}
		if !wanted[name] {
			return errors.New("package contains an unexpected file or link")
		}
		v, err := openPackageInput(filePath, name, installed)
		if err != nil {
			return err
		}
		input.files[name] = v
		total += v.size
		if total > maxArchiveBytes {
			return errors.New("unpacked package exceeds its size boundary")
		}
		return nil
	})
	if err == nil && len(input.files) != len(wanted) {
		err = errors.New("package file set is incomplete")
	}
	if err != nil {
		return nil, errors.Join(err, input.close())
	}
	return input, nil
}
func newPackageCapture(workRoot string) (*packageInput, error) {
	if err := packageWorkRoot(workRoot); err != nil {
		return nil, err
	}
	root, err := os.MkdirTemp(workRoot, ".loom-package-")
	if err != nil {
		return nil, err
	}
	entry, err := os.Lstat(root)
	if err != nil || !packageDirectoryPrivate(entry) {
		os.Remove(root)
		return nil, errors.New("package capture directory is not private")
	}
	return &packageInput{root: root, entry: entry, files: map[string]*packageFileInput{}, remove: true}, nil
}
func capturePackageMember(ctx context.Context, input *packageInput, name string, size int64, source io.Reader, buffer []byte) error {
	if size <= 0 || size > maxArchiveBytes || input.files[name] != nil {
		return errors.New("package member size or uniqueness differs")
	}
	filePath := filepath.Join(input.root, name)
	if err := os.MkdirAll(filepath.Dir(filePath), 0700); err != nil {
		return err
	}
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	n, copyErr := io.CopyBuffer(file, packageContextReader{ctx, io.LimitReader(source, size+1)}, buffer)
	if copyErr == nil && n != size {
		copyErr = errors.New("package member length differs")
	}
	if copyErr == nil {
		copyErr = file.Chmod(packageExpectedMode(name))
	}
	copyErr = errors.Join(copyErr, file.Close())
	if copyErr != nil {
		return copyErr
	}
	v, err := openPackageInput(filePath, name, false)
	if err != nil {
		return err
	}
	input.files[name] = v
	return nil
}
func capturePackageDirectory(ctx context.Context, directory, workRoot string) (*packageInput, error) {
	source, err := openPackageDirectory(ctx, directory, false)
	if err != nil {
		return nil, err
	}
	defer source.close()
	input, err := newPackageCapture(workRoot)
	if err != nil {
		return nil, err
	}
	buffer := make([]byte, packageCopyBuffer)
	for _, name := range packageInputNames() {
		v := source.files[name]
		if err = v.stable(); err == nil {
			err = capturePackageMember(ctx, input, name, v.size, io.NewSectionReader(v.file, 0, v.size), buffer)
		}
		if err == nil {
			err = v.stable()
		}
		if err != nil {
			return nil, errors.Join(err, input.close())
		}
	}
	return input, nil
}
func verifyPackageInput(ctx context.Context, input *packageInput, public ed25519.PublicKey) (VerifiedDirectory, error) {
	var zero VerifiedDirectory
	body, err := smallPackageInput(ctx, input.files["manifest.json"], 64<<10)
	if err != nil {
		return zero, err
	}
	signature, err := smallPackageInput(ctx, input.files["manifest.sig"], ed25519.SignatureSize)
	if err != nil {
		return zero, err
	}
	manifest, err := VerifyManifest(body, signature, public)
	if err != nil {
		return zero, err
	}
	buffer := make([]byte, packageCopyBuffer)
	for _, name := range packageInputNames() {
		v := input.files[name]
		if v == nil {
			return zero, errors.New("package file set is incomplete")
		}
		v.digest, err = hashPackageInput(ctx, v, buffer)
		if err != nil {
			return zero, err
		}
	}
	for _, expected := range manifest.Files {
		v := input.files[expected.Path]
		if v == nil || int64(expected.Size) != v.size || expected.SHA256 != v.digest || expected.Mode != fmt.Sprintf("%04o", v.mode) {
			return zero, errors.New("package payload differs from its signed manifest")
		}
	}
	pubBody, err := smallPackageInput(ctx, input.files["platform.pub"], 4096)
	if err != nil {
		return zero, err
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(pubBody)))
	if err != nil || !bytes.Equal(decoded, public) {
		return zero, errors.New("package public key differs from independent installation trust")
	}
	checksums, err := smallPackageInput(ctx, input.files["checksums.txt"], 16<<10)
	if err != nil {
		return zero, err
	}
	var expectedChecksums strings.Builder
	for _, name := range packageInputNames() {
		if name != "checksums.txt" {
			fmt.Fprintf(&expectedChecksums, "%s  %s\n", input.files[name].digest, name)
		}
	}
	if !bytes.Equal(checksums, []byte(expectedChecksums.String())) {
		return zero, errors.New("checksums.txt is incomplete or not canonical")
	}
	loom, osName, arch, err := inspectLoomReader(ctx, input.files["loom"], true)
	if err != nil || osName != manifest.OS || arch != manifest.Arch || !reflect.DeepEqual(loom, manifest.Loom) {
		return zero, errors.New("package Loom identity differs from its signed manifest")
	}
	plane, err := clientcomponent.InspectLinuxSourceBuildReader(input.files["sing-box"].file, input.files["sing-box"].size, manifest.Arch)
	if err != nil {
		return zero, err
	}
	singBox := Component{Path: plane.Path, SHA256: plane.SHA256, Size: plane.Size, Version: plane.Version, Commit: plane.Commit, Source: &plane.Source}
	if !reflect.DeepEqual(singBox, manifest.SingBox) {
		return zero, errors.New("package data-plane identity differs from its signed manifest")
	}
	readers := map[string]io.Reader{}
	for _, name := range packageInputNames() {
		if strings.HasPrefix(name, "source/") || name == "licenses/sing-box-LICENSE" {
			v := input.files[name]
			readers[name] = packageContextReader{ctx, io.NewSectionReader(v.file, 0, v.size)}
		}
	}
	if err := clientcomponent.VerifyLinuxSourceFilesReaders(readers, manifest.SingBox.Version); err != nil {
		return zero, err
	}
	for _, v := range input.files {
		if err := v.stable(); err != nil {
			return zero, err
		}
	}
	return VerifiedDirectory{Manifest: manifest, ID: sha256Hex(body), Root: input.root, ManifestBody: body, Signature: signature, input: input}, ctx.Err()
}
func inspectLoomReader(ctx context.Context, v *packageFileInput, allowDirty bool) (Component, string, string, error) {
	reader := io.NewSectionReader(v.file, 0, v.size)
	file, err := elf.NewFile(reader)
	if err != nil {
		return Component{}, "", "", err
	}
	defer file.Close()
	info, err := buildinfo.Read(reader)
	if err != nil || info.Path != "loom/cmd/loom" {
		return Component{}, "", "", errors.New("package Loom Go identity differs")
	}
	osName, arch, commit, dirty := buildCoordinates(info)
	if osName != "linux" || (arch != "amd64" && arch != "arm64") || elfArch(file.Machine) != arch || (commit == "" || dirty) && !allowDirty {
		return Component{}, "", "", errors.New("package Loom architecture or source coordinates differ")
	}
	return Component{Path: "loom", SHA256: v.digest, Size: int(v.size), Commit: commit, Dirty: dirty}, osName, arch, ctx.Err()
}

type packageCompareWriter struct {
	ctx      context.Context
	expected io.Reader
	buffer   [packageCopyBuffer]byte
}

func (w *packageCompareWriter) Write(body []byte) (int, error) {
	count := 0
	for len(body) > 0 {
		if err := w.ctx.Err(); err != nil {
			return count, err
		}
		n := min(len(body), len(w.buffer))
		chunk := w.buffer[:n]
		if _, err := io.ReadFull(w.expected, chunk); err != nil {
			return count, err
		}
		if !bytes.Equal(body[:n], chunk) {
			return count, errors.New("Linux archive is not canonical")
		}
		body, count = body[n:], count+n
	}
	return count, nil
}
func comparePackageArchive(ctx context.Context, input *packageInput, arch string, original io.Reader) error {
	compare := &packageCompareWriter{ctx: ctx, expected: packageContextReader{ctx, original}}
	gz, err := gzip.NewWriterLevel(compare, gzip.BestCompression)
	if err != nil {
		return err
	}
	gz.Header.ModTime, gz.Header.OS = time.Unix(0, 0).UTC(), 255
	tw := tar.NewWriter(gz)
	root, epoch := "loom-client-linux-"+arch, time.Unix(0, 0).UTC()
	for _, name := range []string{root + "/", root + "/systemd/"} {
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeDir, Mode: 0755, ModTime: epoch, Format: tar.FormatUSTAR}); err != nil {
			return err
		}
	}
	buffer := make([]byte, packageCopyBuffer)
	for _, name := range packageInputNames() {
		v := input.files[name]
		if err := v.stable(); err != nil {
			return err
		}
		if err := tw.WriteHeader(&tar.Header{Name: root + "/" + name, Typeflag: tar.TypeReg, Mode: int64(v.mode), Size: v.size, ModTime: epoch, Format: tar.FormatUSTAR}); err != nil {
			return err
		}
		n, err := io.CopyBuffer(tw, packageContextReader{ctx, io.NewSectionReader(v.file, 0, v.size)}, buffer)
		if err != nil || n != v.size {
			return errors.Join(errors.New("canonical archive member changed"), err)
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	var extra [1]byte
	if n, err := compare.expected.Read(extra[:]); n != 0 || !errors.Is(err, io.EOF) {
		return errors.New("Linux archive has extra bytes or an uncertain end")
	}
	return ctx.Err()
}

// The caller chooses an existing disk workRoot. Received archive and signature
// bytes are preserved; canonical equality is checked bytewise, not by digest.
func VerifyArchiveFile(ctx context.Context, archive *os.File, public ed25519.PublicKey, workRoot string) (result VerifiedDirectory, resultErr error) {
	var zero VerifiedDirectory
	if workRoot == "" {
		absolute, err := filepath.Abs(archive.Name())
		if err != nil {
			return zero, err
		}
		workRoot = filepath.Dir(absolute)
	}
	entry, err := archive.Stat()
	if err != nil || !entry.Mode().IsRegular() || entry.Size() <= 0 || entry.Size() > maxArchiveBytes {
		return zero, errors.New("Linux archive file bounds or type differ")
	}
	input, err := newPackageCapture(workRoot)
	if err != nil {
		return zero, err
	}
	failed := true
	defer func() {
		if failed {
			resultErr = errors.Join(resultErr, input.close())
		}
	}()
	gz, err := gzip.NewReader(packageContextReader{ctx, io.NewSectionReader(archive, 0, entry.Size())})
	if err != nil {
		return zero, err
	}
	defer gz.Close()
	tr, root, total := tar.NewReader(gz), "", int64(0)
	wanted := map[string]bool{}
	for _, name := range packageInputNames() {
		wanted[name] = true
	}
	buffer := make([]byte, packageCopyBuffer)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return zero, err
		}
		clean := path.Clean(header.Name)
		if clean == "." || clean != strings.TrimSuffix(header.Name, "/") || strings.HasPrefix(clean, "/") || strings.HasPrefix(clean, "../") || strings.Contains(clean, "/../") {
			return zero, errors.New("Linux archive path is not canonical")
		}
		parts := strings.Split(clean, "/")
		if root == "" {
			root = parts[0]
		}
		if parts[0] != root || !strings.HasPrefix(root, "loom-client-linux-") {
			return zero, errors.New("Linux archive root differs")
		}
		if header.Typeflag == tar.TypeDir {
			continue
		}
		if header.Typeflag != tar.TypeReg || len(parts) < 2 {
			return zero, errors.New("Linux archive contains a link or special file")
		}
		name := strings.Join(parts[1:], "/")
		if !wanted[name] || header.Size <= 0 || header.Size > maxArchiveBytes || total+header.Size > maxArchiveBytes || header.Mode != int64(packageExpectedMode(name)) {
			return zero, errors.New("Linux archive member set, mode or length differs")
		}
		if err := capturePackageMember(ctx, input, name, header.Size, tr, buffer); err != nil {
			return zero, err
		}
		total += header.Size
	}
	value, err := verifyPackageInput(ctx, input, public)
	if err != nil {
		return zero, err
	}
	if root != "loom-client-linux-"+value.Manifest.Arch {
		return zero, errors.New("Linux archive root and architecture differ")
	}
	if err := comparePackageArchive(ctx, input, value.Manifest.Arch, io.NewSectionReader(archive, 0, entry.Size())); err != nil {
		return zero, err
	}
	current, err := archive.Stat()
	if err != nil || !os.SameFile(entry, current) || current.Size() != entry.Size() || current.ModTime() != entry.ModTime() {
		return zero, errors.New("Linux archive changed during verification")
	}
	failed = false
	return value, nil
}
