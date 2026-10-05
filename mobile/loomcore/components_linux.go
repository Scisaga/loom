package loomcore

import (
	"archive/zip"
	"bufio"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"loom/internal/control"
)

// AndroidRuntimeComponents measures the APK backing this executing Go module.
// Libbox and loomcore are bound into the same native library. The host supplies
// only its primary package path and the versions embedded in executing code.
func AndroidRuntimeComponents(apkPath, sourceCommit, dataPlaneVersion string) []byte {
	pc := uint64(reflect.ValueOf(AndroidRuntimeComponents).Pointer())
	components, err := measureAndroidComponents(apkPath, sourceCommit, dataPlaneVersion, runtime.GOARCH, pc, func() ([]byte, error) {
		return os.ReadFile("/proc/self/maps")
	})
	if err != nil {
		// Never log package paths, map contents or host inputs.
		log.Print("Android runtime component measurement incomplete: ", err)
	}
	if components == nil {
		components = []control.ComponentReadback{}
	}
	body, _ := json.Marshal(components)
	return body
}

type executableMapping struct {
	start, end, offset, major, minor, inode uint64
}

func mappingForPC(body []byte, pc uint64) (executableMapping, error) {
	var found executableMapping
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 5 {
			return found, errors.New("invalid process mapping")
		}
		bounds, device := strings.Split(fields[0], "-"), strings.Split(fields[3], ":")
		if len(bounds) != 2 || len(device) != 2 {
			return found, errors.New("invalid process mapping")
		}
		values := []string{bounds[0], bounds[1], fields[2], device[0], device[1], fields[4]}
		var numbers [6]uint64
		for i, value := range values {
			base := 16
			if i == 5 {
				base = 10
			}
			number, err := strconv.ParseUint(value, base, 64)
			if err != nil {
				return found, errors.New("invalid process mapping")
			}
			numbers[i] = number
		}
		if numbers[0] > pc || pc >= numbers[1] {
			continue
		}
		if found.end != 0 || len(fields[1]) != 4 || fields[1][2] != 'x' || numbers[5] == 0 {
			return found, errors.New("code mapping is not unique and file backed")
		}
		found = executableMapping{numbers[0], numbers[1], numbers[2], numbers[3], numbers[4], numbers[5]}
	}
	if scanner.Err() != nil || found.end == 0 {
		return found, errors.New("executing code mapping unavailable")
	}
	return found, nil
}

func androidLibrary(arch string) (string, elf.Machine, error) {
	switch arch {
	case "amd64":
		return "lib/x86_64/libbox.so", elf.EM_X86_64, nil
	case "arm64":
		return "lib/arm64-v8a/libbox.so", elf.EM_AARCH64, nil
	default:
		return "", 0, errors.New("unsupported Android execution ABI")
	}
}

func loadedLibrary(apk *os.File, size int64, name string, machine elf.Machine, codeOffset uint64) (io.Reader, error) {
	archive, err := zip.NewReader(apk, size)
	if err != nil {
		return nil, errors.New("APK archive unavailable")
	}
	var entry *zip.File
	for _, candidate := range archive.File {
		if candidate.Name == name {
			if entry != nil {
				return nil, errors.New("ambiguous native library")
			}
			entry = candidate
		}
	}
	if entry == nil || entry.Method != zip.Store || entry.UncompressedSize64 == 0 || entry.UncompressedSize64 > 256<<20 || entry.CompressedSize64 != entry.UncompressedSize64 {
		return nil, errors.New("native library is not directly mapped")
	}
	offset, err := entry.DataOffset()
	length := int64(entry.UncompressedSize64)
	if err != nil || offset < 0 || offset > size || length > size-offset || codeOffset < uint64(offset) || codeOffset-uint64(offset) >= uint64(length) {
		return nil, errors.New("executing code is outside native library")
	}
	library := io.NewSectionReader(apk, offset, length)
	object, err := elf.NewFile(library)
	if err != nil {
		return nil, errors.New("native ELF unavailable")
	}
	defer object.Close()
	if object.Class != elf.ELFCLASS64 || object.Machine != machine || object.Type != elf.ET_DYN {
		return nil, errors.New("native ELF execution ABI mismatch")
	}
	relative := codeOffset - uint64(offset)
	for _, program := range object.Progs {
		if program.Type == elf.PT_LOAD && program.Flags&elf.PF_X != 0 && program.Off <= relative && relative-program.Off < program.Filesz && program.Off <= uint64(length) && program.Filesz <= uint64(length)-program.Off {
			return io.NewSectionReader(apk, offset, length), nil
		}
	}
	return nil, errors.New("executing code is outside native ELF text")
}

func measureAndroidComponents(path, source, version, arch string, pc uint64, readMaps func() ([]byte, error)) ([]control.ComponentReadback, error) {
	name, machine, err := androidLibrary(arch)
	if err != nil {
		return nil, err
	}
	apk, err := os.Open(path)
	if err != nil {
		return nil, errors.New("APK unavailable")
	}
	defer apk.Close()
	var before, after unix.Stat_t
	if unix.Fstat(int(apk.Fd()), &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Size <= 0 || before.Size > 512<<20 {
		return nil, errors.New("APK file identity unavailable")
	}
	maps, err := readMaps()
	if err != nil {
		return nil, errors.New("process mappings unavailable")
	}
	mapping, err := mappingForPC(maps, pc)
	if err != nil || mapping.inode != before.Ino || mapping.major != uint64(unix.Major(before.Dev)) || mapping.minor != uint64(unix.Minor(before.Dev)) || mapping.offset > ^uint64(0)-(pc-mapping.start) {
		return nil, errors.New("APK is not backing executing code")
	}
	library, libraryErr := loadedLibrary(apk, before.Size, name, machine, mapping.offset+pc-mapping.start)
	components := []control.ComponentReadback{}
	commit, err := hex.DecodeString(source)
	if err != nil || len(commit) != 20 || hex.EncodeToString(commit) != source {
		source = "devel"
	}
	for _, item := range []struct {
		id, version string
		reader      io.Reader
	}{{"agent", source, io.NewSectionReader(apk, 0, before.Size)}, {"sing-box", version, library}} {
		if item.reader == nil || control.ValidateText(item.version) != nil {
			libraryErr = errors.New("native component unavailable")
			continue
		}
		hash := sha256.New()
		if _, err := io.Copy(hash, item.reader); err != nil {
			return nil, errors.New("component measurement failed")
		}
		components = append(components, control.ComponentReadback{ComponentID: item.id, Platform: "android-" + arch, Version: item.version, ArtifactDigest: "sha256:" + hex.EncodeToString(hash.Sum(nil))})
	}
	maps, err = readMaps()
	if err != nil {
		return nil, errors.New("process mappings unavailable after measurement")
	}
	current, err := mappingForPC(maps, pc)
	if err != nil || current != mapping || unix.Fstat(int(apk.Fd()), &after) != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		return nil, errors.New("executing APK changed during measurement")
	}
	return components, libraryErr
}
