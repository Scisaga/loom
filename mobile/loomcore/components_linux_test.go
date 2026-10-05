package loomcore

import (
	"archive/zip"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func androidMappedFixture(t *testing.T, machine elf.Machine, entryName string) (string, []byte, []byte) {
	t.Helper()
	native := make([]byte, 256)
	copy(native, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	order := binary.LittleEndian
	order.PutUint16(native[16:], uint16(elf.ET_DYN))
	order.PutUint16(native[18:], uint16(machine))
	order.PutUint32(native[20:], 1)
	order.PutUint64(native[32:], 64)
	order.PutUint16(native[52:], 64)
	order.PutUint16(native[54:], 56)
	order.PutUint16(native[56:], 1)
	order.PutUint32(native[64:], uint32(elf.PT_LOAD))
	order.PutUint32(native[68:], uint32(elf.PF_R|elf.PF_X))
	order.PutUint64(native[72:], 128)
	order.PutUint64(native[96:], 128)
	order.PutUint64(native[104:], 128)
	path := filepath.Join(t.TempDir(), "demo.apk")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(file)
	entry, err := writer.CreateHeader(&zip.FileHeader{Name: entryName, Method: zip.Store})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = entry.Write(native); err != nil {
		t.Fatal(err)
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	file.Close()
	archive, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	offset, err := archive.File[0].DataOffset()
	if err != nil {
		t.Fatal(err)
	}
	var stat unix.Stat_t
	if err = unix.Stat(path, &stat); err != nil {
		t.Fatal(err)
	}
	maps := []byte(fmt.Sprintf("1000-2000 r-xp %08x %x:%x %d /demo.apk\n", offset+128, unix.Major(stat.Dev), unix.Minor(stat.Dev), stat.Ino))
	return path, native, maps
}

func TestAndroidMeasuresLoadedPackageAndNativeWithoutExpectations(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		t.Run(arch, func(t *testing.T) {
			name, machine, _ := androidLibrary(arch)
			path, native, maps := androidMappedFixture(t, machine, name)
			read := func() ([]byte, error) { return maps, nil }
			components, err := measureAndroidComponents(path, strings.Repeat("a", 40), "demo-native", arch, 0x1010, read)
			if err != nil || len(components) != 2 {
				t.Fatalf("actual components unavailable: %v", err)
			}
			apk, _ := os.ReadFile(path)
			for index, body := range [][]byte{apk, native} {
				if components[index].Platform != "android-"+arch || components[index].ArtifactDigest != fmt.Sprintf("sha256:%x", sha256.Sum256(body)) {
					t.Fatal("runtime digest does not describe the executing package/library")
				}
			}
			if components[0].Version != strings.Repeat("a", 40) || components[1].Version != "demo-native" {
				t.Fatal("actual version replaced")
			}
			components, err = measureAndroidComponents(path, "dirty", "demo-native", arch, 0x1010, read)
			if err != nil || components[0].Version != "devel" {
				t.Fatal("untracked source presented as a release")
			}
			other := filepath.Join(t.TempDir(), "demo-other.apk")
			if err := os.WriteFile(other, apk, 0600); err != nil {
				t.Fatal(err)
			}
			if got, err := measureAndroidComponents(other, "", "demo-native", arch, 0x1010, read); err == nil || len(got) != 0 {
				t.Fatal("byte-identical replacement path substituted for actual mapped inode")
			}
		})
	}
}

func TestAndroidRejectsUnprovedNativeLibraryAndChangingPackage(t *testing.T) {
	for _, problem := range []string{"abi", "entry", "offset", "mapping-change", "file-change", "missing-code"} {
		t.Run(problem, func(t *testing.T) {
			machine, name := elf.EM_X86_64, "lib/x86_64/libbox.so"
			if problem == "abi" {
				machine = elf.EM_AARCH64
			}
			if problem == "entry" {
				name = "lib/arm64-v8a/libbox.so"
			}
			path, _, maps := androidMappedFixture(t, machine, name)
			pc := uint64(0x1010)
			if problem == "offset" {
				pc = 0x1800
			}
			if problem == "missing-code" {
				pc = 0x3000
			}
			calls := 0
			read := func() ([]byte, error) {
				calls++
				if calls == 2 && problem == "mapping-change" {
					return []byte(strings.Replace(string(maps), "1000-2000", "1000-1900", 1)), nil
				}
				if calls == 2 && problem == "file-change" {
					file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
					if err != nil {
						t.Fatal(err)
					}
					_, err = file.Write([]byte("changed"))
					file.Close()
					if err != nil {
						t.Fatal(err)
					}
				}
				return maps, nil
			}
			got, err := measureAndroidComponents(path, "", "demo-native", "amd64", pc, read)
			if err == nil {
				t.Fatal("unproved runtime component accepted")
			}
			if problem == "abi" || problem == "entry" || problem == "offset" {
				if len(got) != 1 || got[0].ComponentID != "agent" {
					t.Fatal("independent package measurement lost or unproved native library reported")
				}
			} else if len(got) != 0 {
				t.Fatal("changed/unmapped package reported as running")
			}
		})
	}
}
