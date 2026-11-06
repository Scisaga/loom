package clientcomponent

import (
	"bytes"
	"crypto/sha256"
	"debug/buildinfo"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
)

// LinuxSourceFiles checks the same reviewed source inputs used by the Windows
// component package. Its result is payload, never installation authority.
func LinuxSourceFiles(inputs map[string][]byte, version string) (map[string][]byte, error) {
	review, ok := reviewedArtifacts[version]
	if !ok {
		return nil, errors.New("unreviewed data-plane source artifact")
	}
	files := make(map[string][]byte, len(review.sources)+1)
	for _, name := range slices.Sorted(maps.Keys(review.sources)) {
		digest := review.sources[name]
		if sha256Hex(inputs[name]) != digest {
			return nil, fmt.Errorf("data-plane source file %s differs from reviewed inputs", name)
		}
		destination := "source/" + name
		if name == "LICENSE" {
			destination = SingBoxLicense
		}
		files[destination] = append([]byte(nil), inputs[name]...)
	}
	files["source/BUILD.txt"] = linuxSourceBuildInstructions(version)
	return files, nil
}

// VerifyLinuxSourceFilesReaders verifies the same exact source payload without
// retaining file bodies. Keys are the canonical package payload destinations.
func VerifyLinuxSourceFilesReaders(readers map[string]io.Reader, version string) error {
	review, ok := reviewedArtifacts[version]
	if !ok {
		return errors.New("unreviewed data-plane source artifact")
	}
	for _, name := range slices.Sorted(maps.Keys(review.sources)) {
		destination := "source/" + name
		if name == "LICENSE" {
			destination = SingBoxLicense
		}
		reader := readers[destination]
		if reader == nil {
			return errors.New("reviewed data-plane source input is missing")
		}
		hash := sha256.New()
		if _, err := io.CopyBuffer(hash, reader, make([]byte, 32<<10)); err != nil {
			return err
		}
		if fmt.Sprintf("%x", hash.Sum(nil)) != review.sources[name] {
			return errors.New("data-plane source input differs from reviewed bytes")
		}
	}
	want := linuxSourceBuildInstructions(version)
	reader := readers["source/BUILD.txt"]
	if reader == nil {
		return errors.New("reviewed build instructions are missing")
	}
	body, err := io.ReadAll(io.LimitReader(reader, int64(len(want))+1))
	if err != nil || !bytes.Equal(body, want) {
		return errors.New("reviewed build instructions differ")
	}
	return nil
}

func linuxSourceBuildInstructions(version string) []byte {
	instructions, _, _ := strings.Cut(sourceBuildInstructions, " Wintun is")
	// Signed build instructions belong to the immutable artifact coordinate,
	// even after another artifact becomes the current Linux target.
	if version == "1.11.4-loom.13" || version == "1.11.4-loom.14" || version == "1.11.4-loom.15" || version == "1.11.4-loom.18" {
		instructions = strings.Replace(instructions, "bash scripts/build-dataplane.sh", "bash scripts/build-dataplane.sh linux/amd64 linux/arm64", 1)
		instructions = strings.Replace(instructions, "the four deterministic executables", "the two deterministic Linux executables", 1)
	}
	return []byte(instructions + "\n")
}

// InspectLinuxSourceBuild validates the exact reviewed ELF and honest Go build
// coordinates. Neither a forged version string nor a module name is provenance.
func InspectLinuxSourceBuild(body []byte, arch string) (Component, error) {
	return InspectLinuxSourceBuildReader(bytes.NewReader(body), int64(len(body)), arch)
}

// InspectLinuxSourceBuildReader checks the same reviewed original ELF through a
// fixed ReaderAt. The caller retains ownership and stability of that input.
func InspectLinuxSourceBuildReader(reader io.ReaderAt, size int64, arch string) (Component, error) {
	if reader == nil || size <= 0 || size > maxUpstreamArchiveSize || arch != "amd64" && arch != "arm64" {
		return Component{}, errors.New("invalid Linux data-plane reader bounds")
	}
	hash := sha256.New()
	n, err := io.CopyBuffer(hash, io.NewSectionReader(reader, 0, size), make([]byte, 32<<10))
	if err != nil || n != size {
		return Component{}, errors.New("Linux data-plane input is incomplete")
	}
	digest := fmt.Sprintf("%x", hash.Sum(nil))
	version := ""
	for _, candidate := range slices.Sorted(maps.Keys(reviewedArtifacts)) {
		if reviewedArtifacts[candidate].linux[arch] == digest {
			if version != "" {
				return Component{}, errors.New("ambiguous reviewed Linux data-plane input")
			}
			version = candidate
		}
	}
	if version == "" {
		return Component{}, errors.New("Linux data-plane binary differs from reviewed source build")
	}
	file, err := elf.NewFile(io.NewSectionReader(reader, 0, size))
	if err != nil {
		return Component{}, fmt.Errorf("invalid Linux ELF: %w", err)
	}
	defer file.Close()
	wantMachine := elf.EM_X86_64
	if arch == "arm64" {
		wantMachine = elf.EM_AARCH64
	}
	if file.Machine != wantMachine || file.Class != elf.ELFCLASS64 {
		return Component{}, errors.New("Linux data-plane ELF architecture mismatch")
	}
	info, err := buildinfo.Read(io.NewSectionReader(reader, 0, size))
	if err != nil || info.Path != "github.com/sagernet/sing-box/cmd/sing-box" || info.Main.Path != "github.com/sagernet/sing-box" || info.Main.Version != "(devel)" || info.GoVersion != "go1.27.0" {
		return Component{}, errors.New("invalid reviewed Linux data-plane Go identity")
	}
	settings := make(map[string]string, len(info.Settings))
	for _, setting := range info.Settings {
		settings[setting.Key] = setting.Value
	}
	if settings["GOOS"] != "linux" || settings["GOARCH"] != arch || settings["CGO_ENABLED"] != "0" || settings["-trimpath"] != "true" || settings["-tags"] != "with_gvisor,with_quic,with_wireguard,with_ech,with_utls,with_clash_api,http2legacy" || settings["vcs.revision"] != "" {
		return Component{}, errors.New("Linux data-plane build settings differ from reviewed inputs")
	}
	return Component{Path: "sing-box", SHA256: digest, Size: int(size), Version: version, Commit: upstreamCommit,
		Source: Source{URL: upstreamURL, ArchiveSHA256: upstreamArchive, Evidence: evidenceSingBox, UpstreamVersion: upstreamVersion, ModuleSum: upstreamModuleSum, PatchSHA256: reviewedArtifacts[version].sources["domain-cache.patch"]}}, nil
}
