package clientcomponent

import (
	"bytes"
	"debug/buildinfo"
	"debug/elf"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
)

var reviewedLinuxBuilds = map[string]string{
	"amd64": "06e809d876216481bb88b761c2a0feaee417fc5381af5a2121600450a95f61c9",
	"arm64": "a8ca6c98d3a30708048b8760ff24f76c988ae0d2750fb015dd537bf11330a93f",
}

// LinuxSourceFiles checks the same reviewed source inputs used by the Windows
// component package. Its result is payload, never installation authority.
func LinuxSourceFiles(inputs map[string][]byte) (map[string][]byte, error) {
	files := make(map[string][]byte, len(reviewedSources)+1)
	for _, name := range slices.Sorted(maps.Keys(reviewedSources)) {
		digest := reviewedSources[name]
		if sha256Hex(inputs[name]) != digest {
			return nil, fmt.Errorf("data-plane source file %s differs from reviewed inputs", name)
		}
		destination := "source/" + name
		if name == "LICENSE" {
			destination = SingBoxLicense
		}
		files[destination] = append([]byte(nil), inputs[name]...)
	}
	instructions, _, _ := strings.Cut(sourceBuildInstructions, " Wintun is")
	files["source/BUILD.txt"] = []byte(instructions + "\n")
	return files, nil
}

// InspectLinuxSourceBuild validates the exact reviewed ELF and honest Go build
// coordinates. Neither a forged version string nor a module name is provenance.
func InspectLinuxSourceBuild(body []byte, arch string) (Component, error) {
	if reviewedLinuxBuilds[arch] == "" || sha256Hex(body) != reviewedLinuxBuilds[arch] {
		return Component{}, errors.New("Linux data-plane binary differs from reviewed source build")
	}
	file, err := elf.NewFile(bytes.NewReader(body))
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
	info, err := buildinfo.Read(bytes.NewReader(body))
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
	return Component{Path: "sing-box", SHA256: sha256Hex(body), Size: len(body), Version: DataPlaneVersion, Commit: upstreamCommit,
		Source: Source{URL: upstreamURL, ArchiveSHA256: upstreamArchive, Evidence: evidenceSingBox, UpstreamVersion: upstreamVersion, ModuleSum: upstreamModuleSum, PatchSHA256: patchDigest}}, nil
}
