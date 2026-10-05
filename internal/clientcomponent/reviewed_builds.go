package clientcomponent

import (
	"errors"
	"maps"
	"slices"
)

// ReviewedSourceVersion identifies original source provenance bytes. It does
// not certify an executable or infer that a component has been loaded.
func ReviewedSourceVersion(body []byte) (string, error) {
	digest := sha256Hex(body)
	for _, version := range slices.Sorted(maps.Keys(reviewedArtifacts)) {
		if reviewedArtifacts[version].sources["source-provenance.json"] == digest {
			return version, nil
		}
	}
	return "", errors.New("data-plane source provenance is not a reviewed artifact")
}

// Artifact coordinates identify exact reproducible source and executable bytes.
// Every entry uses the same schema and verifier. Only DataPlaneVersion is writable;
// earlier signed artifacts retain their original meaning and never act as a runtime fallback.
type reviewedArtifact struct {
	sources map[string]string
	windows map[string]string
	linux   map[string]string
}

var reviewedArtifacts = map[string]reviewedArtifact{
	"1.11.4-loom.1": {
		sources: map[string]string{
			"LICENSE":                "650d5e3b99a446fb38e820fa87a49562e0c79eab868fff58618ac487a58e554c",
			"source-provenance.json": "3272bb452fd24129d8d78ab8744b6d377990b236a79c576e9615728f1ade0dfe",
			"domain-cache.patch":     "5c8a8b8403834dedfe35345aa914fda2c909cca5c89ffb06868d19f7c5c65b08",
			"prepare-sing-box.py":    "2cfcd7b16889f0ab7553b51253be4680f331d0c08ba6a7081653c8cb0a73daed",
			"build-dataplane.sh":     "d2704928f0b9ceb3f5b01a458b0ad534e754d75039f234445705a3bfd323f337",
		},
		windows: map[string]string{
			"amd64": "59aa4de23625dfc309292a27363507687dfa5ed12e9095b190b4f3d9e6916218",
			"arm64": "9c66eb2d9a828769f84e54be975cb51c41324c7f03aef0b0e91d2d97d27ba3a6",
		},
		linux: map[string]string{
			"amd64": "06e809d876216481bb88b761c2a0feaee417fc5381af5a2121600450a95f61c9",
			"arm64": "a8ca6c98d3a30708048b8760ff24f76c988ae0d2750fb015dd537bf11330a93f",
		},
	},
	"1.11.4-loom.2": {
		sources: map[string]string{
			"LICENSE":                "650d5e3b99a446fb38e820fa87a49562e0c79eab868fff58618ac487a58e554c",
			"source-provenance.json": "e1a9e5b67426e4f2069e1e201865673ade43573d87feccc6a4015dc9619dca87",
			"domain-cache.patch":     "467cc2c1fafa4768d441f3975ecece47cde794c9a2268e37fad5370955bca77c",
			"prepare-sing-box.py":    "4573c81985d359077cad2c955055a0a9f70cf50e1183798320c5db448b78025b",
			"build-dataplane.sh":     "cfe41ef214cb478182e0f9ac3b6e7565a98930fbb82503c02f166c29f1a5819c",
		},
		windows: map[string]string{
			"amd64": "e21c1f2dfbe28c2c7424b1e7d8ba1416d6d7457b4a0d7f0a264b57770bd43d95",
			"arm64": "d26a9fcd0c7fe3e1a7154d3f897a2e5c8aba0afba41f31d2d39cc16687efc4af",
		},
		linux: map[string]string{
			"amd64": "6d53b10bd76fdc49e5439e13d1a7e88c64674a5f3e1e8b75ddaa3e863ee27dc3",
			"arm64": "7147e44a474249903884b206ba4ccb091ffe02ac6f4adccdb9543b8b1b833444",
		},
	},
}

func reviewedBinaryVersion(body []byte, platform, arch string) string {
	digest := sha256Hex(body)
	found := ""
	for _, version := range slices.Sorted(maps.Keys(reviewedArtifacts)) {
		review := reviewedArtifacts[version]
		builds := review.linux
		if platform == "windows" {
			builds = review.windows
		}
		if builds[arch] == digest {
			if found != "" {
				return ""
			}
			found = version
		}
	}
	return found
}
