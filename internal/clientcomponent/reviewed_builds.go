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
	"1.11.4-loom.9": {
		sources: map[string]string{
			"LICENSE":                "650d5e3b99a446fb38e820fa87a49562e0c79eab868fff58618ac487a58e554c",
			"source-provenance.json": "b004299f798a63cb8a416a9bd8c9fb4375caefc89f91084066663486d49bd5d8",
			"domain-cache.patch":     "59f00d8985636a576b43cb6a26b1e0ccd43f9030ec4a43f96f06c030f360f5a5",
			"prepare-sing-box.py":    "7124750a60e5911951fa9228668012be98b8eb1a8177682a8f388aac6152b1d2",
			"build-dataplane.sh":     "5017606a9a0be1455178c2552ed4e73b2bd4c50652d4f1dba288dc65aafce085",
		},
		windows: map[string]string{
			"amd64": "10255ced8e82ee022df7f7e3b80720f632b09d6f86f9d0f549fcd02bcd7472b5",
			"arm64": "9a0a4a75fe8a1d69c37688d1944817707d38b6ac219dfcaca9cb3a775f81fa51",
		},
		linux: map[string]string{
			"amd64": "ab7b4636e764bb76b6d7ee932dcfca45ca2c650950d20ec83d4c53ee2cf4c06a",
			"arm64": "8e813c02fe441c9a3a260712dd4fedb431ce5a262e26b2dd5b759219d9c39cbb",
		},
	},
	"1.11.4-loom.8": {
		sources: map[string]string{
			"LICENSE":                "650d5e3b99a446fb38e820fa87a49562e0c79eab868fff58618ac487a58e554c",
			"source-provenance.json": "d3aa4365b48258b7caebd6def4d5343bb5de567630d328ea7a354e5e39ea74bc",
			"domain-cache.patch":     "2eebb7ec685423e8f08b24150f288a534e4aefbe753ea866b723ff80f3aea96c",
			"prepare-sing-box.py":    "f853d6e74f01275801eeac2b6d57c71b773d26e041089a25bf0c4b2b745a7229",
			"build-dataplane.sh":     "8c833a56a48d3135bda025da991ff1d8abde18dd85063e1a3588801af8b6e4e3",
		},
		windows: map[string]string{
			"amd64": "e2f277e0434efd95bc331d3cf03188a4f3dfd2a6744c15549da06e704fcb1997",
			"arm64": "420f3c29dfbc9ed6c20f8f1c81a596a4c7410e484d54fb4ca825d362b4e6be1c",
		},
		linux: map[string]string{
			"amd64": "c601c155b24ca66de3f550ccdb0c66c151c92ed9e85521383e24b5d75b55d03f",
			"arm64": "a24f69fdfd91a97fbafdabcfed022062a4c449f35188e1d21aa159866d99d19a",
		},
	},
	"1.11.4-loom.7": {
		sources: map[string]string{
			"LICENSE":                "650d5e3b99a446fb38e820fa87a49562e0c79eab868fff58618ac487a58e554c",
			"source-provenance.json": "4e71ebd7351e6d4d6121bd5498972b6f3b1d488e98167b57cba5eab8784da803",
			"domain-cache.patch":     "468d703a98dc0a28129ec1b98445de64a71eabb3116ae011c23e53ed7759bf05",
			"prepare-sing-box.py":    "5c2cdc244e5d2d8bafd39b2240dea9cf1d874d9d441490271b264e62c81a92b8",
			"build-dataplane.sh":     "75ca909d74c1361eee03adbca074be8c819f7ebd517e7740f09edbc46e9d8dd5",
		},
		windows: map[string]string{
			"amd64": "c821de3fdb81ac3e0a2f0a4959195951d30b7f314afc968b346ac3ff3136322c",
			"arm64": "7817010875e6d5f54e99cab796254f34043e05475c0d38df1fb91b31c5cbf9e3",
		},
		linux: map[string]string{
			"amd64": "2eb46cdce373860ff5dbfef420fe5048b94c0970d92b180418cdebb52921bb72",
			"arm64": "b0608282e35fc4b2b8f2801d5ee12612bd0a13cf57aad6916b06d5da40bc86c1",
		},
	},
	"1.11.4-loom.6": {
		sources: map[string]string{
			"LICENSE":                "650d5e3b99a446fb38e820fa87a49562e0c79eab868fff58618ac487a58e554c",
			"source-provenance.json": "acba7fb5db383ea11eb60257f1a5572b4bada60ddba75f7aa899a2e8c7cdbf2e",
			"domain-cache.patch":     "1e73651e3789e4f0d4c4e94272eef923cfd1e6e3fd0e04f85f703d0ffaedd0b4",
			"prepare-sing-box.py":    "c03bf393650a680e596fdbaaf6ff71a685024597103d647a0cb9d81f113157b7",
			"build-dataplane.sh":     "cdfa1cea1d75bfbc11207ffc0c66c6d8c3f472d97f0cd4090af1b3328217d2cb",
		},
		windows: map[string]string{
			"amd64": "893be7b0d922f66824e3d2a78010b18f63c3043914d50eef9cf4839b157ce4a3",
			"arm64": "55f61b87b395a661ca91e2b3c016aab7b0defd7337be579831208f2a4662114a",
		},
		linux: map[string]string{
			"amd64": "56fe5bb3446f19767205e41de9aa6214e1d355aefd9a952027b439e23ea359f9",
			"arm64": "595be5091f8f38cca0fb5ed6f52ff45f8e1ab16542becfaf85c701bb72de533e",
		},
	},
	"1.11.4-loom.5": {
		sources: map[string]string{
			"LICENSE":                "650d5e3b99a446fb38e820fa87a49562e0c79eab868fff58618ac487a58e554c",
			"source-provenance.json": "331d7157225886dfee2892c376646bb580dce1277b88870ec711a585f1abe2c5",
			"domain-cache.patch":     "58eb3951e1432b0ed253ccc0f44bda19d316233e0adc33f1cf4addb3192dfd4e",
			"prepare-sing-box.py":    "330dc7cf04dee17be6b5117be62f8a29e89c2a1fbce3cc123f97e51a17163173",
			"build-dataplane.sh":     "61de506418b2dfc28a1c7e7ebfe7c7aa8e600a6701f55cbc49f4200e1b4be0a7",
		},
		windows: map[string]string{
			"amd64": "1eb4de1cf50c55aa8654617284bac4aabc7fb4c1fa91a8db529f5a28f8cc0171",
			"arm64": "4a3cbefaf0037f285d7fe392fd9ec85f5310d0db797698fc3eba24b8b81c861c",
		},
		linux: map[string]string{
			"amd64": "f9fb6e56bae4907cdc8eb95ca3e1bd0be80b6ab56cb83069d7b78fcda1f3a038",
			"arm64": "b044f260353fa0ffa5bc075d4ca2c8fa9bcf6af3bcf41a1c7ba00767216b57fd",
		},
	},

	"1.11.4-loom.4": {
		sources: map[string]string{
			"LICENSE":                "650d5e3b99a446fb38e820fa87a49562e0c79eab868fff58618ac487a58e554c",
			"source-provenance.json": "ede01419eaa0f1c8fd2dbebb0c1a912f7da621243d50c33f2c55fedbdba0634a",
			"domain-cache.patch":     "e3828a17d8bb10b252f5964f5e1d59d885bdeb405be80acb302b22ad45413106",
			"prepare-sing-box.py":    "f2f18065f4ccf9a295e339971f3e1ddac373c3d70352a45326cef478f58acb5e",
			"build-dataplane.sh":     "1459c75a54b781bc9279dce0df66c311b08c246dcc3b627eb10580faabcb86cc",
		},
		windows: map[string]string{
			"amd64": "5b34972edf8f75c04cbfb376f0ee04d47e16ceab8c92d1d3cedff842200b1650",
			"arm64": "81a494f9c6d2c577095f2dd4e30d7a90493e03ba0d967af9890c90454c349631",
		},
		linux: map[string]string{
			"amd64": "93bfb328bbaebdab8c21cee19e5899f862f091ebd1ef2bbaa6f67df7a0fc3c36",
			"arm64": "a7b96c199feb7461992bbaec84c85e04528b6ecd6a166a8eafed8e18c84042f6",
		},
	},
	"1.11.4-loom.3": {
		sources: map[string]string{
			"LICENSE":                "650d5e3b99a446fb38e820fa87a49562e0c79eab868fff58618ac487a58e554c",
			"source-provenance.json": "026ebb21a0bd54a179d02e74806757cecf4d262d9d93a469bdac14072ca93f0c",
			"domain-cache.patch":     "8c9abc289002ce8711ebb015a4d15d7d34d8811e45204c22037dc22d4f27ce4f",
			"prepare-sing-box.py":    "3928519376c53f24ee0c0060fb9e8fb275517fff49f493f67a03c74736b357b5",
			"build-dataplane.sh":     "9c463444e09e23fc9ef2056c9115c78c84240889de0312516acbffb18238c708",
		},
		windows: map[string]string{
			"amd64": "6a73614bcace2c56b3043e85719acfccff4e447cebc82596269ed39bf87494c1",
			"arm64": "b5ae201ee130d4c86086dd7e30cacceda39bf2c023ca9f7c58fdc7aa925c506a",
		},
		linux: map[string]string{
			"amd64": "b11af45fd03243884d57c6fc5fb0b33d6d516eb669aceba960362fcaf5d03fc3",
			"arm64": "bb3aaee7dd85c268fbf61b850e3cde8052827385daf1914ad4939f5fb443a203",
		},
	},
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
