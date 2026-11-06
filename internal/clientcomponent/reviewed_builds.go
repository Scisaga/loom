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
// Every entry uses the same schema and verifier. Current artifact coordinates
// are selected per platform; historical authenticated bytes remain verifiable.
// Earlier signed artifacts retain their original meaning and never act as a runtime fallback.
type reviewedArtifact struct {
	sources map[string]string
	windows map[string]string
	linux   map[string]string
}

var reviewedArtifacts = map[string]reviewedArtifact{
	DataPlaneVersion: {
		sources: map[string]string{
			"LICENSE":                "650d5e3b99a446fb38e820fa87a49562e0c79eab868fff58618ac487a58e554c",
			"build-dataplane.sh":     "f5997022827512f2038959cfed55a840379f9239e4ac791d48fe8ae529b99c94",
			"domain-cache.patch":     "c34c799bee295f8089844a93f12169488de578bc21dc3bb62bb2700419b5d5ab",
			"prepare-sing-box.py":    "d080220b397186c8c725ab50d2b11a9be0cacfc5a5cc431a3ef0dfb1c9c5905f",
			"source-provenance.json": "e79394c57a7fd5651577a3e3939d6e72c989ce1218cddffe5517b70b630a4bbd",
		},
		linux: map[string]string{
			"amd64": "51d4396dadb91d10dcaabc3db93b3343c1fdb5a415bab4364cf7e35692c902bf",
			"arm64": "587ded948d5efe2f5caddec3ad1cf87c4a6939b5cf147482c67ee48fe5accb92",
		},
		windows: map[string]string{
			"amd64": "b18327abf967525913ca95faad5c229eff2c653e30ed8d1c7ce4c786e3d86df2",
			"arm64": "a821faf70949e1c83c627d32ddbe629908341416947c9c1adf72cc720b992744",
		},
	},
	"1.11.4-loom.26": {
		sources: map[string]string{
			"LICENSE":                "650d5e3b99a446fb38e820fa87a49562e0c79eab868fff58618ac487a58e554c",
			"build-dataplane.sh":     "31fb2fc1ca3e89222273f820ff69e74775e4aa9b9edad4a1f4fdbed368c81872",
			"domain-cache.patch":     "c877a591af3ab5a10c68921bc4edccb181efff213c22b29cec2f9a0f53e9f736",
			"prepare-sing-box.py":    "55f1b60df1f5748c6962c50846e7a74b9896a53f95fc45761fb32431e533c96c",
			"source-provenance.json": "ca71fa9136f5189de74d13151aa4d5a787a37c46b38f1561479c4c573f969301",
		},
		linux: map[string]string{
			"amd64": "7ce314f2e61e6d2ac7d65143c069730010dbdf18d64e92cf64c40b15270a0606",
			"arm64": "d95a635b8ff1bb4e0391306bebf4b9c80d1f85f4af55ae4b962c4a49fe7d46f4",
		},
		windows: map[string]string{
			"amd64": "d5c9846cadda28aea902a53d4dc3634ed92d9d8ab978d1af6d9bcefc6f7df562",
			"arm64": "e7a4c592db91fff114151b2d17908fd7206238d8a697e1820cafca114311b905",
		},
	},
	"1.11.4-loom.25": {
		sources: map[string]string{
			"LICENSE":                "650d5e3b99a446fb38e820fa87a49562e0c79eab868fff58618ac487a58e554c",
			"build-dataplane.sh":     "2c3c144528c10a54c6708d42155313028619f122710887a88305042c71bf91ca",
			"domain-cache.patch":     "d6406d2368115dea670d2623f8fc096d283f579ec976156cf4fab828568e0144",
			"prepare-sing-box.py":    "0c0599004081a3d0fbc048f678833f0fc5ab95783b9e319af959112a36ba034d",
			"source-provenance.json": "841b97c2a1c0ae4a0ab581f8e3feb47575ac748bb01b2c45cb2455a3128fdb5e",
		},
		linux: map[string]string{
			"amd64": "8d73d53b77643984673dfb656e8feea8bcc5219a0f52c4424aeefe43bed8f571",
			"arm64": "e659aa6eb11881b3965a3ec8d90a0d125a64399e15fdbdb97a745917f6f4c755",
		},
		windows: map[string]string{
			"amd64": "8b9feb004f566d200d660d134a734bb15bce2c2297f7e9d9c6d0fb4e7d86bb95",
			"arm64": "6bfdf144e941974966d385df678ee9b82fbf272cfbb8308c4fa89eff6f40f37e",
		},
	},
	"1.11.4-loom.24": {
		sources: map[string]string{
			"LICENSE":                "650d5e3b99a446fb38e820fa87a49562e0c79eab868fff58618ac487a58e554c",
			"build-dataplane.sh":     "24b333e64c0b5276e986a83cdbb31113a27e30194a2f84407d0fd393c55983a5",
			"domain-cache.patch":     "2586ab075faa7f44c846ed92e3fe8ea73dec011903af29eaa35d4600b218c21f",
			"prepare-sing-box.py":    "13adeed8605a8a78b7ca2dfbb786bb9ef8ec2d7a4848c66ce4a4370e744de802",
			"source-provenance.json": "481cbeac84873994eae80048f5e88c59b13970c96f3cf23822b97fa3b54362c5",
		},
		linux: map[string]string{
			"amd64": "077848fa7f785724d9b5c1269efe47d32e320175898d856d197f3e7a5e721687",
			"arm64": "1d79ca4a2342eedd6e3310c0d49e922bf7bd816c5b6fc50b51ed99a6af84dbb1",
		},
		windows: map[string]string{
			"amd64": "a7bfd733cc4467cbf526aec37c1b912ff0b91943b5fe2a125b57cb5c93acc81d",
			"arm64": "0d44a2c7b692b3cde82a6523bc154f582ea3a42c4f270c6d656318a6e333b254",
		},
	},
	"1.11.4-loom.23": {
		sources: map[string]string{
			"LICENSE":                "650d5e3b99a446fb38e820fa87a49562e0c79eab868fff58618ac487a58e554c",
			"build-dataplane.sh":     "e4ffc0ea4fe71d2dcaaaff9e669c7d8d1971b1fbbfa8b0f05f27bb161c95b0e0",
			"domain-cache.patch":     "54d90a5ce63ee6b38e12585c5eae59ccdb8d7d40a7f808d26f1296f38e5562e0",
			"prepare-sing-box.py":    "9fec8d7d7836cb38f7fb729704fb07df1969862c99295ae1bec2960232fb3de1",
			"source-provenance.json": "1144ba196b4a3ce95e59bf0c73345a4eb5b159ee35cbbe0559d62890bdb44b6c",
		},
		linux: map[string]string{
			"amd64": "953ddc154bf7289dd8217851b22afbc4dbdf50d3e905e7f9756deacaec53e61e",
			"arm64": "48458d8b362b4bbc1098494177371102a445c0c472cfd5ff31d4f2ea5fe8360f",
		},
		windows: map[string]string{
			"amd64": "e0579999b04640f08f2a75c9836ea3ee3b92cc43f0e9fd40294c5807a126b2ac",
			"arm64": "4fb2fff9547e048af406074d4e5b0c6e02fd8e19fe2b7232426a642c2370b801",
		},
	},
	"1.11.4-loom.22": {
		sources: map[string]string{
			"LICENSE":                "650d5e3b99a446fb38e820fa87a49562e0c79eab868fff58618ac487a58e554c",
			"build-dataplane.sh":     "a2976c2c38dabdc08c4440c5b47b16c9a697e57c2703ab162ad18c3269878eea",
			"domain-cache.patch":     "97788a579eac907ecd35d30dae98759f3810c0669b88d576177ff89b79fc3969",
			"prepare-sing-box.py":    "afbaa6202765f841392f877052dde5c3ecd4c765697910208945e80e64861deb",
			"source-provenance.json": "686d69e4184aa97999aa48801a3280583ddc8ed61ebabb3b231ccd8749d8c773",
		},
		linux: map[string]string{
			"amd64": "43687efb9917ef3cb134806edfe5f08adac158d9d3b9955c56eccf1733cb996b",
			"arm64": "3d0444d8bfc15655f2c94bdcb09b7cdf8c5bd9268e065d9a6e52f0270ece2803",
		},
		windows: map[string]string{
			"amd64": "edc9bf552788f48c9c0c2172a6743c07d5d464fc2b83865123ac96de3714b4f5",
			"arm64": "cf1e9945f9f3869ee7899eb1e216f4ad9bdf92412207d8a41a7753fa7c68c4b4",
		},
	},
	"1.11.4-loom.21": {
		sources: map[string]string{
			"LICENSE":                "650d5e3b99a446fb38e820fa87a49562e0c79eab868fff58618ac487a58e554c",
			"build-dataplane.sh":     "857bcf8bbe0d61153d4f4c9ee77813d8fe385d0a9ce4e4547e578d51cdd6214d",
			"domain-cache.patch":     "90efc3c6154641b47c0771f8a93ac7c386e865b0a0082aee89ef021cd9cd1ecf",
			"prepare-sing-box.py":    "fa02885744327f508fa41d66a0f44e9c594581d74e379a6e7ecafb9b808aa982",
			"source-provenance.json": "6c17acaca8e205f5af9e59e803d9085fff2ffc378f4c9eab197ada07dfec7b76",
		},
		linux: map[string]string{
			"amd64": "63b08e57176df999e32fb74f54d0abaef8e18d94549bd34fab2226a5c9266bb7",
			"arm64": "2eb60c2fd8f6d5971147b7e95b15ee1044f40d1fef128a86af43830310c35760",
		},
		windows: map[string]string{
			"amd64": "5df067432ac4bbc67987d630c0a760033488ec77085b8c74ad34a602afa91709",
			"arm64": "8232657c4c65bf7a0bff93992b66927ec6d7b3411f5e25f44d104a7e338f23ef",
		},
	},
	"1.11.4-loom.20": {
		sources: map[string]string{
			"LICENSE":                "650d5e3b99a446fb38e820fa87a49562e0c79eab868fff58618ac487a58e554c",
			"build-dataplane.sh":     "3e2e734f255dec972f1fa12ccfa22c2e56856794543fe0d5c9d778e518db8c83",
			"domain-cache.patch":     "360a672ac5eb12f072bb45e3775bc0c2256e4e13665ebd91e1def401b7c779bd",
			"prepare-sing-box.py":    "4be954909ff3d9ec23a491fb302b2ff91651b9ba510f90dedf5fb3fe678d9e3d",
			"source-provenance.json": "a0f75e6879817e9b08b46d0aca5001469325fd02727cfd1ab74ba0fe13d55b6b",
		},
		linux: map[string]string{
			"amd64": "3a78a8274954ed29a22b0fc32970260da91bc2102fb9d0d613b3fdc3f48a7ff9",
			"arm64": "b7f41443c6715c9261067e5e8a921cd7d627622921f3b20e85f7159ddd06d868",
		},
		windows: map[string]string{
			"amd64": "a478057c4e1dd0a60731e1c7492912af61a2e60f9c63e63367112e73f039ec66",
			"arm64": "1028167ee3a2076530c55b3e66c65004ca97f6dfa5b54aa8a7c1d7783007babe",
		},
	},
	"1.11.4-loom.19": {
		sources: map[string]string{
			"LICENSE":                "650d5e3b99a446fb38e820fa87a49562e0c79eab868fff58618ac487a58e554c",
			"build-dataplane.sh":     "acea82d3ad68f860adedcc25d4785fab445394749cc66e1b62fc67bfc795f950",
			"domain-cache.patch":     "02c063c4b0561e57accf4caf60be71386e2fcaf02bd34f306dd554b8f9bbeb78",
			"prepare-sing-box.py":    "5c86ff1bbe0d517b9e5e7982fd7b6ccc6be9ffb31680f79443cf70669bc5e348",
			"source-provenance.json": "7c312aa44e72d650e1d9e81b1183b7180ca2aed419ce100daaa6cf04cc6cc6e7",
		},
		linux: map[string]string{
			"amd64": "a7b3d716fb4d1dc34b55a01fa6136352afbba2c7aa617a491cef083d475bb926",
			"arm64": "452723bdf82ac7361c19ab1101785d5f7faf1947434f6c767383ff352f71ffb0",
		},
		windows: map[string]string{
			"amd64": "957b6cc503ca4cedce10a4cc58f26bea210a0a7bea87a001a8dbe0cc0a7d7385",
			"arm64": "d8b9b2422089c94e16d00dac62caf578ce8b3a1a273f2b0bec277c62eeb46bfb",
		},
	},
	"1.11.4-loom.18": {
		sources: map[string]string{
			"LICENSE":                "650d5e3b99a446fb38e820fa87a49562e0c79eab868fff58618ac487a58e554c",
			"source-provenance.json": "c7519323bce75897e1ebe717aba474190742b2b27a9fe10eb4834c72599b5cfc",
			"domain-cache.patch":     "76419cb88554a2bddc2b6a7014769450dd61e09c32a228ae03a67662032a68b1",
			"prepare-sing-box.py":    "20f8b4f0235613291cc8432d94a938d6bea6ce6805076d78f1b9b311a02d7e40",
			"build-dataplane.sh":     "bdded4d80b3f8eb5de99e25db2042aaa7ef30cb3d2555f0bb04268db75375934",
		},
		linux: map[string]string{
			"amd64": "b09b0143c9714785fdf3040fb594d06ddf1aada1e8a883cb1fa8f1f4100c4424",
			"arm64": "2bdda6a69a00fb7c65753776450db09093508cb36a2e287d870f59e64016c22e",
		},
	},
	"1.11.4-loom.17": {
		sources: map[string]string{
			"LICENSE":                "650d5e3b99a446fb38e820fa87a49562e0c79eab868fff58618ac487a58e554c",
			"source-provenance.json": "e1e0d46b8f5b1ed72f196f671c49e4097702ca892a5cc7f3cc9e20dca7ef8957",
			"domain-cache.patch":     "22e49b791274a9ea43c7c28e44854d600b6b68ee41caf99f133148358300ba08",
			"prepare-sing-box.py":    "12577123ec7eb0d0809a38a4075001f4aafca5bf84a585688b320c17557384ef",
			"build-dataplane.sh":     "e0d0821a457748ba1438f0cc77279594dd867c35506c5548080c186931877751",
		},
		linux: map[string]string{
			"amd64": "2d69ffcee12257afbf4b3be60c7abf9d1e226ebaf1a2cc31490b650500551720",
			"arm64": "4d5264ed4e4e1427d0882cf3b5999c7ab15804e7136e8db6093048f1fbb4bced",
		},
		windows: map[string]string{
			"amd64": "a5441897c14b324e300cdcf6566d474486b4e218602fff114b80f39e90cef6f4",
			"arm64": "207e6f61eee273ae1a4c850ef0f3212944599f6a3e12b44089f39ff37a315fec",
		},
	},
	"1.11.4-loom.16": {
		sources: map[string]string{
			"LICENSE":                "650d5e3b99a446fb38e820fa87a49562e0c79eab868fff58618ac487a58e554c",
			"source-provenance.json": "ac5ce934595438bed4a457fe08d592f5d743326068990be0b099b5fccd839e94",
			"domain-cache.patch":     "d544efcaffac523270c05e7f39add00323fac1a0b7620a9e528942923e61fcb6",
			"prepare-sing-box.py":    "3f74d433e4d2ed7a618d08eef5ab93f02e7d6908d9066f55cbc907666a7e8a43",
			"build-dataplane.sh":     "876a0c3ebef31c75d5e22cbc757808bec1dd0541ab9d1bbe8702d39ab02106c7",
		},
		linux: map[string]string{
			"amd64": "12deae970bc4763e29011f60d36a0b109dc0d9d04162e207d7722534c0408a2d",
			"arm64": "faa9afd845c58fbebb1d060e477121a70349f8ac73560728a560c32ae5af597a",
		},
		windows: map[string]string{
			"amd64": "f65897119b2cfa5acb4bf1d68bd2569cc4a0bdfa9f6f58decec45ac0ec2d2fa9",
			"arm64": "25aa9b438d40fceb857051f80c15c85825e687a2bc5ab7df39b839eea7882ec3",
		},
	},
	"1.11.4-loom.15": {
		sources: map[string]string{
			"LICENSE":                "650d5e3b99a446fb38e820fa87a49562e0c79eab868fff58618ac487a58e554c",
			"source-provenance.json": "b395e22c8a84fe32bd7f93331024a11ee0ebd66fdebff1f71ecb4c3c97a4b8f7",
			"domain-cache.patch":     "fb29adf7098de0a3a3cfba62de3fe82e6daf830664adc193e9c605c49fff1c4f",
			"prepare-sing-box.py":    "da863de30c14d1348e3f9be92cc915cd95a041dbfc19920c0f3d3b7ec97e554c",
			"build-dataplane.sh":     "2725ea07eb3b31ae998a8da264257cab02dd9c39f22d7fe190b986d43fec0a5c",
		},
		linux: map[string]string{
			"amd64": "9d5171f193c7d7447c0074346f40d9cab4bc0365aa86377973df87a38caf3e9a",
			"arm64": "9033246122fff69697d1b5f883fcf4d3e950653b7962b532bd6bb6ae192b97fd",
		},
	},
	"1.11.4-loom.14": {
		sources: map[string]string{
			"LICENSE":                "650d5e3b99a446fb38e820fa87a49562e0c79eab868fff58618ac487a58e554c",
			"source-provenance.json": "a43c2d45f590becd13e2133579885bba02d78fdd2c31190356248e00aa74b7e8",
			"domain-cache.patch":     "c9b450f627a53d5dcafd7f5ba09a36964b2aba2f9fc0e2cf04627eb19050990e",
			"prepare-sing-box.py":    "2e52356738db7b4f3a2c326d5b662438d8f4f0f0001c137bcca97da8321272ab",
			"build-dataplane.sh":     "404802e038ff27ed00fbae01f84802e49b47887081d86b79446776d2afc5b947",
		},
		linux: map[string]string{
			"amd64": "dff74c981b5b43b1190bf7b5d09810d6ddd65007a7c85733a74badc99ff318eb",
			"arm64": "15d2b410514635d40d6c72ac67309522cadec9811e78facbab3288995e58d0df",
		},
	},
	"1.11.4-loom.13": {
		sources: map[string]string{
			"LICENSE":                "650d5e3b99a446fb38e820fa87a49562e0c79eab868fff58618ac487a58e554c",
			"source-provenance.json": "2318f19e2244efd6d7af3dea8635961363de55106d2375837edf5b13a7d75c90",
			"domain-cache.patch":     "e22f4def13acc7be3cef3535d8f33cee358f7204956c8a72cccf40ce2d805352",
			"prepare-sing-box.py":    "766469db5a51dae8ee035440d6d8b6f26fcad82a76ada2df8276db73e812fe0b",
			"build-dataplane.sh":     "814920e14f40c39ce149d6f400f731b8905c6ea3e4f287f16d2aadcb69e3371c",
		},
		linux: map[string]string{
			"amd64": "2ef1e73df24ee3049a471938d0c44d38e278a67fe4ec85d8c44972f798c429ff",
			"arm64": "efc4f3b037a130b3f9f17e5be7b12c7daa1eddff65ccb3f7803794e43e357748",
		},
	},
	"1.11.4-loom.12": {
		sources: map[string]string{
			"LICENSE":                "650d5e3b99a446fb38e820fa87a49562e0c79eab868fff58618ac487a58e554c",
			"source-provenance.json": "2074a8683800d35847ccc9c098f2e21063781112e1ea6763a4b510411f82b1da",
			"domain-cache.patch":     "c45351c7c23d25e68962b2f27e116e3377391f7987e5f5f567ec2c8bda4b00ce",
			"prepare-sing-box.py":    "e4fa7d31d311df2b523ceb7272ba251237acdbdad30c92ec54ee91ba415611dc",
			"build-dataplane.sh":     "30c500b92d36eb30fbbe68d34b615de118134d87320c50a9e65135f8d3a486c6",
		},
		windows: map[string]string{
			"amd64": "07a75eeb3a32854e8d4af836ea652d90068c6877b83099dc1d2b22d333751d07",
			"arm64": "d14403e96d8e643628b2abd2b99466cde99265dcbcbfa82a5cd51857f5da0e7c",
		},
		linux: map[string]string{
			"amd64": "cecaa491b7288bbd1d4572444750654e7f44899252396d648cb7060a0e4b1186",
			"arm64": "57a41e91c923c3b7e1214e3c24449ba118c0ada0481d3eeed5076b58aae41449",
		},
	},
	"1.11.4-loom.11": {
		sources: map[string]string{
			"LICENSE":                "650d5e3b99a446fb38e820fa87a49562e0c79eab868fff58618ac487a58e554c",
			"source-provenance.json": "076a9aff638e80f0c74400c94ec3c3e82d215ea0eebe3d6268bcfa870c6b95e5",
			"domain-cache.patch":     "f87c69e1e0aa1085a1d64fc85cb5e570e970b37c010c802dcde22d4b0934c85c",
			"prepare-sing-box.py":    "7b4f8d6715db847fce7143b8d5b01162e511d2b51f7664d50d7341ea8e2786f1",
			"build-dataplane.sh":     "1a2bd233b827bb95bf4d05ede41ef59ec88ab3eb23daeab2bb7fa9023476f1d0",
		},
		windows: map[string]string{
			"amd64": "79b1c9836f92cc29dc0062a923b5bdafaeef2de494cdf5df602504c2dd49f51a",
			"arm64": "9fc9864e0eeda181028b2c7c6fcc1ed2831a64f3af565b11090f98134cff46a1",
		},
		linux: map[string]string{
			"amd64": "e518ca79dc78726142892ac617a320044c7ea849f77954ba332b793d784d76cf",
			"arm64": "6715ab4f896d90fb03fa86321aee4896e5831389c1b407fce402c60b9562b484",
		},
	},
	"1.11.4-loom.10": {
		sources: map[string]string{
			"LICENSE":                "650d5e3b99a446fb38e820fa87a49562e0c79eab868fff58618ac487a58e554c",
			"source-provenance.json": "d74919957875137c1ed840ce1f83aeee63c4dcdf770ca3c1ff089a1f50482d56",
			"domain-cache.patch":     "af5cc2a4bb5cb41dad8e1bd7a118d6e40021424c5465e817753aa6c037a7a6d5",
			"prepare-sing-box.py":    "e12b21106b70217783c279a33b728f358408b6e7e43827fa573a099eba320a12",
			"build-dataplane.sh":     "1c4486186a803b921ff1c587facb17c5b3c3c5a103089dab3e9b89799bcdefd8",
		},
		windows: map[string]string{
			"amd64": "7bcea4ab94a12caed496b7a201c853069fa171e0b25e707b92e66ecccd6df229",
			"arm64": "d540c4c3428912b2a8d6e2411a7f1f8db334fb96763a2e7798407cdf68456b90",
		},
		linux: map[string]string{
			"amd64": "46d8b115b500a13490688d517017d31a8b7371582ccf51a211706591f0f15941",
			"arm64": "9bc2b2064dcb114c373abaaf68abc1aa3ff19a543cbea396a5660a296b3db517",
		},
	},
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
