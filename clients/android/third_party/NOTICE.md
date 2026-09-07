# Android native dependency record

The Android data plane uses [SagerNet/sing-box](https://github.com/SagerNet/sing-box)
under its GPL-3.0-or-later terms. The complete corresponding source for the
native AAR is the upstream repository at the exact revision below plus this
repository's `mobile/loomcore` package.

| Input | Pinned value |
|---|---|
| sing-box version | `1.11.4` |
| sing-box commit | `eb07c7a79eeca943370eafea601e87da76c0e57e` |
| gomobile / gobind | SagerNet fork `v0.1.4` |
| Go toolchain for AAR | `go1.23.6` |
| Android NDK | `28.0.13004108` |
| Android API floor | `26` |
| ABIs | `arm64-v8a`, `x86_64` |
| Build tags | `with_gvisor,with_quic,with_wireguard,with_ech,with_utls,with_clash_api` |
| Verified local AAR SHA-256 | `b0ecf55a27ceaf5a59cd7999371d6e6cbfffa4413eee86ca8f139ec0872007fc` |

`scripts/build-mobile-aar.sh` performs one `gomobile bind` invocation for both
`experimental/libbox` and `loom/mobile/loomcore`; this is the enforced
single-runtime integration. The generated AAR and its SHA-256 are local build
outputs and are not committed.
