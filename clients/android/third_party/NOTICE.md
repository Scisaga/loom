# Android native dependency record

The Android data plane uses [SagerNet/sing-box](https://github.com/SagerNet/sing-box)
under its GPL-3.0-or-later terms. The complete corresponding source for the
native AAR includes the pinned upstream revision, the reviewed
`third_party/sing-box/domain-cache.patch`, the dependency revisions verified by
`scripts/prepare-sing-box.py`, `mobile/loomcore`, and its shared root-module inputs.
Use the actual AAR's `assets/loom/source-provenance.json` to identify its native
source. An upstream revision alone does not describe the patched binary.

| Input | Pinned value |
|---|---|
| sing-box version | `1.11.4` |
| sing-box commit | `eb07c7a79eeca943370eafea601e87da76c0e57e` |
| gomobile / gobind | SagerNet fork `v0.1.13` |
| Go toolchain for AAR | `go1.27.0` |
| Android NDK | `28.0.13004108` |
| Android API floor | `26` |
| ABIs | `arm64-v8a`, `x86_64` |
| Build tags | `with_gvisor,with_quic,with_wireguard,with_ech,with_utls,with_clash_api,http2legacy` |

`scripts/build-mobile-aar.sh` performs one `gomobile bind` invocation for both
`experimental/libbox` and `loom/mobile/loomcore`; this is the enforced
single-runtime integration. The generated AAR and its SHA-256 are local build
outputs and are not committed.

A temporary local AAR digest is not a source pin or release-acceptance record.
Read the digest from the exact generated artifact and retain release evidence in
the protected evidence directory; rebuilding changes it when the inputs change.
