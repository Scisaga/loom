# Generated mobile runtime

`loom-box.aar` is deliberately not committed. Run
`../../scripts/build-mobile-aar.sh` to produce it from the pinned sing-box and
Loom core sources. The single AAR contains only `arm64-v8a` and `x86_64` and
therefore embeds one Go runtime per process.
