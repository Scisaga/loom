# Loom Android client — stage 3 routing and stage 4 reliability

This directory contains the native Kotlin/Compose host and the pinned
sing-box/Loom mobile binding. Stage 2 implements the complete access-only
enrollment path: QR or `.loom-invite` import, a non-exportable Android
Keystore identity, signed pull with a durable anti-rollback floor, candidate
activation/previous recovery, and signed health reporting. Stage 3 adds the
signed mobile route plan, Direct / Auto / fixed-exit preference, authenticated
loopback selector changes, one deduplicated entry-probe round per underlying
network generation, verified server-observation reuse, threshold damping,
actual-selector readback, and plan-scoped offline evidence reuse.

The three route modes are enabled only after a verified managed snapshot carries
a mobile route plan. Direct requires a direct candidate for every selector;
fixed-exit choices are the exact intersection authorized by the signed plan.
If a fixed exit is removed, the client blocks instead of silently falling back.
Auto never probes a complete candidate or business path. It sends one ICMP echo
per distinct authorized entry address in parallel, then reuses fresh canonical
v5 server observations returned by the existing health-report cycle. Missing,
expired, out-of-scope or invalid evidence stays unknown. A lower failure rate
can switch immediately; at equal failure rate, removing a relay without adding
estimated latency is not blocked by the improvement threshold. Same-hop
replacements and added relays still require the configured improvement.

The Current Paths card is a read-only projection of libbox selector readback.
It shows the entry ping, each matching WireGuard or public Hysteria2 server hop,
and each exact target observation separately. It does not infer measurements
from candidate names or present segmented evidence as end-to-end P50/P95,
business throughput, or whole-path health.

The primary Connect action stays disabled until a verified managed snapshot is
available. Debug builds expose the bundled stage-1 Direct fixture in a separate
`Debug Direct TUN` diagnostic card; that action proves only local TUN, DNS and
HTTPS behavior and must never be presented as enrollment or trusted reporting.
Cancelling Android's VPN consent is reported as an explicit connection error
instead of silently returning to the disconnected screen.

For debug-APK acceptance on a locked but already ADB-authorized device, the
debug source set includes `DebugVpnControlReceiver`. It is absent from release
builds and its exported component requires the platform-only
`android.permission.DUMP`, so ordinary applications cannot invoke it. After
the user has granted Android's VPN consent once, ADB can run a bounded test:

```bash
receiver=io.github.scisaga.loom/.debug.DebugVpnControlReceiver
adb -s "$ANDROID_SERIAL" shell am broadcast -n "$receiver" \
  -a io.github.scisaga.loom.debug.CONNECT
# inspect LoomNetworkProbe / LoomVpnService, then always disconnect
adb -s "$ANDROID_SERIAL" shell am broadcast -n "$receiver" \
  -a io.github.scisaga.loom.debug.DISCONNECT
```

When the phone is physically remote and cannot point its camera at a second
screen, the same debug-only receiver can feed a downloaded `.loom-invite` into
the production invitation parser and enrollment state machine. The secret is
carried in a file rather than an ADB argument, the receiver accepts only this
fixed app-specific path, and it deletes the file immediately after a bounded
read:

```bash
remote=/sdcard/Android/data/io.github.scisaga.loom/files/pending.loom-invite
adb -s "$ANDROID_SERIAL" push /secure/path/device.loom-invite "$remote"
adb -s "$ANDROID_SERIAL" shell am broadcast -n "$receiver" \
  -a io.github.scisaga.loom.debug.IMPORT_INVITE
# These return only redacted state, never the Device ID, URL or token.
adb -s "$ANDROID_SERIAL" shell am broadcast -n "$receiver" \
  -a io.github.scisaga.loom.debug.ENROLLMENT_STATUS
adb -s "$ANDROID_SERIAL" shell am broadcast -n "$receiver" \
  -a io.github.scisaga.loom.debug.RETRY_ENROLLMENT
```

`ABANDON_PENDING` is also available for an expired, never-claimed local
transaction. It calls the normal guarded abandon operation and cannot clear a
ready identity or active profile.

For locked-device enrollment acceptance, `ENROLLMENT_KEEPALIVE` starts the
existing foreground service without creating a VPN interface; this mirrors the
foreground lifetime normally supplied by the QR scanner Activity while leaving
the physical network as Android's default.

This transport exists only in the debug source set and still exercises the
same key-fingerprint check, Keystore CSR, claim/recovery, signed pull and
candidate activation used by camera scanning. CameraX/ZXing remains the normal
production input.

The end-to-end HTTPS check uses independent public endpoints and accepts one
valid TLS/HTTP response. This avoids declaring the whole tunnel unhealthy when
one provider is regionally filtered; if every endpoint fails, their individual
errors remain in the connection status.

## Reproducible Linux build

Required tools are OpenJDK 17, Android SDK platform 35, build-tools 35.0.1,
NDK 28.0.13004108 and either an arm64 device or an x86_64 emulator. Set
`ANDROID_HOME` and run:

```bash
./scripts/build-mobile-aar.sh
./gradlew --no-daemon --max-workers=4 testDebugUnitTest lintDebug assembleDebug assembleDebugAndroidTest
```

The first command checks out the exact sing-box commit recorded in
`third_party/NOTICE.md`, binds libbox and `mobile/loomcore` into one AAR,
verifies its two ABIs and prints its SHA-256. Gradle outputs the installable
debug APK under `app/build/outputs/apk/debug/`.

An APK that can enroll must embed the deployment Ed25519 public key. Gradle
uses the first available value from:

1. `-PloomPlatformPublicKey=<canonical-base64>`;
2. `LOOM_PLATFORM_PUBLIC_KEY=<canonical-base64>`;
3. the ignored local file `../../deploy/keys/platform-signing.pub`.

The key is public and contains no device credential or control address. Debug
builds without it remain useful for the emulator data-plane fixture, but QR
import fails closed before sending the one-time token. Every release task
refuses to run without a valid 32-byte trust anchor and all four release-signing
environment variables:

- `LOOM_ANDROID_RELEASE_STORE_FILE`;
- `LOOM_ANDROID_RELEASE_STORE_PASSWORD`;
- `LOOM_ANDROID_RELEASE_KEY_ALIAS`;
- `LOOM_ANDROID_RELEASE_KEY_PASSWORD`.

Keep the encrypted keystore and its credentials outside Git. The repository's
ignored default credential file is `../../deploy/android/android-signing.env`;
it can be overridden with `LOOM_ANDROID_SIGNING_ENV_FILE`. Build and verify a
private signed APK with:

```bash
./scripts/provision-release-key.sh # exactly once; refuses to overwrite
ANDROID_HOME=/path/to/android-sdk ./scripts/build-release.sh
```

Provisioning creates an encrypted PKCS12 upgrade key and a root-only environment
file in the ignored deployment directory. It refuses to replace either file and
does not make a backup. The build helper caps Gradle at four workers, runs unit
tests and release Lint, builds the release APK, and requires the pinned
build-tools `apksigner` to verify every APK signature before printing the
artifact SHA-256. It never creates, copies or backs up the long-lived upgrade
key. Preserve that key and its credentials in a separate protected backup:
losing it makes in-place upgrades of the fixed `io.github.scisaga.loom` package
impossible.

Once `deploy/android` exists, the repository-level `loom backup` default set
includes the complete directory. Create an encrypted backup, copy the archive
off this machine, and store its passphrase through a different channel:

```bash
go run ./cmd/loom backup -o /secure/destination/loom-secrets.bak \
  -passphrase-file /separate/location/backup-passphrase
./clients/android/scripts/verify-release-backup.sh \
  /secure/destination/loom-secrets.bak \
  /separate/location/backup-passphrase
```

The verifier restores into a new temporary directory, requires byte-identical
signing material, and proves that the recovered PKCS12 can be opened with the
recovered credentials. It never overwrites the live key. A backup left on the
builder, or an archive stored beside its passphrase, does not satisfy the
off-machine recovery requirement.

The enrollment endpoint must also serve a complete TLS chain which terminates
at a root in the supported Android system stores. Verify this on physical
devices, not only with a builder's OpenSSL bundle. In particular, the short
Let's Encrypt Generation Y ECDSA chain ending at ISRG Root X2 is not sufficient
for devices which lack X2; serve the default compatibility chain continuing to
ISRG Root X1. The client does not disable certificate or hostname verification
to compensate for a deployment chain error.

## Enrollment and activation transaction

The client compares the QR fingerprint with the embedded key before the first
POST, persists the exact CSR/request identity and retries only within the
bounded enrollment recovery window. A ready response must bind the returned
certificate to the same Keystore P-256 key.

Signed `current.json`, snapshot manifest/signature and the exact node bundle
are retained in Keystore-encrypted app storage. They are all reverified on
restart against the platform key embedded in the currently running APK; a
cached bootstrap cannot keep an older APK trust root alive after an upgrade.
A verified Android manifest must declare exactly the sing-box version embedded
in `Libbox.version()` and no server-only runtime component.
A new pull first advances the authenticated generation floor, then
enters a candidate slot. Its CA uses an immutable content-addressed path, so
preflight cannot replace the active profile's trust file. `VpnService` promotes
the candidate only after libbox starts and real DNS plus HTTPS probes traverse
the TUN; otherwise it restores the last verified profile. Reports use the same
Keystore key through the existing canonical v5 and self-check v1 contracts;
the canonical v5 claim also binds the actual selector, candidate and chain.
The same report POST requests `observations=1`: a current server returns a
bounded JSON snapshot with HTTP 200, while an older server's empty 204 remains
a successful report with no new route evidence.

## Emulator and device acceptance

Create an API 35 Google APIs x86_64 AVD with KVM, boot it headless, then run:

```bash
ANDROID_SERIAL=emulator-5554 ./scripts/emulator-smoke.sh
```

For a physically remote Android device whose vendor UI requires an extra USB
installation confirmation, use the narrowly scoped installer helper. It only
accepts the Loom package, an exact caller-supplied APK hash, a physical device,
an allowlisted system installer window, and a single enabled Install/Continue
node on a screen that also names Loom. It captures the matched screen before
one synthetic tap and verifies the installed signing certificate afterwards:

```bash
apk=app/build/outputs/apk/debug/app-debug.apk
apk_sha=$(sha256sum "$apk" | awk '{print $1}')
ANDROID_SERIAL=device-serial \
LOOM_AUTO_CONFIRM_INSTALL=1 \
INSTALL_EVIDENCE_DIR=/tmp/loom-install-evidence \
./scripts/install-device-apk.sh "$apk" "$apk_sha"
```

This is intentionally not a general system-dialog clicker. A missing Loom
label, ambiguous/disabled button, unexpected foreground package, certificate
mismatch, emulator target, or changed APK bytes fails closed.

The script installs the debug APK and starts the opt-in instrumented smoke
test. Success requires the signed fixture and libbox config checks, a
non-exportable Keystore P-256 key, DNS and HTTPS through TUN, an idempotent
disconnect, a second connect, and the approved logo plus visible Stage 3 route
entrances. It refuses to run unless `ANDROID_SERIAL` names a device that
reports `ro.kernel.qemu=1`, so an attached phone can never become the implicit
test target. When the Linux builder needs an HTTPS proxy,
the script uses a temporary emulator-only relay that is removed on exit.

The Android host deliberately fetches control and distribution data over
HTTPS only, even though the cross-platform signed-artifact format can describe
an HTTP mirror. HTTP entries are skipped and are never a downgrade fallback;
at least one verified HTTPS distribution mirror must therefore be available.

Formal enrollment still needs a control-created Android Device and the APK
built with that deployment's public key. On vendor Android builds, keep the
screen unlocked. ADB authorization alone may not authorize package
installation; the constrained helper above can approve Loom's separate vendor
confirmation when explicitly enabled.

No fixture or source file contains an invitation token, device private key,
production endpoint or private signing key. Third-party versions, source and
licenses are recorded in `third_party/NOTICE.md` and `third_party/sing-box/`.
