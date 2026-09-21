# Loom Android v2 minimal client

The Android app consumes one private, quorum-certified `DeviceView`. The view
contains the authorized route candidates and one canonical sing-box runtime
profile. No public enrollment endpoint, `current.json`, snapshot registry,
route-plan scheduler, entry scanner, sampling window, threshold ranker, or v1
fallback participates in startup.

The protected Android Keystore store contains:

- the Ed25519 device identity, bootstrap capability, monotonic head floor, and
  complete certified LKG as one state record;
- at most one certified candidate awaiting runtime acceptance;
- the user's Direct / Auto / fixed-exit preference;
- bounded business observations keyed by network generation.

Enrollment claim/resume, configuration sync, and signed reporting all use the
TLS 1.3 private tunnel described by the certified endpoint generation. The
client pins its SPKI and proves the device key before HTTP is available.

`RouteCandidate.ID` maps directly to the same sing-box outbound and
`RouteCandidate.Scope` maps directly to its selector. The shared Go model makes
one deterministic choice for each scope. Kotlin only applies that choice and
publishes selector readback. Missing, expired, and prior-network results remain
`unknown`; Direct never receives a synthetic measurement. A selected non-Direct
candidate receives at most one real DNS+HTTPS result per network generation.
If that result is unavailable, the model may choose one same-exit fallback and
the host performs one second business check—there is no full candidate scan.

A candidate becomes current only after `Libbox.checkConfig`, encrypted
write/readback, libbox startup, selector apply/readback, and real DNS/HTTPS all
succeed. Any failure deletes only the candidate and leaves the current LKG
runnable. Process and device restart always revalidate the complete LKG and its
anti-rollback floor before projecting a runtime profile.

## Build

Required inputs are OpenJDK 17, Android SDK platform 35, build-tools 35.0.1,
and NDK 28.0.13004108. The AAR build pins sing-box 1.11.4 and binds libbox and
`mobile/loomcore` into the same Go runtime:

```bash
ANDROID_HOME=/opt/android-sdk ./scripts/build-mobile-aar.sh
ANDROID_HOME=/opt/android-sdk ./gradlew --no-daemon --max-workers=4 \
  testDebugUnitTest lintDebug assembleDebug
```

Release signing uses the ignored operator-owned
`../../deploy/android/android-signing.env`. `build-release.sh` refuses dirty or
untracked Android inputs, rebuilds the AAR from `HEAD`, embeds the source commit
and AAR digest, runs unit tests and release lint, signs the APK, verifies its
signature, and confirms both APK native libraries are byte-identical to the
audited AAR:

```bash
ANDROID_HOME=/opt/android-sdk ./scripts/build-release.sh
```

The package remains `io.github.scisaga.loom`; preserve the existing PKCS12 key
for upgrade continuity. A clean-install acceptance must use the signed release
APK, import a `.loom-invite` through the normal file or QR UI, receive operator
approval, connect through the normal VPN action, and confirm the signed report
from the private control service. Cellular/Wi-Fi transition coverage belongs to
the separate network-switch acceptance item, not this build.

## Visual review in VS Code

The production Compose tree is the design source. `LoomHomeRoute` owns
`StateFlow`, managers, Android permissions, and side effects;
`LoomHomeScreen` consumes only an immutable UI projection and is shared by the
Activity and screenshot fixtures. The nine committed references are rendered
by Compose screenshot alpha16 at Chinese/light/`412×915dp`/font scale 1.0.

From the repository root run:

```bash
scripts/ui-review preview android
scripts/ui-review verify android
```

Open `http://127.0.0.1:4173/index.html` with VS Code's built-in Simple Browser
while `scripts/ui-review serve` is running. No APK installation or preview
extension is required. The only recommended editor extension is the official
JetBrains Kotlin language server; rendering itself always goes through Gradle.
Do not edit reference PNGs by hand. Use `scripts/ui-review record all` only
after the complete Android and Windows gallery has been approved.
