# Loom Android client

This document defines the target client behavior. Implemented behavior, business
acceptance, and release status are tracked in [implementation status](../../docs/progress.md).
Target prototypes follow explicit requirements and the current models; existing
code and native screenshots document implementation and its gaps, not limits on the design.

Invitation QR codes, links and files carry only a transaction credential and
minimal pinned TLS coordinates. They contain no policies, device names or member
proofs. The existing protected identity is saved with this reference before the
first connection. After key binding, the authenticated private response supplies
the original signed enrollment proof and this device's configuration. The same
identity then stores that proof and LKG; existing keys and rollback floors remain
unchanged. Interrupted enrollment reuses its key and request ID.

## Normal user flow

Android keeps zero or more named local profiles, which may not have joined yet.
Create or select a profile, import its access Invite through the file or QR UI,
then complete the private join using that profile's identity. Browsing or renaming
a profile does not switch the running VPN. An explicit connect/switch action
changes the requested profile; only runtime and selector readback establish the
active profile. Business observations follow separately, so absent probe targets
leave business status unknown without preventing an active VPN. These Android
catalog rules differ from Windows, which adds a new profile to its list only
after joining and saving. See the [profile model](../../docs/clients/android-profile-model.md).
The final disconnected profile can be deleted. The empty catalog remains empty
after restart and offers an explicit Add action; it never recreates a deleted
identity. First installation still offers its initial empty profile for scanning.

Scan opens a centered camera dialog over the current page. The square camera
viewport has no surrounding card; the underlying page keeps its scroll position
and pauses interaction. Close, outside tap and Back dismiss the dialog and release
its camera use cases. Permission and camera errors stay within the viewport.
Dismissed sessions cannot deliver queued scan results; accepted results continue
through the existing profile invitation import.

The client selects one current Internet Policy per active profile. That Policy
uniquely determines its Service; the granted PolicyIDs are available choices,
including multiple policies under one Service, not simultaneous Internet rules.
The Service contains expected-service probe URLs and an optional restriction to
those targets. With the restriction off, the URLs do not form an Internet allowlist.
There is no separate Destinations editor, Probe object, or geographic classifier.
LAN authorization remains independent. See the [current business baseline](../../docs/core/control-model.md#服务与策略的当前业务基线).

The previous per-Service preference shape requires explicit forward replacement;
its presence in old storage, screenshots, or tests does not constrain the target.
The current preference records one Internet Policy and independent LAN choices.
Replacement preserves identity, signed originals, high-water/floor, latch, and
report sequence. Implementation and physical migration acceptance are recorded
separately in [delivery status](../../docs/delivery-audit.md); a migration helper
does not by itself prove that an existing device has completed the transition.

The existing certified-file import implements an earlier one-time replacement;
it does not prove migration to the new single-current-Policy model. A revised
forward replacement must preserve original protected identity and preference bytes,
verify an actual certified fact-frontier advance, retain high-water/floor, latch,
and report sequence, and become the only current representation. Ordinary startup
and sync must not gain a historical runtime fallback. Normal imports of unchanged
current values retain their identity and frontier checks.

## Shared client contract

The Android TUN inbound uses gVisor by default, as defined by the
[Android capture contract](../../docs/clients/client-runtime-model.md#android-capture-边界).
It adapts local TCP/UDP traffic to the existing native execution path; WG and Hy2
remain independent transports. UDP adaptation preserves the original domain/IP,
port, and payload. There is no additional stack setting or automatic system-stack
fallback. Enabling a stack implementation upgrade uses normal VPN stop/restart;
performance routing changes continue to preserve existing connections.

The Android app consumes a private `DeviceView` signed by an effective control,
with a continuous control membership proof and signer fact frontier. The view
contains stable authorization, eligible nodes and resources, and necessary
transport identity material. The client derives candidates and runtime inputs
for its current Internet Policy and independent LAN choices. Measurements and
recommendations do not change that signed View. Enrollment, configuration sync,
and reporting use the private device
channel defined by the [Enrollment model](../../docs/core/enrollment-endpoint-model.md).

The protected Android Keystore store contains:

- the Ed25519 device identity, bootstrap capability, monotonic observed-fact floor,
  control membership proof, and complete signed LKG as one state record;
- the user's current Internet Policy choice or waiting intent, after explicit forward migration;
- bounded business observations keyed by network generation.
- a deletable first-hop observation cache bound to the profile identity, exact
  authorized resource inputs and network generation; original sample times survive restart.

Enrollment claim/resume, configuration sync, and signed reporting all use the
TLS 1.3 private tunnel described by the certified endpoint generation. The
client pins its SPKI and proves the device key before HTTP is available.

`RouteCandidate.ID` maps directly to the same sing-box outbound and
`RouteCandidate.Scope` maps directly to its selector. The shared Go model makes
choices only within the current Internet Policy. Kotlin applies those choices and
publishes selector readback. Missing, expired, and prior-network results remain
`unknown`; Direct never receives a synthetic measurement. Access measures its own
qualified first hops and consumes shared directed-link and exit measurements.
Forward nodes measure their outgoing links, and each Internet exit measures its
applicable Service URLs. The access does not repeat the exit's URL checks across
every complete path. Limited end-to-end calibration and actual business evidence
retain their original target, measurement location, parameters and lifetime; a
success for one target does not establish another target's health.
Connection starts with an available allowed path while bounded exploration and
segmented measurements continue. A fixed exit remains fixed through every relay;
there is no fixed "2+1" budget or full candidate-by-URL scan. Measurement refresh,
sample validity, and minimum performance-switch interval are separate. Performance
switches keep existing connections and apply the preference to new connections.

The normal connection page shows the selected Policy and its Service. Diagnostics
can retain explicitly scoped historical results for other Services. It displays each measured
HTTPS target with its original candidate, result, sample time and expiry. A failed
candidate leaving selection retains its historical explanation; missing samples
remain unknown. UI expiry changes only the display, and normal stop or configuration
replacement does not restore cleared samples. VPN connection and actual business
outcomes remain separate. See the [business display projection](../../docs/clients/client-runtime-model.md#android-的业务观测展示).

After runtime readback, first-hop measurement uses protected underlay sockets and
a node-wide budget. Reporting, configuration sync, measurement, and UI operations
must not wait behind one shared network-operation lock. Successful samples can be
remeasured before expiry; identical in-flight work is shared.
These resource observations enter the original signed report and management
device page; they do not establish a Service's availability. Normal stop retains
the diagnostic cache but reports no current resource health. Revocation, changed
execution inputs or a different network generation prevent reuse; profile deletion
removes its cache. Corrupt cache bytes are retained and resource samples stay
unknown while authorized business execution remains independent.

Ordinary Direct has `final_exit=direct` and no managed hops. An authorized local
egress candidate also has no network hops, but retains this device's NodeID as
its logical final exit. Local egress has no entry hop, so entry-node scopes do not
apply and it needs no self-dial or inbound resource.
Where the HostAdapter supports local egress, the selected Policy must explicitly
authorize it. Candidate choice stays inside that Policy, including its final-exit
restriction. Rebuilding a candidate must preserve this distinction and its authorization source.

A verified signed View becomes the `CertifiedLKG` when authentication, member
proof, device binding, floor checks, and protected atomic write/readback succeed.
The profile becomes runtime `active` only after `Libbox.checkConfig`, libbox
startup, and selector apply/readback succeed. Runtime failure leaves the
authenticated LKG available for repair but does not mark the VPN active;
an older runtime may continue only if it remains authorized by the newly
verified View. Real DNS/HTTPS checks follow runtime application and determine business availability for their actual
Service and network generation. Missing authorized probe targets leave that
business scope `unknown` without blocking LKG acceptance or VPN operation;
a real target failure records its actual scope and can inform same-Policy recovery.
A single URL failure does not establish whole-Internet failure.
Process and device restart always revalidate the complete LKG and its
anti-rollback floor before projecting a runtime profile.

The signed report measures the executing primary APK as `agent` and the loaded
ABI's `libbox.so` as `sing-box`, independently of release expectations. The shared
core binds its executing code address to the APK inode and native ELF segment,
then hashes the same open APK and uncompressed library. An unavailable measurement
is omitted; it never falls back to a downloaded or expected digest. A loaded native
library does not imply a running VPN: the report's runtime state remains separate.

## Build

Required inputs are OpenJDK 17, Android SDK platform 35, build-tools 35.0.1,
and NDK 28.0.13004108. The AAR build pins sing-box 1.11.4 and binds libbox and
`mobile/loomcore` into the same Go runtime:

```bash
ANDROID_HOME=/opt/android-sdk bash ./scripts/build-mobile-aar.sh
ANDROID_HOME=/opt/android-sdk bash ./gradlew --no-daemon --max-workers=4 \
  testDebugUnitTest lintDebug assembleDebug
```

Release signing uses the ignored operator-owned
`../../deploy/android/android-signing.env`. `build-release.sh` refuses staged,
unstaged or untracked Android and shared Go inputs, rebuilds the AAR from `HEAD`, embeds the source commit
and AAR digest, runs unit tests and release lint, signs the APK, verifies its
signature, and confirms both APK native libraries are byte-identical to the
audited AAR:

```bash
ANDROID_HOME=/opt/android-sdk bash ./scripts/build-release.sh
```

The AAR and APK carry the same reviewed `assets/loom/source-provenance.json`;
the release reader binds that record to the actual APK BuildConfig and both
native libraries. From the repository root, package the signed APK with its
original AAR using `loom release package-android -env .env -pubkey <public-key>
-apk <signed-apk> -aar <original-aar> -sdk <absolute-sdk-directory>
-generation <application-generation> -o <new-output-directory>`. Pass the
resulting `loom-android.apk` to the normal `release stage` and `release publish`
commands. The adjacent manifest and signature must remain with the APK.
The private Releases page provides all three files and exposes the original
component expectations; publication itself does not install an application.
See the [application manifest](../../docs/core/current-contract.md#android-应用-manifest-的规范字段)
and [publication workflow](../../docs/operations/configuration-model.md#签名发布记录到实际运行的闭环).

The package ID remains `io.github.scisaga.loom`; preserve its PKCS12 signing key
for upgrade continuity. A clean-install acceptance must use the signed release
APK, import a `.loom-invite` through the normal file or QR UI, complete claim with
the issuing control, connect through the normal VPN action, and confirm the signed report
from the private control service. Cellular/Wi-Fi transition evidence is required
for runtime acceptance and is tracked in [implementation status](../../docs/progress.md).

`scripts/emulator-smoke.sh` runs the empty-profile UI check on an explicitly
selected API 35+ emulator. Use a fresh test profile; the script preserves existing
app data and system proxy, DNS, and VPN consent settings. The opt-in
`CertifiedRuntimeInstrumentedTest` additionally needs an isolated real control
fixture: it imports a signed invitation through DocumentsUI, exercises system VPN
consent, sends HTTPS through Hy2, and checks withdrawal, protected process
restart, and reauthorization against private signed reports. This debug emulator check does not replace
the release or physical-device acceptance above.

## Visual review in VS Code

The production Compose tree is the sole rendering source for native visual
regression screenshots. `LoomHomeRoute` owns
`StateFlow`, managers, Android permissions, and side effects;
`LoomHomeScreen` consumes only an immutable UI projection and is shared by the
Activity and screenshot fixtures. The twelve committed references are rendered
by Compose screenshot alpha16 at Chinese/light/`412×915dp`/font scale 1.0.
The set includes `connection-business-failed` and the empty configuration and
connection pages. References come from the native renderers and are strictly verified.

The editable [Android SVGs](../../assets/client/android/) express target behavior.
The connection error scene keeps an accepted configuration while VPN startup fails;
the business-failure variant keeps the VPN connected and reports each Service's
target separately. The configuration scene shows the authenticated configuration
has been saved. Join errors distinguish retrying the same transaction from
abandoning local pending join data; diagnostics labels each Service, actual target,
result and observation time. Target scenes may differ from the existing native
PNGs or have no native counterpart. Requirements determine scene coverage, not
the current count of reference images. SVG changes do not update production UI
or approve new screenshot baselines; those require implementation and native review.

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
