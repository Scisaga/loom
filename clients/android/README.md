# Loom Android client — native host, v1 compatibility and v2 bootstrap

> **Protocol contract:** v1 compatibility uses a strict invitation, a single platform-key current,
> and same-origin reporting. V2 accepts only a certified head and Device view, and adds ControlSet
> checkpoints/QCs; four durable rollback-floor groups for recovery (including statement and policy
> hashes), ControlSet, head, and Device view; a compact QR descriptor, immutable bootstrap catalog,
> restricted bootstrap tunnel, three purpose-scoped public EndpointSets, a private
> `ControlServiceDirectoryV1`, overlapping Hysteria2/Trojan
> listener generations, and a bootstrap transition hash;
> WireGuard rotation remains disruptive until a dedicated dual-interface/peer profile is validated; and an irreversible
> v2 latch. V2 resources are versioned and never extend strict v1 JSON in place. See
> [the distributed control-plane design](../../docs/distributed-control-plane.md#19-从当前实现迁移).
> Code, deployment, and device-acceptance progress is recorded only in
> [the current status](../../docs/status/current.md).

In the target v2 flow, an already-enrolled administrator reaches **Create Device**
only through a `role=control_api` service in the private
`ControlServiceDirectoryV1`, verifies its overlay IP and internal service
certificate, and authenticates with an admin certificate. Before it has
a Device identity, Android downloads an immutable bootstrap bundle without a
token from one of the QR's two or three public distribution mirrors. It verifies
the separately hashed catalog and public proof bundle, measures the actual
bootstrap transports from the current Android network, and uses a short-lived
restricted tunnel to reach only the
`PrivateEnrollmentServiceRefV1` carried by the invitation. That bounded ref is
the projection of a private `role=enroll` directory entry, not a public
EndpointSet. Public Nginx serves only a fake website and
immutable distribution; it never receives or proxies an enrollment claim.

This directory defines the native Kotlin/Compose host and the pinned
sing-box/Loom mobile binding. The Stage 2 contract covers the access-only
enrollment path: QR or `.loom-invite` import, a non-exportable Android
Keystore identity, signed pull with a durable anti-rollback floor, candidate
activation/previous recovery, and signed health reporting. The Stage 3 contract covers the
signed mobile route plan, Direct / Auto / fixed-exit preference, authenticated
loopback selector changes, one deduplicated entry-probe round per underlying
network generation, verified server-observation reuse, threshold damping,
actual-selector readback, and plan-scoped offline evidence reuse.

For v2, Raft durable commit alone is never an activation or authorization signal.
A `committed_not_certified` head cannot update mutable current, change grants,
select an endpoint, or trigger external side effects; the app continues its
last-known-good profile. Before installing a candidate, it verifies the bootstrap
or recovery lineage (including `recovery_policy_hash`), the ControlSet transition,
the post-commit replication QC, the Device inclusion proof, and the signed
EndpointSet. It then atomically advances all four durable floor groups:

```text
recovery_epoch + recovery_statement_hash + recovery_policy_hash
control_epoch + control_set_hash
control_revision + head_hash
device_generation + device_leaf_hash + device_view_hash
```

The first v2 install atomically persists those floors, the
`bootstrap_transition_hash`, and `protocol_latch=v2`. After that latch, no v1
current, invitation, view, or recovery statement can regain authority. Endpoint
purposes are not inferred from an enrollment URL. Public
`DistributionEndpointSetV1`, `BootstrapIngressEndpointSetV1`, and
`DataIngressEndpointSetV2` are the only public endpoint sets. Private
`control_api`, `enroll`, `device_config`, and `device_report` are role-separated
services in `ControlServiceDirectoryV1`; they are never modeled as public
EndpointSets. Public HTTPS,
Hysteria2, and Trojan endpoints use their exact signed server identity;
private services use a purpose-specific internal certificate bound to the signed
overlay IP or pin.

The target v2 bootstrap transaction is:

```text
scan compact QR
  -> validate schema/cluster/invite/expiry, token/commitment,
     minimum_recovery_epoch/trusted_checkpoint_hash,
     bootstrap_catalog_hash,
     proof_bundle_hash, 2-3 mirrors, PrivateEnrollmentServiceRefV1 and
     BootstrapTunnelCapabilityV1
  -> fetch immutable catalog/public proof from the mirrors without token/cookie
  -> verify both hashes, authority/QC, intent commitment and BootstrapIngressEndpointSetV1
  -> from the current Android network, probe each actual HY2 bootstrap entry at most once
  -> use an independently signed Trojan/TLS TCP entry only when UDP is blocked
  -> present BootstrapTunnelCapabilityV1 and establish an ACL-restricted tunnel
  -> verify inner Enrollment server certificate/private IP
  -> run EnrollmentIntentPreflightRequestV1/ResponseV1 without token/CSR/key,
     obtain DeviceEnrollmentIntentOpeningV1 and verify its hiding commitment
  -> create the identity/CSR signing key and distinct credential-wrapping key
  -> build stable EnrollmentClaimCoreV2 and obtain EnrollmentPoPChallengeV1
  -> sign EnrollmentPoPBodyV2 with the identity key over the fresh server nonce
  -> send EnrollmentClaimSubmissionV2 (token + core + challenge + detached PoP)
     inside that TLS channel
  -> require the stable ControlSet's enrollment voters to form
     StableEnrollmentAdmissionQCV1 before the Raft reservation CAS
  -> accept only the Raft-CAS/QC-bound ready result for the same key and request
  -> atomically install the permanent certificate/view/credentials
  -> destroy token, capability, temporary profile, tunnel, and retry state
  -> establish the permanent WireGuard control/L3 overlay in the same libbox/VpnService host
```

HY2 is the first implementation slice. A daily-use release also implements a
separate Trojan/TLS TCP fallback for networks that block UDP. WireGuard is not a
first-enrollment bootstrap transport and does not start a second Android VPN or
a separate Tailscale/Headscale client. The same libbox/`VpnService` host owns its
permanent overlay routes. Bootstrap HY2/TCP sockets must be protected
with `VpnService.protect()` before the temporary TUN becomes active. Mirror HTTPS
latency may order downloads but never substitutes for measuring the actual tunnel
transport.

The capability is derived from a certified Invite and signed by a dedicated
ControlSet-authorized bootstrap issuer. Its ACL allows only the certified private
Enrollment `/32` or `/128` and TLS TCP port—never general overlay routes, Internet
egress, DNS, ICMP, control API, Raft, SSH, configuration, or reporting. The
default capability lifetime is 15 minutes (configurable from 5 through 30 minutes,
with a hard 30-minute limit); one tunnel lasts at most 180 seconds and 8 MiB, with
at most three sequential connection attempts and one concurrent session per
`cap_id` at an ingress. The enrollment token remains the authoritative one-shot
boundary through Raft CAS.

The public proof bundle contains only `DeviceEnrollmentIntentCommitmentV1` and
its authority path; it never exposes the exact intent or opening. Only after the
restricted tunnel and inner TLS are verified does preflight without token/CSR/key return
`DeviceEnrollmentIntentOpeningV1`. Android recomputes the commitment and checks
the exact platform, responsibilities and grants before building a claim. An
offline `.loom-invite` may embed the same catalog/public proof, but never this
private opening.

The inner TLS authenticates the Enrollment server before any secret leaves the
app. Android signs proof-of-possession with the non-exportable identity/CSR
Keystore key over the stable `claim_core_hash`, network, invite and request IDs,
CSR/identity/wrapping-key hashes, and server nonce. The distinct wrapping key
only unwraps device credentials; it never signs Enrollment PoP. Exact retries
reuse the token and byte-identical `EnrollmentClaimCoreV2`. A fresh
`EnrollmentPoPChallengeV1` may change the server nonce and detached signature,
but not the stable core/hash; changing the key or core is rejected. No temporary
client private key is placed in the QR merely to make the first connection look
like mTLS.

The identity/CSR signing key is a non-exportable Keystore P-256 signing key. The
wrapping profile is separate: API 31+ uses a non-exportable P-256 ECDH key with
`AGREE_KEY`, while API 26–30 uses only the intent-authorized RSA-2048 OAEP
fallback with `DECRYPT`. Neither wrapping profile receives signing authority.

Automatic retries stop when either the Invite or capability expires. If the
claim is already committed, an administrator first performs a linearizable read
through the private `role=control_api` service. For a reserved or completed
transaction it may generate a one-time `EnrollmentResumeDescriptorV1`, containing
no token and carrying the exact resume capability, claim-core/transaction
binding, and catalog/proof/service/mirror refs. It is delivered out of band as a
QR or `.loom-resume`, never generated by a public mirror and never automatically
refreshed by Android. The app accepts it only when it matches its protected
pending identity and stable core, then signs a fresh server nonce with that same
identity key. The ControlSet continues or returns the existing idempotent result
without resetting or consuming the token again or extending the old capability.

Android TUN address queries use a persistent, dual-stack FakeIP mapping. The
subsequent connection is restored to an FQDN before routing, carried unchanged
through the selected proxy chain, and resolved by the final egress with that
node's DNS configuration. The FakeIP rule matches only DNS originating from
`tun-in`; libbox bootstrap resolution for a named public entry remains on the
first real DNS server, with an independent cache, so tunnel startup cannot
resolve its own entry to a FakeIP. If libbox supplies a TUN address family but
no explicit route for that family, the Android host adds its default route;
this prevents IPv6 FakeIP traffic from bypassing the VPN or becoming
unreachable.

The three route modes are enabled only after an activatable configuration carries
a mobile route plan: a certified Device view for v2, or an explicitly verified
v1 snapshot before the protocol latch. Direct requires a direct candidate for every selector;
fixed-exit choices are the exact intersection authorized by the signed plan.
If a fixed exit is removed, the client blocks instead of silently falling back.
Auto never probes a complete candidate or business path. Direct does not freeze a
candidate snapshot or spend probe budget. On the first transition into Auto or fixed-exit
mode in each underlying-network generation, the client atomically freezes the then-current
candidate snapshot and sends at most one lightweight probe per authorized entry deduplicated
by address and source interface in that snapshot,
in parallel, then reuses fresh canonical v5 server observations returned by the
existing health-report cycle. Configuration refreshes, mode or exit changes, and
reconnects within the same generation do not probe again. Entries introduced later
in that generation receive no active probe; real dial/fallback attempts may only
produce passive evidence. Missing, expired, out-of-scope or invalid evidence stays
unknown, and neither the one-shot entry round nor server evidence gates data-plane
startup. A lower failure rate
can switch immediately; at equal failure rate, removing a relay without adding
estimated latency is not blocked by the improvement threshold. Same-hop
replacements and added relays still require the configured improvement.

The signed configuration pins the Android TUN MTU to 1500 instead of inheriting
sing-box's 9000-byte default. Before the v2 latch, a server whose verified v1
snapshot enables `public_data_ingress` may contribute a single-hop client candidate
using its configured data-ingress transport (Hysteria2 or Trojan), even when its
WireGuard direction remains `reverse_only`. After the latch, that Boolean has no
authority by itself: a certified `PublicEndpointIntent` and this Device's
`DataIngressEndpointSetV2` must authorize the candidate. Such an endpoint is
never promoted into an intermediate relay. This keeps the reverse tunnel policy
while avoiding unnecessary same-transport nesting for an authorized fixed exit.

The Current Paths card is a read-only projection of libbox selector readback.
It shows the entry ping, each matching WireGuard or public data-ingress server hop
with its actual protocol, and each exact target observation separately. Hysteria2-
specific variation/rate evidence is shown only when that signed metric exists;
Trojan is not assigned synthetic Hy2 telemetry. The card does not infer measurements
from candidate names or present segmented evidence as end-to-end P50/P95,
business throughput, or whole-path health.

The primary Connect action stays disabled until a verified managed snapshot is
available. Debug builds expose the bundled stage-1 Direct fixture in a separate
`Debug Direct TUN` diagnostic card; that action proves only local libbox, TUN,
route and selector plumbing and must never be presented as enrollment, trusted
reporting or business-path health.
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
# inspect LoomVpnService local lifecycle and selector state, then always disconnect
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

The required connection-health contract combines local `VpnService`/libbox/TUN
state, the one-shot entry result, verified server observations, and passive
feedback from actual connections and handshakes. Production self-checks must not
send business DNS/HTTPS requests or probe complete paths; reachability outside
the available evidence remains unknown. Remaining implementation gaps are
tracked only in `docs/status/current.md`; this paragraph is not a completion claim.

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

Every public distribution mirror and Trojan/TLS bootstrap fallback must serve a
complete TLS chain which terminates at a root in the supported Android system
stores. Verify this on physical devices, not only with a builder's OpenSSL bundle.
The private Enrollment service instead presents the catalog-authorized internal
certificate for its overlay IP (or the exact authorized SPKI); it is never
validated by disabling certificate or hostname/IP checks. The app does not
weaken either public or private verification to compensate for a deployment
chain error.

## Enrollment and activation transaction

In the v1 compatibility transaction, the client compares the QR fingerprint with the embedded key before the first
POST, persists the exact CSR/request identity and retries only within the
bounded enrollment recovery window. A ready response must bind the returned
certificate to the same Keystore P-256 key.

That direct public HTTPS POST is retained only by the strict v1 reader. It is not
the v2 target and must not be retrofitted with v2 fields. V2 follows the compact
QR, static distribution, measured HY2/TCP bootstrap, private inner TLS, token +
identity-key Keystore PoP and Raft CAS flow above. Once ready is atomically installed, all
temporary bootstrap material is deleted before the permanent overlay and private
configuration/report channels become active.

V1 signed `current.json`, snapshot manifest/signature and the exact node bundle
are retained in Keystore-encrypted app storage. They are all reverified on
restart against the platform key embedded in the currently running APK; a
cached bootstrap cannot keep an older APK trust root alive after an upgrade.
A verified Android manifest must declare exactly the sing-box version embedded
in `Libbox.version()` and no server-only runtime component.
A new pull first advances the authenticated generation floor, then
enters a candidate slot. Its CA uses an immutable content-addressed path, so
preflight cannot replace the active profile's trust file. `VpnService` must
promote the candidate after static validation, bundle hydration, libbox
configuration preflight, and successful local TUN/route/selector startup. It
must not wait for an entry probe or server observation or send a business
DNS/HTTPS request as an activation gate. Only a local startup-transaction failure
may restore the last verified profile; runtime connection/handshake failures
remain scoped evidence and do not roll back a verified configuration. The current
implementation gaps are listed in `docs/status/current.md`. Reports use the same
Keystore key through the existing canonical v5 and self-check v1 contracts;
the canonical v5 claim also binds the actual selector, candidate and chain.
Before the v2 latch, the same-origin v1 report POST requests `observations=1`:
a compatible server may return a bounded JSON snapshot with HTTP 200, while an
empty 204 remains a successful report with no new route evidence. After the
latch, configuration and reporting use the role-separated `device_config` and
`device_report` services from private `ControlServiceDirectoryV1`, with Device
mTLS. Neither service can be derived from a distribution, bootstrap, or
enrollment URL.

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
non-exportable Keystore P-256 key, local TUN/route/selector lifecycle without a
business DNS/HTTPS probe, an idempotent disconnect, a second connect, and the
approved logo plus visible Stage 3 route entrances. It refuses to run unless
`ANDROID_SERIAL` names a device that
reports `ro.kernel.qemu=1`, so an attached phone can never become the implicit
test target. When the Linux builder needs an HTTPS proxy,
the script uses a temporary emulator-only relay that is removed on exit.

The Android host deliberately fetches public distribution data over HTTPS only,
even though the cross-platform signed-artifact format can describe an HTTP
mirror. HTTP entries are skipped and are never a downgrade fallback; at least
one verified HTTPS distribution mirror must therefore be available. Private
control, Enrollment, configuration and reporting use their purpose-specific
TLS service over the temporary or permanent Loom overlay, not public Nginx.

Enrollment acceptance requires a control-created Android Device and, for the
v1 compatibility flow, an APK built with that deployment's public key. On vendor Android builds, keep the
screen unlocked. ADB authorization alone may not authorize package
installation; the constrained helper above can approve Loom's separate vendor
confirmation when explicitly enabled.

Target-v2 acceptance additionally proves all of the following on both emulator
and a physical device where applicable:

- the QR stays within its size limit and contains exactly the compact descriptor:
  token/commitment, trust checkpoint, catalog/proof hashes, 2–3 mirrors, the
  bounded private Enrollment ref and capability;
- every distribution request is token-free and a mirror cannot observe a claim;
- catalog/proof hash or QC, redirect, rollback, expiry, and endpoint substitution
  failures stop before capability or token disclosure; the public proof exposes
  only the intent hiding commitment, never its opening;
- actual HY2 bootstrap entries are probed once from the current Android network,
  and the independent Trojan/TLS fallback is used only when UDP is unavailable;
- capability expiry, connection-count, concurrency, byte/time limits and route
  ACL are enforced, including denial of Internet and non-Enrollment overlay access;
- inner Enrollment certificate/IP verification and token-free intent preflight
  precede token/CSR/PoP; the opening must reproduce the public hiding commitment;
- exact stable claim-core retries are idempotent while detached identity-key PoP
  may be resigned for a fresh server nonce; changed key/core replays fail;
- a token-free `EnrollmentResumeDescriptorV1` is issued only after a private
  linearizable transaction read, delivered out of band, matches the protected
  pending core/identity, cannot auto-refresh, and does not consume the token again;
- ready installs the certificate/view/credentials atomically, deletes every
  temporary artifact, establishes the permanent WG overlay inside the same
  libbox/VpnService, and reaches private configuration/report services with Device mTLS;
- process death, Wi-Fi/mobile transitions and device reboot cannot resurrect an
  expired capability, duplicate token consumption, or a partially installed identity.

No fixture or source file contains an invitation token, device private key,
production endpoint or private signing key. Third-party versions, source and
licenses are recorded in `third_party/NOTICE.md` and `third_party/sing-box/`.
