package io.github.scisaga.loom.enrollment

import io.github.scisaga.loom.profiles.ProfileContext
import io.github.scisaga.loom.profiles.ProfileCatalog
import android.content.Context
import android.content.Intent
import androidx.core.content.ContextCompat
import io.github.scisaga.loom.security.DeviceKeyStore
import io.github.scisaga.loom.security.TrustAnchor
import io.github.scisaga.loom.route.RouteManager
import io.github.scisaga.loom.vpn.ConnectionPhase
import io.github.scisaga.loom.vpn.BootstrapServiceRegistry
import io.github.scisaga.loom.vpn.LoomVpnService
import io.github.scisaga.loom.vpn.VpnConnectionPreference
import io.github.scisaga.loom.vpn.VpnRuntime
import io.github.scisaga.loomcore.Loomcore
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.cancel
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeout
import org.json.JSONArray
import org.json.JSONObject
import java.io.EOFException
import java.io.IOException
import java.net.ConnectException
import java.net.NoRouteToHostException
import java.net.ProtocolException
import java.net.SocketException
import java.net.SocketTimeoutException
import java.time.Instant
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.SSLException

enum class EnrollmentPhase { CHECKING, NOT_JOINED, CLAIMING, WAITING, PULLING, READY, TERMINAL, ERROR }

internal class V2TerminalDeviceException(val lifecycleState: String) : IllegalStateException(
    "[Android runtime] Device 已 $lifecycleState；durable v2 latch 禁止恢复旧配置或 Debug Direct",
)

internal class DeviceMigrationRequiredException : IllegalStateException(
    "此连接需要完成认证迁移后才能使用；原 Device 身份与数据已保留",
)

/** 正式连接只消费 v2；旧记录只用于认证迁移，不能重新启动旧协议。 */
internal fun <T> selectLatchedRuntime(
    lifecycleState: String?,
    v2Runtime: T?,
    hasLegacyIdentity: Boolean,
): T? = when (lifecycleState) {
    null -> {
        check(v2Runtime == null) { "[Android runtime] 未 latch v2 Device 却存在 v2 runtime" }
        if (hasLegacyIdentity) throw DeviceMigrationRequiredException()
        null
    }
    "active" -> checkNotNull(v2Runtime) { "[Android runtime] active v2 Device 缺可启动 runtime" }
    "revoked", "decommissioned" -> throw V2TerminalDeviceException(lifecycleState)
    else -> error("[Android runtime] v2 Device lifecycle 无效：$lifecycleState")
}

data class EnrollmentStatus(
    val phase: EnrollmentPhase = EnrollmentPhase.CHECKING,
    val detail: String = "正在读取设备身份…",
    val nodeID: String = "",
    val snapshot: String = "",
    val generation: Long = 0,
    val protocol: Int = 0,
    val canAbandonPending: Boolean = false,
    val canImportResume: Boolean = false,
    val diagnostic: String = "",
)

class EnrollmentManager private constructor(context: Context) {
    private val appContext = context.applicationContext
    private val store = ManagedProfileStore(appContext)
    private val v2StateStore = V2DeviceStateStore(appContext)
    private val keys = DeviceKeyStore(ProfileContext.keySuffix(context))
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val transaction = Mutex()
    private val started = AtomicBoolean(false)
    private var activeJob: Job? = null
    private val mutableStatus = MutableStateFlow(EnrollmentStatus())
    val status = mutableStatus.asStateFlow()

    private suspend fun dispose() {
        scope.cancel()
        activeJob?.cancelAndJoin()
        transaction.withLock { }
    }

    fun initialize() {
        if (!started.compareAndSet(false, true)) return
        activeJob = scope.launch { resumeInternal() }
    }

    fun importInvite(raw: String) {
        activeJob?.cancel()
        activeJob = scope.launch {
            transaction.withLock {
                guarded("加入失败") { beginJoin(raw) }
            }
        }
    }

    fun importInviteFile(raw: ByteArray) {
        activeJob?.cancel()
        activeJob = scope.launch {
            transaction.withLock {
                guarded("加入失败") { beginJoinFile(raw) }
            }
        }
    }

    fun reportImportError(error: Throwable) = fail("读取加入文件失败", error)

    fun retry() {
        activeJob?.cancel()
        activeJob = scope.launch {
            transaction.withLock {
                guarded("重试失败") { resumeUnlocked() }
            }
        }
    }

    fun refreshConfiguration() {
        activeJob?.cancel()
        activeJob = scope.launch {
            transaction.withLock {
                guarded("配置更新失败") {
                    v2StateStore.installed()?.let { installed ->
                        val profile = installed.runtimeProfile
                        if (profile == null) {
                            terminal(installed)
                            return@guarded
                        }
                        if (isActiveProfile() && VpnRuntime.status.value.phase == ConnectionPhase.CONNECTED) {
                            ContextCompat.startForegroundService(
                                appContext,
                                Intent(appContext, LoomVpnService::class.java)
                                    .setAction(LoomVpnService.ACTION_REFRESH_V2)
                                    .putExtra(LoomVpnService.EXTRA_PROFILE_ID, ProfileContext.id(appContext)),
                            )
                            ready(profile, "已请求经 private device_config 刷新；失败时继续沿用 certified LKG")
                        } else {
                            ready(profile, "v2 Device 已使用当前 certified LKG；连接后才能访问 private device_config")
                        }
                        return@guarded
                    }
                    if (store.hasLegacyIdentity()) throw DeviceMigrationRequiredException()
                    error("设备尚未完成加入")
                }
            }
        }
    }

    fun abandonPending() {
        activeJob?.cancel()
        activeJob = scope.launch {
            transaction.withLock {
                guarded("无法放弃待加入事务") {
                    check(
                        !store.hasLegacyIdentity() && v2StateStore.current() == null,
                    ) { "设备已经加入；不会删除正式身份" }
                    store.clearPending()
                    mutableStatus.value = EnrollmentStatus(
                        EnrollmentPhase.NOT_JOINED,
                        "已放弃本机待加入事务；中控 Device 状态不会因此撤销",
                    )
                }
            }
        }
    }

    fun currentProfile(): ManagedProfile? {
        val installed = v2StateStore.installed()
        return try {
            selectLatchedRuntime(
                installed?.lifecycleState,
                installed?.runtimeProfile,
                installed == null && store.hasLegacyIdentity(),
            )
        } catch (error: V2TerminalDeviceException) {
            terminal(checkNotNull(installed))
            throw error
        }
    }

    private suspend fun resumeInternal() = transaction.withLock {
        guarded("恢复加入状态失败") { resumeUnlocked(continuePending = false) }
    }

    private suspend fun resumeUnlocked(continuePending: Boolean = true) {
        v2StateStore.installed()?.let { installed ->
            store.pending()?.let { pendingBytes ->
                val pending = V2PendingEnrollment.decode(pendingBytes)
                Loomcore.validateAndroidV2InstalledPending(
                    installed.encoded,
                    checkNotNull(pending.claimCore) { "durable v2 installation 对应的 pending 缺 stable core" },
                    checkNotNull(pending.claimResult) { "durable v2 installation 对应的 pending 缺 completed result" },
                )
                store.clearPending()
            }
            val profile = installed.runtimeProfile
            if (profile == null) {
                terminal(installed)
                return
            }
            ready(profile, "已重放 v2 Device LKG 并加载正式 WG/Data runtime")
            return
        }
        if (store.hasLegacyIdentity()) throw DeviceMigrationRequiredException()
        store.pending()?.let { pendingBytes ->
            val pending = V2PendingEnrollment.decode(pendingBytes)
            // 查看配置只恢复本地状态，不启动注册隧道或接管当前连接。
            if (!continuePending) {
                mutableStatus.value = EnrollmentStatus(
                    phase = EnrollmentPhase.WAITING,
                    detail = "已有待完成的加入事务；点继续以复用原身份和恢复信息",
                    canAbandonPending = true,
                    canImportResume = pending.progressStatus != null,
                )
            } else if (pending.resumeDescriptor != null) {
                resumeV2UntilResult(pending)
            } else if (pending.progressStatus != null) {
                awaitExplicitV2Resume()
            } else {
                claimV2UntilResult(pending)
            }
            return
        }
        mutableStatus.value = EnrollmentStatus(EnrollmentPhase.NOT_JOINED, "扫描中控二维码或导入加入文件")
    }

    private suspend fun beginJoin(raw: String) {
        when {
            raw.startsWith(V2_RESUME_URI_PREFIX) -> {
                beginV2Resume(Loomcore.decodeAndroidV2ResumeURI(raw))
                return
            }

            raw.startsWith(V2_INVITE_URI_PREFIX) -> {
                beginV2Join(Loomcore.decodeAndroidV2InviteURI(raw))
                return
            }
        }
        error("加入码格式无效；请使用中控当前生成的 v2 加入码")
    }

    private suspend fun beginJoinFile(raw: ByteArray) {
        val carrier = runCatching { JSONObject(raw.decodeToString()) }.getOrNull()
        when {
            carrier?.has("resume_tunnel_capability") == true -> {
                beginV2Resume(Loomcore.decodeAndroidV2ResumeFile(raw))
            }

            carrier?.optInt("schema") == 2 -> beginV2Join(Loomcore.decodeAndroidV2InviteFile(raw))
            else -> error("加入文件格式无效；请使用中控当前生成的 v2 加入文件")
        }
    }

    private suspend fun beginV2Join(canonicalDescriptor: ByteArray) {
        check(!store.hasLegacyIdentity() && v2StateStore.current() == null) {
            "设备已经加入；不会覆盖现有身份"
        }
        store.pending()?.let { existing ->
            val pending = V2PendingEnrollment.decode(existing)
            check(pending.descriptor.contentEquals(canonicalDescriptor)) {
                "已有另一笔未完成 v2 加入；不会覆盖一次性凭据"
            }
            if (pending.progressStatus != null) {
                awaitExplicitV2Resume()
            } else {
                claimV2UntilResult(pending)
            }
            return
        }
        val trustedTime = Instant.now().toString()
        mutableStatus.value = EnrollmentStatus(EnrollmentPhase.CLAIMING, "正在下载并验证公开 bootstrap 证明…")
        val artifacts = V2MirrorFetcher(appContext).fetch(canonicalDescriptor, trustedTime)
        val pending = V2PendingEnrollment(
            descriptor = canonicalDescriptor,
            proofBundle = artifacts.proofBundle,
            bootstrapCatalog = artifacts.bootstrapCatalog,
        )
        store.putV2Pending(pending)
        claimV2UntilResult(pending)
    }

    private suspend fun beginV2Resume(canonicalDescriptor: ByteArray) {
        check(!store.hasLegacyIdentity() && v2StateStore.current() == null) {
            "设备已经加入；resume 不会覆盖现有正式身份"
        }
        val pendingBytes = checkNotNull(store.pending()) {
            "本机没有可由 resume 恢复的 pending transaction"
        }
        check(JSONObject(pendingBytes.decodeToString()).optInt("schema") == 2) {
            "resume 不能恢复 v1 pending transaction"
        }
        var pending = V2PendingEnrollment.decode(pendingBytes)
        check(pending.claimCore != null && pending.progressStatus != null && pending.resumeExpected != null) {
            "本机 pending 尚未取得 certified reservation；不能使用 resume"
        }
        val trustedTime = Instant.now().toString()
        mutableStatus.value = EnrollmentStatus(
            EnrollmentPhase.CLAIMING,
            "正在下载并验证带外 resume authority…",
        )
        val artifacts = V2MirrorFetcher(appContext).fetchResume(
            canonicalDescriptor,
            TrustAnchor.platformPublicKey(),
            trustedTime,
        )
        pending = pending.withResume(
            canonicalDescriptor,
            artifacts.proofBundle,
            artifacts.bootstrapCatalog,
            trustedTime,
        )
        store.putV2Resume(pending)
        resumeV2UntilResult(pending)
    }

    private suspend fun claimV2UntilResult(initial: V2PendingEnrollment) {
        check(initial.progressStatus == null && initial.resumeDescriptor == null) {
            "已预约的 v2 transaction 只能用显式 exact-bound resume capability 恢复"
        }
        var pending = initial
        ContextCompat.startForegroundService(
            appContext,
            Intent(appContext, LoomVpnService::class.java).setAction(LoomVpnService.ACTION_ENROLLMENT_KEEPALIVE),
        )
        val service = withTimeout(BOOTSTRAP_SERVICE_TIMEOUT_MS) { BootstrapServiceRegistry.await() }
        val network = service.prepareBootstrapNetwork(store::recordV2ConnectionAttempt)
        val trustedTime = Instant.now().toString()
        val session = try {
            Loomcore.newAndroidV2BootstrapSession(
                pending.descriptor,
                pending.proofBundle,
                pending.bootstrapCatalog,
                trustedTime,
                pending.connectionAttempts,
                network,
            )
        } catch (error: Throwable) {
            service.finishBootstrapNetwork()
            throw error
        }
        try {
            val underlayIdentity = network.underlayIdentity()
            val selection = if (
                pending.selectedUnderlay == underlayIdentity && pending.selectedTransport != null
            ) {
                mutableStatus.value = EnrollmentStatus(EnrollmentPhase.CLAIMING, "正在恢复当前网络已验证的注册入口…")
                session.restoreProbe(pending.selectedTransport, Instant.now().toString())
            } else {
                mutableStatus.value = EnrollmentStatus(EnrollmentPhase.CLAIMING, "正在验证当前网络的 HY2/Trojan 注册入口…")
                session.probe(Instant.now().toString())
            }
            pending = pending.withSelection(underlayIdentity, selection)
            store.putV2Pending(pending)

            val crypto = V2EnrollmentCrypto(keys)
            val preflightRequest = crypto.preparePreflight(
                pending.descriptor,
                pending.proofBundle,
                Instant.now().toString(),
            )
            mutableStatus.value = EnrollmentStatus(EnrollmentPhase.CLAIMING, "正在私有隧道内核对设备授权…")
            val preflight = session.preflight(preflightRequest, Instant.now().toString())
            crypto.verifyPreflightBeforeKeys(
                pending.descriptor,
                pending.proofBundle,
                preflight,
                Instant.now().toString(),
            )
            pending = pending
                .withConnectionAttempts(session.connectionAttempts())
                .withPreflight(preflight)
            store.putV2Pending(pending)

            // request ID/nonce 先于 Keystore/CSR 生成落盘；server 一旦见到 core，
            // 后续所有重试都复用这里的 exact bytes。
            pending = pending.withStableCoordinates()
            store.putV2Pending(pending)
            val core = pending.claimCore ?: crypto.prepareStableClaimCore(
                pending.descriptor,
                pending.proofBundle,
                checkNotNull(pending.preflightResponse),
                checkNotNull(pending.requestID),
                checkNotNull(pending.clientNonce),
                Instant.now().toString(),
            )
            pending = pending.withClaimCore(core)
            store.putV2Pending(pending)

            val challenge = session.challenge(core, Instant.now().toString())
            pending = pending.withConnectionAttempts(session.connectionAttempts())
            store.putV2Pending(pending)
            val submission = crypto.assembleClaimSubmission(
                pending.descriptor,
                pending.proofBundle,
                checkNotNull(pending.preflightResponse),
                core,
                challenge,
                Instant.now().toString(),
            )
            mutableStatus.value = EnrollmentStatus(EnrollmentPhase.CLAIMING, "正在提交一次性 token 与 Keystore PoP…")
            val result = session.submitClaim(submission, Instant.now().toString())
            val verifiedResult = crypto.verifyClaimResult(
                pending.descriptor,
                pending.proofBundle,
                checkNotNull(pending.preflightResponse),
                core,
                result,
                Instant.now().toString(),
            )
            pending = pending
                .withConnectionAttempts(session.connectionAttempts())
                .withVerifiedClaimResult(result, verifiedResult)
            store.putV2Pending(pending)
            val status = JSONObject(verifiedResult.decodeToString()).getString("status")
            if (status == "completed") {
                mutableStatus.value = EnrollmentStatus(
                    EnrollmentPhase.PULLING,
                    "正在按完成回执取回 exact 配置与密封凭据…",
                )
                val installedConfigs = V2MirrorFetcher(appContext).fetchCompletionConfigs(
                    session.completionConfigFetchPlan(),
                )
                val released = session.fetchReleasedArtifacts(Instant.now().toString())
                val profile = installV2Completion(
                    pending, result, verifiedResult, released, installedConfigs, crypto,
                )
                ready(profile, "v2 正式身份、Device view、配置与凭据已原子安装")
                return
            }
            mutableStatus.value = EnrollmentStatus(
                EnrollmentPhase.WAITING,
                "v2 claim 已耐久预约；继续前需导入管理员显式签发的 exact-bound resume",
                canAbandonPending = true,
                canImportResume = true,
            )
        } finally {
            session.close()
            service.finishBootstrapNetwork()
        }
    }

    private fun awaitExplicitV2Resume() {
        mutableStatus.value = EnrollmentStatus(
            EnrollmentPhase.WAITING,
            "本机已保存 certified reservation；请扫码或导入管理员显式签发的 .loom-resume",
            canAbandonPending = true,
            canImportResume = true,
        )
    }

    private suspend fun resumeV2UntilResult(initial: V2PendingEnrollment) {
        var pending = initial
        val descriptor = checkNotNull(pending.resumeDescriptor) { "v2 resume descriptor 缺失" }
        val proof = checkNotNull(pending.resumeProofBundle) { "v2 resume proof 缺失" }
        val catalog = checkNotNull(pending.resumeBootstrapCatalog) { "v2 resume catalog 缺失" }
        val core = checkNotNull(pending.claimCore) { "v2 resume stable core 缺失" }
        val progressStatus = checkNotNull(pending.progressStatus) { "v2 resume progress status 缺失" }
        val expected = checkNotNull(pending.resumeExpected) { "v2 resume expected transaction 缺失" }
        ContextCompat.startForegroundService(
            appContext,
            Intent(appContext, LoomVpnService::class.java).setAction(LoomVpnService.ACTION_ENROLLMENT_KEEPALIVE),
        )
        val service = withTimeout(BOOTSTRAP_SERVICE_TIMEOUT_MS) { BootstrapServiceRegistry.await() }
        val network = service.prepareBootstrapNetwork(store::recordV2ConnectionAttempt)
        val session = try {
            Loomcore.newAndroidV2ResumeSession(
                descriptor,
                proof,
                catalog,
                core,
                expected,
                TrustAnchor.platformPublicKey(),
                progressStatus,
                Instant.now().toString(),
                pending.resumeConnectionAttempts,
                network,
            )
        } catch (error: Throwable) {
            service.finishBootstrapNetwork()
            throw error
        }
        try {
            val underlayIdentity = network.underlayIdentity()
            val selection = if (
                pending.resumeSelectedUnderlay == underlayIdentity &&
                pending.resumeSelectedTransport != null
            ) {
                mutableStatus.value = EnrollmentStatus(
                    EnrollmentPhase.CLAIMING,
                    "正在恢复当前网络已验证的 resume 入口…",
                )
                session.restoreProbe(pending.resumeSelectedTransport, Instant.now().toString())
            } else {
                mutableStatus.value = EnrollmentStatus(
                    EnrollmentPhase.CLAIMING,
                    "正在验证当前网络的 HY2/Trojan resume 入口…",
                )
                session.probe(Instant.now().toString())
            }
            pending = pending.withResumeSelection(underlayIdentity, selection)
            store.putV2Pending(pending)

            val crypto = V2EnrollmentCrypto(keys)
            val preflightMessage = session.resumePreflightAuthorizationMessage(Instant.now().toString())
            val preflightRequest = session.resumePreflightRequest(
                crypto.signPreflightMessage(preflightMessage),
                Instant.now().toString(),
            )
            mutableStatus.value = EnrollmentStatus(
                EnrollmentPhase.CLAIMING,
                "正在私有隧道内恢复 exact committed opening…",
            )
            session.preflight(preflightRequest, Instant.now().toString())
            pending = pending.withResumeConnectionAttempts(session.connectionAttempts())
            store.putV2Pending(pending)

            session.challenge(core, Instant.now().toString())
            pending = pending.withResumeConnectionAttempts(session.connectionAttempts())
            store.putV2Pending(pending)
            val pop = session.prepareResumePoPBody(Instant.now().toString())
            val submission = session.assembleResumeSubmission(
                pop,
                crypto.signPoP(pop),
                Instant.now().toString(),
            )
            mutableStatus.value = EnrollmentStatus(
                EnrollmentPhase.CLAIMING,
                "正在以 Keystore 新鲜 PoP 恢复原注册事务…",
            )
            val verifiedResult = session.submitResume(submission, Instant.now().toString())
            val verified = JSONObject(verifiedResult.decodeToString())
            val result = Loomcore.canonicalizeV2(
                verified.getJSONObject("exact_result").toString().encodeToByteArray(),
            )
            pending = pending
                .withResumeConnectionAttempts(session.connectionAttempts())
                .withVerifiedClaimResult(result, verifiedResult)
            store.putV2Pending(pending)
            if (verified.getString("status") == "completed") {
                mutableStatus.value = EnrollmentStatus(
                    EnrollmentPhase.PULLING,
                    "resume 已完成；正在取回 exact 配置与密封凭据…",
                )
                val installedConfigs = V2MirrorFetcher(appContext).fetchCompletionConfigs(
                    session.completionConfigFetchPlan(),
                )
                val released = session.fetchReleasedArtifacts(Instant.now().toString())
                val installed = prepareV2InstalledCredentials(verifiedResult, released, crypto)
                val state = session.prepareResumeInstallationStateWithConfigs(installed, installedConfigs)
                v2StateStore.installCompletion(state, store::clearPending)
                val profile = checkNotNull(v2StateStore.runtimeProfile()) { "v2 resume 安装后缺 runtime" }
                ready(profile, "v2 正式身份、配置与凭据已由 exact-bound resume 原子安装")
                return
            }
            mutableStatus.value = EnrollmentStatus(
                EnrollmentPhase.WAITING,
                "resume 已验证事务继续等待 quorum；不会自动取得新 capability",
                canAbandonPending = true,
                canImportResume = true,
            )
        } finally {
            session.close()
            service.finishBootstrapNetwork()
        }
    }

    private fun installV2Completion(
        pending: V2PendingEnrollment,
        result: ByteArray,
        verifiedResult: ByteArray,
        releasedArtifacts: ByteArray,
        installedConfigs: ByteArray,
        crypto: V2EnrollmentCrypto,
    ): ManagedProfile {
        val installedCanonical = prepareV2InstalledCredentials(verifiedResult, releasedArtifacts, crypto)
        val state = Loomcore.prepareAndroidV2EnrollmentInstallationStateWithConfigs(
            pending.descriptor,
            pending.proofBundle,
            checkNotNull(pending.preflightResponse),
            checkNotNull(pending.claimCore),
            result,
            installedCanonical,
            installedConfigs,
            Instant.now().toString(),
        )
        v2StateStore.installCompletion(state, store::clearPending)
        return checkNotNull(v2StateStore.runtimeProfile()) { "v2 completion 安装后缺 runtime" }
    }

    private fun prepareV2InstalledCredentials(
        verifiedResult: ByteArray,
        releasedArtifacts: ByteArray,
        crypto: V2EnrollmentCrypto,
    ): ByteArray {
        val verified = JSONObject(verifiedResult.decodeToString())
        check(verified.getInt("schema") == 1 && verified.getString("status") == "completed") {
            "v2 completion projection 无效"
        }
        val artifact = verified.getJSONObject("result_artifact")
        val refs = artifact.getJSONArray("secret_artifact_refs")
        val released = JSONObject(releasedArtifacts.decodeToString())
        check(released.getInt("schema") == 1) { "released artifact bundle schema 无效" }
        val envelopes = released.getJSONArray("envelopes")
        check(refs.length() == envelopes.length()) { "released artifacts 未 exact 覆盖 result refs" }
        val recipientID = artifact.getJSONObject("initial_device_view").getString("device_id")
        val installed = JSONArray()
        for (index in 0 until refs.length()) {
            val ref = Loomcore.canonicalizeV2(refs.getJSONObject(index).toString().encodeToByteArray())
            val envelope = Loomcore.canonicalizeV2(
                envelopes.getJSONObject(index).toString().encodeToByteArray(),
            )
            val credential = crypto.unsealInstalledSecret(ref, envelope, recipientID)
            installed.put(JSONObject(credential.decodeToString()))
        }
        return Loomcore.canonicalizeV2(installed.toString().encodeToByteArray())
    }

    private fun isActiveProfile(): Boolean = VpnRuntime.status.value.profileId == ProfileContext.id(appContext)

    private fun ready(profile: ManagedProfile, detail: String) {
        RouteManager.get(appContext).profileAvailable(profile)
        mutableStatus.value = EnrollmentStatus(
            phase = EnrollmentPhase.READY,
            detail = detail,
            nodeID = profile.nodeID,
            snapshot = profile.snapshot,
            generation = profile.generation,
            protocol = profile.protocol,
        )
    }

    private fun terminal(installed: V2InstalledDeviceState) {
        // 清理失败不能遮蔽供 VpnService fail-closed 的终止态信号。
        if (isActiveProfile()) runCatching { VpnConnectionPreference(appContext).setDesiredConnected(false) }
        val label = when (installed.lifecycleState) {
            "revoked" -> "已撤权"
            "decommissioned" -> "已退役"
            else -> error("v2 Device 终止态无效：${installed.lifecycleState}")
        }
        mutableStatus.value = EnrollmentStatus(
            phase = EnrollmentPhase.TERMINAL,
            detail = "Device $label；已禁止数据连接、旧配置恢复与 Debug Direct",
            nodeID = installed.nodeID,
            generation = installed.generation,
            protocol = 2,
        )
        if (isActiveProfile()) runCatching {
            ContextCompat.startForegroundService(
                appContext,
                Intent(appContext, LoomVpnService::class.java).setAction(LoomVpnService.ACTION_V2_TERMINAL)
                    .putExtra(LoomVpnService.EXTRA_PROFILE_ID, ProfileContext.id(appContext)),
            )
        }
    }

    private fun fail(prefix: String, error: Throwable) {
        val pending = try {
            store.pending()
        } catch (_: Throwable) {
            null
        }
        val canImportResume = runCatching {
            pending != null && JSONObject(pending.decodeToString()).optInt("schema") == 2 &&
                V2PendingEnrollment.decode(pending).progressStatus != null
        }.getOrDefault(false)
        val hasPending = if (pending != null) {
            true
        } else {
            runCatching { store.pending() != null }.getOrDefault(true)
        }
        mutableStatus.value = EnrollmentStatus(
            EnrollmentPhase.ERROR,
            "$prefix：${error.message ?: error.javaClass.simpleName}",
            canAbandonPending = hasPending,
            canImportResume = canImportResume,
        )
    }

    private suspend fun guarded(prefix: String, block: suspend () -> Unit) {
        try {
            block()
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (error: Throwable) {
            fail(prefix, error)
        }
    }

    companion object {
        private const val BOOTSTRAP_SERVICE_TIMEOUT_MS = 10_000L
        private const val V2_INVITE_URI_PREFIX = "loom://enroll/v2#d="
        private const val V2_RESUME_URI_PREFIX = "loom://enroll/resume/v1#d="

        private val instances = mutableMapOf<String, EnrollmentManager>()

        @Synchronized
        fun get(context: Context): EnrollmentManager {
            val scoped = ProfileCatalog.scoped(context)
            return instances.getOrPut(scoped.filesDir.absolutePath) { EnrollmentManager(scoped) }
        }

        suspend fun remove(context: Context) {
            val key = context.filesDir.absolutePath
            val manager = synchronized(this) { instances[key] } ?: return
            manager.dispose()
        }

        @Synchronized
        fun forgetRemoved(context: Context) {
            check(!ProfileCatalog.get(context).contains(ProfileContext.id(context))) { "配置尚未移除" }
            instances.remove(context.filesDir.absolutePath)
        }
    }
}

internal fun networkFailureKind(error: Throwable): String {
    val chain = generateSequence(error) { it.cause }.toList()
    return when {
        chain.any { it is java.net.UnknownHostException } -> "dns"
        chain.any { it is SSLException } -> "tls"
        chain.any { it is SocketTimeoutException } -> "timeout"
        chain.any { it is ConnectException || it is NoRouteToHostException } -> {
            val errno = chain.firstNotNullOfOrNull(::androidErrno)
            if (errno == null) "connect" else "connect-e$errno"
        }
        chain.any { it is ProtocolException } -> "protocol"
        chain.any { it is EOFException } -> "eof"
        chain.any { it is SocketException } -> {
            val errno = chain.firstNotNullOfOrNull(::androidErrno)
            if (errno != null) {
                "socket-e$errno"
            } else {
                val message = chain.filterIsInstance<SocketException>()
                    .firstNotNullOfOrNull { it.message }
                    ?.lowercase()
                    .orEmpty()
                when {
                    "network is unreachable" in message -> "socket-unreachable"
                    "connection reset" in message -> "socket-reset"
                    "connection abort" in message -> "socket-aborted"
                    "socket closed" in message -> "socket-closed"
                    "operation not permitted" in message || "permission denied" in message -> "socket-denied"
                    else -> "socket"
                }
            }
        }
        chain.any { it is IOException } -> "io"
        else -> "unexpected"
    }
}

private fun androidErrno(error: Throwable): Int? {
    if (error.javaClass.name != "android.system.ErrnoException") return null
    return runCatching { error.javaClass.getField("errno").getInt(error) }.getOrNull()
}
