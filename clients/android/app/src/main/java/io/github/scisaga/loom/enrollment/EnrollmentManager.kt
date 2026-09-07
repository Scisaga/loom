package io.github.scisaga.loom.enrollment

import android.content.Context
import android.content.Intent
import androidx.core.content.ContextCompat
import io.github.scisaga.loom.security.DeviceKeyStore
import io.github.scisaga.loom.security.TrustAnchor
import io.github.scisaga.loom.route.RouteManager
import io.github.scisaga.loom.vpn.ConnectionPhase
import io.github.scisaga.loom.vpn.LoomVpnService
import io.github.scisaga.loom.vpn.VpnRuntime
import io.github.scisaga.loomcore.Loomcore
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
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
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.SSLException

enum class EnrollmentPhase { CHECKING, NOT_JOINED, CLAIMING, WAITING, PULLING, READY, ERROR }

data class EnrollmentStatus(
    val phase: EnrollmentPhase = EnrollmentPhase.CHECKING,
    val detail: String = "正在读取设备身份…",
    val nodeID: String = "",
    val snapshot: String = "",
    val generation: Long = 0,
    val canAbandonPending: Boolean = false,
    val diagnostic: String = "",
)

class EnrollmentManager private constructor(context: Context) {
    private val appContext = context.applicationContext
    private val store = ManagedProfileStore(appContext)
    private val keys = DeviceKeyStore()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val transaction = Mutex()
    private val started = AtomicBoolean(false)
    private var activeJob: Job? = null
    private val mutableStatus = MutableStateFlow(EnrollmentStatus())
    val status = mutableStatus.asStateFlow()

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
                    candidateProfile()?.let {
                        awaitingActivation(it)
                        requestCandidateActivationIfConnected(it)
                        return@guarded
                    }
                    val ready = store.ready() ?: currentEnrollment()
                    checkNotNull(ready) { "设备尚未完成加入" }
                    pullAndActivate(ready)
                }
            }
        }
    }

    fun abandonPending() {
        activeJob?.cancel()
        activeJob = scope.launch {
            transaction.withLock {
                guarded("无法放弃待加入事务") {
                    check(store.loadCurrent() == null && store.ready() == null) { "设备已经加入；不会删除正式身份" }
                    store.clearPending()
                    mutableStatus.value = EnrollmentStatus(
                        EnrollmentPhase.NOT_JOINED,
                        "已放弃本机待加入事务；中控 Device 状态不会因此撤销",
                    )
                }
            }
        }
    }

    fun candidateProfile(): ManagedProfile? = try {
        store.loadCandidate()
    } catch (error: Exception) {
        // A candidate has never been promoted. It is therefore safe to remove
        // a corrupt candidate and retain current/previous plus the latched
        // release floor; the same or newer signed payload can be fetched again.
        val current = runCatching { loadCurrentWithRecovery() }.getOrNull()
        if (current != null) {
            ready(current, "未激活候选校验失败；已隔离并沿用最后可用配置")
        } else {
            throw IllegalStateException("未激活候选校验失败，已隔离；请重新拉取", error)
        }
        null
    }

    fun candidateActivated(profile: ManagedProfile): ManagedProfile {
        val committed = store.commitCandidate(profile.recordID)
        store.clearReady()
        ready(committed, "正式入网完成；候选已通过真实 DNS/HTTPS 并成为当前配置")
        return committed
    }

    fun candidateRejected(profile: ManagedProfile, reason: String): ManagedProfile? {
        check(store.discardCandidate(profile.recordID)) { "候选在失败恢复期间发生变化" }
        return runCatching { currentProfile() }.getOrNull()?.also {
            ready(it, "候选激活失败，继续沿用最后可用配置：$reason")
        }
    }

    fun currentProfile(): ManagedProfile? {
        val current = loadCurrentWithRecovery()
        check(current != null || store.ready() == null && store.loadCandidate() == null) {
            "正式身份尚无可激活的验签配置"
        }
        return current
    }

    private fun loadCurrentWithRecovery(): ManagedProfile? {
        try {
            store.loadCurrent()?.let { return it }
        } catch (currentError: Throwable) {
            val previous = runCatching { store.restorePrevious() }.getOrNull()
            if (previous != null) {
                ready(previous, "当前缓存校验失败；已恢复 previous 验签配置")
                return previous
            }
            throw currentError
        }
        store.restorePrevious()?.let {
            ready(it, "当前缓存缺失；已恢复 previous 验签配置")
            return it
        }
        return null
    }

    fun previousProfile(): ManagedProfile? = store.loadPrevious()

    fun promotePrevious(): ManagedProfile? = store.restorePrevious()?.also {
        ready(it, "新配置激活失败；已恢复 previous 验签配置")
    }

    private suspend fun resumeInternal() = transaction.withLock {
        guarded("恢复加入状态失败") { resumeUnlocked() }
    }

    private suspend fun resumeUnlocked() {
        candidateProfile()?.let {
            awaitingActivation(it)
            requestCandidateActivationIfConnected(it)
            return
        }
        loadCurrentWithRecovery()?.let {
            ready(it, "已重放签名链并加载最后可用配置")
            return
        }
        if (
            resumeReadyAfterPendingCleanup(
                ready = store.ready(),
                clearPending = store::clearPending,
                continuePull = ::pullAndActivate,
            )
        ) return
        store.pending()?.let {
            claimUntilReady(it)
            return
        }
        mutableStatus.value = EnrollmentStatus(EnrollmentPhase.NOT_JOINED, "扫描中控二维码或导入加入文件")
    }

    private suspend fun beginJoin(raw: String) {
        check(store.loadCurrent() == null && store.ready() == null) { "设备已经加入；不会覆盖现有身份" }
        val canonicalInvite = Loomcore.parseEnrollmentInvite(raw)
        TrustAnchor.validateEnrollmentInvite(canonicalInvite)
        val expiresAt = JSONObject(canonicalInvite.decodeToString()).getString("expires_at")
        enrollmentAttemptWindow(expiresAt, null, Instant.now())
        val existing = store.pending()
        if (existing != null) {
            val pendingInvite = JSONObject(existing.decodeToString()).getString("invite_json").encodeToByteArray()
            check(pendingInvite.contentEquals(canonicalInvite)) { "已有另一笔未完成加入；不会覆盖一次性凭据" }
            claimUntilReady(existing)
            return
        }
        val requestID = UUID.randomUUID().toString()
        val publicKey = keys.ensureIdentity()
        val csr = keys.createCSR(requestID)
        Loomcore.buildAndroidClaim(canonicalInvite, csr, publicKey, requestID)
        val pending = JSONObject()
            .put("schema", 1)
            .put("invite_json", canonicalInvite.decodeToString())
            .put("request_id", requestID)
            .put("csr_pem", csr.decodeToString())
            .toString()
            .encodeToByteArray()
        store.putPending(pending)
        claimUntilReady(pending)
    }

    private suspend fun claimUntilReady(pendingBytes: ByteArray) {
        val pending = JSONObject(pendingBytes.decodeToString())
        check(pending.getInt("schema") == 1) { "受保护的加入事务无效" }
        val invite = pending.getString("invite_json").encodeToByteArray()
        TrustAnchor.validateEnrollmentInvite(invite)
        val requestID = pending.getString("request_id")
        val csr = pending.getString("csr_pem").encodeToByteArray()
        val endpoint = Loomcore.enrollmentEndpoint(invite)
        val publicKey = keys.ensureIdentity()
        val claim = Loomcore.buildAndroidClaim(invite, csr, publicKey, requestID)
        val expiresAt = JSONObject(invite.decodeToString()).getString("expires_at")
        val firstAttempt = pending.optString(FIRST_ATTEMPTED_AT).takeIf(String::isNotBlank)
        val attemptNow = Instant.now()
        val initialWindow = enrollmentAttemptWindow(expiresAt, firstAttempt, attemptNow)
        if (initialWindow.markFirstAttempt) {
            pending.put(FIRST_ATTEMPTED_AT, attemptNow.toString())
            store.putPending(pending.toString().encodeToByteArray())
        }
        var retryDelay = INITIAL_RETRY_MS
        while (true) {
            enrollmentAttemptWindow(
                expiresAt,
                pending.optString(FIRST_ATTEMPTED_AT).takeIf(String::isNotBlank),
                Instant.now(),
            )
            mutableStatus.value = EnrollmentStatus(EnrollmentPhase.CLAIMING, "正在提交 Keystore 设备身份…")
            val result = try {
                HttpTransport.postJSON(appContext, endpoint, claim, ENROLLMENT_RESPONSE_LIMIT)
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (failure: Exception) {
                mutableStatus.value = EnrollmentStatus(
                    EnrollmentPhase.WAITING,
                    "网络暂不可用；将安全重试同一身份",
                    diagnostic = networkFailureKind(failure),
                )
                delay(retryDelay)
                retryDelay = (retryDelay * 2).coerceAtMost(MAX_RETRY_MS)
                continue
            }
            currentCoroutineContext().ensureActive()
            if (result.status >= 500 || result.status == 429) {
                mutableStatus.value = EnrollmentStatus(
                    EnrollmentPhase.WAITING,
                    "中控暂不可用；将安全重试同一身份",
                    diagnostic = "http-${result.status}",
                )
                delay(retryDelay)
                retryDelay = (retryDelay * 2).coerceAtMost(MAX_RETRY_MS)
                continue
            }
            check(result.status == 200 || result.status == 202) { "中控拒绝加入（HTTP ${result.status}）" }
            check(result.contentType?.substringBefore(';') == "application/json") { "中控加入响应不是 application/json" }
            val validated = Loomcore.validateAndroidEnrollmentResponse(invite, result.body, publicKey, result.status.toLong())
            val response = JSONObject(validated.decodeToString()).getJSONObject("response")
            bindPendingResponse(pending, response)
            if (response.getString("configuration") == "pending") {
                mutableStatus.value = EnrollmentStatus(
                    EnrollmentPhase.WAITING,
                    "身份已绑定；正在等待中控发布首份签名配置…",
                    nodeID = response.getString("client_id"),
                )
                delay(retryDelay)
                retryDelay = (retryDelay * 2).coerceAtMost(MAX_RETRY_MS)
                continue
            }
            store.putReady(validated)
            store.clearPending()
            pullAndActivate(validated)
            return
        }
    }

    private fun bindPendingResponse(pending: JSONObject, response: JSONObject) {
        val clientID = response.getString("client_id")
        val claimedAt = response.getString("claimed_at")
        pending.optString(CLAIMED_CLIENT_ID).takeIf(String::isNotBlank)?.let {
            check(it == clientID) { "加入重试返回了不同的 Device 身份" }
        }
        pending.optString(CLAIMED_AT).takeIf(String::isNotBlank)?.let {
            check(it == claimedAt) { "加入重试返回了不同的 claimed_at" }
        }
        pending.put(CLAIMED_CLIENT_ID, clientID)
        pending.put(CLAIMED_AT, claimedAt)
        store.putPending(pending.toString().encodeToByteArray())
    }

    private fun currentEnrollment(): ByteArray? {
        val current = store.currentRecord() ?: return null
        return JSONObject(current.decodeToString()).getJSONObject("enrollment").toString().encodeToByteArray()
    }

    private suspend fun pullAndActivate(enrollmentBytes: ByteArray) {
        val enrollment = JSONObject(enrollmentBytes.decodeToString())
        val response = enrollment.getJSONObject("response")
        val bootstrap = response.getJSONObject("bootstrap")
        val nodeID = bootstrap.getString("node_id")
        mutableStatus.value = EnrollmentStatus(EnrollmentPhase.PULLING, "正在验签并预检配置…", nodeID = nodeID)
        val platformKey = TrustAnchor.platformPublicKeyForBootstrap(bootstrap.getString("platform_public_key"))
        val expected = bootstrap.getString("release_authority").encodeToByteArray()
        val oldFloor = store.floor()
        val mirrors = bootstrap.getJSONArray("distribution_urls").strings()
        val candidates = JSONArray()
        mirrors.forEachIndexed { index, mirror ->
            val result = fetch(mirror.trimEnd('/') + "/current.json", CURRENT_LIMIT)
            if (result?.status == 200) {
                candidates.put(JSONObject().put("id", index.toString()).put("current_json", result.body.decodeToString()))
            }
        }
        check(candidates.length() > 0) { "所有配置镜像均不可用" }
        val selected = Loomcore.selectVerifiedCurrents(
            JSONObject().put("schema", 1).put("candidates", candidates).toString().encodeToByteArray(),
            platformKey,
            nodeID,
            expected,
            oldFloor,
        )
        val selection = JSONObject(selected.decodeToString())
        val current = selection.getString("current_json").encodeToByteArray()
        val snapshot = selection.getString("selected_snapshot")
        val nextFloor = selection.getJSONObject("next_floor").toString().encodeToByteArray()
        // The authenticated mutable decision is latched before any mirror is
        // asked for immutable payload. A withheld payload cannot reopen an old generation.
        currentCoroutineContext().ensureActive()
        store.putFloor(nextFloor)

        var acceptedManifest: ByteArray? = null
        var acceptedSignature: ByteArray? = null
        var acceptedBundle: ByteArray? = null
        for (mirror in mirrors) {
            val root = mirror.trimEnd('/') + "/$snapshot"
            val manifest = fetch("$root/snapshot.json", MANIFEST_LIMIT)
            val signature = fetch("$root/snapshot.sig", SIGNATURE_LIMIT)
            val bundle = fetch("$root/nodes/$nodeID.json", BUNDLE_LIMIT)
            if (manifest?.status != 200 || signature?.status != 200 || bundle?.status != 200) continue
            val verified = runCatching {
                Loomcore.verifyPull(
                    current,
                    manifest.body,
                    signature.body,
                    bundle.body,
                    platformKey,
                    nodeID,
                    ByteArray(0),
                    nextFloor,
                )
            }.getOrNull()
            if (verified != null) {
                acceptedManifest = manifest.body
                acceptedSignature = signature.body
                acceptedBundle = bundle.body
                break
            }
        }
        val manifest = checkNotNull(acceptedManifest) { "所有镜像的签名配置制品均被拒绝" }
        val signature = checkNotNull(acceptedSignature)
        val bundle = checkNotNull(acceptedBundle)
        currentCoroutineContext().ensureActive()
        val profile = store.stageCandidate(
            enrollmentBytes,
            current,
            manifest,
            signature,
            bundle,
            nextFloor,
        )
        awaitingActivation(profile)
        requestCandidateActivationIfConnected(profile)
    }

    private suspend fun fetch(endpoint: String, maximum: Int): HttpResult? {
        currentCoroutineContext().ensureActive()
        val result = try {
            HttpTransport.get(appContext, endpoint, maximum)
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            null
        }
        currentCoroutineContext().ensureActive()
        return result
    }

    private fun awaitingActivation(profile: ManagedProfile) {
        mutableStatus.value = EnrollmentStatus(
            phase = EnrollmentPhase.PULLING,
            detail = "签名链与 libbox 预检通过；连接后执行真实 DNS/HTTPS 再原子激活",
            nodeID = profile.nodeID,
            snapshot = profile.snapshot,
            generation = profile.generation,
        )
    }

    private fun requestCandidateActivationIfConnected(profile: ManagedProfile) {
        if (VpnRuntime.status.value.phase !in setOf(ConnectionPhase.CONNECTED, ConnectionPhase.STARTING)) return
        ContextCompat.startForegroundService(
            appContext,
            Intent(appContext, LoomVpnService::class.java)
                .setAction(LoomVpnService.ACTION_RELOAD)
                .putExtra(LoomVpnService.EXTRA_CANDIDATE_ID, profile.recordID),
        )
    }

    private fun ready(profile: ManagedProfile, detail: String) {
        RouteManager.get(appContext).profileAvailable(profile)
        mutableStatus.value = EnrollmentStatus(
            phase = EnrollmentPhase.READY,
            detail = detail,
            nodeID = profile.nodeID,
            snapshot = profile.snapshot,
            generation = profile.generation,
        )
    }

    private fun fail(prefix: String, error: Throwable) {
        val hasPending = try {
            store.pending() != null
        } catch (_: Throwable) {
            true
        }
        mutableStatus.value = EnrollmentStatus(
            EnrollmentPhase.ERROR,
            "$prefix：${error.message ?: error.javaClass.simpleName}",
            canAbandonPending = hasPending,
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

    private fun JSONArray.strings(): List<String> = (0 until length()).map(::getString)

    companion object {
        private const val INITIAL_RETRY_MS = 2_000L
        private const val MAX_RETRY_MS = 30_000L
        private const val ENROLLMENT_RESPONSE_LIMIT = 4 * 1024 * 1024
        private const val CURRENT_LIMIT = 1024 * 1024
        private const val MANIFEST_LIMIT = 4 * 1024 * 1024
        private const val SIGNATURE_LIMIT = 1024
        private const val BUNDLE_LIMIT = 16 * 1024 * 1024
        private const val FIRST_ATTEMPTED_AT = "first_attempted_at"
        private const val CLAIMED_CLIENT_ID = "claimed_client_id"
        private const val CLAIMED_AT = "claimed_at"

        @Volatile private var instance: EnrollmentManager? = null

        fun get(context: Context): EnrollmentManager = instance ?: synchronized(this) {
            instance ?: EnrollmentManager(context).also { instance = it }
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

/**
 * A validated READY record no longer needs the one-time invitation. Keep the
 * deletion before pull so a process death after READY persistence cannot leave
 * the bearer token stranded when recovery later advances to candidate/current.
 */
internal suspend fun <T> resumeReadyAfterPendingCleanup(
    ready: T?,
    clearPending: () -> Unit,
    continuePull: suspend (T) -> Unit,
): Boolean {
    if (ready == null) return false
    clearPending()
    continuePull(ready)
    return true
}
