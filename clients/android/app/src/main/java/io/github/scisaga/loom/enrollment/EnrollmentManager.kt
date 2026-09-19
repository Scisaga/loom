package io.github.scisaga.loom.enrollment

import android.content.Context
import android.content.Intent
import androidx.core.content.ContextCompat
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
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.json.JSONObject
import java.util.concurrent.atomic.AtomicBoolean

enum class EnrollmentPhase { CHECKING, NOT_JOINED, CLAIMING, WAITING, PULLING, READY, ERROR }

data class EnrollmentStatus(
    val phase: EnrollmentPhase = EnrollmentPhase.CHECKING,
    val detail: String = "正在读取设备身份…",
    val nodeID: String = "",
    val profileName: String = "",
    val snapshot: String = "",
    val generation: Long = 0,
    val canAbandonPending: Boolean = false,
    val diagnostic: String = "",
)

class EnrollmentManager private constructor(context: Context) {
    private val appContext = context.applicationContext
    private val store = ManagedProfileStore(appContext)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val operation = Mutex()
    private val started = AtomicBoolean(false)
    private var activeJob: Job? = null
    private val mutableStatus = MutableStateFlow(EnrollmentStatus())
    val status = mutableStatus.asStateFlow()

    fun initialize() {
        if (!started.compareAndSet(false, true)) return
        activeJob = scope.launch { operation.withLock { guarded("恢复设备状态失败", ::resumeUnlocked) } }
    }

    fun importInvite(raw: String) = launch("加入失败") {
        check(store.state() == null) { "设备已有身份；不会用另一份邀请覆盖" }
        val state = Loomcore.newAndroidDeviceState(raw)
        store.saveState(state)
        advanceUntilReady(state)
    }

    fun reportImportError(error: Throwable) = fail("读取加入文件失败", error)

    fun retry() = launch("重试失败", ::resumeUnlocked)

    fun refreshConfiguration() = launch("配置更新失败") {
        store.loadCandidate()?.let {
            awaitingActivation(it)
            requestCandidateActivationIfConnected(it)
            return@launch
        }
        val state = checkNotNull(store.state()) { "设备尚未加入" }
        check(store.loadCurrent() != null) { "设备尚未获得首份认证配置" }
        mutableStatus.value = mutableStatus.value.copy(phase = EnrollmentPhase.PULLING, detail = "正在通过私有通道检查认证配置…")
        val next = Loomcore.syncAndroidDevice(state)
        val profile = store.decodeProfile(next)
        if (profile.recordID == store.loadCurrent()?.recordID) {
            ready(profile, "认证配置已是最新")
        } else {
            awaitingActivation(store.stageCandidate(next))
            requestCandidateActivationIfConnected(profile)
        }
    }

    fun abandonPending() = launch("无法放弃待加入事务") {
        store.clearUncompletedIdentity()
        mutableStatus.value = EnrollmentStatus(EnrollmentPhase.NOT_JOINED, "已清除未完成的本机身份")
    }

    fun candidateProfile(): ManagedProfile? = store.loadCandidate()

    fun candidateActivated(profile: ManagedProfile): ManagedProfile {
        val committed = store.commitCandidate(profile.recordID)
        ready(committed, "认证 LKG 已通过 libbox 与真实 DNS/HTTPS，现已原子激活")
        return committed
    }

    fun candidateRejected(profile: ManagedProfile, reason: String): ManagedProfile? {
        check(store.discardCandidate(profile.recordID)) { "候选在失败恢复期间发生变化" }
        return store.loadCurrent()?.also { ready(it, "候选激活失败，继续沿用最后可用 LKG：$reason") }
    }

    fun currentProfile(): ManagedProfile? = store.loadCurrent()

    fun currentState(): ByteArray = checkNotNull(store.state()) { "设备状态不存在" }

    private suspend fun resumeUnlocked() {
        store.loadCandidate()?.let {
            awaitingActivation(it)
            requestCandidateActivationIfConnected(it)
            return
        }
        store.loadCurrent()?.let {
            ready(it, "已从受保护存储恢复完整认证 LKG")
            return
        }
        val state = store.state()
        if (state == null) {
            mutableStatus.value = EnrollmentStatus(EnrollmentPhase.NOT_JOINED, "扫描中控二维码或导入加入文件")
            return
        }
        advanceUntilReady(state)
    }

    private suspend fun advanceUntilReady(initial: ByteArray) {
        var state = initial
        while (true) {
            currentCoroutineContext().ensureActive()
            val before = JSONObject(Loomcore.androidEnrollmentState(state).decodeToString())
            mutableStatus.value = EnrollmentStatus(
                phase = if (before.getBoolean("claimed")) EnrollmentPhase.WAITING else EnrollmentPhase.CLAIMING,
                detail = if (before.getBoolean("claimed")) "身份已绑定；等待中控批准…" else "正在通过私有通道提交设备身份…",
                canAbandonPending = true,
            )
            state = try {
                Loomcore.advanceAndroidEnrollment(state)
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Throwable) {
                mutableStatus.value = EnrollmentStatus(
                    EnrollmentPhase.WAITING,
                    "私有通道暂不可用；将重试同一身份",
                    canAbandonPending = true,
                    diagnostic = error.javaClass.simpleName,
                )
                delay(RETRY_MS)
                continue
            }
            val after = JSONObject(Loomcore.androidEnrollmentState(state).decodeToString())
            if (!after.getBoolean("ready")) {
                store.saveState(state)
                delay(RETRY_MS)
                continue
            }
            val profile = store.stageCandidate(state)
            awaitingActivation(profile)
            requestCandidateActivationIfConnected(profile)
            return
        }
    }

    private fun awaitingActivation(profile: ManagedProfile) {
        mutableStatus.value = EnrollmentStatus(
            phase = EnrollmentPhase.PULLING,
            detail = "认证 LKG 与 libbox 预检通过；连接后用真实 DNS/HTTPS 验证",
            nodeID = profile.nodeID,
            profileName = profile.profileName,
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
            profileName = profile.profileName,
            snapshot = profile.snapshot,
            generation = profile.generation,
        )
    }

    private fun launch(prefix: String, block: suspend () -> Unit) {
        activeJob?.cancel()
        activeJob = scope.launch { operation.withLock { guarded(prefix, block) } }
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

    private fun fail(prefix: String, error: Throwable) {
        store.loadCurrent()?.let {
            ready(it, "$prefix，继续沿用最后可用 LKG：${error.message ?: error.javaClass.simpleName}")
            return
        }
        mutableStatus.value = EnrollmentStatus(
            EnrollmentPhase.ERROR,
            "$prefix：${error.message ?: error.javaClass.simpleName}",
            canAbandonPending = runCatching { store.loadCurrent() == null && store.state() != null }.getOrDefault(false),
        )
    }

    companion object {
        private const val RETRY_MS = 5_000L
        @Volatile private var instance: EnrollmentManager? = null

        fun get(context: Context): EnrollmentManager = instance ?: synchronized(this) {
            instance ?: EnrollmentManager(context).also { instance = it }
        }
    }
}
