package io.github.scisaga.loom.enrollment

import android.content.Context
import android.content.Intent
import androidx.core.content.ContextCompat
import io.github.scisaga.loom.profiles.ProfileStorage
import io.github.scisaga.loom.route.RouteManager
import io.github.scisaga.loom.vpn.ConnectionPhase
import io.github.scisaga.loom.vpn.LoomVpnService
import io.github.scisaga.loom.vpn.VpnRuntime
import io.github.scisaga.loomcore.Loomcore
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.json.JSONObject

enum class EnrollmentPhase { CHECKING, NOT_JOINED, CLAIMING, WAITING, PULLING, READY, ERROR }

data class EnrollmentStatus(
    val phase: EnrollmentPhase = EnrollmentPhase.CHECKING,
    val detail: String = "正在读取设备身份…",
    val nodeID: String = "",
    val deviceName: String = "",
    val snapshot: String = "",
    val generation: Long = 0,
    val canAbandonPending: Boolean = false,
    val diagnostic: String = "",
)

class EnrollmentManager private constructor(context: Context) {
    private val appContext = context.applicationContext
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val operation = Mutex()
    private val statusLock = Any()
    private val jobLock = Any()
    private val mutableStatuses = mutableMapOf<String, MutableStateFlow<EnrollmentStatus>>()
    private var activeJob: Job? = null
    private var activeJobProfileId = ""

    fun status(profileId: String): StateFlow<EnrollmentStatus> = statusSink(profileId).asStateFlow()

    fun initialize(profileId: String) {
        requireProfileId(profileId)
        synchronized(jobLock) {
            if (activeJobProfileId == profileId && activeJob?.isActive == true) return
        }
        launch(profileId, "恢复设备状态失败") { store -> resumeUnlocked(profileId, store) }
    }

    fun importInvite(profileId: String, raw: String) = launch(profileId, "加入失败") { store ->
        check(store.state() == null) { "设备已有身份；不会用另一份邀请覆盖" }
        val state = Loomcore.newAndroidDeviceState(raw)
        currentCoroutineContext().ensureActive()
        store.saveState(state)
        advanceUntilReady(profileId, store, state)
    }

    fun reportImportError(profileId: String, error: Throwable) =
        fail(profileId, store(profileId), "读取加入文件失败", error)

    fun retry(profileId: String) =
        launch(profileId, "重试失败") { store -> resumeUnlocked(profileId, store) }

    fun refreshConfiguration(profileId: String) = launch(profileId, "配置更新失败") { store ->
        store.loadCandidate()?.let {
            awaitingActivation(profileId, it)
            requestCandidateActivationIfConnected(profileId, it)
            return@launch
        }
        val state = checkNotNull(store.state()) { "设备尚未加入" }
        check(store.loadCurrent() != null) { "设备尚未获得首份认证配置" }
        statusSink(profileId).let { status ->
            status.value = status.value.copy(
                phase = EnrollmentPhase.PULLING,
                detail = "正在通过私有通道检查认证配置…",
            )
        }
        val next = Loomcore.syncAndroidDevice(state)
        currentCoroutineContext().ensureActive()
        val profile = store.decodeProfile(next)
        if (profile.recordID == store.loadCurrent()?.recordID) {
            ready(profileId, profile, "认证配置已是最新")
        } else {
            awaitingActivation(profileId, store.stageCandidate(next))
            requestCandidateActivationIfConnected(profileId, profile)
        }
    }

    fun abandonPending(profileId: String) = launch(profileId, "无法放弃待加入事务") { store ->
        store.clearUncompletedIdentity()
        statusSink(profileId).value = EnrollmentStatus(EnrollmentPhase.NOT_JOINED, "已清除未完成的本机身份")
    }

    fun candidateProfile(profileId: String): ManagedProfile? = store(profileId).loadCandidate()

    fun candidateActivated(profileId: String, profile: ManagedProfile): ManagedProfile {
        val store = store(profileId)
        val committed = store.commitCandidate(profile.recordID)
        ready(profileId, committed, "认证 LKG 已通过 libbox 与真实 DNS/HTTPS，现已原子激活")
        return committed
    }

    fun candidateRejected(profileId: String, profile: ManagedProfile, reason: String): ManagedProfile? {
        val store = store(profileId)
        check(store.discardCandidate(profile.recordID)) { "候选在失败恢复期间发生变化" }
        return store.loadCurrent()?.also {
            ready(profileId, it, "候选激活失败，继续沿用最后可用 LKG：$reason")
        }
    }

    fun currentProfile(profileId: String): ManagedProfile? = store(profileId).loadCurrent()

    fun currentState(profileId: String): ByteArray =
        checkNotNull(store(profileId).state()) { "设备状态不存在" }

    suspend fun quiesceProfile(profileId: String) {
        requireProfileId(profileId)
        val job = synchronized(jobLock) {
            if (activeJobProfileId != profileId) {
                null
            } else {
                activeJob.also {
                    activeJob = null
                    activeJobProfileId = ""
                }
            }
        }
        job?.cancelAndJoin()
    }

    suspend fun removeProfile(profileId: String) {
        quiesceProfile(profileId)
        store(profileId).clear()
        synchronized(statusLock) { mutableStatuses.remove(profileId) }
    }

    private suspend fun resumeUnlocked(profileId: String, store: ManagedProfileStore) {
        store.loadCandidate()?.let {
            awaitingActivation(profileId, it)
            requestCandidateActivationIfConnected(profileId, it)
            return
        }
        store.loadCurrent()?.let {
            ready(profileId, it, "已从受保护存储恢复完整认证 LKG")
            return
        }
        val state = store.state()
        if (state == null) {
            statusSink(profileId).value = EnrollmentStatus(EnrollmentPhase.NOT_JOINED, "扫描中控二维码或导入加入文件")
            return
        }
        advanceUntilReady(profileId, store, state)
    }

    private suspend fun advanceUntilReady(profileId: String, store: ManagedProfileStore, initial: ByteArray) {
        var state = initial
        while (true) {
            currentCoroutineContext().ensureActive()
            val before = JSONObject(Loomcore.androidEnrollmentState(state).decodeToString())
            statusSink(profileId).value = EnrollmentStatus(
                phase = if (before.getBoolean("claimed")) EnrollmentPhase.WAITING else EnrollmentPhase.CLAIMING,
                detail = if (before.getBoolean("claimed")) "身份已绑定；等待中控批准…" else "正在通过私有通道提交设备身份…",
                canAbandonPending = true,
            )
            state = try {
                Loomcore.advanceAndroidEnrollment(state)
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Throwable) {
                currentCoroutineContext().ensureActive()
                statusSink(profileId).value = EnrollmentStatus(
                    EnrollmentPhase.WAITING,
                    "私有通道暂不可用；将重试同一身份",
                    canAbandonPending = true,
                    diagnostic = error.javaClass.simpleName,
                )
                delay(RETRY_MS)
                continue
            }
            currentCoroutineContext().ensureActive()
            val after = JSONObject(Loomcore.androidEnrollmentState(state).decodeToString())
            if (!after.getBoolean("ready")) {
                store.saveState(state)
                delay(RETRY_MS)
                continue
            }
            val profile = store.stageCandidate(state)
            awaitingActivation(profileId, profile)
            requestCandidateActivationIfConnected(profileId, profile)
            return
        }
    }

    private fun awaitingActivation(profileId: String, profile: ManagedProfile) {
        statusSink(profileId).value = EnrollmentStatus(
            phase = EnrollmentPhase.PULLING,
            detail = "认证 LKG 与 libbox 预检通过；连接后用真实 DNS/HTTPS 验证",
            nodeID = profile.nodeID,
            deviceName = profile.deviceName,
            snapshot = profile.snapshot,
            generation = profile.generation,
        )
    }

    private fun requestCandidateActivationIfConnected(profileId: String, profile: ManagedProfile) {
        val runtime = VpnRuntime.status.value
        if (runtime.phase !in setOf(ConnectionPhase.CONNECTED, ConnectionPhase.STARTING) ||
            profileId !in setOf(runtime.requestedProfileId, runtime.activeProfileId)
        ) return
        ContextCompat.startForegroundService(
            appContext,
            Intent(appContext, LoomVpnService::class.java)
                .setAction(LoomVpnService.ACTION_RELOAD)
                .putExtra(LoomVpnService.EXTRA_PROFILE_ID, profileId)
                .putExtra(LoomVpnService.EXTRA_CANDIDATE_ID, profile.recordID),
        )
    }

    private fun ready(profileId: String, profile: ManagedProfile, detail: String) {
        RouteManager.get(appContext).profileAvailable(profileId, profile)
        statusSink(profileId).value = EnrollmentStatus(
            phase = EnrollmentPhase.READY,
            detail = detail,
            nodeID = profile.nodeID,
            deviceName = profile.deviceName,
            snapshot = profile.snapshot,
            generation = profile.generation,
        )
    }

    private fun launch(
        profileId: String,
        prefix: String,
        block: suspend (ManagedProfileStore) -> Unit,
    ) {
        requireProfileId(profileId)
        val store = store(profileId)
        val job = scope.launch(start = CoroutineStart.LAZY) {
            operation.withLock { guarded(profileId, store, prefix) { block(store) } }
        }
        synchronized(jobLock) {
            activeJob?.cancel()
            activeJob = job
            activeJobProfileId = profileId
        }
        job.invokeOnCompletion {
            synchronized(jobLock) {
                if (activeJob === job) {
                    activeJob = null
                    activeJobProfileId = ""
                }
            }
        }
        job.start()
    }

    private suspend fun guarded(
        profileId: String,
        store: ManagedProfileStore,
        prefix: String,
        block: suspend () -> Unit,
    ) {
        try {
            block()
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (error: Throwable) {
            currentCoroutineContext().ensureActive()
            fail(profileId, store, prefix, error)
        }
    }

    private fun fail(profileId: String, store: ManagedProfileStore, prefix: String, error: Throwable) {
        store.loadCurrent()?.let {
            ready(profileId, it, "$prefix，继续沿用最后可用 LKG：${error.message ?: error.javaClass.simpleName}")
            return
        }
        statusSink(profileId).value = EnrollmentStatus(
            EnrollmentPhase.ERROR,
            "$prefix：${error.message ?: error.javaClass.simpleName}",
            canAbandonPending = runCatching { store.loadCurrent() == null && store.state() != null }.getOrDefault(false),
        )
    }

    private fun statusSink(profileId: String): MutableStateFlow<EnrollmentStatus> {
        requireProfileId(profileId)
        return synchronized(statusLock) {
            mutableStatuses.getOrPut(profileId) { MutableStateFlow(EnrollmentStatus()) }
        }
    }

    private fun store(profileId: String): ManagedProfileStore {
        requireProfileId(profileId)
        return ManagedProfileStore(appContext, profileId)
    }

    private fun requireProfileId(profileId: String) {
        require(ProfileStorage.validId(profileId)) { "配置标识无效" }
    }

    companion object {
        private const val RETRY_MS = 5_000L
        @Volatile private var instance: EnrollmentManager? = null

        fun get(context: Context): EnrollmentManager = instance ?: synchronized(this) {
            instance ?: EnrollmentManager(context).also { instance = it }
        }
    }
}
