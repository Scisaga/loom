package io.github.scisaga.loom.enrollment

import android.content.Context
import io.github.scisaga.libbox.Libbox
import io.github.scisaga.loom.BuildConfig
import io.github.scisaga.loom.profiles.ProfileCatalog
import io.github.scisaga.loom.profiles.ProfileStorage
import io.github.scisaga.loom.route.RouteManager
import io.github.scisaga.loom.vpn.LoomVpnService
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
import java.time.Instant
import java.time.temporal.ChronoUnit

enum class EnrollmentPhase { CHECKING, NOT_JOINED, CLAIMING, WAITING, PULLING, READY, ERROR }

data class EnrollmentStatus(
    val phase: EnrollmentPhase = EnrollmentPhase.CHECKING,
    val detail: String = "正在读取设备身份…",
    val nodeID: String = "",
    val deviceName: String = "",
    val viewDigest: String = "",
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
        val state = checkNotNull(store.state()) { "设备尚未加入" }
        check(store.acceptedViewDigest().isNotEmpty()) { "设备尚未获得首份认证配置" }
        statusSink(profileId).let { status ->
            status.value = status.value.copy(
                phase = EnrollmentPhase.PULLING,
                detail = "正在通过私有通道检查认证配置…",
            )
        }
        val next = Loomcore.syncAndroidDevice(state)
        currentCoroutineContext().ensureActive()
        if (store.certifiedViewDigest(next) == store.acceptedViewDigest()) {
            store.saveState(next)
            ready(profileId, store.decodeProfile(next), "认证配置已是最新")
        } else {
            acceptCertified(profileId, store, next)
        }
    }

    /** Accept authenticated updates independently of the current VPN or business outcome. */
    fun refreshConfigurationInBackground(profileId: String) {
        requireProfileId(profileId)
        scope.launch {
            operation.withLock {
                val store = store(profileId)
                guarded(profileId, store, "配置更新失败") {
                    if (store.acceptedViewDigest().isEmpty()) return@guarded
                    val state = store.state() ?: return@guarded
                    val next = try {
                        Loomcore.syncAndroidDevice(state)
                    } catch (cancelled: CancellationException) {
                        throw cancelled
                    } catch (_: Throwable) {
                        // An unavailable private channel does not revoke the accepted LKG.
                        return@guarded
                    }
                    currentCoroutineContext().ensureActive()
                    if (store.certifiedViewDigest(next) == store.acceptedViewDigest()) {
                        store.saveState(next)
                        return@guarded
                    }
                    acceptCertified(profileId, store, next)
                }
            }
        }
    }

    fun abandonPending(profileId: String) = launch(profileId, "无法放弃待加入事务") { store ->
        store.clearUncompletedIdentity()
        statusSink(profileId).value = EnrollmentStatus(EnrollmentPhase.NOT_JOINED, "已清除未完成的本机身份")
    }

    fun currentProfile(profileId: String): ManagedProfile? = store(profileId).loadCurrent()

    internal fun prepareRuntimeProfile(profileId: String): ManagedProfile = store(profileId).prepareRuntime()

    internal suspend fun postReport(profileId: String) = operation.withLock {
        check(ProfileCatalog.get(appContext).contains(profileId)) { "配置已删除" }
        val store = store(profileId)
        val acceptedView = store.acceptedViewDigest().also { check(it.isNotEmpty()) { "设备尚未获得认证配置" } }
        LoomVpnService.withRuntimeReport(profileId) { runtime ->
            val routing = RouteManager.get(appContext).reportData(
                profileId, acceptedView, runtime.optString("applied_view_digest"),
            )
            // The sequence and complete identity/LKG are one durable write. A
            // network failure burns this number; no stale handle can reuse it.
            val reserved = store.updateState(Loomcore::reserveAndroidReportSequence)
            Loomcore.postAndroidDeviceReport(
                reserved, routing.observations, routing.selections, runtime.toString().encodeToByteArray(),
                Loomcore.androidRuntimeComponents(appContext.packageCodePath, BuildConfig.LOOM_SOURCE_COMMIT, Libbox.version()),
                routing.networkGeneration, Instant.now().truncatedTo(ChronoUnit.SECONDS).toString(),
            )
        }
    }

    internal fun reportRuntimeOutcome(profileId: String) {
        requireProfileId(profileId)
        scope.launch { runCatching { postReport(profileId) } }
    }

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
        operation.withLock {
            store(profileId).clear()
            synchronized(statusLock) { mutableStatuses.remove(profileId) }
        }
    }

    private suspend fun resumeUnlocked(profileId: String, store: ManagedProfileStore) {
        if (store.acceptedViewDigest().isNotEmpty() && runCatching { store.loadCurrent() }.isFailure) {
            val next = Loomcore.syncAndroidDevice(checkNotNull(store.state()))
            currentCoroutineContext().ensureActive()
            acceptCertified(profileId, store, next)
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
                detail = if (before.getBoolean("claimed")) "正在恢复同一设备的认证配置…" else "正在通过私有通道提交设备身份…",
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
            acceptCertified(profileId, store, state)
            return
        }
    }

    private suspend fun acceptCertified(profileId: String, store: ManagedProfileStore, body: ByteArray) {
        // Validate the accepted authority independently of runtime projection.
        store.certifiedViewDigest(body)
        val profile = LoomVpnService.acceptConfiguration(profileId) {
            check(ProfileCatalog.get(appContext).contains(profileId)) { "配置已删除" }
            store.acceptCertified(body)
        }
        ready(profileId, profile, "认证配置已原子保存；连接状态由 VPN 运行回读确认")
    }

    private fun ready(profileId: String, profile: ManagedProfile, detail: String) {
        RouteManager.get(appContext).profileAvailable(profileId, profile)
        statusSink(profileId).value = EnrollmentStatus(
            phase = EnrollmentPhase.READY,
            detail = detail,
            nodeID = profile.nodeID,
            deviceName = profile.deviceName,
            viewDigest = profile.viewDigest,
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
        statusSink(profileId).value = EnrollmentStatus(
            EnrollmentPhase.ERROR,
            "$prefix：${error.message ?: error.javaClass.simpleName}",
            viewDigest = runCatching { store.acceptedViewDigest() }.getOrDefault(""),
            canAbandonPending = runCatching { store.acceptedViewDigest().isEmpty() && store.state() != null }.getOrDefault(false),
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
