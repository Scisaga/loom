package io.github.scisaga.loom.enrollment

import android.content.Context
import io.github.scisaga.libbox.Libbox
import io.github.scisaga.loom.BuildConfig
import io.github.scisaga.loom.profiles.ProfileCatalog
import io.github.scisaga.loom.profiles.ProfileStorage
import io.github.scisaga.loom.route.RouteManager
import io.github.scisaga.loom.vpn.LoomVpnService
import io.github.scisaga.loom.vpn.ConnectionPhase
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
import java.time.Instant

enum class EnrollmentPhase { CHECKING, NOT_JOINED, CLAIMING, WAITING, PULLING, READY, ERROR }

data class EnrollmentStatus(
    val phase: EnrollmentPhase = EnrollmentPhase.CHECKING,
    val detail: String = "正在读取设备身份…",
    val nodeID: String = "",
    val deviceName: String = "",
    val viewDigest: String = "",
    val canAbandonPending: Boolean = false,
    val diagnostic: String = "",
    val possiblePermissionRestoration: Boolean = false,
)

class EnrollmentManager private constructor(context: Context) {
    private val appContext = context.applicationContext
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val operation = Mutex()
    private val reporting = Mutex()
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
        val state = operation.withLock {
            check(ProfileCatalog.get(appContext).contains(profileId)) { "配置已删除" }
            check(store.state() == null) { "设备已有身份；不会用另一份邀请覆盖" }
            Loomcore.newAndroidDeviceState(raw).also {
                currentCoroutineContext().ensureActive()
                store.saveState(it)
            }
        }
        advanceUntilReady(profileId, store, state)
    }

    fun importFile(profileId: String, body: ByteArray) {
        if (runCatching { JSONObject(body.decodeToString()).has("view") }.getOrDefault(false)) {
            launch(profileId, "配置替换失败") { store ->
                operation.withLock {
                    val profile = LoomVpnService.acceptConfiguration(profileId) {
                        check(ProfileCatalog.get(appContext).contains(profileId)) { "配置已删除" }
                        store.importCertifiedView(body)
                    }
                    ready(profileId, profile, "认证配置已更新，原设备身份已保留")
                }
            }
        } else {
            require(body.size <= 16 * 1024) { "加入文件必须小于 16 KiB" }
            // The download is one canonical URI followed by a text-file line ending.
            importInvite(profileId, body.decodeToString().removeSuffix("\n").removeSuffix("\r"))
        }
    }

    fun reportImportError(profileId: String, error: Throwable) =
        fail(profileId, store(profileId), "读取加入文件失败", error)

    fun retry(profileId: String) =
        launch(profileId, "重试失败") { store -> resumeUnlocked(profileId, store) }

    fun refreshConfiguration(profileId: String) = launch(profileId, "配置更新失败") { store ->
        syncConfiguration(profileId, store, background = false)
    }

    /** Accept authenticated updates independently of the current VPN or business outcome. */
    suspend fun refreshConfigurationInBackground(profileId: String, round: Long): Boolean {
        requireProfileId(profileId)
        val store = store(profileId)
        return try {
            syncConfiguration(profileId, store, background = true, round = round)
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (error: Throwable) {
            currentCoroutineContext().ensureActive()
            fail(profileId, store, "配置更新失败", error)
            false
        }
    }

    private suspend fun syncConfiguration(profileId: String, store: ManagedProfileStore, background: Boolean, round: Long = 0): Boolean {
        val input = operation.withLock {
            if (!ProfileCatalog.get(appContext).contains(profileId)) return false
            val state = store.state()
            val digest = store.acceptedViewDigest()
            if (background && (state == null || digest.isEmpty())) return false
            checkNotNull(state) { "设备尚未加入" }
            check(digest.isNotEmpty()) { "设备尚未获得首份认证配置" }
            if (!background) {
                statusSink(profileId).let { status ->
                    status.value = status.value.copy(
                        phase = EnrollmentPhase.PULLING,
                        detail = "正在通过私有通道检查认证配置…",
                    )
                }
            }
            state to digest
        }
        val envelope = try {
            val request = Loomcore.newAndroidConfigurationRequest(input.first, background, round)
            privateCall(request::run, request::cancel)
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (error: Throwable) {
            currentCoroutineContext().ensureActive()
            if (background) return false // Keep the accepted LKG when its channel is unavailable.
            throw error
        }
        currentCoroutineContext().ensureActive()
        operation.withLock {
            if (!ProfileCatalog.get(appContext).contains(profileId) || store.acceptedViewDigest() != input.second) return true
            // Apply only the envelope to the latest record. In particular, a
            // report sequence reserved during the HTTP wait cannot be lost.
            val current = checkNotNull(store.state()) { "设备身份不存在" }
            val next = Loomcore.acceptAndroidCertifiedView(current, envelope)
            if (store.certifiedViewDigest(next) == input.second) {
                store.saveState(next)
                if (!background) ready(profileId, store.decodeProfile(next), "认证配置已是最新")
            } else {
                acceptCertifiedUnlocked(profileId, store, next)
            }
        }
        return true
    }

    fun abandonPending(profileId: String) = launch(profileId, "无法放弃待加入事务") { store ->
        operation.withLock {
            store.clearUncompletedIdentity()
            statusSink(profileId).value = EnrollmentStatus(EnrollmentPhase.NOT_JOINED, "已清除未完成的本机身份")
        }
    }

    fun currentProfile(profileId: String): ManagedProfile? = store(profileId).loadCurrent()

    internal fun prepareRuntimeProfile(profileId: String): ManagedProfile =
        store(profileId).prepareRuntime(readLocalInterfaceAddresses())

    internal suspend fun postReport(profileId: String) = reporting.withLock {
        val send = operation.withLock {
            check(ProfileCatalog.get(appContext).contains(profileId)) { "配置已删除" }
            val store = store(profileId)
            val acceptedView = store.acceptedViewDigest().also { check(it.isNotEmpty()) { "设备尚未获得认证配置" } }
            LoomVpnService.withRuntimeReport(profileId) { runtime, capturedAt ->
                val routing = RouteManager.get(appContext).reportData(
                    profileId, checkNotNull(store.state()), acceptedView, runtime.optString("applied_view_digest"),
                    runtime.optString("permission_view_digest"),
                )
                if (runtime.optString("state") == "running" && !routing.applicationComplete) {
                    runtime.put("state", "unknown").put("applied_view_digest", "").put("error_code", "runtime_apply_pending")
                }
                // The sequence and complete identity/LKG are one durable write. A
                // network failure burns this number; no stale handle can reuse it.
                val reserved = store.updateState(Loomcore::reserveAndroidReportSequence)
                val runtimeBytes = runtime.toString().encodeToByteArray()
                val transmit: suspend () -> Unit = {
                    val components = Loomcore.androidRuntimeComponents(appContext.packageCodePath, BuildConfig.LOOM_SOURCE_COMMIT, Libbox.version())
                    val addresses = readLocalInterfaceAddresses()
                    val observedAt = reportTimestamp(capturedAt)
                    val request = Loomcore.newAndroidReportRequest(
                        reserved, routing.preference, routing.resourceObservations, routing.observations, routing.selections, runtimeBytes,
                        components, addresses, routing.networkGeneration, observedAt,
                    )
                    privateCall(request::run, request::cancel)
                }
                transmit
            }
        }
        // Only the immutable signed report crosses the network. Enrollment,
        // configuration, profile deletion and VPN lifecycle own no HTTP wait.
        send()
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
        val input = operation.withLock {
            check(ProfileCatalog.get(appContext).contains(profileId)) { "配置已删除" }
            val repair = store.acceptedViewDigest().isNotEmpty() && runCatching { store.loadCurrent() }.isFailure
            if (!repair) {
                store.loadCurrent()?.let {
                    ready(profileId, it, "已从受保护存储恢复完整认证 LKG")
                    return
                }
            }
            val state = store.state()
            if (state == null) {
                statusSink(profileId).value = EnrollmentStatus(EnrollmentPhase.NOT_JOINED, "扫描中控二维码或导入加入文件")
                return
            }
            state to repair
        }
        if (input.second) syncConfiguration(profileId, store, background = false)
        else advanceUntilReady(profileId, store, input.first)
    }

    private suspend fun advanceUntilReady(profileId: String, store: ManagedProfileStore, initial: ByteArray) {
        var state = initial
        while (true) {
            currentCoroutineContext().ensureActive()
            val before = JSONObject(Loomcore.androidEnrollmentState(state).decodeToString())
            operation.withLock {
                if (!ProfileCatalog.get(appContext).contains(profileId) || store.state()?.contentEquals(state) != true) return
                statusSink(profileId).value = EnrollmentStatus(
                    phase = if (before.getBoolean("claimed")) EnrollmentPhase.WAITING else EnrollmentPhase.CLAIMING,
                    detail = if (before.getBoolean("claimed")) "正在恢复同一设备的认证配置…" else "正在通过私有通道提交设备身份…",
                    canAbandonPending = true,
                )
            }
            val next = try {
                val request = Loomcore.newAndroidEnrollmentRequest(state)
                privateCall(request::run, request::cancel)
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Throwable) {
                currentCoroutineContext().ensureActive()
                operation.withLock {
                    if (!ProfileCatalog.get(appContext).contains(profileId) || store.state()?.contentEquals(state) != true) return
                    statusSink(profileId).value = EnrollmentStatus(
                        EnrollmentPhase.WAITING,
                        "私有通道暂不可用；将重试同一身份",
                        canAbandonPending = true,
                        diagnostic = error.javaClass.simpleName,
                    )
                }
                delay(RETRY_MS)
                continue
            }
            currentCoroutineContext().ensureActive()
            val after = JSONObject(Loomcore.androidEnrollmentState(next).decodeToString())
            operation.withLock {
                if (!ProfileCatalog.get(appContext).contains(profileId) || store.state()?.contentEquals(state) != true) return
                if (after.getBoolean("ready")) {
                    acceptCertifiedUnlocked(profileId, store, next)
                    return
                }
                store.saveState(next)
                state = next
            }
            delay(RETRY_MS)
        }
    }

    // The caller owns the short commit operation, never a private network wait.
    private suspend fun acceptCertifiedUnlocked(profileId: String, store: ManagedProfileStore, body: ByteArray) {
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
            possiblePermissionRestoration = profile.possiblePermissionRestoration,
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
            guarded(profileId, store, prefix) { block(store) }
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
        if (!ProfileCatalog.get(appContext).contains(profileId)) return
        val accepted = runCatching { store.acceptedViewDigest() }.getOrDefault("")
        val runtime = VpnRuntime.status.value
        val preparationFailed = accepted.isNotEmpty() && (runCatching { store.loadCurrent() }.isFailure ||
            runtime.phase == ConnectionPhase.ERROR && runtime.requestedProfileId == profileId)
        statusSink(profileId).value = EnrollmentStatus(
            EnrollmentPhase.ERROR,
            "${if (preparationFailed) "已加入，认证配置已保存；运行未就绪" else if (accepted.isNotEmpty()) "已加入；$prefix" else prefix}：${error.message ?: error.javaClass.simpleName}",
            viewDigest = accepted,
            possiblePermissionRestoration = runCatching { store.possiblePermissionRestoration() }.getOrDefault(false),
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
        return ManagedProfileStore.get(appContext, profileId)
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
