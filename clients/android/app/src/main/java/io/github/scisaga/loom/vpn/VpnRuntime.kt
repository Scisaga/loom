package io.github.scisaga.loom.vpn

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

enum class ConnectionPhase { DISCONNECTED, STARTING, CONNECTED, STOPPING, ERROR }

data class VpnStatus(
    val phase: ConnectionPhase = ConnectionPhase.DISCONNECTED,
    val detail: String = "未连接",
    val requestedProfileId: String = "",
    val activeProfileId: String = "",
    val deviceName: String = "",
    val viewDigest: String = "",
    val dnsProbe: String = "未检查",
    val httpsProbe: String = "未检查",
    val trustedReport: String = "未上报",
    val alwaysOn: Boolean = false,
)

object VpnRuntime {
    private val mutable = MutableStateFlow(VpnStatus())
    val status = mutable.asStateFlow()

    fun update(value: VpnStatus) {
        mutable.value = value
    }

    fun transform(block: (VpnStatus) -> VpnStatus) {
        mutable.value = block(mutable.value)
    }
}

/** The authentication write and runtime stop have independent outcomes; both are attempted. */
internal suspend fun <T> acceptAuthorityAndStopRuntime(
    accept: () -> T,
    canRetainExecution: suspend (T) -> Boolean = { false },
    stop: suspend () -> Unit,
): Pair<Result<T>, Result<Unit>> {
    val accepted = runCatching(accept)
    val retain = accepted.isSuccess && runCatching { canRetainExecution(accepted.getOrThrow()) }.getOrDefault(false)
    val stopped = runCatching { if (!retain) stop() }
    return accepted to stopped
}

/** An execution reply is a disposable readback, separate from accepted authority. */
internal data class RuntimeAuthorizationResult(
    val supported: Boolean,
    val permissionCurrent: Boolean,
    val resourcesReady: Boolean,
    val config: String,
) {
    init {
        require(!resourcesReady || permissionCurrent) { "resource completion lacks current permission" }
        require(!permissionCurrent || supported && config.isNotBlank()) { "current permission lacks its execution projection" }
    }

    val retainExecution: Boolean get() = supported && permissionCurrent
}

internal fun runtimeReportState(activeRuntime: Boolean, resourcesReady: Boolean, failed: Boolean): String = when {
    activeRuntime && resourcesReady -> "running"
    activeRuntime -> "unknown"
    failed -> "error"
    else -> "stopped"
}

internal fun runtimeReportPermissionViewDigest(activeView: String?, permissionCurrent: Boolean): String =
    if (permissionCurrent) activeView.orEmpty() else ""

internal fun shouldRetryRuntimeResources(permissionCurrent: Boolean, resourcesReady: Boolean): Boolean =
    permissionCurrent && !resourcesReady

internal suspend fun <S, T> withRuntimeReportSnapshot(lock: Mutex, capture: () -> S, send: suspend (S) -> T): T {
    val snapshot = lock.withLock { capture() }
    return send(snapshot)
}

internal suspend fun confirmInitialSelection(
    lock: Mutex,
    ready: suspend () -> Boolean,
    isCurrent: () -> Boolean,
    connected: suspend () -> Unit,
) {
    // Selection work cannot own the lifecycle lock used by stop and reports.
    if (!ready()) return
    currentCoroutineContext().ensureActive()
    lock.withLock { if (isCurrent()) connected() }
}
