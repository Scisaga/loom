package io.github.scisaga.loom.debug

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import androidx.core.content.ContextCompat
import io.github.scisaga.loom.BuildConfig
import io.github.scisaga.loom.LoomApplication
import io.github.scisaga.loom.enrollment.EnrollmentManager
import io.github.scisaga.loom.enrollment.V2DeviceStateStore
import io.github.scisaga.loom.profiles.ProfileCatalog
import io.github.scisaga.loom.readBounded
import io.github.scisaga.loom.route.RouteManager
import io.github.scisaga.loom.route.RouteMode
import io.github.scisaga.loom.vpn.LoomVpnService
import io.github.scisaga.loom.vpn.NetworkProbe
import io.github.scisaga.loom.vpn.ProbeSession
import io.github.scisaga.loom.vpn.VpnRuntime
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/** ADB-only control surface for physical-device data-plane acceptance. */
class DebugVpnControlReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        check(BuildConfig.DEBUG) { "debug VPN control is unavailable in release builds" }
        if (intent.action == ACTION_IMPORT_INVITE) {
            importPendingInvite(context)
            return
        }
        if (intent.action == ACTION_RETRY_ENROLLMENT) {
            EnrollmentManager.get(context).retry()
            return
        }
        if (intent.action == ACTION_ABANDON_PENDING) {
            EnrollmentManager.get(context).abandonPending()
            return
        }
        if (intent.action == ACTION_ENROLLMENT_STATUS) {
            val status = EnrollmentManager.get(context).status.value
            resultData = buildString {
                append("phase=").append(status.phase.name)
                append(";abandonable=").append(status.canAbandonPending)
                append(";snapshot=").append(status.snapshot.isNotEmpty())
                append(";generation=").append(status.generation)
                append(";protocol=").append(status.protocol)
                append(";diagnostic=").append(status.diagnostic.ifEmpty { "none" })
            }
            return
        }
        if (intent.action == ACTION_ROUTE_STATUS) {
            val status = RouteManager.get(context).status.value
            resultData = buildString {
                append("available=").append(status.available)
                append(";running=").append(status.running)
                append(";busy=").append(status.busy)
                append(";blocked=").append(status.blocked)
                append(";mode=").append(status.mode.wire)
                append(";exitIndex=").append(status.exits.indexOf(status.exit))
                append(";exits=").append(status.exits.size)
                append(";paths=").append(status.currentPaths.size)
                append(";detail=").append(status.detail)
            }
            return
        }
        if (intent.action == ACTION_RUNTIME_STATUS) {
            val status = VpnRuntime.status.value
            resultData = buildString {
                append("phase=").append(status.phase.name)
                append(";dns=").append(status.dnsProbe)
                append(";https=").append(status.httpsProbe)
                append(";report=").append(status.trustedReport)
                append(";alwaysOn=").append(status.alwaysOn)
            }
            return
        }
        if (intent.action == ACTION_PROBE_REGISTRY_STATUS) {
            val status = (context.applicationContext as LoomApplication).underlayProbeRegistry.debugState()
            resultData = buildString {
                append("generation=").append(status.generation)
                append(";activeProbeRounds=").append(status.activeProbeRounds)
                append(";frozen=").append(status.frozenFingerprint.isNotEmpty())
                append(";fingerprint=").append(status.frozenFingerprint.ifEmpty { "none" })
            }
            return
        }
        if (intent.action == ACTION_BUSINESS_PROBE) {
            val generation = ++businessProbeGeneration
            val session = ProbeSession()
            businessProbeSession?.cancel()
            businessProbeSession = session
            lastBusinessProbe = "running"
            VpnRuntime.transform {
                it.copy(dnsProbe = "执行中", httpsProbe = "执行中")
            }
            businessProbeScope.launch {
                val result = runCatching { NetworkProbe.run(session) }.getOrNull() ?: return@launch
                if (businessProbeGeneration != generation) return@launch
                lastBusinessProbe = "dns=${result.dns};https=${result.https}"
                VpnRuntime.transform {
                    it.copy(dnsProbe = result.dns, httpsProbe = result.https)
                }
            }
            return
        }
        if (intent.action == ACTION_BUSINESS_PROBE_STATUS) {
            resultData = lastBusinessProbe
            return
        }
        if (intent.action == ACTION_EGRESS_PROBE) {
            val generation = ++egressProbeGeneration
            lastEgressProbe = "running"
            businessProbeScope.launch {
                val result = runCatching {
                    val connection = URL(EGRESS_URL).openConnection() as HttpURLConnection
                    connection.connectTimeout = EGRESS_TIMEOUT_MS
                    connection.readTimeout = EGRESS_TIMEOUT_MS
                    connection.useCaches = false
                    try {
                        check(connection.responseCode == 200) { "出口回读未成功" }
                        val value = connection.inputStream.use { readBounded(it, MAX_EGRESS_BYTES) }
                            .decodeToString().trim()
                        check(value.length in 3..45 && value.all { it.isDigit() || it in "abcdefABCDEF:." }) {
                            "出口回读格式无效"
                        }
                        "sha256:${digest(value.encodeToByteArray())}"
                    } finally {
                        connection.disconnect()
                    }
                }.getOrElse { "failed:${it.javaClass.simpleName}" }
                if (egressProbeGeneration == generation) lastEgressProbe = result
            }
            return
        }
        if (intent.action == ACTION_EGRESS_PROBE_STATUS) {
            resultData = lastEgressProbe
            return
        }
        if (intent.action == ACTION_DURABLE_STATE_STATUS) {
            val store = V2DeviceStateStore(ProfileCatalog.scoped(context))
            resultData = "state=${store.current()?.let { digest(it) } ?: "missing"};floors=${store.floors()?.let { digest(it) } ?: "missing"}"
            return
        }
        if (intent.action == ACTION_ROUTE_SAVE_AND_DIRECT) {
            RouteManager.get(context).status.value.let {
                savedRoutePreference = it.mode to it.exit
            }
            RouteManager.get(context).select(RouteMode.DIRECT)
            return
        }
        if (intent.action == ACTION_ROUTE_RESTORE) {
            savedRoutePreference?.let { (mode, exit) ->
                RouteManager.get(context).select(mode, exit)
            }
            return
        }
        if (intent.action == ACTION_ROUTE_FIXED_EXIT_INDEX) {
            val status = RouteManager.get(context).status.value
            val index = intent.getIntExtra(EXTRA_EXIT_INDEX, -1)
            require(index in status.exits.indices) { "固定出口索引无效" }
            RouteManager.get(context).select(RouteMode.FIXED_EXIT, status.exits[index])
            return
        }
        if (intent.action == ACTION_ROUTE_DIRECT || intent.action == ACTION_ROUTE_AUTO) {
            RouteManager.get(context).select(
                if (intent.action == ACTION_ROUTE_DIRECT) RouteMode.DIRECT else RouteMode.AUTO,
            )
            return
        }
        val serviceAction = when (intent.action) {
            ACTION_CONNECT -> LoomVpnService.ACTION_CONNECT
            ACTION_ENROLLMENT_KEEPALIVE -> LoomVpnService.ACTION_ENROLLMENT_KEEPALIVE
            ACTION_DISCONNECT -> LoomVpnService.ACTION_DISCONNECT
            else -> return
        }
        ContextCompat.startForegroundService(
            context,
            Intent(context, LoomVpnService::class.java).setAction(serviceAction),
        )
    }

    private fun importPendingInvite(context: Context) {
        val manager = EnrollmentManager.get(context)
        var pending: File? = null
        val result = runCatching {
            pending = File(
                checkNotNull(context.getExternalFilesDir(null)) { "external app storage is unavailable" },
                PENDING_INVITE,
            )
            val file = checkNotNull(pending)
            require(file.isFile) { "pending debug invitation is missing" }
            val body = file.inputStream().use { readBounded(it, MAX_INVITE_BYTES) }
            require(body.isNotEmpty() && body.size <= MAX_INVITE_BYTES) {
                "debug invitation must be between 1 byte and 16 KiB"
            }
            val raw = body.decodeToString()
            check(file.delete()) { "cannot remove pending debug invitation" }
            raw
        }
        if (result.isFailure) pending?.delete()
        result.onSuccess(manager::importInvite).onFailure(manager::reportImportError)
    }

    companion object {
        const val ACTION_CONNECT = "io.github.scisaga.loom.debug.CONNECT"
        const val ACTION_ENROLLMENT_KEEPALIVE = "io.github.scisaga.loom.debug.ENROLLMENT_KEEPALIVE"
        const val ACTION_DISCONNECT = "io.github.scisaga.loom.debug.DISCONNECT"
        const val ACTION_IMPORT_INVITE = "io.github.scisaga.loom.debug.IMPORT_INVITE"
        const val ACTION_RETRY_ENROLLMENT = "io.github.scisaga.loom.debug.RETRY_ENROLLMENT"
        const val ACTION_ABANDON_PENDING = "io.github.scisaga.loom.debug.ABANDON_PENDING"
        const val ACTION_ENROLLMENT_STATUS = "io.github.scisaga.loom.debug.ENROLLMENT_STATUS"
        const val ACTION_ROUTE_STATUS = "io.github.scisaga.loom.debug.ROUTE_STATUS"
        const val ACTION_RUNTIME_STATUS = "io.github.scisaga.loom.debug.RUNTIME_STATUS"
        const val ACTION_PROBE_REGISTRY_STATUS = "io.github.scisaga.loom.debug.PROBE_REGISTRY_STATUS"
        const val ACTION_BUSINESS_PROBE = "io.github.scisaga.loom.debug.BUSINESS_PROBE"
        const val ACTION_BUSINESS_PROBE_STATUS = "io.github.scisaga.loom.debug.BUSINESS_PROBE_STATUS"
        const val ACTION_EGRESS_PROBE = "io.github.scisaga.loom.debug.EGRESS_PROBE"
        const val ACTION_EGRESS_PROBE_STATUS = "io.github.scisaga.loom.debug.EGRESS_PROBE_STATUS"
        const val ACTION_DURABLE_STATE_STATUS = "io.github.scisaga.loom.debug.DURABLE_STATE_STATUS"
        const val ACTION_ROUTE_DIRECT = "io.github.scisaga.loom.debug.ROUTE_DIRECT"
        const val ACTION_ROUTE_AUTO = "io.github.scisaga.loom.debug.ROUTE_AUTO"
        const val ACTION_ROUTE_SAVE_AND_DIRECT = "io.github.scisaga.loom.debug.ROUTE_SAVE_AND_DIRECT"
        const val ACTION_ROUTE_RESTORE = "io.github.scisaga.loom.debug.ROUTE_RESTORE"
        const val ACTION_ROUTE_FIXED_EXIT_INDEX = "io.github.scisaga.loom.debug.ROUTE_FIXED_EXIT_INDEX"
        const val EXTRA_EXIT_INDEX = "exit_index"
        private const val PENDING_INVITE = "pending.loom-invite"
        private const val MAX_INVITE_BYTES = 16 * 1024
        private const val MAX_EGRESS_BYTES = 64
        private const val EGRESS_TIMEOUT_MS = 10_000
        private const val EGRESS_URL = "https://api.ipify.org/"
        private val businessProbeScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        @Volatile private var lastBusinessProbe = "not-run"
        @Volatile private var businessProbeGeneration = 0L
        @Volatile private var businessProbeSession: ProbeSession? = null
        @Volatile private var egressProbeGeneration = 0L
        @Volatile private var lastEgressProbe = "not-run"
        private var savedRoutePreference: Pair<RouteMode, String>? = null

        private fun digest(value: ByteArray): String = MessageDigest.getInstance("SHA-256")
            .digest(value).joinToString("") { "%02x".format(it) }
    }
}
