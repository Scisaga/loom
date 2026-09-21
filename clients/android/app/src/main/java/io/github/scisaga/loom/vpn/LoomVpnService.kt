package io.github.scisaga.loom.vpn

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.IpPrefix
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.provider.Settings
import android.system.OsConstants
import android.util.Log
import androidx.annotation.RequiresApi
import androidx.core.app.NotificationCompat
import androidx.core.content.getSystemService
import io.github.scisaga.libbox.BoxService
import io.github.scisaga.libbox.InterfaceUpdateListener
import io.github.scisaga.libbox.Libbox
import io.github.scisaga.libbox.NetworkInterface as BoxNetworkInterface
import io.github.scisaga.libbox.NetworkInterfaceIterator
import io.github.scisaga.libbox.Notification
import io.github.scisaga.libbox.PlatformInterface
import io.github.scisaga.libbox.TunOptions
import io.github.scisaga.libbox.WIFIState
import io.github.scisaga.loom.MainActivity
import io.github.scisaga.loom.R
import io.github.scisaga.loom.enrollment.EnrollmentManager
import io.github.scisaga.loom.enrollment.HealthReporter
import io.github.scisaga.loom.enrollment.ManagedProfile
import io.github.scisaga.loom.profiles.ProfileCatalog
import io.github.scisaga.loom.route.RouteManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.net.InetSocketAddress
import java.net.InetAddress
import java.net.NetworkInterface
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap

internal data class RankedUnderlying<T>(
    val value: T,
    val rank: Int,
    val stableID: String,
)

internal fun <T> selectStableUnderlying(candidates: List<RankedUnderlying<T>>, current: T?): T? {
    val bestRank = candidates.maxOfOrNull(RankedUnderlying<T>::rank) ?: return null
    return candidates.firstOrNull { it.value == current && it.rank == bestRank }?.value
        ?: candidates.asSequence().filter { it.rank == bestRank }.minBy { it.stableID }.value
}

internal fun underlyingNetworkRank(
    validated: Boolean,
    notSuspended: Boolean,
    unmetered: Boolean,
    transportPriority: Int,
): Int? {
    if (!notSuspended) return null
    require(transportPriority in 1..4) { "underlying transport priority is invalid" }
    return (if (validated) 1_000 else 0) + (if (unmetered) 10 else 0) + transportPriority
}

internal fun networkGenerationIdentity(bootCount: Int, networkHandle: Long): String = "$bootCount:$networkHandle"

internal class UnderlyingPublicationTracker<T> {
    private var published: T? = null

    fun builderBound(value: T?) {
        published = value
    }

    fun needsRuntimePublish(value: T?): Boolean = published != value

    fun runtimePublished(value: T?) {
        published = value
    }

    fun clear() {
        published = null
    }
}

class LoomVpnService : VpnService(), PlatformInterface {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val lifecycle = Mutex()
    private val monitors = ConcurrentHashMap<InterfaceUpdateListener, UnderlyingMonitor>()
    private val underlyingPublicationLock = Any()
    private val underlyingPublication = UnderlyingPublicationTracker<Network>()
    private val connectivity by lazy { getSystemService<ConnectivityManager>()!! }
    private var boxService: BoxService? = null
    @Volatile private var tunnel: ParcelFileDescriptor? = null
    private var reportJob: Job? = null
    @Volatile private var sessionID = 0L
    @Volatile private var desiredProfileId = ""
    @Volatile private var runtimeProfileId = ""
    @Volatile private var activeProbe: ProbeSession? = null
    @Volatile private var selectedUnderlyingNetwork: Network? = null
    @Volatile private var activeManagedProfile: ManagedProfile? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        VpnRuntime.transform { it.copy(alwaysOn = alwaysOnEnabled()) }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (boxService == null) startForeground(NOTIFICATION_ID, foregroundNotification("正在准备…"))
        when (intent?.action) {
            null, SERVICE_INTERFACE -> {
                // §8.3：sticky 重建与系统 always-on 启动都没有应用自定义 action。
                val restored = restoredProfileId()
                    ?: return rejectConnectionStart(startId, "没有可恢复的连接配置")
                desiredProfileId = restored
                projectConnectionRequest(restored, "正在恢复连接…")
                scope.launch { startTunnel(restored) }
            }
            ACTION_CONNECT -> {
                val requested = intent.getStringExtra(EXTRA_PROFILE_ID).orEmpty()
                if (!ProfileCatalog.get(this).contains(requested)) {
                    return rejectConnectionStart(startId, "连接配置不存在")
                }
                val previousDesired = desiredProfileId
                VpnConnectionPreference(this).save(true, requested)
                desiredProfileId = requested
                projectConnectionRequest(requested, "正在准备连接…")
                if (requested != previousDesired || requested != runtimeProfileId) activeProbe?.cancel()
                scope.launch { startTunnel(requested) }
            }
            ACTION_RELOAD -> {
                val candidateID = intent?.getStringExtra(EXTRA_CANDIDATE_ID).orEmpty()
                val profileID = intent?.getStringExtra(EXTRA_PROFILE_ID).orEmpty()
                scope.launch { reloadTunnel(profileID, candidateID, startId) }
            }
            ACTION_SYNC_SYSTEM_POLICY -> {
                val alwaysOn = alwaysOnEnabled()
                VpnRuntime.transform { it.copy(alwaysOn = alwaysOn) }
                if (desiredProfileId.isBlank() && boxService == null && tunnel == null) {
                    stopIdleForeground(startId)
                } else {
                    val detail = VpnRuntime.status.value.detail
                    updateNotification(if (alwaysOn) "始终开启 · $detail" else detail)
                }
            }
            ACTION_DISCONNECT -> {
                if (!shouldOfferAppDisconnect(alwaysOnEnabled())) {
                    // Android 的始终开启策略是期望态来源；应用内断开不能与系统策略对打。
                    desiredProfileId = desiredProfileId
                        .takeIf(ProfileCatalog.get(this)::contains)
                        ?: runtimeProfileId.takeIf(ProfileCatalog.get(this)::contains)
                        ?: restoredProfileId()
                        ?: return rejectConnectionStart(startId, "始终开启 VPN 没有可用的连接配置")
                    VpnConnectionPreference(this).save(true, desiredProfileId)
                    VpnRuntime.transform { it.copy(alwaysOn = true) }
                    updateNotification("始终开启 · ${VpnRuntime.status.value.detail}")
                    if (boxService == null) {
                        val profileID = desiredProfileId
                        projectConnectionRequest(profileID, "正在恢复始终开启 VPN…")
                        scope.launch { startTunnel(profileID) }
                    }
                } else {
                    VpnConnectionPreference(this).save(false, desiredProfileId)
                    desiredProfileId = ""
                    activeProbe?.cancel()
                    scope.launch { stopTunnel(stopStartId = startId) }
                }
            }
            else -> stopIdleForeground(startId)
        }
        // §8.3：连接是用户明确发出的长期请求；主动断开已在返回前清除该请求。
        return vpnServiceRestartMode(desiredProfileId.isNotBlank())
    }

    override fun onBind(intent: Intent): IBinder? = super.onBind(intent)

    override fun onRevoke() {
        VpnConnectionPreference(this).save(false, desiredProfileId)
        desiredProfileId = ""
        activeProbe?.cancel()
        scope.launch {
            stopTunnel()
            stopSelf()
        }
    }

    override fun onDestroy() {
        desiredProfileId = ""
        activeProbe?.cancel()
        runBlocking(Dispatchers.IO) { stopTunnel() }
        scope.cancel()
        super.onDestroy()
    }

    private suspend fun startTunnel(profileID: String) = lifecycle.withLock {
        if (!connectionWanted(profileID)) return@withLock
        if (boxService != null && runtimeProfileId == profileID) return@withLock
        if (boxService != null || tunnel != null) closeResources()
        startTunnelLocked(profileID)
    }

    private suspend fun reloadTunnel(profileID: String, candidateID: String, startId: Int) = lifecycle.withLock {
        if (profileID != desiredProfileId || candidateID.isBlank()) {
            stopIdleForeground(startId)
            return@withLock
        }
        val pending = runCatching { EnrollmentManager.get(this).candidateProfile(profileID) }.getOrNull()
        if (pending?.recordID != candidateID) {
            stopIdleForeground(startId)
            return@withLock
        }
        closeResources()
        if (connectionWanted(profileID)) startTunnelLocked(profileID)
    }

    private suspend fun startTunnelLocked(profileID: String) {
        val catalog = ProfileCatalog.get(this)
        check(catalog.contains(profileID)) { "连接配置不存在" }
        runtimeProfileId = profileID
        // A queued disconnect may have removed foreground state while a newer
        // connect command was waiting for the lifecycle mutex.
        VpnRuntime.update(
            VpnStatus(
                phase = ConnectionPhase.STARTING,
                detail = "正在验签并建立 TUN…",
                requestedProfileId = profileID,
                alwaysOn = alwaysOnEnabled(),
            ),
        )
        startForeground(NOTIFICATION_ID, foregroundNotification("正在连接…"))
        try {
            val manager = EnrollmentManager.get(this)
            val candidate = manager.candidateProfile(profileID)
            if (candidate != null) {
                try {
                    val probe = activateAndProbe(profileID, candidate)
                    ensureConnectionWanted(profileID)
                    val committed = manager.candidateActivated(profileID, candidate)
                    connected(profileID, committed, probe, "新认证配置已验证并激活")
                    return
                } catch (cancelled: CancellationException) {
                    closeResources()
                    throw cancelled
                } catch (candidateError: Throwable) {
                    Log.e(TAG, "candidate activation rejected", candidateError)
                    closeResources()
                    ensureConnectionWanted(profileID)
                    runtimeProfileId = profileID
                    val fallback = manager.candidateRejected(profileID, candidate, "真实 DNS/HTTPS 未通过")
                    if (fallback != null) {
                        val probe = activateAndProbe(profileID, fallback)
                        ensureConnectionWanted(profileID)
                        connected(profileID, fallback, probe, "新配置验证失败，已继续使用最后可用配置")
                        return
                    }
                    throw candidateError
                }
            }

            val current = manager.currentProfile(profileID)
            if (current != null) {
                val probe = activateAndProbe(profileID, current)
                ensureConnectionWanted(profileID)
                connected(profileID, current, probe, "认证配置已激活")
                return
            }
            error("请先通过私有 Enrollment 完成正式入网")
        } catch (error: Throwable) {
            Log.e(TAG, "start tunnel", error)
            closeResources()
            if (!connectionWanted(profileID)) return
            VpnConnectionPreference(this).save(false, profileID)
            desiredProfileId = ""
            VpnRuntime.update(
                VpnStatus(
                    phase = ConnectionPhase.ERROR,
                    detail = error.message ?: error.javaClass.simpleName,
                    requestedProfileId = profileID,
                    alwaysOn = alwaysOnEnabled(),
                ),
            )
            updateNotification("连接失败")
            stopForegroundCompat()
            stopSelf()
        }
    }

    private suspend fun activateAndProbe(profileID: String, profile: ManagedProfile): ProbeResult {
        ensureConnectionWanted(profileID)
        val routing = RouteManager.get(this)
        val active = connectivity.activeNetwork
        val activeCapabilities = active?.let(connectivity::getNetworkCapabilities)
        routing.beginNetworkGeneration(
            profileID,
            active?.takeIf { activeCapabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) == true }
                ?.let(::networkGenerationIdentity),
        )
        ensureConnectionWanted(profileID)
        activate(profile.config)
        ensureConnectionWanted(profileID)
        val before = routing.applyToRunning(profileID, profile)
        ensureConnectionWanted(profileID)
        var probe = runBusinessProbe(profileID)
        val after = routing.recordBusinessOutcome(profileID, profile, probe)
        ensureConnectionWanted(profileID)
        if (!probe.healthy) {
            check(after.selectors.map { it.candidate } != before.selectors.map { it.candidate }) {
                "真实 DNS/HTTPS 失败且没有可用 fallback"
            }
            probe = runBusinessProbe(profileID)
            routing.recordBusinessOutcome(profileID, profile, probe)
            ensureConnectionWanted(profileID)
        }
        check(probe.healthy) { "TUN 已启动，但真实 DNS/HTTPS 端到端结果不可用" }
        return probe
    }

    private suspend fun runBusinessProbe(profileID: String): ProbeResult {
        val probeSession = ProbeSession()
        activeProbe = probeSession
        val probe = try {
            NetworkProbe.run(probeSession)
        } finally {
            if (activeProbe === probeSession) activeProbe = null
        }
        ensureConnectionWanted(profileID)
        VpnRuntime.transform { it.copy(dnsProbe = probe.dns, httpsProbe = probe.https) }
        return probe
    }

    private fun connectionWanted(profileID: String): Boolean =
        profileID.isNotBlank() && desiredProfileId == profileID

    private fun projectConnectionRequest(profileID: String, detail: String) {
        VpnRuntime.transform { current ->
            val switching = current.activeProfileId.isNotBlank() && current.activeProfileId != profileID
            current.copy(
                phase = if (current.phase == ConnectionPhase.CONNECTED && current.activeProfileId.isNotBlank()) {
                    ConnectionPhase.CONNECTED
                } else {
                    ConnectionPhase.STARTING
                },
                requestedProfileId = profileID,
                detail = if (switching) "正在切换连接配置…" else detail,
            )
        }
    }

    private fun ensureConnectionWanted(profileID: String) {
        if (!connectionWanted(profileID)) throw CancellationException("连接请求已取消或已切换")
    }

    private fun connected(profileID: String, profile: ManagedProfile, probe: ProbeResult, detail: String) {
        ensureConnectionWanted(profileID)
        VpnRuntime.update(
            VpnStatus(
                phase = ConnectionPhase.CONNECTED,
                detail = detail,
                requestedProfileId = profileID,
                activeProfileId = profileID,
                deviceName = profile.deviceName,
                generation = profile.generation,
                dnsProbe = probe.dns,
                httpsProbe = probe.https,
                alwaysOn = alwaysOnEnabled(),
            ),
        )
        updateNotification("已连接 · $detail")
        activeManagedProfile = profile
        startReporter(profileID)
    }

    private fun activate(config: String) {
        // libbox can register its interface monitor synchronously from start().
        // Publish the new generation first so those callbacks belong to this
        // service instance instead of becoming stale as soon as start returns.
        sessionID++
        val candidate = Libbox.newService(config, this)
        boxService = candidate
        candidate.start()
    }

    private fun startReporter(profileID: String) {
        reportJob?.cancel()
        val reporterSession = sessionID
        reportJob = scope.launch {
            val reporter = HealthReporter(this@LoomVpnService, profileID)
            while (isActive && reporterSession == sessionID) {
                val status = VpnRuntime.status.value
                if (status.phase != ConnectionPhase.CONNECTED) return@launch
                val report = runCatching { reporter.send() }
                if (!isActive || reporterSession != sessionID) return@launch
                if (report.isSuccess) {
                    VpnRuntime.transform { it.copy(trustedReport = "签名上报成功") }
                } else {
                    VpnRuntime.transform { it.copy(trustedReport = "失败；将重试") }
                }
                // Fetching a newer certified view only stages a candidate.
                // The service reload path below remains the sole place that
                // can promote it after libbox, selector and business readback.
                EnrollmentManager.get(this@LoomVpnService).refreshConfigurationInBackground(profileID)
                delay(REPORT_INTERVAL_MS)
            }
        }
    }

    private suspend fun stopTunnel(stopStartId: Int? = null) = lifecycle.withLock {
        if (stopStartId != null && desiredProfileId.isNotBlank()) return@withLock
        if (boxService == null && tunnel == null) {
            VpnRuntime.update(VpnStatus())
        } else {
            VpnRuntime.transform { it.copy(phase = ConnectionPhase.STOPPING, detail = "正在释放网络资源…") }
            closeResources()
            VpnRuntime.update(VpnStatus())
        }
        // Only remove foreground state when this stop is still the newest
        // command. A newer queued connect must inherit a valid foreground
        // service until startTunnelLocked refreshes its notification.
        if (stopStartId == null) {
            stopForegroundCompat()
        } else if (stopSelfResult(stopStartId)) {
            stopForegroundCompat()
        }
    }

    private suspend fun closeResources() {
        val stoppedProfileId = runtimeProfileId
        sessionID++
        activeProbe?.cancel()
        activeProbe = null
        reportJob?.cancel()
        reportJob = null
        activeManagedProfile = null
        monitors.entries.toList().forEach { (listener, monitor) ->
            removeUnderlyingMonitor(listener, monitor)
        }
        selectedUnderlyingNetwork = null
        synchronized(underlyingPublicationLock) { underlyingPublication.clear() }
        if (stoppedProfileId.isNotBlank()) RouteManager.get(this).tunnelStopped(stoppedProfileId)
        runCatching { boxService?.close() }.onFailure { Log.w(TAG, "close libbox", it) }
        boxService = null
        runCatching { tunnel?.close() }.onFailure { Log.w(TAG, "close tun", it) }
        tunnel = null
        runtimeProfileId = ""
    }

    private fun stopForegroundCompat() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) stopForeground(STOP_FOREGROUND_REMOVE) else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }
    }

    private fun stopIdleForeground(startId: Int) {
        if (desiredProfileId.isBlank() && boxService == null && tunnel == null && stopSelfResult(startId)) {
            stopForegroundCompat()
        }
    }

    override fun usePlatformAutoDetectInterfaceControl(): Boolean = true

    override fun autoDetectInterfaceControl(fd: Int) {
        check(protect(fd)) { "android: protect libbox socket failed" }
    }

    override fun openTun(options: TunOptions): Int {
        check(prepare(this) == null) { "android: missing VPN permission" }
        check(tunnel == null) { "android: TUN already open" }
        check(!options.includePackage.hasNext() && !options.excludePackage.hasNext()) {
            "[Stage 1] package routing is not enabled"
        }

        val sessionName = runtimeProfileId.takeIf(String::isNotBlank)
            ?.let { runCatching { ProfileCatalog.get(this).name(it) }.getOrNull() }
            ?.let { "Loom · $it" }
            ?: "Loom"
        val builder = Builder().setSession(sessionName).setMtu(options.mtu)
        val builderUnderlying = selectedUnderlyingNetwork
        builderUnderlying?.let { builder.setUnderlyingNetworks(arrayOf(it)) }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) builder.setMetered(false)

        val addressFamilies = addAddresses(builder, options)
        if (options.autoRoute) {
            options.dnsServerAddress?.value?.takeIf { it.isNotBlank() }?.let(builder::addDnsServer)
            addRoutes(builder, options, addressFamilies)
        }
        val descriptor = checkNotNull(builder.establish()) { "android: VPN permission revoked while opening TUN" }
        synchronized(underlyingPublicationLock) { underlyingPublication.builderBound(builderUnderlying) }
        tunnel = descriptor
        publishUnderlyingNetwork(selectedUnderlyingNetwork)
        return descriptor.fd
    }

    private fun addAddresses(builder: Builder, options: TunOptions): TunAddressFamilies {
        var hasIPv4 = false
        val ipv4 = options.inet4Address
        while (ipv4.hasNext()) ipv4.next().also {
            hasIPv4 = true
            builder.addAddress(it.address(), it.prefix())
        }
        var hasIPv6 = false
        val ipv6 = options.inet6Address
        while (ipv6.hasNext()) ipv6.next().also {
            hasIPv6 = true
            builder.addAddress(it.address(), it.prefix())
        }
        return TunAddressFamilies(ipv4 = hasIPv4, ipv6 = hasIPv6)
    }

    private fun addRoutes(builder: Builder, options: TunOptions, families: TunAddressFamilies) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            var hasIPv4Route = false
            val ipv4 = options.inet4RouteAddress
            while (ipv4.hasNext()) ipv4.next().also {
                hasIPv4Route = true
                builder.addRoute(IpPrefix(InetAddress.getByName(it.address()), it.prefix()))
            }
            if (requiresDefaultRoute(families.ipv4, hasIPv4Route)) builder.addRoute("0.0.0.0", 0)

            var hasIPv6Route = false
            val ipv6 = options.inet6RouteAddress
            while (ipv6.hasNext()) ipv6.next().also {
                hasIPv6Route = true
                builder.addRoute(IpPrefix(InetAddress.getByName(it.address()), it.prefix()))
            }
            if (requiresDefaultRoute(families.ipv6, hasIPv6Route)) builder.addRoute("::", 0)

            val exclude4 = options.inet4RouteExcludeAddress
            while (exclude4.hasNext()) exclude4.next().also {
                builder.excludeRoute(IpPrefix(InetAddress.getByName(it.address()), it.prefix()))
            }
            val exclude6 = options.inet6RouteExcludeAddress
            while (exclude6.hasNext()) exclude6.next().also {
                builder.excludeRoute(IpPrefix(InetAddress.getByName(it.address()), it.prefix()))
            }
        } else {
            var hasIPv4Route = false
            val ipv4 = options.inet4RouteRange
            while (ipv4.hasNext()) ipv4.next().also {
                hasIPv4Route = true
                builder.addRoute(it.address(), it.prefix())
            }
            if (requiresDefaultRoute(families.ipv4, hasIPv4Route)) builder.addRoute("0.0.0.0", 0)

            var hasIPv6Route = false
            val ipv6 = options.inet6RouteRange
            while (ipv6.hasNext()) ipv6.next().also {
                hasIPv6Route = true
                builder.addRoute(it.address(), it.prefix())
            }
            if (requiresDefaultRoute(families.ipv6, hasIPv6Route)) builder.addRoute("::", 0)
        }
    }

    private data class TunAddressFamilies(val ipv4: Boolean, val ipv6: Boolean)

    override fun useProcFS(): Boolean = Build.VERSION.SDK_INT < Build.VERSION_CODES.Q

    override fun findConnectionOwner(
        ipProtocol: Int,
        sourceAddress: String,
        sourcePort: Int,
        destinationAddress: String,
        destinationPort: Int,
    ): Int {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            error("connection owner needs Android 10")
        }
        return findConnectionOwnerApi29(
            ipProtocol,
            sourceAddress,
            sourcePort,
            destinationAddress,
            destinationPort,
        )
    }

    @RequiresApi(Build.VERSION_CODES.Q)
    private fun findConnectionOwnerApi29(
        ipProtocol: Int,
        sourceAddress: String,
        sourcePort: Int,
        destinationAddress: String,
        destinationPort: Int,
    ): Int {
        val uid = connectivity.getConnectionOwnerUid(
            ipProtocol,
            InetSocketAddress(sourceAddress, sourcePort),
            InetSocketAddress(destinationAddress, destinationPort),
        )
        check(uid >= 0) { "android: connection owner not found" }
        return uid
    }

    override fun packageNameByUid(uid: Int): String =
        packageManager.getPackagesForUid(uid)?.firstOrNull().orEmpty()

    override fun uidByPackageName(name: String): Int = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        packageManager.getApplicationInfo(name, PackageManager.ApplicationInfoFlags.of(0)).uid
    } else {
        @Suppress("DEPRECATION")
        packageManager.getApplicationInfo(name, 0).uid
    }

    override fun startDefaultInterfaceMonitor(listener: InterfaceUpdateListener) {
        val monitor = UnderlyingMonitor(sessionID)
        monitor.callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                refreshUnderlyingNetwork(listener, monitor, available = network)
            }

            override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
                refreshUnderlyingNetwork(listener, monitor, network = network, capabilities = capabilities)
            }

            override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) =
                refreshUnderlyingNetwork(listener, monitor, network = network, linkProperties = linkProperties)

            override fun onLost(network: Network) {
                refreshUnderlyingNetwork(listener, monitor, lost = network)
            }
        }
        if (monitors.putIfAbsent(listener, monitor) != null) return
        try {
            val request = NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .build()
            synchronized(monitor) {
                if (monitor.session != sessionID || monitors[listener] !== monitor) return
                connectivity.registerNetworkCallback(request, monitor.callback)
                monitor.registered = true
            }
            seedUnderlyingNetworks(listener, monitor)
            if (monitor.session != sessionID || monitors[listener] !== monitor) {
                removeUnderlyingMonitor(listener, monitor)
            }
        } catch (error: Throwable) {
            removeUnderlyingMonitor(listener, monitor)
            throw error
        }
    }

    override fun closeDefaultInterfaceMonitor(listener: InterfaceUpdateListener) {
        monitors[listener]?.let { removeUnderlyingMonitor(listener, it) }
    }

    private fun removeUnderlyingMonitor(listener: InterfaceUpdateListener, monitor: UnderlyingMonitor) {
        val unregister = synchronized(monitor) {
            monitors.remove(listener, monitor)
            val shouldUnregister = monitor.registered && !monitor.unregistered
            monitor.unregistered = true
            shouldUnregister
        }
        if (unregister) runCatching { connectivity.unregisterNetworkCallback(monitor.callback) }
    }

    private fun refreshUnderlyingNetwork(
        listener: InterfaceUpdateListener,
        monitor: UnderlyingMonitor,
        available: Network? = null,
        lost: Network? = null,
        network: Network? = null,
        capabilities: NetworkCapabilities? = null,
        linkProperties: LinkProperties? = null,
        seeded: List<SeededUnderlying>? = null,
    ) = synchronized(monitor) {
        if (monitor.session != sessionID || monitors[listener] !== monitor) return@synchronized
        lost?.let {
            monitor.snapshots.remove(it)
            monitor.lostNetworks.add(it)
            monitor.callbackNetworks.add(it)
        }
        available?.let {
            monitor.lostNetworks.remove(it)
            monitor.callbackNetworks.add(it)
            monitor.snapshots.putIfAbsent(it, UnderlyingSnapshot())
        }
        network?.takeUnless(monitor.lostNetworks::contains)?.let {
            monitor.callbackNetworks.add(it)
            val snapshot = monitor.snapshots.getOrPut(it, ::UnderlyingSnapshot)
            capabilities?.let { value -> snapshot.capabilities = value }
            linkProperties?.let { value -> snapshot.linkProperties = value }
        }
        seeded?.asSequence()
            ?.filterNot { it.network in monitor.lostNetworks || it.network in monitor.callbackNetworks }
            ?.forEach {
                monitor.snapshots[it.network] = UnderlyingSnapshot(it.capabilities, it.linkProperties)
            }
        val candidates = monitor.snapshots
            .asSequence()
            .mapNotNull { (candidateNetwork, snapshot) -> underlyingCandidate(candidateNetwork, snapshot) }
            .toList()
        val selectedNetwork = selectStableUnderlying(
            candidates.map { RankedUnderlying(it.network, it.rank, it.network.toString()) },
            monitor.selected,
        )
        val selected = candidates.firstOrNull { it.network == selectedNetwork }

        if (monitor.session != sessionID || monitors[listener] !== monitor) return@synchronized
        monitor.selected = selected?.network
        selectedUnderlyingNetwork = selected?.network
        if (tunnel != null) publishUnderlyingNetwork(selected?.network)
        val selectionChanged = !monitor.notified || monitor.lastSelection != selected
        monitor.notified = true
        monitor.lastSelection = selected
        if (!selectionChanged) return@synchronized
        if (selected != null) {
            activeManagedProfile?.let { profile ->
                val profileID = runtimeProfileId
                if (profileID.isBlank()) return@let
                val callbackSession = sessionID
                val recordID = profile.recordID
                scope.launch {
                    runCatching {
                        lifecycle.withLock {
                            if (callbackSession != sessionID ||
                                runtimeProfileId != profileID ||
                                activeManagedProfile?.recordID != recordID ||
                                selectedUnderlyingNetwork != selected.network ||
                                !connectionWanted(profileID)
                            ) return@withLock
                            val routing = RouteManager.get(this@LoomVpnService)
                            if (routing.beginNetworkGeneration(profileID, networkGenerationIdentity(selected.network))) {
                                routing.applyToRunning(profileID, profile)
                            }
                        }
                    }.onFailure { Log.w(TAG, "network-generation route apply failed", it) }
                }
            }
        }
        if (selected == null) {
            listener.updateDefaultInterface("", -1, false, false)
        } else {
            listener.updateDefaultInterface(selected.name, selected.index, selected.metered, false)
        }
    }

    private fun networkGenerationIdentity(network: Network): String {
        val boot = Settings.Global.getInt(contentResolver, Settings.Global.BOOT_COUNT, -1)
        return networkGenerationIdentity(boot, network.networkHandle)
    }

    @Suppress("DEPRECATION")
    private fun seedUnderlyingNetworks(listener: InterfaceUpdateListener, monitor: UnderlyingMonitor) {
        val snapshots = connectivity.allNetworks.map { network ->
            SeededUnderlying(
                network = network,
                capabilities = connectivity.getNetworkCapabilities(network),
                linkProperties = connectivity.getLinkProperties(network),
            )
        }
        refreshUnderlyingNetwork(listener, monitor, seeded = snapshots)
    }

    private fun publishUnderlyingNetwork(network: Network?) {
        synchronized(underlyingPublicationLock) {
            if (!underlyingPublication.needsRuntimePublish(network)) return
            runCatching { setUnderlyingNetworks(network?.let { arrayOf(it) }) }
                .onFailure { Log.w(TAG, "publish selected VPN underlying network", it) }
                .onSuccess { published ->
                    if (published) {
                        underlyingPublication.runtimePublished(network)
                    } else {
                        Log.w(TAG, "android: failed to publish selected VPN underlying network")
                    }
                }
        }
    }

    private fun underlyingCandidate(network: Network, snapshot: UnderlyingSnapshot): UnderlyingCandidate? {
        val capabilities = snapshot.capabilities ?: return null
        if (!capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) ||
            !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
        ) return null
        val notSuspended = Build.VERSION.SDK_INT < Build.VERSION_CODES.P ||
            capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_SUSPENDED)
        val name = snapshot.linkProperties?.interfaceName ?: return null
        val index = runCatching { NetworkInterface.getByName(name)?.index }.getOrNull() ?: return null
        val transportPriority = when {
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> 4
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> 3
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> 2
            else -> 1
        }
        val rank = underlyingNetworkRank(
            validated = capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED),
            notSuspended = notSuspended,
            unmetered = capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED),
            transportPriority = transportPriority,
        ) ?: return null
        return UnderlyingCandidate(
            network = network,
            name = name,
            index = index,
            metered = !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED),
            rank = rank,
        )
    }

    @Suppress("DEPRECATION")
    override fun getInterfaces(): NetworkInterfaceIterator {
        val systemInterfaces = Collections.list(NetworkInterface.getNetworkInterfaces()).associateBy { it.name }
        val result = mutableListOf<BoxNetworkInterface>()
        for (network in connectivity.allNetworks) {
            val capabilities = connectivity.getNetworkCapabilities(network) ?: continue
            if (!capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) continue
            val properties = connectivity.getLinkProperties(network) ?: continue
            val name = properties.interfaceName ?: continue
            val system = systemInterfaces[name] ?: continue
            result += BoxNetworkInterface().apply {
                this.name = name
                index = system.index
                mtu = runCatching { system.mtu }.getOrDefault(1500)
                type = when {
                    capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> Libbox.InterfaceTypeWIFI
                    capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> Libbox.InterfaceTypeCellular
                    capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> Libbox.InterfaceTypeEthernet
                    else -> Libbox.InterfaceTypeOther
                }
                var interfaceFlags = 0
                if (system.isUp) interfaceFlags = interfaceFlags or OsConstants.IFF_UP or OsConstants.IFF_RUNNING
                if (system.isLoopback) interfaceFlags = interfaceFlags or OsConstants.IFF_LOOPBACK
                if (system.isPointToPoint) interfaceFlags = interfaceFlags or OsConstants.IFF_POINTOPOINT
                if (system.supportsMulticast()) interfaceFlags = interfaceFlags or OsConstants.IFF_MULTICAST
                flags = interfaceFlags
                metered = !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)
                // netip prefixes cannot carry an IPv6 zone; the interface index
                // already supplies that scope to libbox.
                addresses = Strings(
                    system.interfaceAddresses.map {
                        "${checkNotNull(it.address.hostAddress).substringBefore('%')}/${it.networkPrefixLength}"
                    },
                )
                dnsServer = Strings(properties.dnsServers.mapNotNull { it.hostAddress })
            }
        }
        return Interfaces(result.sortedBy { it.index })
    }

    override fun underNetworkExtension(): Boolean = false
    override fun includeAllNetworks(): Boolean = false
    override fun readWIFIState(): WIFIState? = null
    override fun clearDNSCache() = Unit
    override fun writeLog(message: String) {
        Log.i(TAG, message)
    }
    override fun sendNotification(notification: Notification) {
        Log.i(TAG, "libbox notification: ${notification.title}: ${notification.body}")
    }

    private fun foregroundNotification(text: String): android.app.Notification {
        val displayedProfileId = VpnRuntime.status.value.activeProfileId
            .ifBlank { VpnRuntime.status.value.requestedProfileId }
            .ifBlank { desiredProfileId }
        val title = displayedProfileId.takeIf(String::isNotBlank)
            ?.let { runCatching { ProfileCatalog.get(this).name(it) }.getOrNull() }
            ?.let { "Loom · $it" }
            ?: "Loom VPN"
        val open = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val builder = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_loom)
            .setContentTitle(title)
            .setContentText(text)
            .setContentIntent(open)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
        if (shouldOfferAppDisconnect(alwaysOnEnabled())) {
            val disconnect = PendingIntent.getService(
                this,
                1,
                Intent(this, LoomVpnService::class.java).setAction(ACTION_DISCONNECT),
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            )
            builder.addAction(0, "断开", disconnect)
        }
        return builder.build()
    }

    private fun alwaysOnEnabled(): Boolean =
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && isAlwaysOn

    private fun restoredProfileId(): String? {
        val catalog = ProfileCatalog.get(this)
        val preference = VpnConnectionPreference(this)
        return runCatching { preference.profileId() }.getOrNull()?.takeIf(catalog::contains)
    }

    private fun rejectConnectionStart(startId: Int, detail: String): Int {
        if (boxService != null && runtimeProfileId.isNotBlank()) {
            updateNotification("保持当前连接 · $detail")
            return vpnServiceRestartMode(desiredProfileId.isNotBlank())
        }
        desiredProfileId = ""
        VpnConnectionPreference(this).save(false, "")
        VpnRuntime.update(
            VpnStatus(
                phase = ConnectionPhase.ERROR,
                detail = detail,
                alwaysOn = alwaysOnEnabled(),
            ),
        )
        updateNotification("连接失败 · $detail")
        stopIdleForeground(startId)
        return START_NOT_STICKY
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            getSystemService<NotificationManager>()!!.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "VPN 连接", NotificationManager.IMPORTANCE_LOW),
            )
        }
    }

    private fun updateNotification(text: String) {
        getSystemService<NotificationManager>()!!.notify(NOTIFICATION_ID, foregroundNotification(text))
    }

    private class UnderlyingMonitor(val session: Long) {
        lateinit var callback: ConnectivityManager.NetworkCallback
        var registered = false
        var unregistered = false
        var selected: Network? = null
        var notified = false
        var lastSelection: UnderlyingCandidate? = null
        val snapshots = linkedMapOf<Network, UnderlyingSnapshot>()
        val callbackNetworks = mutableSetOf<Network>()
        val lostNetworks = mutableSetOf<Network>()
    }

    private data class UnderlyingSnapshot(
        var capabilities: NetworkCapabilities? = null,
        var linkProperties: LinkProperties? = null,
    )

    private data class SeededUnderlying(
        val network: Network,
        val capabilities: NetworkCapabilities?,
        val linkProperties: LinkProperties?,
    )

    private data class UnderlyingCandidate(
        val network: Network,
        val name: String,
        val index: Int,
        val metered: Boolean,
        val rank: Int,
    )

    companion object {
        private const val TAG = "LoomVpnService"
        private const val CHANNEL_ID = "loom-vpn"
        private const val NOTIFICATION_ID = 4101
        private const val REPORT_INTERVAL_MS = 60_000L
        const val ACTION_CONNECT = "io.github.scisaga.loom.action.CONNECT"
        const val ACTION_RELOAD = "io.github.scisaga.loom.action.RELOAD"
        const val ACTION_SYNC_SYSTEM_POLICY = "io.github.scisaga.loom.action.SYNC_SYSTEM_POLICY"
        const val ACTION_DISCONNECT = "io.github.scisaga.loom.action.DISCONNECT"
        const val EXTRA_PROFILE_ID = "io.github.scisaga.loom.extra.PROFILE_ID"
        const val EXTRA_CANDIDATE_ID = "io.github.scisaga.loom.extra.CANDIDATE_ID"
    }
}

internal fun requiresDefaultRoute(hasAddress: Boolean, hasExplicitRoute: Boolean): Boolean =
    hasAddress && !hasExplicitRoute

internal fun vpnServiceRestartMode(desiredConnected: Boolean): Int =
    if (desiredConnected) android.app.Service.START_STICKY else android.app.Service.START_NOT_STICKY

internal fun shouldOfferAppDisconnect(alwaysOn: Boolean): Boolean = !alwaysOn
