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
import io.github.scisaga.loom.enrollment.ManagedProfile
import io.github.scisaga.loom.enrollment.HealthReporter
import io.github.scisaga.loom.security.DeviceKeyStore
import io.github.scisaga.loom.route.RouteManager
import io.github.scisaga.loom.stage1.Stage1Config
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
    private var routeJob: Job? = null
    @Volatile private var sessionID = 0L
    private var lastUseEmulatorProxy = false
    @Volatile private var desiredConnected = false
    @Volatile private var activeProbe: ProbeSession? = null
    @Volatile private var selectedUnderlyingNetwork: Network? = null
    @Volatile private var activeManagedProfile: ManagedProfile? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (boxService == null) startForeground(NOTIFICATION_ID, foregroundNotification("正在准备…"))
        when (intent?.action) {
            null, SERVICE_INTERFACE -> {
                // §8.3：sticky 重建与系统 always-on 启动都没有应用自定义 action。
                desiredConnected = true
                scope.launch { startTunnel(useEmulatorProxy = false, startId) }
            }
            ACTION_CONNECT -> {
                desiredConnected = true
                VpnConnectionPreference(this).setDesiredConnected(true)
                val useEmulatorProxy = intent?.getBooleanExtra(EXTRA_EMULATOR_PROXY, false) == true
                check(!useEmulatorProxy || applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE != 0) {
                    "emulator proxy fixture is debug-only"
                }
                scope.launch { startTunnel(useEmulatorProxy, startId) }
            }
            ACTION_RELOAD -> {
                val candidateID = intent?.getStringExtra(EXTRA_CANDIDATE_ID).orEmpty()
                scope.launch { reloadTunnel(candidateID, startId) }
            }
            ACTION_ENROLLMENT_KEEPALIVE -> {
                desiredConnected = false
                updateNotification("正在完成设备入网…")
            }
            ACTION_DISCONNECT -> {
                desiredConnected = false
                VpnConnectionPreference(this).setDesiredConnected(false)
                activeProbe?.cancel()
                scope.launch { stopTunnel(stopStartId = startId) }
            }
            else -> stopIdleForeground(startId)
        }
        // §8.3：连接是用户明确发出的长期请求；主动断开已在返回前清除该请求。
        return vpnServiceRestartMode(desiredConnected)
    }

    override fun onBind(intent: Intent): IBinder? = super.onBind(intent)

    override fun onRevoke() {
        desiredConnected = false
        VpnConnectionPreference(this).setDesiredConnected(false)
        activeProbe?.cancel()
        scope.launch {
            stopTunnel()
            stopSelf()
        }
    }

    override fun onDestroy() {
        desiredConnected = false
        activeProbe?.cancel()
        runBlocking(Dispatchers.IO) { stopTunnel() }
        scope.cancel()
        super.onDestroy()
    }

    private suspend fun startTunnel(useEmulatorProxy: Boolean, startId: Int) = lifecycle.withLock {
        if (!desiredConnected) return@withLock
        if (boxService != null) return@withLock
        lastUseEmulatorProxy = useEmulatorProxy
        startTunnelLocked(useEmulatorProxy, startId)
    }

    private suspend fun reloadTunnel(candidateID: String, startId: Int) = lifecycle.withLock {
        if (!desiredConnected || candidateID.isBlank()) {
            stopIdleForeground(startId)
            return@withLock
        }
        val pending = runCatching { EnrollmentManager.get(this).candidateProfile() }.getOrNull()
        if (pending?.recordID != candidateID) {
            stopIdleForeground(startId)
            return@withLock
        }
        closeResources()
        if (desiredConnected) startTunnelLocked(lastUseEmulatorProxy, startId)
    }

    private suspend fun startTunnelLocked(useEmulatorProxy: Boolean, startId: Int) {
        // A queued disconnect may have removed foreground state while a newer
        // connect command was waiting for the lifecycle mutex.
        startForeground(NOTIFICATION_ID, foregroundNotification("正在准备…"))
        VpnRuntime.update(VpnStatus(ConnectionPhase.STARTING, "正在验签并建立 TUN…"))
        updateNotification("正在连接…")
        try {
            DeviceKeyStore().proveBinding()
            val manager = EnrollmentManager.get(this)
            val candidate = manager.candidateProfile()
            if (candidate != null) {
                try {
                    val probe = activateAndProbe(candidate)
                    ensureConnectionWanted()
                    val committed = manager.candidateActivated(candidate)
                    connected(committed, probe, "已验证并激活 snapshot ${committed.snapshot}")
                    return
                } catch (cancelled: CancellationException) {
                    closeResources()
                    throw cancelled
                } catch (candidateError: Throwable) {
                    Log.e(TAG, "candidate activation rejected", candidateError)
                    closeResources()
                    ensureConnectionWanted()
                    val fallback = manager.candidateRejected(candidate, "真实 DNS/HTTPS 未通过")
                    if (fallback != null) {
                        val (restored, probe) = activateManagedWithFallback(fallback, manager)
                        ensureConnectionWanted()
                        connected(restored, probe, "候选失败，沿用 snapshot ${restored.snapshot}")
                        return
                    }
                    throw candidateError
                }
            }

            val current = manager.currentProfile()
            if (current != null) {
                val (active, probe) = activateManagedWithFallback(current, manager)
                ensureConnectionWanted()
                connected(active, probe, "已激活验签配置 · snapshot ${active.snapshot}")
                return
            }

            check(applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE != 0) {
                "请先扫描中控二维码完成正式入网"
            }
            val config = Stage1Config.load(this, useEmulatorProxy).content
            val probe = activateAndProbe(config)
            ensureConnectionWanted()
            val route = if (useEmulatorProxy) "Debug Emulator 数据面" else "Debug Direct 数据面"
            connected(null, probe, route)
        } catch (error: Throwable) {
            Log.e(TAG, "start tunnel", error)
            closeResources()
            if (!desiredConnected) {
                VpnRuntime.update(VpnStatus())
                return
            }
            VpnRuntime.transform {
                it.copy(phase = ConnectionPhase.ERROR, detail = error.message ?: error.javaClass.simpleName)
            }
            updateNotification("连接失败")
            if (stopSelfResult(startId)) {
                desiredConnected = false
                stopForegroundCompat()
            }
        }
    }

    private suspend fun activateManagedWithFallback(
        current: ManagedProfile,
        manager: EnrollmentManager,
    ): Pair<ManagedProfile, ProbeResult> {
        try {
            return current to activateAndProbe(current)
        } catch (cancelled: CancellationException) {
            closeResources()
            throw cancelled
        } catch (currentError: Throwable) {
            Log.e(TAG, "active profile rejected", currentError)
            closeResources()
            ensureConnectionWanted()
            val previous = runCatching { manager.previousProfile() }
                .getOrNull()
                ?.takeIf { it.recordID != current.recordID }
                ?: throw currentError
            return try {
                val probe = activateAndProbe(previous)
                val promoted = checkNotNull(manager.promotePrevious()) { "previous 配置在恢复时消失" }
                promoted to probe
            } catch (cancelled: CancellationException) {
                closeResources()
                throw cancelled
            } catch (previousError: Throwable) {
                closeResources()
                currentError.addSuppressed(previousError)
                throw currentError
            }
        }
    }

    private suspend fun activateAndProbe(profile: ManagedProfile): ProbeResult =
        activateAndProbe(profile.config, profile)

    private suspend fun activateAndProbe(config: String, profile: ManagedProfile? = null): ProbeResult {
        activate(config)
        profile?.let { RouteManager.get(this).applyToRunning(it) }
        val probeSession = ProbeSession()
        activeProbe = probeSession
        val probe = try {
            NetworkProbe.run(probeSession)
        } finally {
            if (activeProbe === probeSession) activeProbe = null
        }
        ensureConnectionWanted()
        VpnRuntime.transform { it.copy(dnsProbe = probe.dns, httpsProbe = probe.https) }
        check(probe.healthy) { "TUN 已启动，但真实 DNS/HTTPS 端到端探测未通过" }
        return probe
    }

    private fun ensureConnectionWanted() {
        if (!desiredConnected) throw CancellationException("连接请求已取消")
    }

    private fun connected(profile: ManagedProfile?, probe: ProbeResult, detail: String) {
        ensureConnectionWanted()
        VpnRuntime.update(
            VpnStatus(
                phase = ConnectionPhase.CONNECTED,
                detail = detail,
                dnsProbe = probe.dns,
                httpsProbe = probe.https,
            ),
        )
        updateNotification("已连接 · $detail")
        profile?.let {
            activeManagedProfile = it
            startRouteSession(it)
            startReporter(it, probe)
        }
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

    private fun startReporter(profile: ManagedProfile, initialProbe: ProbeResult) {
        reportJob?.cancel()
        val reporterSession = sessionID
        reportJob = scope.launch {
            val reporter = HealthReporter(this@LoomVpnService)
            while (isActive && reporterSession == sessionID) {
                val status = VpnRuntime.status.value
                if (status.phase != ConnectionPhase.CONNECTED) return@launch
                val report = runCatching { reporter.send(profile, initialProbe.problems()) }
                if (!isActive || reporterSession != sessionID) return@launch
                if (report.isSuccess) {
                    val result = report.getOrThrow()
                    VpnRuntime.transform { it.copy(trustedReport = "成功（HTTP ${result.status}）") }
                    runCatching {
                        RouteManager.get(this@LoomVpnService).consumeObservations(
                            profile,
                            result.observations,
                            result.observationError,
                        )
                    }.onFailure { error ->
                        if (error !is CancellationException) {
                            Log.w(TAG, "Android server observation update failed", error)
                            RouteManager.get(this@LoomVpnService).routeUpdateFailed(error)
                        }
                    }
                } else {
                    VpnRuntime.transform { it.copy(trustedReport = "失败；将重试") }
                }
                delay(REPORT_INTERVAL_MS)
            }
        }
    }

    private fun startRouteSession(profile: ManagedProfile, sourceOverride: String? = null) {
        routeJob?.cancel()
        val routeSession = sessionID
        routeJob = scope.launch {
            val manager = RouteManager.get(this@LoomVpnService)
            val source = sourceOverride ?: selectedUnderlyingNetwork?.let {
                connectivity.getLinkProperties(it)?.interfaceName
            }.orEmpty()
            try {
                manager.beginRouteSession(profile, source)
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Throwable) {
                if (!isActive || routeSession != sessionID || !desiredConnected) return@launch
                Log.w(TAG, "Android entry route round failed", error)
                manager.routeUpdateFailed(error)
            }
        }
    }

    private suspend fun stopTunnel(stopStartId: Int? = null) = lifecycle.withLock {
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

    private fun closeResources() {
        sessionID++
        activeProbe?.cancel()
        activeProbe = null
        reportJob?.cancel()
        reportJob = null
        routeJob?.cancel()
        routeJob = null
        activeManagedProfile = null
        monitors.entries.toList().forEach { (listener, monitor) ->
            removeUnderlyingMonitor(listener, monitor)
        }
        selectedUnderlyingNetwork = null
        synchronized(underlyingPublicationLock) { underlyingPublication.clear() }
        runCatching { boxService?.close() }.onFailure { Log.w(TAG, "close libbox", it) }
        boxService = null
        runCatching { tunnel?.close() }.onFailure { Log.w(TAG, "close tun", it) }
        tunnel = null
        RouteManager.get(this).tunnelStopped()
    }

    private fun stopForegroundCompat() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) stopForeground(STOP_FOREGROUND_REMOVE) else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }
    }

    private fun stopIdleForeground(startId: Int) {
        if (boxService == null && tunnel == null && stopSelfResult(startId)) stopForegroundCompat()
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

        val builder = Builder().setSession("Loom").setMtu(options.mtu)
        val builderUnderlying = selectedUnderlyingNetwork
        builderUnderlying?.let { builder.setUnderlyingNetworks(arrayOf(it)) }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) builder.setMetered(false)

        addAddresses(builder, options)
        if (options.autoRoute) {
            options.dnsServerAddress?.value?.takeIf { it.isNotBlank() }?.let(builder::addDnsServer)
            addRoutes(builder, options)
        }
        val descriptor = checkNotNull(builder.establish()) { "android: VPN permission revoked while opening TUN" }
        synchronized(underlyingPublicationLock) { underlyingPublication.builderBound(builderUnderlying) }
        tunnel = descriptor
        publishUnderlyingNetwork(selectedUnderlyingNetwork)
        return descriptor.fd
    }

    private fun addAddresses(builder: Builder, options: TunOptions) {
        val ipv4 = options.inet4Address
        while (ipv4.hasNext()) ipv4.next().also { builder.addAddress(it.address(), it.prefix()) }
        val ipv6 = options.inet6Address
        while (ipv6.hasNext()) ipv6.next().also { builder.addAddress(it.address(), it.prefix()) }
    }

    private fun addRoutes(builder: Builder, options: TunOptions) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val ipv4 = options.inet4RouteAddress
            if (ipv4.hasNext()) while (ipv4.hasNext()) ipv4.next().also {
                builder.addRoute(IpPrefix(InetAddress.getByName(it.address()), it.prefix()))
            } else builder.addRoute("0.0.0.0", 0)
            val ipv6 = options.inet6RouteAddress
            while (ipv6.hasNext()) ipv6.next().also {
                builder.addRoute(IpPrefix(InetAddress.getByName(it.address()), it.prefix()))
            }
            val exclude4 = options.inet4RouteExcludeAddress
            while (exclude4.hasNext()) exclude4.next().also {
                builder.excludeRoute(IpPrefix(InetAddress.getByName(it.address()), it.prefix()))
            }
            val exclude6 = options.inet6RouteExcludeAddress
            while (exclude6.hasNext()) exclude6.next().also {
                builder.excludeRoute(IpPrefix(InetAddress.getByName(it.address()), it.prefix()))
            }
        } else {
            val ipv4 = options.inet4RouteRange
            while (ipv4.hasNext()) ipv4.next().also { builder.addRoute(it.address(), it.prefix()) }
            val ipv6 = options.inet6RouteRange
            while (ipv6.hasNext()) ipv6.next().also { builder.addRoute(it.address(), it.prefix()) }
        }
    }

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
            activeManagedProfile?.let { profile -> startRouteSession(profile, selected.name) }
        }
        if (selected == null) {
            listener.updateDefaultInterface("", -1, false, false)
        } else {
            listener.updateDefaultInterface(selected.name, selected.index, selected.metered, false)
        }
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
        val open = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val disconnect = PendingIntent.getService(
            this,
            1,
            Intent(this, LoomVpnService::class.java).setAction(ACTION_DISCONNECT),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_loom)
            .setContentTitle("Loom VPN")
            .setContentText(text)
            .setContentIntent(open)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .addAction(0, "断开", disconnect)
            .build()
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
        const val ACTION_ENROLLMENT_KEEPALIVE = "io.github.scisaga.loom.action.ENROLLMENT_KEEPALIVE"
        const val ACTION_DISCONNECT = "io.github.scisaga.loom.action.DISCONNECT"
        const val EXTRA_CANDIDATE_ID = "io.github.scisaga.loom.extra.CANDIDATE_ID"
        const val EXTRA_EMULATOR_PROXY = "io.github.scisaga.loom.extra.EMULATOR_PROXY"
    }
}

internal fun vpnServiceRestartMode(desiredConnected: Boolean): Int =
    if (desiredConnected) android.app.Service.START_STICKY else android.app.Service.START_NOT_STICKY
