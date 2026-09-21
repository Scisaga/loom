package io.github.scisaga.loom.route

import android.content.Context
import io.github.scisaga.loom.enrollment.ManagedProfile
import io.github.scisaga.loom.profiles.ProfileCatalog
import io.github.scisaga.loom.profiles.ProfileStorage
import io.github.scisaga.loom.security.EncryptedStore
import io.github.scisaga.loom.vpn.ProbeResult
import io.github.scisaga.loomcore.Loomcore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.json.JSONArray
import org.json.JSONObject
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.UUID

enum class RouteMode(val wire: String) {
    DIRECT("direct"),
    AUTO("auto"),
    FIXED_EXIT("fixed_exit"),
}

data class RouteStatus(
    val available: Boolean = false,
    val busy: Boolean = false,
    val mode: RouteMode = RouteMode.AUTO,
    val exit: String = "",
    val exits: List<String> = emptyList(),
    val directAvailable: Boolean = false,
    val blocked: Boolean = false,
    val detail: String = "等待认证 DeviceView",
    val observationDetail: String = "业务结果尚未产生",
    val currentPaths: List<RoutePathStatus> = emptyList(),
    val running: Boolean = false,
)

data class RoutePathStatus(
    val service: String,
    val candidate: String,
    val serverChain: List<String>,
    val state: String,
    val updatedAt: String,
)

internal data class AppliedRoute(
    val mode: RouteMode,
    val exit: String,
    val directAvailable: Boolean,
    val exits: List<String>,
    val selectors: List<AppliedSelector>,
)

internal data class AppliedSelector(
    val selector: String,
    val candidate: String,
    val chain: List<String>,
    val state: String = "unknown",
)

/** Applies the shared pure selection and only publishes selector readback. */
class RouteManager private constructor(context: Context) {
    private val protected = EncryptedStore(context.applicationContext)
    private val catalog = ProfileCatalog.get(context.applicationContext)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val operation = Mutex()
    private val profiles = mutableMapOf<String, ProfileRuntime>()

    fun status(profileId: String): StateFlow<RouteStatus> = runtime(profileId).mutableStatus.asStateFlow()

    fun profileAvailable(profileId: String, profile: ManagedProfile) {
        val runtime = runtime(profileId)
        scope.launch {
            operation.withLock {
                if (!catalog.contains(profileId)) return@withLock
                ensureNetworkGeneration(profileId, runtime)
                runtime.availableProfile = profile
                val projected = evaluate(profileId, runtime, profile, emptyMap())
                publish(runtime, projected, running = runtime.runningProfile?.recordID == profile.recordID)
            }
        }
    }

    suspend fun beginNetworkGeneration(profileId: String, identity: String? = null): Boolean = operation.withLock {
        val runtime = runtime(profileId)
        ensureNetworkGeneration(profileId, runtime)
        if (identity == null || identity == runtime.networkIdentity) return@withLock false
        require(identity.isNotBlank()) { "底层网络身份不能为空" }
        runtime.generation = UUID.randomUUID().toString()
        runtime.networkIdentity = identity
        runtime.actual = linkedMapOf()
        runtime.application = null
        protected.put(ProfileStorage.networkGeneration(profileId), runtime.generation.encodeToByteArray())
        protected.put(ProfileStorage.networkIdentity(profileId), identity.encodeToByteArray())
        protected.put(ProfileStorage.observations(profileId), "[]".encodeToByteArray())
        true
    }

    internal suspend fun applyToRunning(profileId: String, profile: ManagedProfile): AppliedRoute = operation.withLock {
        val runtime = runtime(profileId)
        ensureNetworkGeneration(profileId, runtime)
        runtime.mutableStatus.value = runtime.mutableStatus.value.copy(busy = true, detail = "正在应用候选并读回 selector…")
        val initial = evaluate(profileId, runtime, profile, runtime.actual)
        val client = SelectorClient(profile.config)
        val current = client.readCurrent(initial.selectors)
        val desired = evaluate(profileId, runtime, profile, current)
        client.apply(desired.selectors)
        val readback = client.readCurrent(desired.selectors)
        check(desired.selectors.all { readback[it.selector] == it.candidate }) { "selector 回读与选择不一致" }
        runtime.actual = LinkedHashMap(readback)
        runtime.application = desired
        runtime.runningProfile = profile
        publish(runtime, desired, running = true)
        desired
    }

    fun select(profileId: String, mode: RouteMode, exit: String = "") {
        val runtime = runtime(profileId)
        scope.launch {
            operation.withLock {
                if (!catalog.contains(profileId)) return@withLock
                val preference = JSONObject().put("schema", 1).put("mode", mode.wire)
                    .apply { if (mode == RouteMode.FIXED_EXIT) put("exit", exit) }
                    .toString().encodeToByteArray()
                protected.put(ProfileStorage.routePreference(profileId), preference)
                val available = runtime.runningProfile ?: runtime.availableProfile ?: return@withLock
                if (runtime.runningProfile != null) {
                    val desired = evaluate(profileId, runtime, available, runtime.actual)
                    SelectorClient(available.config).apply(desired.selectors)
                    runtime.actual = LinkedHashMap(SelectorClient(available.config).readCurrent(desired.selectors))
                    runtime.application = desired
                    publish(runtime, desired, running = true)
                } else {
                    publish(runtime, evaluate(profileId, runtime, available, emptyMap()), running = false)
                }
            }
        }
    }

    /** Records at most one business result for each selected candidate in this network generation. */
    internal suspend fun recordBusinessOutcome(
        profileId: String,
        profile: ManagedProfile,
        probe: ProbeResult,
    ): AppliedRoute = operation.withLock {
        val runtime = runtime(profileId)
        val currentApplication = checkNotNull(runtime.application) { "尚未应用候选" }
        val observations = observations(profileId)
        val now = Instant.now().truncatedTo(ChronoUnit.SECONDS)
        val existing = observations.objects().map { it.getString("candidate_id") to it.getString("network_generation") }.toSet()
        currentApplication.selectors.distinctBy(AppliedSelector::candidate).forEach { selected ->
            // Direct participates in selection without a synthetic latency measurement.
            if (selected.chain.isEmpty() || selected.candidate to runtime.generation in existing) return@forEach
            observations.put(
                JSONObject()
                    .put("candidate_id", selected.candidate)
                    .put("network_generation", runtime.generation)
                    .put("scope", selected.selector)
                    .put("result", if (probe.healthy) "available" else "unavailable")
                    .put("action", "dns_https")
                    .put("observed_at", now.toString())
                    .put("valid_until", now.plus(10, ChronoUnit.MINUTES).toString()),
            )
        }
        val sorted = observations.objects().sortedBy { it.getString("candidate_id") }
        protected.put(ProfileStorage.observations(profileId), JSONArray(sorted).toString().encodeToByteArray())
        val next = evaluate(profileId, runtime, profile, runtime.actual)
        if (next.selectors != currentApplication.selectors) {
            val client = SelectorClient(profile.config)
            client.apply(next.selectors)
            runtime.actual = LinkedHashMap(client.readCurrent(next.selectors))
        }
        runtime.application = next
        publish(
            runtime,
            next,
            running = true,
            observation = if (probe.healthy) "真实 DNS/HTTPS 可用" else "真实 DNS/HTTPS 不可用；已切换候选",
        )
        next
    }

    fun reportObservations(profileId: String): ByteArray {
        val runtime = runtime(profileId)
        return synchronized(runtime) {
            val currentGeneration = runtime.generation
            val values = observations(profileId).objects().filter { it.getString("network_generation") == currentGeneration }
                .sortedBy { it.getString("candidate_id") }
            JSONArray(values).toString().encodeToByteArray()
        }
    }

    fun selectedCandidate(profileId: String): String =
        runtime(profileId).application?.selectors?.firstOrNull()?.candidate.orEmpty()

    fun reportSelections(profileId: String): ByteArray {
        val runtime = runtime(profileId)
        return synchronized(runtime) {
            val values = runtime.application?.selectors.orEmpty().sortedBy { it.selector }.map {
                JSONObject().put("scope", it.selector).put("candidate_id", it.candidate)
            }
            JSONArray(values).toString().encodeToByteArray()
        }
    }

    suspend fun tunnelStopped(profileId: String) = operation.withLock {
        val runtime = runtime(profileId)
        runtime.runningProfile = null
        runtime.application = null
        runtime.actual = linkedMapOf()
        runtime.mutableStatus.value = runtime.mutableStatus.value.copy(running = false, busy = false)
    }

    suspend fun removeProfile(profileId: String) = operation.withLock {
        require(ProfileStorage.validId(profileId)) { "配置标识无效" }
        synchronized(profiles) {
            check(profiles[profileId]?.runningProfile == null) { "运行中的配置不能删除" }
            profiles.remove(profileId)
        }
        protected.remove(ProfileStorage.routePreference(profileId))
        protected.remove(ProfileStorage.observations(profileId))
        protected.remove(ProfileStorage.networkGeneration(profileId))
        protected.remove(ProfileStorage.networkIdentity(profileId))
    }

    private fun evaluate(
        profileId: String,
        runtime: ProfileRuntime,
        profile: ManagedProfile,
        current: Map<String, String>,
    ): AppliedRoute {
        val currentBody = JSONObject(current).toString().encodeToByteArray()
        val body = Loomcore.evaluateAndroidRoutes(
            profile.routes.encodeToByteArray(),
            observations(profileId).toString().encodeToByteArray(),
            protected.get(ProfileStorage.routePreference(profileId)) ?: ByteArray(0),
            currentBody,
            runtime.generation.ifBlank { "startup" },
            Instant.now().truncatedTo(ChronoUnit.SECONDS).toString(),
        )
        val root = JSONObject(body.decodeToString())
        return AppliedRoute(
            mode = RouteMode.entries.first { it.wire == root.getString("mode") },
            exit = root.optString("exit"),
            directAvailable = root.getBoolean("direct_available"),
            exits = root.getJSONArray("exits").strings(),
            selectors = root.getJSONArray("selections").objects().map {
                AppliedSelector(
                    it.getString("selector"),
                    it.getString("candidate"),
                    it.optJSONArray("chain")?.strings().orEmpty(),
                    it.getString("state"),
                )
            },
        )
    }

    private fun observations(profileId: String): JSONArray = protected.get(ProfileStorage.observations(profileId))?.let {
        runCatching { JSONArray(it.decodeToString()) }.getOrNull()
    } ?: JSONArray()

    private fun ensureNetworkGeneration(profileId: String, runtime: ProfileRuntime) {
        if (runtime.generation.isNotBlank()) return
        runtime.generation = protected.get(ProfileStorage.networkGeneration(profileId))?.decodeToString().orEmpty()
        runtime.networkIdentity = protected.get(ProfileStorage.networkIdentity(profileId))?.decodeToString().orEmpty()
        if (runtime.generation.isNotBlank()) return
        runtime.generation = UUID.randomUUID().toString()
        protected.put(ProfileStorage.networkGeneration(profileId), runtime.generation.encodeToByteArray())
    }

    private fun publish(
        runtime: ProfileRuntime,
        route: AppliedRoute,
        running: Boolean,
        observation: String = runtime.mutableStatus.value.observationDetail,
    ) {
        val label = when (route.mode) {
            RouteMode.DIRECT -> "Direct"
            RouteMode.AUTO -> "Auto"
            RouteMode.FIXED_EXIT -> "指定出口 ${route.exit}"
        }
        val now = Instant.now().truncatedTo(ChronoUnit.SECONDS).toString()
        runtime.mutableStatus.value = RouteStatus(
            available = route.selectors.isNotEmpty(),
            mode = route.mode,
            exit = route.exit,
            exits = route.exits,
            directAvailable = route.directAvailable,
            detail = if (running) "$label 已应用并读回" else "$label · 等待连接",
            observationDetail = observation,
            currentPaths = route.selectors.map { selected ->
                RoutePathStatus(
                    service = selected.selector,
                    candidate = selected.candidate,
                    serverChain = selected.chain,
                    state = selected.state,
                    updatedAt = now,
                )
            },
            running = running,
        )
    }

    private fun runtime(profileId: String): ProfileRuntime {
        require(ProfileStorage.validId(profileId)) { "配置标识无效" }
        return synchronized(profiles) { profiles.getOrPut(profileId, ::ProfileRuntime) }
    }

    private class ProfileRuntime {
        val mutableStatus = MutableStateFlow(RouteStatus())
        @Volatile var availableProfile: ManagedProfile? = null
        @Volatile var runningProfile: ManagedProfile? = null
        @Volatile var generation: String = ""
        @Volatile var networkIdentity: String = ""
        @Volatile var actual = linkedMapOf<String, String>()
        @Volatile var application: AppliedRoute? = null
    }

    companion object {
        @Volatile private var instance: RouteManager? = null

        fun get(context: Context): RouteManager = instance ?: synchronized(this) {
            instance ?: RouteManager(context).also { instance = it }
        }
    }
}

private fun JSONArray.objects(): List<JSONObject> = (0 until length()).map(::getJSONObject)
private fun JSONArray.strings(): List<String> = (0 until length()).map(::getString)
