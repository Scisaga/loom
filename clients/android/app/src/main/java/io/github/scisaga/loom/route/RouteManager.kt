package io.github.scisaga.loom.route

import android.content.Context
import android.util.Log
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
    val finalExit: String,
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
    val finalExit: String,
    val state: String = "unknown",
)

internal data class BusinessProbeInput(
    val selector: AppliedSelector,
    val networkGeneration: String,
    val dns: String,
    val target: String,
)

internal data class RuntimeReportData(
    val preference: ByteArray,
    val resourceObservations: ByteArray,
    val observations: ByteArray,
    val selections: ByteArray,
    val networkGeneration: String,
)

internal fun singleBusinessProbeInput(
    profile: ManagedProfile,
    application: AppliedRoute?,
    networkGeneration: String,
): BusinessProbeInput? {
    val selected = application?.selectors?.singleOrNull() ?: return null
    val group = profile.businessProbeTargets.singleOrNull() ?: return null
    if (selected.selector != "service:${group.serviceID}" && selected.selector != "local_network:${group.serviceID}") return null
    val target = group.targets.singleOrNull() ?: return null
    val dns = profile.dns.firstOrNull() ?: return null
    return BusinessProbeInput(selected, networkGeneration, dns, target)
}

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
                if (runtime.availableProfile?.recordID != profile.recordID) {
                    protected.put(ProfileStorage.observations(profileId), "[]".encodeToByteArray())
                }
                runtime.availableProfile = profile
                val current = if (runtime.runningProfile?.recordID == profile.recordID) runtime.actual else emptyMap()
                runCatching { evaluate(profileId, runtime, profile, current) }
                    .onSuccess { projected ->
                        publish(runtime, projected, running = runtime.runningProfile?.recordID == profile.recordID)
                    }
                    .onFailure { error ->
                        runtime.mutableStatus.value = runtime.mutableStatus.value.copy(
                            available = false, currentPaths = emptyList(), running = false,
                            detail = "认证配置已保存；运行投影不可用：${error.message ?: error.javaClass.simpleName}",
                            observationDetail = "业务结果尚未产生",
                        )
                    }
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
        // Observations cannot carry across accepted Views without proving that every
        // target and execution input is unchanged. No such projection exists yet.
        protected.put(ProfileStorage.observations(profileId), "[]".encodeToByteArray())
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
                val preference = Loomcore.newAndroidPreference(mode.wire, if (mode == RouteMode.FIXED_EXIT) exit else "")
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

    internal suspend fun businessProbeInput(profileId: String, profile: ManagedProfile): BusinessProbeInput? = operation.withLock {
        val runtime = runtime(profileId)
        if (runtime.runningProfile?.recordID != profile.recordID) return@withLock null
        val input = singleBusinessProbeInput(profile, runtime.application, runtime.generation) ?: return@withLock null
        val now = Instant.now()
        if (observations(profileId).objects().any {
            it.getString("candidate_id") == input.selector.candidate &&
                it.getString("network_generation") == input.networkGeneration &&
                runCatching { Instant.parse(it.getString("valid_until")).isAfter(now) }.getOrDefault(false)
        }) return@withLock null
        val unknown = runtime.application!!.copy(selectors = listOf(input.selector.copy(state = "unknown")))
        runtime.application = unknown
        publish(runtime, unknown, running = true, observation = "${input.target} · 尚无有效观测")
        input
    }

    internal suspend fun recordBusinessOutcome(
        profileId: String,
        profile: ManagedProfile,
        input: BusinessProbeInput,
        result: ProbeResult,
        allowFallback: Boolean,
        onRecorded: () -> Unit,
    ): BusinessProbeInput? = operation.withLock {
        val runtime = runtime(profileId)
        val current = runtime.application ?: return@withLock null
        if (runtime.runningProfile?.recordID != profile.recordID || runtime.generation != input.networkGeneration ||
            current.selectors.singleOrNull()?.candidate != input.selector.candidate || result.target != input.target
        ) return@withLock null
        val now = Instant.now().truncatedTo(ChronoUnit.SECONDS)
        val observation = JSONObject()
            .put("candidate_id", input.selector.candidate)
            .put("network_generation", input.networkGeneration)
            .put("scope", input.selector.selector)
            .put("result", if (result.healthy) "available" else "unavailable")
            .put("action", "https_request")
            .put("target", input.target)
            .put("observed_at", now.toString())
            .put("valid_until", now.plus(10, ChronoUnit.MINUTES).toString())
        if (result.healthy) observation.put("metric_millis", result.metricMillis)
        val retained = observations(profileId).objects().filter {
            it.getString("candidate_id") != input.selector.candidate &&
                it.getString("network_generation") == runtime.generation
        } + observation
        protected.put(ProfileStorage.observations(profileId), JSONArray(retained.sortedBy { it.getString("candidate_id") }).toString().encodeToByteArray())
        val observed = current.copy(selectors = listOf(input.selector.copy(state = if (result.healthy) "available" else "unavailable")))
        runtime.application = observed
        val detail = "${input.selector.selector} · ${input.target} · ${if (result.healthy) "该目标成功" else "该目标失败"} · $now"
        publish(runtime, observed, running = true, observation = detail)
        onRecorded()
        if (result.healthy || !allowFallback) return@withLock null
        val next = runCatching { evaluate(profileId, runtime, profile, runtime.actual) }.getOrNull() ?: return@withLock null
        if (next.selectors.singleOrNull()?.candidate == input.selector.candidate) return@withLock null
        val selector = SelectorClient(profile.config)
        selector.apply(next.selectors)
        val actual = selector.readCurrent(next.selectors)
        check(next.selectors.all { actual[it.selector] == it.candidate }) { "fallback selector 回读不一致" }
        runtime.actual = LinkedHashMap(actual)
        runtime.application = next
        publish(runtime, next, running = true, observation = detail)
        singleBusinessProbeInput(profile, next, runtime.generation)
    }

    internal suspend fun reportData(profileId: String, state: ByteArray, acceptedView: String, appliedView: String): RuntimeReportData = operation.withLock {
        val runtime = runtime(profileId)
        ensureNetworkGeneration(profileId, runtime)
        val running = appliedView == acceptedView && runtime.runningProfile?.viewDigest == acceptedView
        val selected = if (running) runtime.application?.selectors.orEmpty() else emptyList()
        val selections = JSONArray(selected.sortedBy { it.selector }.map {
            JSONObject().put("scope", it.selector).put("candidate_id", it.candidate)
        }).toString().encodeToByteArray()
        val resources = if (running) {
            runCatching {
                val key = ProfileStorage.resourceObservations(profileId)
                val previous = runtime.resourceObservations ?: protected.get(key) ?: ByteArray(0)
                val sampled = Loomcore.observeAndroidFirstHops(state, selections, previous, runtime.generation)
                runtime.resourceObservations = sampled
                if (!sampled.contentEquals(previous)) {
                    runCatching { protected.put(key, sampled) }.onFailure {
                        Log.w("Loom", "首跳样本缓存写入失败；本进程保留原样本")
                    }
                }
                sampled
            }.getOrElse {
                Log.w("Loom", "首跳样本不可用；保留原缓存与独立业务结果")
                ByteArray(0)
            }
        } else ByteArray(0)
        val now = Instant.now()
        val values = if (running) observations(profileId).objects().filter { observation ->
            observation.getString("network_generation") == runtime.generation &&
                selected.any { it.selector == observation.getString("scope") && it.candidate == observation.getString("candidate_id") } &&
                runCatching { Instant.parse(observation.getString("valid_until")).isAfter(now) }.getOrDefault(false)
        }.sortedBy { it.getString("candidate_id") } else emptyList()
        RuntimeReportData(
            protected.get(ProfileStorage.routePreference(profileId)) ?: ByteArray(0),
            resources,
            JSONArray(values).toString().encodeToByteArray(),
            selections,
            runtime.generation,
        )
    }

    suspend fun tunnelStopped(profileId: String) = operation.withLock {
        val runtime = runtime(profileId)
        runtime.runningProfile = null
        runtime.application = null
        runtime.actual = linkedMapOf()
        protected.put(ProfileStorage.observations(profileId), "[]".encodeToByteArray())
        runtime.mutableStatus.value = runtime.mutableStatus.value.copy(running = false, busy = false, currentPaths = emptyList(), observationDetail = "业务结果尚未产生")
    }

    suspend fun removeProfile(profileId: String) = operation.withLock {
        require(ProfileStorage.validId(profileId)) { "配置标识无效" }
        synchronized(profiles) {
            check(profiles[profileId]?.runningProfile == null) { "运行中的配置不能删除" }
            profiles.remove(profileId)
        }
        protected.remove(ProfileStorage.routePreference(profileId))
        protected.remove(ProfileStorage.observations(profileId))
        protected.remove(ProfileStorage.resourceObservations(profileId))
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
                    it.getString("final_exit"),
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
                    finalExit = selected.finalExit,
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
        var resourceObservations: ByteArray? = null
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
