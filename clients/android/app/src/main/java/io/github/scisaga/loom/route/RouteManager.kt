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
    val blockedScopes: List<String> = emptyList(),
) {
    fun execution(): List<AppliedSelector> = selectors + blockedScopes.map {
        AppliedSelector(it, "reject", emptyList(), "", "unavailable")
    }
}

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

internal fun serviceBusinessProbeInputs(
    profile: ManagedProfile,
    application: AppliedRoute?,
    networkGeneration: String,
): List<BusinessProbeInput> {
    val dns = profile.dns.firstOrNull() ?: return emptyList()
    val groups = profile.businessProbeTargets.associateBy { it.serviceID }
    return application?.selectors.orEmpty().sortedBy { it.selector }.flatMap { selected ->
        val group = groups.values.singleOrNull {
            selected.selector == "service:${it.serviceID}" || selected.selector == "local_network:${it.serviceID}"
        } ?: return@flatMap emptyList()
        group.targets.map { target -> BusinessProbeInput(selected, networkGeneration, dns, target) }
    }
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
        val current = client.readCurrent(initial.execution())
        val desired = evaluate(profileId, runtime, profile, current)
        client.apply(desired.execution())
        val readback = client.readCurrent(desired.execution())
        check(desired.execution().all { readback[it.selector] == it.candidate }) { "selector 回读与选择不一致" }
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
                    SelectorClient(available.config).apply(desired.execution())
                    runtime.actual = LinkedHashMap(SelectorClient(available.config).readCurrent(desired.execution()))
                    runtime.application = desired
                    publish(runtime, desired, running = true, observation = businessObservationDetail(profileId, runtime))
                } else {
                    publish(runtime, evaluate(profileId, runtime, available, emptyMap()), running = false)
                }
            }
        }
    }

    internal suspend fun businessProbeInputs(profileId: String, profile: ManagedProfile): List<BusinessProbeInput> = operation.withLock {
        val runtime = runtime(profileId)
        if (runtime.runningProfile?.recordID != profile.recordID) return@withLock emptyList()
        // Expired failures permit a new attempt; no sample is deleted to force it.
        val desired = evaluate(profileId, runtime, profile, runtime.actual)
        val selector = SelectorClient(profile.config)
        selector.apply(desired.execution())
        runtime.actual = LinkedHashMap(selector.readCurrent(desired.execution()))
        runtime.application = desired
        publish(runtime, desired, running = true, observation = businessObservationDetail(profileId, runtime))
        val now = Instant.now()
        serviceBusinessProbeInputs(profile, desired, runtime.generation).filter { input ->
            observations(profileId).objects().none {
                it.getString("candidate_id") == input.selector.candidate &&
                    it.getString("scope") == input.selector.selector &&
                    it.getString("target") == input.target && it.getString("action") == "https_request" &&
                    it.getString("network_generation") == input.networkGeneration &&
                    it.currentAt(now)
            }
        }
    }

    internal suspend fun recordBusinessOutcome(
        profileId: String,
        profile: ManagedProfile,
        input: BusinessProbeInput,
        result: ProbeResult,
        allowFallback: Boolean,
        finishBatch: Boolean,
        onRecorded: () -> Unit,
    ): List<BusinessProbeInput> = operation.withLock {
        val runtime = runtime(profileId)
        val current = runtime.application ?: return@withLock emptyList()
        if (runtime.runningProfile?.recordID != profile.recordID || runtime.generation != input.networkGeneration ||
            current.selectors.singleOrNull { it.selector == input.selector.selector }?.candidate != input.selector.candidate || result.target != input.target
        ) return@withLock emptyList()
        val now = Instant.now().truncatedTo(ChronoUnit.SECONDS)
        val observation = JSONObject()
            .put("candidate_id", input.selector.candidate)
            .put("network_generation", input.networkGeneration)
            .put("scope", input.selector.selector)
            .put("result", if (result.healthy) "available" else "unavailable")
            .put("action", "https_request")
            .put("target", input.target)
            .put("observed_at", now.toString())
            .put("valid_until", now.plusSeconds(if (result.healthy) 600 else 30).toString())
        if (result.healthy) observation.put("metric_millis", result.metricMillis)
        val retained = observations(profileId).objects().filter {
            (it.getString("candidate_id") != input.selector.candidate ||
                it.getString("scope") != input.selector.selector || it.getString("target") != input.target ||
                it.getString("action") != "https_request") && it.getString("network_generation") == runtime.generation
        } + observation
        protected.put(ProfileStorage.observations(profileId), JSONArray(retained.sortedWith(compareBy({ it.getString("candidate_id") }, { it.getString("scope") }, { it.getString("target") }, { it.getString("action") }))).toString().encodeToByteArray())
        val evaluated = evaluate(profileId, runtime, profile, runtime.actual)
        val nextForScope = evaluated.selectors.singleOrNull { it.selector == input.selector.selector }
        val observed = current.copy(selectors = current.selectors.map {
            if (it.selector == input.selector.selector) it.copy(state =
                if (nextForScope?.candidate == it.candidate) nextForScope.state else "unknown") else it
        })
        runtime.application = observed
        val detail = businessObservationDetail(profileId, runtime)
        publish(runtime, observed, running = true, observation = detail)
        onRecorded()
        if (!finishBatch || nextForScope?.candidate == input.selector.candidate) return@withLock emptyList()
        // Only this Service may change during its fallback. After the second
        // failure its selector is rejected until the next normal refresh.
        val next = observed.copy(
            selectors = observed.selectors.filter { it.selector != input.selector.selector } +
                if (allowFallback && nextForScope != null) listOf(nextForScope) else emptyList(),
            blockedScopes = observed.blockedScopes.filter { it != input.selector.selector } +
                if (!allowFallback || nextForScope == null) listOf(input.selector.selector) else emptyList(),
        )
        val selector = SelectorClient(profile.config)
        selector.apply(next.execution())
        val actual = selector.readCurrent(next.execution())
        check(next.execution().all { actual[it.selector] == it.candidate }) { "fallback selector 回读不一致" }
        runtime.actual = LinkedHashMap(actual)
        runtime.application = next
        publish(runtime, next, running = true, observation = businessObservationDetail(profileId, runtime))
        if (!allowFallback || nextForScope == null || nextForScope.candidate == input.selector.candidate) return@withLock emptyList()
        serviceBusinessProbeInputs(profile, next, runtime.generation).filter { it.selector.selector == input.selector.selector }.filter { candidate ->
            observations(profileId).objects().none { it.optString("candidate_id") == candidate.selector.candidate &&
                it.optString("scope") == candidate.selector.selector && it.optString("target") == candidate.target &&
                it.optString("network_generation") == runtime.generation && it.optString("action") == "https_request" &&
                it.currentAt(Instant.now())
            }
        }
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
                observation.currentAt(now)
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
        val resources = runCatching {
            Loomcore.androidCachedResourceObservations(
                runtime.resourceObservations ?: protected.get(ProfileStorage.resourceObservations(profileId)) ?: ByteArray(0),
                profile.resourceCacheIdentity,
                runtime.generation.ifBlank { "startup" },
            )
        }.getOrElse {
            Log.w("Loom", "首跳样本缓存不可用；继续必要业务尝试")
            "[]".encodeToByteArray()
        }
        val body = Loomcore.evaluateAndroidRoutes(
            profile.routes.encodeToByteArray(),
            observations(profileId).toString().encodeToByteArray(),
            protected.get(ProfileStorage.routePreference(profileId)) ?: ByteArray(0),
            currentBody,
            runtime.generation.ifBlank { "startup" },
            Instant.now().truncatedTo(ChronoUnit.SECONDS).toString(),
            JSONArray(profile.businessProbeTargets.map { group -> JSONObject()
                .put("service_id", group.serviceID).put("targets", JSONArray(group.targets))
            }).toString().encodeToByteArray(),
            resources,
        )
        val root = JSONObject(body.decodeToString())
        return AppliedRoute(
            mode = RouteMode.entries.first { it.wire == root.getString("mode") },
            exit = root.optString("exit"),
            directAvailable = root.getBoolean("direct_available"),
            exits = root.getJSONArray("exits").strings(),
            blockedScopes = root.getJSONArray("blocked_scopes").strings(),
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

    private fun businessObservationDetail(profileId: String, runtime: ProfileRuntime): String {
        val profile = runtime.runningProfile ?: return "业务结果尚未产生"
        val samples = observations(profileId).objects()
        val now = Instant.now()
        return serviceBusinessProbeInputs(profile, runtime.application, runtime.generation).joinToString("\n") { input ->
            val sample = samples.singleOrNull { it.optString("candidate_id") == input.selector.candidate &&
                it.optString("scope") == input.selector.selector && it.optString("target") == input.target &&
                it.optString("action") == "https_request" && it.optString("network_generation") == runtime.generation }
            val valid = sample != null && sample.currentAt(now)
            val outcome = if (!valid) "尚无有效结果" else when (sample?.optString("result")) {
                "available" -> "成功"
                "unavailable" -> "失败"
                else -> "尚无有效结果"
            }
            "${input.selector.selector} · ${input.target} · $outcome · ${sample?.optString("observed_at").orEmpty()}"
        }.ifBlank { "业务结果尚未产生" }
    }

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
            detail = (if (running) "$label 已应用并读回" else "$label · 等待连接") +
                if (route.blockedScopes.isEmpty()) "" else "；暂无可用路径：${route.blockedScopes.joinToString()}",
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

private fun JSONObject.currentAt(now: Instant): Boolean = runCatching {
    !Instant.parse(getString("observed_at")).isAfter(now) && Instant.parse(getString("valid_until")).isAfter(now)
}.getOrDefault(false)
