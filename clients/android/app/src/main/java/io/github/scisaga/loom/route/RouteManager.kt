package io.github.scisaga.loom.route

import android.content.Context
import io.github.scisaga.loom.enrollment.ManagedProfile
import io.github.scisaga.loom.security.EncryptedStore
import io.github.scisaga.loom.vpn.ProbeResult
import io.github.scisaga.loomcore.Loomcore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
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
    val chain: String,
    val links: List<RouteLinkStatus>,
    val reason: String,
    val updatedAt: String,
)

data class RouteLinkStatus(val from: String, val to: String, val label: String, val detail: String)

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
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val operation = Mutex()
    private val mutableStatus = MutableStateFlow(RouteStatus())
    val status = mutableStatus.asStateFlow()

    @Volatile private var availableProfile: ManagedProfile? = null
    @Volatile private var runningProfile: ManagedProfile? = null
    @Volatile private var generation = ""
    private var actual = linkedMapOf<String, String>()
    private var application: AppliedRoute? = null

    fun profileAvailable(profile: ManagedProfile) {
        scope.launch {
            operation.withLock {
                availableProfile = profile
                val projected = evaluate(profile, emptyMap())
                publish(projected, running = runningProfile?.recordID == profile.recordID)
            }
        }
    }

    fun beginNetworkGeneration(changed: Boolean = false): String {
        val saved = protected.get(NETWORK_GENERATION)?.decodeToString().orEmpty()
        if (!changed && generation.isBlank() && saved.isNotBlank()) {
            generation = saved
            return saved
        }
        if (!changed && generation.isNotBlank()) return generation
        val next = UUID.randomUUID().toString()
        generation = next
        actual = linkedMapOf()
        application = null
        protected.put(NETWORK_GENERATION, next.encodeToByteArray())
        protected.put(OBSERVATIONS, "[]".encodeToByteArray())
        return next
    }

    internal suspend fun applyToRunning(profile: ManagedProfile): AppliedRoute = operation.withLock {
        if (generation.isBlank()) beginNetworkGeneration()
        mutableStatus.value = mutableStatus.value.copy(busy = true, detail = "正在应用候选并读回 selector…")
        val initial = evaluate(profile, actual)
        val client = SelectorClient(profile.config)
        val current = client.readCurrent(initial.selectors)
        val desired = evaluate(profile, current)
        client.apply(desired.selectors)
        val readback = client.readCurrent(desired.selectors)
        check(desired.selectors.all { readback[it.selector] == it.candidate }) { "selector 回读与选择不一致" }
        actual = LinkedHashMap(readback)
        application = desired
        runningProfile = profile
        publish(desired, running = true)
        desired
    }

    fun select(mode: RouteMode, exit: String = "") {
        scope.launch {
            operation.withLock {
                val preference = JSONObject().put("schema", 1).put("mode", mode.wire)
                    .apply { if (mode == RouteMode.FIXED_EXIT) put("exit", exit) }
                    .toString().encodeToByteArray()
                protected.put(PREFERENCE, preference)
                val profile = runningProfile ?: availableProfile ?: return@withLock
                if (runningProfile != null) {
                    val desired = evaluate(profile, actual)
                    SelectorClient(profile.config).apply(desired.selectors)
                    actual = LinkedHashMap(SelectorClient(profile.config).readCurrent(desired.selectors))
                    application = desired
                    publish(desired, running = true)
                } else {
                    publish(evaluate(profile, emptyMap()), running = false)
                }
            }
        }
    }

    /** Records at most one business result for each selected candidate in this network generation. */
    internal suspend fun recordBusinessOutcome(profile: ManagedProfile, probe: ProbeResult): AppliedRoute = operation.withLock {
        val currentApplication = checkNotNull(application) { "尚未应用候选" }
        val observations = observations()
        val now = Instant.now().truncatedTo(ChronoUnit.SECONDS)
        val existing = observations.objects().map { it.getString("candidate_id") to it.getString("network_generation") }.toSet()
        currentApplication.selectors.distinctBy(AppliedSelector::candidate).forEach { selected ->
            // Direct participates in selection without a synthetic latency measurement.
            if (selected.chain.isEmpty() || selected.candidate to generation in existing) return@forEach
            observations.put(
                JSONObject()
                    .put("candidate_id", selected.candidate)
                    .put("network_generation", generation)
                    .put("scope", selected.selector)
                    .put("result", if (probe.healthy) "available" else "unavailable")
                    .put("action", "dns_https")
                    .put("observed_at", now.toString())
                    .put("valid_until", now.plus(10, ChronoUnit.MINUTES).toString()),
            )
        }
        val sorted = observations.objects().sortedBy { it.getString("candidate_id") }
        protected.put(OBSERVATIONS, JSONArray(sorted).toString().encodeToByteArray())
        val next = evaluate(profile, actual)
        if (next.selectors != currentApplication.selectors) {
            val client = SelectorClient(profile.config)
            client.apply(next.selectors)
            actual = LinkedHashMap(client.readCurrent(next.selectors))
        }
        application = next
        publish(next, running = true, observation = if (probe.healthy) "真实 DNS/HTTPS 可用" else "真实 DNS/HTTPS 不可用；已切换候选")
        next
    }

    fun reportObservations(): ByteArray = synchronized(this) {
        val currentGeneration = generation
        val values = observations().objects().filter { it.getString("network_generation") == currentGeneration }
            .sortedBy { it.getString("candidate_id") }
        JSONArray(values).toString().encodeToByteArray()
    }

    fun selectedCandidate(): String = application?.selectors?.firstOrNull()?.candidate.orEmpty()

    fun tunnelStopped() {
        runningProfile = null
        application = null
        actual = linkedMapOf()
        mutableStatus.value = mutableStatus.value.copy(running = false, busy = false)
    }

    private fun evaluate(profile: ManagedProfile, current: Map<String, String>): AppliedRoute {
        val currentBody = JSONObject(current).toString().encodeToByteArray()
        val body = Loomcore.evaluateAndroidRoutes(
            profile.routes.encodeToByteArray(),
            observations().toString().encodeToByteArray(),
            protected.get(PREFERENCE) ?: ByteArray(0),
            currentBody,
            generation.ifBlank { "startup" },
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

    private fun observations(): JSONArray = protected.get(OBSERVATIONS)?.let {
        runCatching { JSONArray(it.decodeToString()) }.getOrNull()
    } ?: JSONArray()

    private fun publish(route: AppliedRoute, running: Boolean, observation: String = mutableStatus.value.observationDetail) {
        val label = when (route.mode) {
            RouteMode.DIRECT -> "Direct"
            RouteMode.AUTO -> "Auto"
            RouteMode.FIXED_EXIT -> "指定出口 ${route.exit}"
        }
        val now = Instant.now().truncatedTo(ChronoUnit.SECONDS).toString()
        mutableStatus.value = RouteStatus(
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
                    chain = if (selected.chain.isEmpty()) "Direct" else selected.chain.joinToString(" → "),
                    links = emptyList(),
                    reason = "${selected.state} · 来自认证候选与当前网络代业务结果",
                    updatedAt = now,
                )
            },
            running = running,
        )
    }

    companion object {
        private const val PREFERENCE = "route-preference-v2"
        private const val OBSERVATIONS = "route-observations-v2"
        private const val NETWORK_GENERATION = "network-generation-v2"
        @Volatile private var instance: RouteManager? = null

        fun get(context: Context): RouteManager = instance ?: synchronized(this) {
            instance ?: RouteManager(context).also { instance = it }
        }
    }
}

private fun JSONArray.objects(): List<JSONObject> = (0 until length()).map(::getJSONObject)
private fun JSONArray.strings(): List<String> = (0 until length()).map(::getString)
