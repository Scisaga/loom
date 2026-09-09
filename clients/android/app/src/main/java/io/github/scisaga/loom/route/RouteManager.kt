package io.github.scisaga.loom.route

import android.content.Context
import io.github.scisaga.loom.enrollment.ManagedProfile
import io.github.scisaga.loom.security.EncryptedStore
import io.github.scisaga.loomcore.Loomcore
import kotlinx.coroutines.CancellationException
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
    val detail: String = "等待已验证的移动调度计划",
    val observationDetail: String = "服务器观测尚未读取",
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

data class RouteLinkStatus(
    val from: String,
    val to: String,
    val label: String,
    val detail: String,
)

internal data class AppliedRoute(
    val planScope: String,
    val mode: RouteMode,
    val exit: String,
    val blocked: Boolean,
    val blockReason: String,
    val directAvailable: Boolean,
    val exits: List<String>,
    val selectors: List<AppliedSelector>,
)

internal data class AppliedSelector(
    val selector: String,
    val candidate: String,
    val chain: List<String>,
)

private data class RouteTick(
    val state: String,
    val application: AppliedRoute,
    val changed: Boolean,
    val nextAfterMs: Long,
    val detail: String,
    val observationError: String,
    val decisions: List<RouteDecision>,
)

internal data class RouteDecision(
    val declaration: String,
    val selector: String,
    val current: String,
    val choice: String,
    val chain: List<String>,
    val reason: String,
    val updatedAt: String,
    val candidates: Int,
    val measurements: List<RouteMeasurement>,
)

internal data class RouteMeasurement(
    val hop: Int,
    val from: String,
    val to: String,
    val kind: String,
    val observedAt: String,
    val error: String,
    val delayMs: Long?,
    val variationMs: Long?,
    val rateBps: Double?,
    val samples: Long,
    val failures: Long,
)

class RouteManager private constructor(context: Context) {
    private val protected = EncryptedStore(context.applicationContext)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val operation = Mutex()
    private val mutableStatus = MutableStateFlow(RouteStatus())
    val status = mutableStatus.asStateFlow()

    @Volatile private var availableProfile: ManagedProfile? = null
    @Volatile private var runningRecordID: String? = null
    private var runningInputs = ByteArray(0)
    private var runningEntries = ByteArray(0)
    private var pendingObservations: ByteArray? = null
    @Volatile private var lastDecisions: List<RouteDecision> = emptyList()

    fun profileAvailable(profile: ManagedProfile) {
        scope.launch {
            operation.withLock {
                availableProfile = profile
                try {
                    publish(evaluate(profile), runningRecordID == profile.recordID)
                } catch (error: Throwable) {
                    mutableStatus.value = RouteStatus(
                        blocked = true,
                        detail = "移动调度状态不可用：${message(error)}",
                        running = runningRecordID == profile.recordID,
                    )
                }
            }
        }
    }

    /** §7.3.1：只在 libbox 已启动带认证的回环 API 后调用。 */
    suspend fun applyToRunning(profile: ManagedProfile) = operation.withLock {
        availableProfile = profile
        val routePlan = profile.routePlan
        if (routePlan == null) {
            runningRecordID = profile.recordID
            mutableStatus.value = RouteStatus(
                detail = "当前缓存来自 Stage 2；刷新签名配置后才能切换移动端路径",
                running = true,
            )
            return@withLock
        }
        val application = evaluate(profile)
        check(!application.blocked) { application.blockReason }
        val selector = SelectorClient(routePlan)
        selector.apply(application.selectors)
        val actual = selector.readCurrent(application.selectors)
        protected.put(SELECTIONS, encodeSelections(application, actual))
        runningRecordID = profile.recordID
        runningInputs = ByteArray(0)
        runningEntries = ByteArray(0)
        pendingObservations = null
        lastDecisions = emptyList()
        publish(application, true, actualSelections = actual)
    }

    fun select(mode: RouteMode, exit: String = "") {
        mutableStatus.value = mutableStatus.value.copy(busy = true, detail = "正在应用路由偏好…")
        scope.launch {
            operation.withLock {
                val profile = availableProfile
                if (profile?.routePlan == null) {
                    mutableStatus.value = mutableStatus.value.copy(
                        busy = false,
                        detail = "当前签名配置尚未携带移动调度计划",
                    )
                    return@withLock
                }
                val previous = protected.get(PREFERENCE)
                val previousSelections = protected.get(SELECTIONS)
                val previousSchedulerState = protected.get(SCHEDULER_STATE)
                val previousDecisions = lastDecisions
                val next = encodePreference(mode, exit)
                try {
                    val application = evaluate(profile, next)
                    check(!application.blocked) { application.blockReason }
                    val running = runningRecordID == profile.recordID
                    val actual = if (running) {
                        SelectorClient(profile.routePlan).let { selector ->
                            selector.apply(application.selectors)
                            selector.readCurrent(application.selectors)
                        }
                    } else {
                        application.selectors.associate { it.selector to it.candidate }
                    }
                    try {
                        protected.put(PREFERENCE, next)
                        protected.put(SELECTIONS, encodeSelections(application, actual))
                    } catch (persistError: Throwable) {
                        if (running) {
                            runCatching {
                                val rollback = evaluate(profile, previous ?: ByteArray(0))
                                if (!rollback.blocked) SelectorClient(profile.routePlan).apply(rollback.selectors)
                            }
                        }
                        restore(PREFERENCE, previous)
                        restore(SELECTIONS, previousSelections)
                        throw persistError
                    }
                    lastDecisions = emptyList()
                    publish(
                        application,
                        running,
                        if (running && runningInputs.isNotEmpty()) "路由偏好已生效；正在按当前分段证据重算" else if (running) "路由偏好已生效；等待当前连接代入口结果" else "偏好已保存；下次连接生效",
                        actual,
                    )
                    if (running && runningInputs.isNotEmpty()) runRouteTickLocked(profile, null)
                } catch (error: Throwable) {
                    restore(PREFERENCE, previous)
                    restore(SELECTIONS, previousSelections)
                    restore(SCHEDULER_STATE, previousSchedulerState)
                    lastDecisions = previousDecisions
                    val restored = runCatching { evaluate(profile, previous ?: ByteArray(0)) }.getOrNull()
                    if (restored != null) {
                        val running = runningRecordID == profile.recordID
                        val actual = if (running) {
                            runCatching {
                                SelectorClient(profile.routePlan).let { selector ->
                                    selector.apply(restored.selectors)
                                    selector.readCurrent(restored.selectors)
                                }
                            }.getOrElse { rollbackError ->
                                mutableStatus.value = mutableStatus.value.copy(
                                    busy = false,
                                    blocked = true,
                                    detail = "切换与回滚均失败：${message(error)}；${message(rollbackError)}",
                                )
                                return@withLock
                            }
                        } else {
                            restored.selectors.associate { it.selector to it.candidate }
                        }
                        publish(restored, running, "切换失败，已恢复：${message(error)}", actual, previousDecisions)
                    } else {
                        mutableStatus.value = mutableStatus.value.copy(busy = false, detail = "切换失败：${message(error)}")
                    }
                }
            }
        }
    }

    /** §16.1.2：当前物理网络代只执行一轮并行入口测量。 */
    suspend fun beginRouteSession(profile: ManagedProfile, source: String) {
        val plan = profile.routePlan ?: return
        val inputs = Loomcore.androidRoutingInputs(profile.config.encodeToByteArray(), plan.encodeToByteArray())
        val entries = AndroidEntryProbe.measure(inputs, source)
        operation.withLock {
            if (runningRecordID != profile.recordID) throw CancellationException("隧道会话已经结束")
            runningInputs = inputs
            runningEntries = entries
            val latest = pendingObservations
            pendingObservations = null
            runRouteTickLocked(profile, latest)
        }
    }

    /** §16.1.2：仅在既有签名上报周期返回证据时重算，不新增轮询。 */
    suspend fun consumeObservations(profile: ManagedProfile, observations: ByteArray?, readError: String? = null) =
        operation.withLock {
            if (runningRecordID != profile.recordID) throw CancellationException("隧道会话已经结束")
            if (readError != null) {
                mutableStatus.value = mutableStatus.value.copy(observationDetail = readError)
                return@withLock
            }
            if (runningInputs.isEmpty()) {
                pendingObservations = observations?.copyOf()
                return@withLock
            }
            runRouteTickLocked(profile, observations)
        }

    private suspend fun runRouteTickLocked(profile: ManagedProfile, observations: ByteArray?) {
        val plan = checkNotNull(profile.routePlan) { "当前签名配置没有移动调度计划" }
        check(runningInputs.isNotEmpty()) { "当前连接代尚未完成入口输入推导" }
        val previousSelections = protected.get(SELECTIONS)
        val previousState = protected.get(SCHEDULER_STATE)
        val baseline = evaluate(profile)
        val selector = SelectorClient(plan)
        val actual = selector.readCurrent(baseline.selectors)
        val actualBody = encodeSelections(baseline, actual)
        val body = Loomcore.runAndroidRouteTick(
            plan.encodeToByteArray(),
            protected.get(PREFERENCE) ?: ByteArray(0),
            previousSelections ?: ByteArray(0),
            runningInputs,
            actualBody,
            runningEntries,
            previousState ?: ByteArray(0),
            observations ?: ByteArray(0),
            profile.caPEM,
            java.time.Instant.now().toString(),
        )
        if (runningRecordID != profile.recordID) throw CancellationException("隧道会话已经结束")
        val result = decodeTick(body)
        val rollback = baseline.selectors.map { selection ->
            selection.copy(candidate = checkNotNull(actual[selection.selector]))
        }
        try {
            if (result.changed) selector.apply(result.application.selectors)
            val readback = selector.readCurrent(result.application.selectors)
            check(result.application.selectors.all { readback[it.selector] == it.candidate }) {
                "selector 实际路径与共享核心选择不一致"
            }
            protected.put(SELECTIONS, encodeSelections(result.application, readback))
            protected.put(SCHEDULER_STATE, result.state.encodeToByteArray())
            lastDecisions = result.decisions
            publish(
                result.application,
                true,
                result.detail,
                readback,
                result.decisions,
                result.observationError.ifBlank { "服务器观测已验签；缺失项保持未知" },
            )
        } catch (error: Throwable) {
            if (result.changed) runCatching { selector.apply(rollback) }
            restore(SELECTIONS, previousSelections)
            restore(SCHEDULER_STATE, previousState)
            throw error
        }
    }

    fun routeUpdateFailed(error: Throwable) {
        mutableStatus.value = mutableStatus.value.copy(
            busy = false,
            detail = "自动选路更新失败；保留实际路径：${message(error)}",
        )
    }

    fun agentState(nodeID: String, timestamp: String): ByteArray? {
        val decisions = lastDecisions
        if (decisions.isEmpty()) return null
        return JSONObject()
            .put("node", nodeID)
            .put("ts", timestamp)
            .put("component_version", "android-client-route-v2")
            .put(
                "selections",
                JSONArray().apply {
                    decisions.sortedBy(RouteDecision::declaration).forEach { decision ->
                        put(
                            JSONObject()
                                .put("declaration", decision.declaration)
                                .put("selector", decision.selector)
                                .put("candidate", decision.choice)
                                .put("chain", JSONArray(decision.chain))
                                .put("reason", decision.reason)
                                .put("updated_at", decision.updatedAt)
                                .put(
                                    "health",
                                    JSONObject()
                                        .put("candidates", decision.candidates)
                                        .put("recent_success", 0)
                                        .put("recent_failed", 0)
                                        .put("stale", 0)
                                        .put("unknown", decision.candidates)
                                        .put("selected_state", "unknown"),
                                ),
                        )
                    }
                },
            )
            .toString()
            .encodeToByteArray()
    }

    fun tunnelStopped() {
        runningRecordID = null
        runningInputs = ByteArray(0)
        runningEntries = ByteArray(0)
        pendingObservations = null
        lastDecisions = emptyList()
        mutableStatus.value = mutableStatus.value.copy(running = false, busy = false)
    }

    private fun evaluate(profile: ManagedProfile, preference: ByteArray? = null): AppliedRoute {
        val plan = profile.routePlan ?: return AppliedRoute(
            planScope = "",
            mode = RouteMode.AUTO,
            exit = "",
            blocked = true,
            blockReason = "当前签名配置没有移动调度计划",
            directAvailable = false,
            exits = emptyList(),
            selectors = emptyList(),
        )
        val body = Loomcore.evaluateAndroidRoute(
            plan.encodeToByteArray(),
            preference ?: protected.get(PREFERENCE) ?: ByteArray(0),
            protected.get(SELECTIONS) ?: ByteArray(0),
        )
        return decodeApplication(body)
    }

    private fun publish(
        application: AppliedRoute,
        running: Boolean,
        overrideDetail: String? = null,
        actualSelections: Map<String, String> = application.selectors.associate { it.selector to it.candidate },
        decisions: List<RouteDecision> = lastDecisions,
        observationDetail: String = mutableStatus.value.observationDetail,
    ) {
        val label = when (application.mode) {
            RouteMode.DIRECT -> "Direct"
            RouteMode.AUTO -> "Auto"
            RouteMode.FIXED_EXIT -> "指定出口 ${application.exit}"
        }
        mutableStatus.value = RouteStatus(
            available = application.planScope.isNotEmpty(),
            busy = false,
            mode = application.mode,
            exit = application.exit,
            exits = application.exits,
            directAvailable = application.directAvailable,
            blocked = application.blocked,
            detail = overrideDetail ?: when {
                application.blocked -> application.blockReason
                running -> "$label 已生效"
                else -> "$label · 等待连接"
            },
            observationDetail = observationDetail,
            currentPaths = buildRoutePaths(application, actualSelections, decisions),
            running = running,
        )
    }

    private fun encodePreference(mode: RouteMode, exit: String): ByteArray = JSONObject()
        .put("schema", 1)
        .put("mode", mode.wire)
        .apply { if (mode == RouteMode.FIXED_EXIT) put("exit", exit) }
        .toString()
        .encodeToByteArray()

    private fun encodeSelections(
        application: AppliedRoute,
        actualSelections: Map<String, String> = application.selectors.associate { it.selector to it.candidate },
    ): ByteArray = JSONObject()
        .put("schema", 1)
        .put("plan_scope", application.planScope)
        .put(
            "selections",
            JSONArray().apply {
                application.selectors.forEach {
                    put(JSONObject().put("selector", it.selector).put("candidate", actualSelections[it.selector] ?: it.candidate))
                }
            },
        )
        .toString()
        .encodeToByteArray()

    private fun decodeApplication(body: ByteArray): AppliedRoute {
        return decodeApplication(JSONObject(body.decodeToString()))
    }

    private fun decodeApplication(root: JSONObject): AppliedRoute {
        check(root.getInt("schema") == 1) { "共享核心返回未知路由 schema" }
        val selectors = root.getJSONArray("selectors").objects().map { selector ->
            AppliedSelector(
                selector = selector.getString("selector"),
                candidate = selector.getString("candidate"),
                chain = selector.optJSONArray("chain")?.strings().orEmpty(),
            )
        }
        return AppliedRoute(
            planScope = root.getString("plan_scope"),
            mode = RouteMode.entries.first { it.wire == root.getString("mode") },
            exit = root.optString("exit"),
            blocked = root.getBoolean("blocked"),
            blockReason = root.optString("block_reason"),
            directAvailable = root.getBoolean("direct_available"),
            exits = root.getJSONArray("exits").strings(),
            selectors = selectors,
        )
    }

    private fun decodeTick(body: ByteArray): RouteTick {
        val root = JSONObject(body.decodeToString())
        check(root.getInt("schema") == 2) { "共享核心返回未知调度 schema" }
        return RouteTick(
            state = root.getString("state"),
            application = decodeApplication(root.getJSONObject("application")),
            changed = root.getBoolean("changed"),
            nextAfterMs = root.getLong("next_after_ms"),
            detail = root.getString("detail"),
            observationError = root.optString("observation_error"),
            decisions = root.optJSONArray("decisions")?.objects()?.map { decision ->
                RouteDecision(
                    declaration = decision.getString("declaration"),
                    selector = decision.getString("selector"),
                    current = decision.getString("current"),
                    choice = decision.getString("choice"),
                    chain = decision.optJSONArray("chain")?.strings().orEmpty(),
                    reason = decision.getString("reason"),
                    updatedAt = decision.getString("updated_at"),
                    candidates = decision.getInt("candidates"),
                    measurements = decision.optJSONArray("measurements")?.objects()?.map { measurement ->
                        RouteMeasurement(
                            hop = measurement.getInt("hop"),
                            from = measurement.getString("from"),
                            to = measurement.getString("to"),
                            kind = measurement.getString("kind"),
                            observedAt = measurement.optString("observed_at"),
                            error = measurement.optString("error"),
                            delayMs = measurement.longOrNull("delay_ms"),
                            variationMs = measurement.longOrNull("variation_ms"),
                            rateBps = measurement.doubleOrNull("rate_bps"),
                            samples = measurement.optLong("samples"),
                            failures = measurement.optLong("failures"),
                        )
                    }.orEmpty(),
                )
            }.orEmpty(),
        )
    }

    private fun restore(key: String, value: ByteArray?) {
        if (value == null) protected.remove(key) else protected.put(key, value)
    }

    private fun JSONArray.strings(): List<String> = (0 until length()).map(::getString)
    private fun JSONArray.objects(): List<JSONObject> = (0 until length()).map(::getJSONObject)
    private fun JSONObject.longOrNull(name: String): Long? = if (has(name) && !isNull(name)) getLong(name) else null
    private fun JSONObject.doubleOrNull(name: String): Double? = if (has(name) && !isNull(name)) getDouble(name) else null
    private fun message(error: Throwable): String = error.message ?: error.javaClass.simpleName

    companion object {
        private const val PREFERENCE = "route-preference"
        private const val SELECTIONS = "route-selections"
        private const val SCHEDULER_STATE = "route-scheduler-state"
        @Volatile private var instance: RouteManager? = null

        fun get(context: Context): RouteManager = instance ?: synchronized(this) {
            instance ?: RouteManager(context).also { instance = it }
        }
    }
}

internal fun buildRoutePaths(
    application: AppliedRoute,
    actualSelections: Map<String, String>,
    decisions: List<RouteDecision>,
): List<RoutePathStatus> = application.selectors.map { planned ->
    val actual = actualSelections[planned.selector] ?: planned.candidate
    val decision = decisions.firstOrNull { it.selector == planned.selector && it.choice == actual }
    val chain = decision?.chain ?: planned.chain
    RoutePathStatus(
        service = decision?.declaration ?: planned.selector,
        candidate = actual,
        chain = if (chain.isEmpty()) "本机 → 目标（直连）" else "本机 → ${chain.joinToString(" → ")} → 目标",
        links = decision?.measurements.orEmpty().sortedBy(RouteMeasurement::hop).map(::routeLinkStatus),
        reason = decision?.reason ?: when {
            chain.isEmpty() -> "本机直连；不执行完整路径测量"
            else -> "实际 selector 已读回；当前连接代尚无可用分段选择证据"
        },
        updatedAt = decision?.updatedAt.orEmpty(),
    )
}

private fun routeLinkStatus(measurement: RouteMeasurement): RouteLinkStatus {
    val source = when (measurement.kind) {
        "entry" -> "客户端连接时单次 ping"
        "neighbor" -> "服务器 WireGuard 邻居 RTT"
        "public-hysteria2" -> "服务器公网 Hy2 单跳；Δ=P95−P50；固定响应探测速率"
        "target" -> "服务器直连目标的首次响应耗时"
        else -> "暂无对应承载的有效观测"
    }
    val label = when {
        measurement.delayMs != null -> buildString {
            if (measurement.kind == "entry") append("ping ")
            append("${measurement.delayMs} ms")
            measurement.variationMs?.let { append(" · Δ$it ms") }
            measurement.rateBps?.let { append(" · ${formatRate(it)}") }
        }
        measurement.samples > 0 && measurement.failures == measurement.samples ->
            if (measurement.kind == "entry") "ping 无响应" else "探测失败"
        else -> "—"
    }
    val detail = buildString {
        append(source)
        if (measurement.observedAt.isNotBlank()) append(" · 测量于 ${measurement.observedAt}")
        if (measurement.failures > 0) append(" · 失败 ${measurement.failures}/${measurement.samples}")
        if (measurement.error.isNotBlank()) append(" · ${measurement.error}")
    }
    return RouteLinkStatus(measurement.from, measurement.to, label, detail)
}

private fun formatRate(bitsPerSecond: Double): String {
    var value = bitsPerSecond
    var unit = "bit/s"
    for (next in listOf("kb/s", "Mb/s", "Gb/s")) {
        if (value < 1000) break
        value /= 1000
        unit = next
    }
    return "%.1f %s".format(java.util.Locale.ROOT, value, unit)
}
