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
    val currentPaths: List<String> = emptyList(),
    val running: Boolean = false,
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
)

class RouteManager private constructor(context: Context) {
    private val protected = EncryptedStore(context.applicationContext)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val operation = Mutex()
    private val mutableStatus = MutableStateFlow(RouteStatus())
    val status = mutableStatus.asStateFlow()

    @Volatile private var availableProfile: ManagedProfile? = null
    @Volatile private var runningRecordID: String? = null

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

    /** Called only after libbox has started its authenticated loopback API. */
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
        SelectorClient(routePlan).apply(application.selectors)
        protected.put(SELECTIONS, encodeSelections(application))
        runningRecordID = profile.recordID
        publish(application, true)
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
                val next = encodePreference(mode, exit)
                try {
                    val application = evaluate(profile, next)
                    check(!application.blocked) { application.blockReason }
                    val running = runningRecordID == profile.recordID
                    if (running) SelectorClient(profile.routePlan).apply(application.selectors)
                    try {
                        protected.put(PREFERENCE, next)
                        protected.put(SELECTIONS, encodeSelections(application))
                        protected.remove(SCHEDULER_STATE)
                    } catch (persistError: Throwable) {
                        if (running) {
                            runCatching {
                                val rollback = evaluate(profile, previous ?: ByteArray(0))
                                if (!rollback.blocked) SelectorClient(profile.routePlan).apply(rollback.selectors)
                            }
                        }
                        restore(PREFERENCE, previous)
                        restore(SELECTIONS, previousSelections)
                        restore(SCHEDULER_STATE, previousSchedulerState)
                        throw persistError
                    }
                    publish(application, running, if (running) "路由偏好已生效" else "偏好已保存；下次连接生效")
                } catch (error: Throwable) {
                    val restored = runCatching { evaluate(profile, previous ?: ByteArray(0)) }.getOrNull()
                    if (restored != null) {
                        publish(restored, runningRecordID == profile.recordID, "切换失败：${message(error)}")
                    } else {
                        mutableStatus.value = mutableStatus.value.copy(busy = false, detail = "切换失败：${message(error)}")
                    }
                }
            }
        }
    }

    /** Runs one signed scheduling round. Network probes happen in the Go core. */
    suspend fun runSchedulerTick(profile: ManagedProfile): Long = operation.withLock {
        val plan = profile.routePlan ?: return@withLock IDLE_RETRY_MS
        if (runningRecordID != profile.recordID) throw CancellationException("隧道会话已经结束")
        val previousSelections = protected.get(SELECTIONS)
        val previousState = protected.get(SCHEDULER_STATE)
        val body = Loomcore.runAndroidRouteTick(
            plan.encodeToByteArray(),
            protected.get(PREFERENCE) ?: ByteArray(0),
            previousSelections ?: ByteArray(0),
            previousState ?: ByteArray(0),
            java.time.Instant.now().toString(),
        )
        if (runningRecordID != profile.recordID) throw CancellationException("隧道会话已经结束")
        val result = decodeTick(body)
        val previousApplication = evaluate(profile)
        try {
            if (result.changed) SelectorClient(plan).apply(result.application.selectors)
            protected.put(SELECTIONS, encodeSelections(result.application))
            protected.put(SCHEDULER_STATE, result.state.encodeToByteArray())
        } catch (error: Throwable) {
            if (result.changed && !previousApplication.blocked) {
                runCatching { SelectorClient(plan).apply(previousApplication.selectors) }
            }
            restore(SELECTIONS, previousSelections)
            restore(SCHEDULER_STATE, previousState)
            throw error
        }
        publish(result.application, true, result.detail)
        result.nextAfterMs.coerceAtLeast(1_000L)
    }

    fun schedulerFailed(error: Throwable) {
        mutableStatus.value = mutableStatus.value.copy(
            busy = false,
            detail = "自动选路本轮失败；稍后重试：${message(error)}",
        )
    }

    fun tunnelStopped() {
        runningRecordID = null
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

    private fun publish(application: AppliedRoute, running: Boolean, overrideDetail: String? = null) {
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
            currentPaths = application.selectors.map { selection ->
                val path = if (selection.chain.isEmpty()) "本机直连" else selection.chain.joinToString(" → ")
                "${selection.selector}：$path"
            },
            running = running,
        )
    }

    private fun encodePreference(mode: RouteMode, exit: String): ByteArray = JSONObject()
        .put("schema", 1)
        .put("mode", mode.wire)
        .apply { if (mode == RouteMode.FIXED_EXIT) put("exit", exit) }
        .toString()
        .encodeToByteArray()

    private fun encodeSelections(application: AppliedRoute): ByteArray = JSONObject()
        .put("schema", 1)
        .put("plan_scope", application.planScope)
        .put(
            "selections",
            JSONArray().apply {
                application.selectors.forEach {
                    put(JSONObject().put("selector", it.selector).put("candidate", it.candidate))
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
        check(root.getInt("schema") == 1) { "共享核心返回未知调度 schema" }
        return RouteTick(
            state = root.getString("state"),
            application = decodeApplication(root.getJSONObject("application")),
            changed = root.getBoolean("changed"),
            nextAfterMs = root.getLong("next_after_ms"),
            detail = root.getString("detail"),
        )
    }

    private fun restore(key: String, value: ByteArray?) {
        if (value == null) protected.remove(key) else protected.put(key, value)
    }

    private fun JSONArray.strings(): List<String> = (0 until length()).map(::getString)
    private fun JSONArray.objects(): List<JSONObject> = (0 until length()).map(::getJSONObject)
    private fun message(error: Throwable): String = error.message ?: error.javaClass.simpleName

    companion object {
        private const val PREFERENCE = "route-preference"
        private const val SELECTIONS = "route-selections"
        private const val SCHEDULER_STATE = "route-scheduler-state"
        private const val IDLE_RETRY_MS = 5 * 60 * 1_000L

        @Volatile private var instance: RouteManager? = null

        fun get(context: Context): RouteManager = instance ?: synchronized(this) {
            instance ?: RouteManager(context).also { instance = it }
        }
    }
}
