package io.github.scisaga.loom.route

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.scisaga.loom.enrollment.ManagedProfile
import io.github.scisaga.loom.profiles.ProfileContext
import io.github.scisaga.loom.security.EncryptedStore
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/** 使用真实 RouteManager、Keystore 和 Go 决策；只替换网络 I/O，不启动 VPN 或探测真实地址。 */
@RunWith(AndroidJUnit4::class)
class RouteManagerProbeInstrumentedTest {
    @Test
    fun directToProxyAppliesBeforeTheOnlyEntryRoundAndLaterModesRemainResponsive() = runBlocking {
        fixture { test ->
            test.startDirect()
            assertEquals(0, test.probes.get())
            test.select(RouteMode.AUTO)
            withTimeout(5_000) { test.probeStarted.await() }
            assertFalse(test.finishProbe.isCompleted)
            assertEquals("demo-via", test.selector.current.getValue("demo-selector"))
            test.select(RouteMode.DIRECT)
            test.select(RouteMode.FIXED_EXIT, "demo-entry")
            assertEquals("demo-via", test.selector.current.getValue("demo-selector"))
            test.select(RouteMode.DIRECT)
            assertEquals(1, test.probes.get())
            assertFalse(test.finishProbe.isCompleted)
            test.finishProbe.complete(Unit)
            test.awaitProbeAndUpdates()
            assertEquals(RouteMode.DIRECT, test.manager.status.value.mode)
            assertEquals("demo-direct", test.selector.current.getValue("demo-selector"))

            test.select(RouteMode.AUTO)
            test.manager.stopAndAwait()
            test.manager.applyToRunning(test.profile)
            test.manager.beginRouteSession(test.profile, "wlan0", test.registry)
            test.awaitProbeAndUpdates()
            assertEquals(1, test.probes.get())
            assertEquals(1, test.registry.debugState().activeProbeRounds)
            assertTrue(test.manager.status.value.currentPaths.isNotEmpty())
            assertTrue(test.manager.status.value.currentPaths.flatMap { it.links }
                .any { it.kind == "entry" && it.label == "ping 23 ms" })
        }
    }

    @Test
    fun autoRestoresItsOwnAuthorizedDirectSelection() = runBlocking {
        fixture { test ->
            test.startDirect()
            test.manager.stopAndAwait()
            // 模拟上次 Auto 会话已持久化合法直连选择；该记忆不能被 Direct 模式修复全局清空。
            test.store.put("route-preference", """{"schema":1,"mode":"auto"}""".encodeToByteArray())
            test.manager.applyToRunning(test.profile)
            test.manager.beginRouteSession(test.profile, "wlan0", test.registry)
            withTimeout(5_000) { test.probeStarted.await() }
            assertEquals(RouteMode.AUTO, test.manager.status.value.mode)
            assertEquals("demo-direct", test.selector.current.getValue("demo-selector"))
            test.select(RouteMode.AUTO)
            assertEquals("demo-direct", test.selector.current.getValue("demo-selector"))
            test.finishProbe.complete(Unit)
            test.awaitProbeAndUpdates()
            assertEquals("demo-direct", test.selector.current.getValue("demo-selector"))
            assertEquals(1, test.probes.get())
        }
    }

    @Test
    fun aStoppedHostCannotApplyTheOutstandingEntryResult() = runBlocking {
        fixture { test ->
            test.startDirect()
            test.select(RouteMode.AUTO)
            withTimeout(5_000) { test.probeStarted.await() }
            test.manager.stopAndAwait()
            val callsAtStop = test.selector.applies.get()
            test.finishProbe.complete(Unit)
            test.awaitProbeAndUpdates()
            assertEquals(callsAtStop, test.selector.applies.get())
            assertFalse(test.manager.status.value.running)
            assertTrue(test.manager.status.value.currentPaths.isEmpty())
        }
    }

    private suspend fun fixture(test: suspend (Fixture) -> Unit) {
        val fixture = Fixture()
        try {
            test(fixture)
        } finally {
            fixture.manager.stopAndAwait()
            fixture.managerScope.cancel()
            fixture.applicationScope.cancel()
            fixture.store.deleteStorageKey()
            fixture.context.filesDir.deleteRecursively()
        }
    }

    private class Fixture {
        val context = ProfileContext(
            InstrumentationRegistry.getInstrumentation().targetContext,
            UUID.randomUUID().toString().replace("-", ""),
        )
        val store = EncryptedStore(context).also {
            it.put("route-preference", """{"schema":1,"mode":"direct"}""".encodeToByteArray())
        }
        val managerScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        val applicationScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        val registry = UnderlayProbeRegistry(applicationScope)
        val selector = MemorySelector()
        val probes = AtomicInteger()
        val probeStarted = CompletableDeferred<Unit>()
        val finishProbe = CompletableDeferred<Unit>()
        var requestedInputs = ByteArray(0)
        val manager = RouteManager(context, { selector }, { inputs, source ->
            requestedInputs = inputs.copyOf()
            probes.incrementAndGet()
            probeStarted.complete(Unit)
            finishProbe.await()
            val entries = JSONObject(inputs.decodeToString()).getJSONArray("entries")
            assertEquals(1, entries.length())
            JSONObject().put("schema", 1).put("source", source).put("measurements", JSONArray().put(
                JSONObject().put("node", "demo-entry").put("address", "192.0.2.1")
                    .put("ts", java.time.Instant.now().toString()).put("rtt_ms", 23),
            )).toString().encodeToByteArray()
        }, managerScope)
        val profile = ManagedProfile(
            nodeID = "demo-client", snapshot = "demo-snapshot", generation = 1,
            config = CONFIG, routePlan = PLAN, caPEM = byteArrayOf(),
            recordID = "demo-record",
        )

        suspend fun startDirect() {
            registry.observeDefaultNetwork("demo-network", "wlan0")
            manager.applyToRunning(profile)
            manager.beginRouteSession(profile, "wlan0", registry)
            assertEquals(RouteMode.DIRECT, manager.status.value.mode)
        }

        suspend fun select(mode: RouteMode, exit: String = "") {
            manager.select(mode, exit)
            withTimeout(5_000) { manager.status.first { it.mode == mode && !it.busy } }
        }

        suspend fun awaitProbeAndUpdates() = withTimeout(5_000) {
            registry.beginEntries(requestedInputs, "wlan0", { _, _ -> error("不得新增测量") }, AndroidEntryProbe::reuse).await()
            managerScope.coroutineContext[Job]!!.children.toList().joinAll()
        }
    }

    private class MemorySelector : RouteSelector {
        val current = ConcurrentHashMap<String, String>()
        val applies = AtomicInteger()

        override suspend fun apply(targets: List<AppliedSelector>) {
            applies.incrementAndGet()
            targets.forEach { current[it.selector] = it.candidate }
        }

        override suspend fun readCurrent(targets: List<AppliedSelector>): Map<String, String> =
            targets.associate { it.selector to current.getValue(it.selector) }
    }

    companion object {
        private const val CANDIDATES = """[
            {"tag":"demo-direct","probe_user":"demo-probe-direct"},
            {"tag":"demo-via","chain":["demo-entry"],"probe_user":"demo-probe-via"}
        ]"""
        private const val PLAN = """{
            "schema":1,"node":"demo-client","api":"127.0.0.1:61800","api_secret":"demo-api-secret",
            "probe":"127.0.0.1:61801","probe_secret":"demo-probe-secret",
            "declarations":[{"id":"demo-web","selector":"demo-selector","objective":"latency",
                "targets":["https://target.example/"],"tuning_period":"1m","switch_threshold":0.2,
                "window":"1h","min_samples":2,"stale_after":"10m","candidates":$CANDIDATES}],
            "selectors":[{"selector":"demo-selector","default":"demo-via","candidates":$CANDIDATES}]
        }"""
        private const val CONFIG = """{
            "inbounds":[{"type":"mixed","tag":"probe-in","listen":"127.0.0.1","listen_port":61801,
                "users":[{"username":"demo-probe-direct","password":"demo-probe-secret"},
                    {"username":"demo-probe-via","password":"demo-probe-secret"}]}],
            "outbounds":[{"type":"selector","tag":"demo-selector","outbounds":["demo-direct","demo-via"],"default":"demo-via"},
                {"type":"direct","tag":"demo-direct"},
                {"type":"hysteria2","tag":"demo-via","server":"192.0.2.1","server_port":443}],
            "route":{"rules":[{"inbound":["probe-in"],"auth_user":["demo-probe-direct"],"outbound":"demo-direct"},
                {"inbound":["probe-in"],"auth_user":["demo-probe-via"],"outbound":"demo-via"}]},
            "experimental":{"clash_api":{"external_controller":"127.0.0.1:61800","secret":"demo-api-secret"}}
        }"""
    }
}
