package io.github.scisaga.loom.route

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.scisaga.loom.enrollment.EnrollmentManager
import io.github.scisaga.loom.enrollment.ManagedProfile
import io.github.scisaga.loom.enrollment.ManagedProfileStore
import io.github.scisaga.loom.profiles.ProfileCatalog
import io.github.scisaga.loom.vpn.ConnectionPhase
import io.github.scisaga.loom.vpn.VpnRuntime
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.BufferedInputStream
import java.io.Closeable
import java.io.IOException
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread

/** Uses an already joined, disconnected profile; never replaces its identity. */
@RunWith(AndroidJUnit4::class)
class SelectorOperationInstrumentedTest {
    @Test
    fun blockedNativeReadDoesNotHoldReportOrStopAndCannotCommitAfterStop() = runBlocking {
        val joined = joinedProfile()
        SelectorServer(joined.profile).use { server ->
            val blocked = server.blockNextRead()
            val applying = async { runCatching { joined.routing.applyToRunning(joined.id, joined.profile) } }
            try {
                await(blocked.entered, "selector read never reached the real loopback socket")
                withTimeout(2_000) { joined.routing.profileAvailable(joined.id, joined.profile).join() }
                assertTrue("same-View sync cleared startup busy state", joined.routing.status(joined.id).value.busy)
                assertEquals("same-View sync cancelled startup", 1L, blocked.closed.count)
                withTimeout(2_000) { joined.report() }
                assertEquals("report must not cancel the independent selector call", 1L, blocked.closed.count)
                withTimeout(2_000) { joined.routing.tunnelStopped(joined.id) }
                val result = withTimeout(2_000) { applying.await() }
                assertTrue(result.exceptionOrNull() is SelectionSuperseded)
                await(blocked.closed, "stop did not close the actual selector socket")
                assertFalse("late selector call republished a stopped runtime", joined.routing.status(joined.id).value.running)
                joined.assertIdentityPreserved()
                server.assertHealthy()
            } finally {
                joined.routing.tunnelStopped(joined.id)
                applying.cancel()
            }
        }
    }

    @Test
    fun committedPutWithLostReadbackDoesNotReportOldConfirmationAndCanRecover() = runBlocking {
        val joined = joinedProfile()
        SelectorServer(joined.profile).use { server ->
            try {
                val initial = withTimeout(10_000) { joined.routing.applyToRunning(joined.id, joined.profile) }
                assertTrue("joined profile must provide an executable selection for this regression", initial.selectors.isNotEmpty())
                assertTrue(JSONArray(joined.report().selections.decodeToString()).length() > 0)
                // The next recommendation must PUT; its subsequent GET loses the reply.
                server.rejectAll()
                val committed = server.loseReadbackAfterNextPut()
                val failed = runCatching {
                    withTimeout(10_000) { joined.routing.refreshFromMeasurements(joined.id, joined.profile) }
                }
                assertTrue("the simulated post-PUT readback fault was not observed", failed.isFailure)
                await(committed, "no selection PUT committed before the readback failed")
                assertEquals("an ended IO call is not a confirmed selection", 0,
                    JSONArray(joined.report().selections.decodeToString()).length())
                withTimeout(10_000) { joined.routing.refreshFromMeasurements(joined.id, joined.profile) }
                assertTrue("a later complete readback must restore confirmation",
                    JSONArray(joined.report().selections.decodeToString()).length() > 0)
                joined.assertIdentityPreserved()
                server.assertHealthy()
            } finally {
                joined.routing.tunnelStopped(joined.id)
            }
        }
    }

    @Test
    fun sameViewPublicationDoesNotConfirmAnUnfinishedSelectorOperation() = runBlocking {
        val joined = joinedProfile()
        SelectorServer(joined.profile).use { server ->
            withTimeout(10_000) { joined.routing.applyToRunning(joined.id, joined.profile) }
            val blocked = server.blockNextRead()
            val applying = async { runCatching { joined.routing.applyToRunning(joined.id, joined.profile) } }
            try {
                await(blocked.entered, "selector read never reached the real loopback socket")
                val pending = joined.routing.status(joined.id).value
                assertTrue(pending.busy)
                // join proves publication completed; no sleep or guessed ordering.
                withTimeout(2_000) { joined.routing.profileAvailable(joined.id, joined.profile).join() }
                val after = joined.routing.status(joined.id).value
                assertTrue("a same-View projection cleared the unfinished operation", after.busy)
                assertEquals("a computed projection claimed a new runtime readback", pending.detail, after.detail)
                assertEquals(0, JSONArray(joined.report().selections.decodeToString()).length())
                assertEquals("same-View publication cancelled the current operation", 1L, blocked.closed.count)
                withTimeout(2_000) { joined.routing.tunnelStopped(joined.id) }
                assertTrue(withTimeout(2_000) { applying.await() }.exceptionOrNull() is SelectionSuperseded)
                await(blocked.closed, "stop did not close the actual selector socket")
                assertFalse(joined.routing.status(joined.id).value.running)
                joined.assertIdentityPreserved()
                server.assertHealthy()
            } finally {
                joined.routing.tunnelStopped(joined.id)
                applying.cancel()
            }
        }
    }

    private fun joinedProfile(): JoinedProfile {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assumeTrue("requires a disconnected test device", VpnRuntime.status.value.phase == ConnectionPhase.DISCONNECTED)
        val id = ProfileCatalog.get(context).state.value.viewedProfileId
        assumeTrue("requires an existing joined test profile", id.isNotBlank())
        val identity = ManagedProfileStore.get(context, id)
        val profile = EnrollmentManager.get(context).currentProfile(id)
        assumeTrue("requires an existing certified profile", profile != null)
        return JoinedProfile(id, checkNotNull(profile), identity, checkNotNull(identity.state()), RouteManager.get(context))
    }

    private data class JoinedProfile(
        val id: String,
        val profile: ManagedProfile,
        val identity: ManagedProfileStore,
        val original: ByteArray,
        val routing: RouteManager,
    ) {
        suspend fun report(): RuntimeReportData = routing.reportData(id, original, profile.viewDigest, profile.viewDigest, profile.viewDigest)

        fun assertIdentityPreserved() {
            assertTrue("selector operation changed protected identity", original.contentEquals(identity.state()))
        }
    }

    private suspend fun await(latch: CountDownLatch, message: String) = withContext(Dispatchers.IO) {
        assertTrue(message, latch.await(2, TimeUnit.SECONDS))
    }

    private class BlockedRead {
        val entered = CountDownLatch(1)
        val closed = CountDownLatch(1)
    }

    /** Local contract fixture only; it does not execute or attest a transport. */
    private class SelectorServer(profile: ManagedProfile) : Closeable {
        private val server = ServerSocket(61800, 8, InetAddress.getByName("127.0.0.1"))
        private val source = JSONObject(profile.config)
        private val secret = source.getJSONObject("experimental").getJSONObject("clash_api").getString("secret")
        private val lock = Any()
        private val snapshots = linkedMapOf<String, JSONObject>()
        private var revision = 0
        private val permissions = permissionSnapshots()
        private val senderTemplates = source.getJSONArray("outbounds").objects().filter {
            it.has("execution") && (it.optString("type") == "hysteria2" ||
                it.optString("type") == "direct" && it.optString("detour") == "wg-shared")
        }.associateBy { it.getString("tag") }
        private val forwardingTemplates = source.getJSONArray("outbounds").objects().filter { it.has("hop") }
            .associate { it.getString("tag") to it.getJSONObject("hop") }
        private var resources = JSONObject().put("revision", "demo-resources-${++revision}")
            .put("authorization_revisions", JSONObject()).put("desired_config_hash", "").put("config_hash", "")
            .put("outbounds", JSONObject()).put("described_outbounds", JSONObject()).put("forwarding", JSONObject()).put("wireguard", false)
        private var blocked: BlockedRead? = null
        private var committed: CountDownLatch? = null
        private var loseReadback = false
        @Volatile private var stopping = false
        @Volatile private var active: Socket? = null
        private val failure = AtomicReference<Throwable?>()
        private val worker = thread(isDaemon = true, name = "demo-selector-loopback") {
            try {
                while (!stopping) server.accept().use { socket ->
                    active = socket
                    try { serve(socket) } finally { active = null }
                }
            } catch (error: Throwable) {
                if (!stopping) failure.compareAndSet(null, error)
            }
        }

        fun blockNextRead(): BlockedRead = synchronized(lock) {
            BlockedRead().also { check(blocked == null); blocked = it }
        }

        fun rejectAll() = synchronized(lock) {
            snapshots.keys.toList().forEach { snapshots[it] = rejected() }
        }

        fun loseReadbackAfterNextPut(): CountDownLatch = synchronized(lock) {
            CountDownLatch(1).also { check(committed == null); committed = it }
        }

        fun assertHealthy() {
            failure.get()?.let { throw AssertionError("loopback native contract server failed", it) }
        }

        private fun rejected() = JSONObject().put("now", "reject").put("targets", JSONObject())
            .put("policy_id", "").put("choices", JSONObject()).put("revision", "demo-${++revision}")

        private fun serve(socket: Socket) {
            socket.soTimeout = 10_000
            val input = BufferedInputStream(socket.getInputStream())
            val request = line(input).split(' ')
            check(request.size == 3)
            val headers = linkedMapOf<String, String>()
            while (true) {
                val value = line(input)
                if (value.isEmpty()) break
                val colon = value.indexOf(':')
                check(colon > 0)
                headers[value.substring(0, colon).lowercase()] = value.substring(colon + 1).trim()
            }
            check(headers["authorization"] == "Bearer $secret") { "unexpected loopback authentication" }
            val length = headers["content-length"]?.toInt() ?: 0
            check(length in 0..SELECTOR_READBACK_LIMIT)
            val bytes = ByteArray(length)
            var offset = 0
            while (offset < bytes.size) {
                val count = input.read(bytes, offset, bytes.size - offset)
                check(count > 0)
                offset += count
            }
            when {
                request[1] == "/loom/resources" -> {
                    val response = synchronized(lock) {
                        if (request[0] == "GET") resources.toString()
                        else {
                            check(request[0] == "PUT")
                            applyResources(JSONObject(bytes.decodeToString())).toString()
                        }
                    }
                    reply(socket, response)
                    return
                }
                request[1].startsWith("/loom/access/") || request[1].startsWith("/loom/receivers/") -> {
                    check(request[0] == "GET") { "selector fixture must not replace permissions" }
                    val path = URLDecoder.decode(request[1], StandardCharsets.UTF_8.name())
                    reply(socket, checkNotNull(permissions[path]) { "unknown permission scope" }.toString())
                    return
                }
                request[1] == "/loom/tcp-observations" -> {
                    check(request[0] == "GET")
                    reply(socket, JSONObject().put("observations", JSONArray()).toString())
                    return
                }
            }
            check(request[1].startsWith("/proxies/")) { "unexpected native API path" }
            val selector = URLDecoder.decode(request[1].removePrefix("/proxies/"), StandardCharsets.UTF_8.name())
            if (request[0] == "GET") {
                val gate = synchronized(lock) { blocked.also { blocked = null } }
                if (gate != null) {
                    gate.entered.countDown()
                    try {
                        check(input.read() == -1) { "blocked socket received unexpected bytes" }
                    } catch (_: IOException) {
                        // A reset also proves the client closed this real FD.
                    }
                    gate.closed.countDown()
                    return
                }
                val response = synchronized(lock) {
                    if (loseReadback) { loseReadback = false; null }
                    else snapshots.getOrPut(selector) { rejected() }.toString()
                }
                if (response != null) reply(socket, response)
                return
            }
            check(request[0] == "PUT")
            val desired = JSONObject(bytes.decodeToString())
            val response = synchronized(lock) {
                if (desired.getString("name") != "reject") {
                    check(resources.getString("config_hash").isNotEmpty()) { "selector CAS preceded resource readback" }
                    val access = source.getJSONArray("outbounds").objects().single { it.getString("tag") == selector }
                        .getJSONObject("access")
                    val choices = desired.getJSONObject("choices")
                    val used = desired.getJSONObject("targets").stringMap().values.toMutableSet().apply {
                        add(desired.getString("name"))
                    }
                    check(choices.keys().asSequence().toSet() == used) { "selector choices differ from used candidates" }
                    choices.keys().forEach { id ->
                        val resource = choices.getJSONObject(id).getString("first_resource_id")
                        if (resource.isNotEmpty()) {
                            val tag = access.getJSONObject("entries").getJSONObject(resource).getString("outbound")
                            check(resources.getJSONObject("described_outbounds").getString(tag) == hash(checkNotNull(senderTemplates[tag]))) {
                                "selector CAS used an unconfirmed sender description"
                            }
                        }
                    }
                }
                val current = snapshots.getOrPut(selector) { rejected() }
                check(desired.getString("expected_name") == current.getString("now"))
                check(desired.getString("expected_revision") == current.getString("revision"))
                check(desired.getJSONObject("expected_targets").stringMap() == current.getJSONObject("targets").stringMap())
                check(desired.getString("expected_policy_id") == current.getString("policy_id"))
                check(desired.getJSONObject("expected_choices").routeChoices() == current.getJSONObject("choices").routeChoices())
                JSONObject().put("now", desired.getString("name")).put("targets", desired.getJSONObject("targets"))
                    .put("policy_id", desired.getString("policy_id")).put("choices", desired.getJSONObject("choices"))
                    .put("revision", "demo-${++revision}").also {
                        snapshots[selector] = it
                        committed?.let { latch -> loseReadback = true; latch.countDown(); committed = null }
                    }.toString()
            }
            reply(socket, response)
        }

        private fun permissionSnapshots(): Map<String, JSONObject> = buildMap {
            for (section in listOf("outbounds", "inbounds", "endpoints")) {
                val entries = source.optJSONArray(section) ?: continue
                for (entry in entries.objects()) {
                    val projection = JSONObject()
                    val prefix = if (entry.has("access")) {
                        projection.put("access", entry.getJSONObject("access"))
                        "/loom/access/"
                    } else if (section != "outbounds" && entry.has("execution")) {
                        projection.put("execution", entry.getJSONObject("execution"))
                        if (entry.getString("type") == "hysteria2") projection.put("hysteria2_users", entry.getJSONArray("users"))
                        "/loom/receivers/"
                    } else continue
                    put(prefix + entry.getString("tag"), JSONObject().put("revision", "demo-permission-${++revision}")
                        .put("config_hash", hash(projection)))
                }
            }
        }

        private fun applyResources(desired: JSONObject): JSONObject {
            check(desired.getString("expected_revision") == resources.getString("revision"))
            val authorizations = JSONObject()
            permissions.forEach { (path, permission) ->
                authorizations.put(path.substringAfterLast('/'), permission.getString("revision"))
            }
            check(canonical(desired.getJSONObject("authorization_revisions")) == canonical(authorizations))
            val described = JSONObject()
            val descriptions = desired.getJSONArray("outbounds").objects()
            check(descriptions.map { it.getString("tag") }.distinct().size == descriptions.size)
            for (outbound in descriptions) {
                val tag = outbound.getString("tag")
                check(canonical(outbound) == canonical(checkNotNull(senderTemplates[tag]))) { "unexpected sender description" }
                described.put(tag, hash(outbound))
            }
            val forwarding = desired.getJSONObject("forwarding")
            check(forwarding.keys().asSequence().toSet() == forwardingTemplates.keys) { "unexpected forwarding description set" }
            val forwardingHashes = JSONObject()
            forwardingTemplates.forEach { (tag, template) ->
                check(canonical(forwarding.getJSONObject(tag)) == canonical(template)) { "unexpected forwarding description" }
                forwardingHashes.put(tag, hash(template))
            }
            desired.remove("expected_revision")
            val digest = hash(desired)
            resources = JSONObject().put("revision", "demo-resources-${++revision}")
                .put("authorization_revisions", authorizations).put("desired_config_hash", digest).put("config_hash", digest)
                .put("outbounds", JSONObject()).put("described_outbounds", described)
                .put("forwarding", forwardingHashes)
                // This contract double does not construct a sender or WG facility.
                .put("wireguard", false)
            return resources
        }

        private fun JSONArray.objects(): List<JSONObject> = (0 until length()).map(::getJSONObject)

        // Mirrors encoding/json's sorted object keys and string escaping for
        // the current native projection hash; arrays keep their supplied order.
        private fun canonical(value: Any?): String = when (value) {
            null, JSONObject.NULL -> "null"
            is JSONObject -> value.keys().asSequence().toList().sorted().joinToString(",", "{", "}") {
                canonical(it) + ":" + canonical(value.get(it))
            }
            is JSONArray -> (0 until value.length()).joinToString(",", "[", "]") { canonical(value.get(it)) }
            is String -> buildString {
                append('"')
                for (char in value) {
                    append(when (char) {
                        '"' -> "\\\""
                        '\\' -> "\\\\"
                        '\b' -> "\\b"
                        '\t' -> "\\t"
                        '\n' -> "\\n"
                        '\u000c' -> "\\f"
                        '\r' -> "\\r"
                        else -> if (char.code < 0x20 || char in "<>&\u2028\u2029") "\\u" + char.code.toString(16).padStart(4, '0') else char.toString()
                    })
                }
                append('"')
            }
            is Boolean, is Number -> value.toString()
            else -> error("unexpected native projection value")
        }

        private fun hash(value: JSONObject): String = "sha256:" + MessageDigest.getInstance("SHA-256")
            .digest(canonical(value).encodeToByteArray()).joinToString("") { "%02x".format(it.toInt() and 255) }

        private fun reply(socket: Socket, body: String) {
            val bytes = body.encodeToByteArray()
            socket.getOutputStream().apply {
                write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${bytes.size}\r\nConnection: close\r\n\r\n".toByteArray(StandardCharsets.US_ASCII))
                write(bytes)
                flush()
            }
        }

        private fun line(input: BufferedInputStream): String {
            val value = StringBuilder()
            while (value.length < 8 * 1024) {
                val next = input.read()
                check(next >= 0)
                if (next == '\n'.code) return value.toString().removeSuffix("\r")
                value.append(next.toChar())
            }
            error("loopback request line exceeded its bound")
        }

        private fun JSONObject.stringMap(): Map<String, String> = keys().asSequence().associateWith { getString(it) }

        override fun close() {
            stopping = true
            active?.close()
            server.close()
            worker.join(2_000)
            check(!worker.isAlive) { "loopback contract server did not stop" }
            assertHealthy()
        }
    }
}
