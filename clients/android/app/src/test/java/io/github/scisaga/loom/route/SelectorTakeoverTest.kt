package io.github.scisaga.loom.route

import java.io.BufferedInputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SelectorTakeoverTest {
    @Test
    fun unconfirmedAccessAndLanAdvanceSameValueSnapshotBeforeConfirmation(): Unit = runBlocking {
        for (scope in listOf("access", "local_network:demo-lan")) {
            val methods = mutableListOf<String>()
            var revision = "demo-r0"
            selectorServer(3) { request ->
                methods += request.method
                if (request.method == "PUT") {
                    assertEquals("demo-r0", request.body.getString("expected_revision"))
                    assertEquals("reject", request.body.getString("expected_name"))
                    revision = "demo-r1"
                }
                200 to rejected(revision)
            }.use { server ->
                val client = client()
                client.planScopes(listOf(scope), requireCAS = listOf(scope))
                client.apply(listOf(reject(scope)))
                server.await()
                assertEquals(listOf("GET", "PUT", "GET"), methods)
                assertEquals("demo-r1", client.readbackRevisions[scope])
                assertEquals(setOf(scope), client.uncertainScopes())
                client.confirmed(scope)
                assertFalse(client.requiresCAS(scope))
                assertTrue(client.uncertainScopes().isEmpty())
                client.cancel()
            }
        }
    }

    @Test
    fun confirmedUnchangedSelectionOnlyReads(): Unit = runBlocking {
        val methods = mutableListOf<String>()
        selectorServer(2) { request ->
            methods += request.method
            200 to rejected("demo-r0")
        }.use { server ->
            val client = client()
            client.planScopes(listOf("access"))
            client.apply(listOf(reject("access")))
            server.await()
            assertEquals(listOf("GET", "GET"), methods)
            assertTrue(client.uncertainScopes().isEmpty())
            client.cancel()
        }
    }

    @Test
    fun conflictAndFreshGetDoNotEraseInheritedCasRequirement(): Unit = runBlocking {
        var putCount = 0
        var revision = "demo-r0"
        selectorServer(5) { request ->
            if (request.method == "PUT") {
                putCount++
                assertEquals(revision, request.body.getString("expected_revision"))
                revision = "demo-r$putCount"
                if (putCount == 1) return@selectorServer 409 to JSONObject()
            }
            200 to rejected(revision)
        }.use { server ->
            val client = client()
            client.planScopes(listOf("access"), requireCAS = listOf("access"))
            try {
                client.apply(listOf(reject("access")))
                throw AssertionError("conflicting CAS was accepted")
            } catch (_: SelectionSuperseded) { /* existing owner retries from a fresh snapshot */ }
            assertTrue(client.requiresCAS("access"))
            client.apply(listOf(reject("access")))
            server.await()
            assertEquals(2, putCount)
            assertEquals("demo-r2", client.readbackRevisions["access"])
            client.confirmed("access")
            assertTrue(client.uncertainScopes().isEmpty())
            client.cancel()
        }
    }

    @Test
    fun inheritedCasRemainsUncertainAcrossLocalFailureAndOtherScopeConfirmation() {
        val scope = "local_network:demo-lan"
        val call = SelectorCallScopes().apply {
            plan(listOf("access", scope), requireCAS = listOf(scope))
        }
        // A GET, a failed preparation, and an ordinary retry do not confirm a
        // successor's snapshot. Only this scope's complete CAS/readback does.
        call.finished(scope)
        assertFalse(call.mayWrite(scope))
        call.plan(listOf(scope))
        call.plan(emptyList())
        call.wrote("access")
        call.confirmed("access")
        assertTrue(call.requiresCAS(scope))
        assertEquals(setOf(scope), call.uncertain())
        call.confirmed(scope)
        assertFalse(call.requiresCAS(scope))
        assertTrue(call.uncertain().isEmpty())
    }

    @Test
    fun cancellingBlockedPutRetainsItsUncertaintyAndReturnsPromptly(): Unit = runBlocking {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        selectorServer(2) { request ->
            if (request.method == "PUT") {
                entered.countDown()
                assertTrue(release.await(3, TimeUnit.SECONDS))
                200 to rejected("demo-r1")
            } else {
                200 to rejected("demo-r0")
            }
        }.use { server ->
            val client = client()
            client.planScopes(listOf("access"), requireCAS = listOf("access"))
            val call = async { runCatching { client.apply(listOf(reject("access"))) } }
            withContext(Dispatchers.IO) { assertTrue(entered.await(2, TimeUnit.SECONDS)) }
            withTimeout(500) { withContext(Dispatchers.Default) { client.cancel() } }
            assertEquals(setOf("access"), client.uncertainScopes())
            assertTrue(withTimeout(1_000) { call.await() }.exceptionOrNull() is SelectionSuperseded)
            release.countDown()
            server.await(allowClosedResponse = true)
        }
        val cancelled = client()
        cancelled.cancel()
        try {
            cancelled.apply(listOf(reject("access")))
            throw AssertionError("cancelled client started another request")
        } catch (_: SelectionSuperseded) { /* no socket and no write */ }
        assertTrue(cancelled.uncertainScopes().isEmpty())
    }

    private fun client() = SelectorClient("""{"experimental":{"clash_api":{"external_controller":"127.0.0.1:61800","secret":"demo-secret"}}}""")
    private fun reject(scope: String) = AppliedSelector(scope, "reject", emptyList(), "")
    private fun rejected(revision: String) = JSONObject().put("now", "reject").put("revision", revision)
        .put("policy_id", "").put("targets", JSONObject()).put("choices", JSONObject())

    private data class Request(val method: String, val body: JSONObject)

    /** Uses the real client's fixed loopback endpoint; never replaces a listener. */
    private fun selectorServer(count: Int, reply: (Request) -> Pair<Int, JSONObject>) = TestServer(count, reply)

    private class TestServer(count: Int, reply: (Request) -> Pair<Int, JSONObject>) : AutoCloseable {
        private val server = ServerSocket().apply {
            reuseAddress = true
            bind(InetSocketAddress(InetAddress.getByName("127.0.0.1"), 61800))
            soTimeout = 5_000
        }
        private val failure = AtomicReference<Throwable?>()
        private val worker = thread(isDaemon = true) {
            try {
                repeat(count) {
                    server.accept().use { socket ->
                        socket.soTimeout = 3_000
                        val input = BufferedInputStream(socket.getInputStream())
                        val method = line(input).substringBefore(' ')
                        var length = 0
                        while (true) {
                            val header = line(input)
                            if (header.isEmpty()) break
                            if (header.startsWith("Content-Length:", ignoreCase = true)) length = header.substringAfter(':').trim().toInt()
                        }
                        require(length in 0..64 * 1024)
                        val bytes = ByteArray(length)
                        var offset = 0
                        while (offset < length) {
                            val read = input.read(bytes, offset, length - offset)
                            check(read > 0)
                            offset += read
                        }
                        val request = Request(method, if (bytes.isEmpty()) JSONObject() else JSONObject(bytes.decodeToString()))
                        val (status, response) = reply(request)
                        val body = response.toString().encodeToByteArray()
                        socket.getOutputStream().write("HTTP/1.1 $status Test\r\nContent-Length: ${body.size}\r\nConnection: close\r\n\r\n".encodeToByteArray())
                        socket.getOutputStream().write(body)
                        socket.getOutputStream().flush()
                    }
                }
            } catch (error: Throwable) { failure.set(error) }
        }

        fun await(allowClosedResponse: Boolean = false) {
            worker.join(4_000)
            assertFalse("selector test worker did not finish", worker.isAlive)
            failure.get()?.let { if (!allowClosedResponse || it !is java.io.IOException) throw AssertionError("selector test server failed", it) }
        }

        override fun close() { server.close(); worker.join(1_000) }

        private fun line(input: BufferedInputStream): String {
            val result = StringBuilder()
            while (true) {
                val value = input.read()
                check(value >= 0) { "incomplete request" }
                if (value == '\n'.code) return result.toString().removeSuffix("\r")
                check(result.length < 4 * 1024)
                result.append(value.toChar())
            }
        }
    }
}
