package io.github.scisaga.loom.route

import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.IOException
import java.net.InetAddress
import java.net.ServerSocket
import java.nio.charset.StandardCharsets
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class SelectorLoopbackHttpTest {
    @Test
    fun readsFiftySevenDerivedCandidatesBeyondFourKiB() {
        val candidates = (0 until 57).map { "sha256:" + it.toString(16).padStart(64, '0') }
        val body = """{"type":"Selector","udp":true,"all":[${candidates.joinToString(",") { "\"$it\"" }}],"now":"${candidates.first()}"}""".encodeToByteArray()
        assertTrue(body.size > 4 * 1024)
        val response = exchange(
            "Content-Length: ${body.size}\r\n",
            body,
        )
        assertEquals(200, response.status)
        assertEquals(body.decodeToString(), response.body.decodeToString())
    }

    @Test
    fun rejectsContentLengthBeyondTheReadbackLimit() {
        assertThrows(IllegalStateException::class.java) {
            exchange("Content-Length: ${SELECTOR_READBACK_LIMIT + 1}\r\n", ByteArray(0))
        }
    }

    @Test
    fun rejectsChunkBeyondTheReadbackLimit() {
        assertThrows(IllegalStateException::class.java) {
            exchange(
                "Transfer-Encoding: chunked\r\n",
                "${(SELECTOR_READBACK_LIMIT + 1).toString(16)}\r\n".encodeToByteArray(),
            )
        }
    }

    @Test
    fun rejectsUnframedResponseBeyondTheReadbackLimit() {
        assertThrows(IllegalStateException::class.java) {
            exchange("", ByteArray(SELECTOR_READBACK_LIMIT + 1) { 'x'.code.toByte() })
        }
    }

    @Test
    fun readsAuthenticatedChunkedLoopbackResponse() {
        ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")).use { server ->
            server.soTimeout = 3_000
            val authorization = AtomicReference("")
            val worker = thread(isDaemon = true) {
                server.accept().use { socket ->
                    val reader = BufferedReader(InputStreamReader(socket.getInputStream(), StandardCharsets.US_ASCII))
                    while (true) {
                        val line = reader.readLine()
                        if (line.isNullOrEmpty()) break
                        if (line.startsWith("Authorization:")) authorization.set(line)
                    }
                    socket.getOutputStream().write(
                        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".toByteArray(),
                    )
                    socket.getOutputStream().write("e\r\n{\"now\":\"auto\"}\r\n0\r\n\r\n".toByteArray())
                    socket.getOutputStream().flush()
                }
            }
            val response = loopbackHttpRequest(
                host = "127.0.0.1",
                port = server.localPort,
                secret = "test-secret",
                method = "GET",
                path = "/proxies/test",
                body = null,
                maximum = 4 * 1024,
            )
            worker.join(3_000)
            assertEquals(200, response.status)
            assertEquals("{\"now\":\"auto\"}", response.body.decodeToString())
            assertEquals("Authorization: Bearer test-secret", authorization.get())
        }
    }

    @Test
    fun rejectsAnyNonLoopbackDestination() {
        val error = assertThrows(IllegalArgumentException::class.java) {
            loopbackHttpRequest("192.0.2.1", 61800, "secret", "GET", "/", null, 1024)
        }
        assertTrue(error.message.orEmpty().contains("回环"))
    }

    private fun exchange(headers: String, body: ByteArray): LoopbackHttpResponse {
        ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")).use { server ->
            server.soTimeout = 3_000
            val serverFailure = AtomicReference<Throwable?>()
            val worker = thread(isDaemon = true) {
                try {
                    server.accept().use { socket ->
                        val reader = BufferedReader(InputStreamReader(socket.getInputStream(), StandardCharsets.US_ASCII))
                        while (!reader.readLine().isNullOrEmpty()) { /* consume only the request headers */ }
                        socket.getOutputStream().write(
                            "HTTP/1.1 200 OK\r\n${headers}Connection: close\r\n\r\n".toByteArray(StandardCharsets.US_ASCII),
                        )
                        socket.getOutputStream().write(body)
                        socket.getOutputStream().flush()
                    }
                } catch (error: Throwable) {
                    // A rejected oversized reply may close while the sender is
                    // still draining the last bytes into the loopback socket.
                    if (error !is IOException) serverFailure.set(error)
                }
            }
            try {
                return loopbackHttpRequest(
                    "127.0.0.1", server.localPort, "demo-secret", "GET", "/proxies/demo-service", null,
                    SELECTOR_READBACK_LIMIT,
                )
            } finally {
                worker.join(3_000)
                assertTrue("loopback worker did not finish", !worker.isAlive)
                serverFailure.get()?.let { throw AssertionError("loopback server failed", it) }
            }
        }
    }
}
