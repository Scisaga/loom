package io.github.scisaga.loom.route

import java.io.BufferedReader
import java.io.InputStreamReader
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
}
