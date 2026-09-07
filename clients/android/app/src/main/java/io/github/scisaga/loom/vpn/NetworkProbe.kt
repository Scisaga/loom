package io.github.scisaga.loom.vpn

import android.util.Log
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.URL

data class ProbeResult(
    val dns: String,
    val https: String,
) {
    val healthy: Boolean
        get() = dns.startsWith("成功") && https.startsWith("成功")

    fun problems(): List<String> = buildList {
        if (!dns.startsWith("成功")) add("Android TUN DNS 端到端探测失败")
        if (!https.startsWith("成功")) add("Android TUN HTTPS 端到端探测失败")
    }
}

class ProbeSession {
    private var cancelled = false
    private var dnsSocket: DatagramSocket? = null
    private var httpsConnection: HttpURLConnection? = null

    @Synchronized
    internal fun attach(socket: DatagramSocket): Boolean {
        if (cancelled) {
            socket.close()
            return false
        }
        dnsSocket = socket
        return true
    }

    @Synchronized
    internal fun detach(socket: DatagramSocket) {
        if (dnsSocket === socket) dnsSocket = null
    }

    @Synchronized
    internal fun attach(connection: HttpURLConnection): Boolean {
        if (cancelled) {
            connection.disconnect()
            return false
        }
        httpsConnection = connection
        return true
    }

    @Synchronized
    internal fun detach(connection: HttpURLConnection) {
        if (httpsConnection === connection) httpsConnection = null
    }

    @Synchronized
    fun cancel() {
        cancelled = true
        dnsSocket?.close()
        dnsSocket = null
        httpsConnection?.disconnect()
        httpsConnection = null
    }

    @Synchronized
    fun isCancelled(): Boolean = cancelled
}

object NetworkProbe {
    suspend fun run(session: ProbeSession = ProbeSession()): ProbeResult = withContext(Dispatchers.IO) {
        val dns = runCatching {
            "成功（${resolveDNS(session)}）"
        }.getOrElse { "失败：${it.message}" }
        if (session.isCancelled()) throw CancellationException("网络探测已取消")
        Log.i("LoomNetworkProbe", "DNS $dns")

        val https = runCatching { probeHTTPS(session) }.getOrElse { "失败：${it.message}" }
        if (session.isCancelled()) throw CancellationException("网络探测已取消")
        Log.i("LoomNetworkProbe", "HTTPS $https")
        ProbeResult(dns, https)
    }

    private fun probeHTTPS(session: ProbeSession): String {
        val failures = mutableListOf<String>()
        for (target in HTTPS_TARGETS) {
            if (session.isCancelled()) throw CancellationException("网络探测已取消")
            val attempt = runCatching {
                val connection = URL(target).openConnection() as HttpURLConnection
                check(session.attach(connection)) { "探测已取消" }
                connection.connectTimeout = HTTPS_TIMEOUT_MS
                connection.readTimeout = HTTPS_TIMEOUT_MS
                connection.instanceFollowRedirects = false
                connection.useCaches = false
                try {
                    val status = connection.responseCode
                    check(status in 200..399) { "HTTP $status" }
                    "成功（${connection.url.host} HTTP $status）"
                } finally {
                    session.detach(connection)
                    connection.disconnect()
                }
            }
            attempt.getOrNull()?.let { return it }
            failures += "${URL(target).host}: ${attempt.exceptionOrNull()?.message ?: "未知错误"}"
        }
        error(failures.joinToString("；"))
    }

    private fun resolveDNS(session: ProbeSession): String {
        val query = dnsQuery("example.com")
        val response = ByteArray(1_500)
        val packet = DatagramPacket(response, response.size)
        DatagramSocket().use { socket ->
            check(session.attach(socket)) { "探测已取消" }
            try {
                socket.soTimeout = 10_000
                socket.connect(InetAddress.getByName(PUBLIC_DNS), 53)
                socket.send(DatagramPacket(query, query.size))
                socket.receive(packet)
            } finally {
                session.detach(socket)
            }
        }

        check(packet.length >= 12) { "DNS response too short" }
        check(response[0] == query[0] && response[1] == query[1]) { "DNS transaction mismatch" }
        val flags = unsignedShort(response, 2)
        check(flags and 0x8000 != 0) { "DNS packet is not a response" }
        check(flags and 0x000f == 0) { "DNS rcode=${flags and 0x000f}" }
        val answers = unsignedShort(response, 6)
        check(answers > 0) { "DNS returned no answers" }
        return "$answers answer(s)"
    }

    private fun dnsQuery(host: String): ByteArray {
        val labels = host.split('.')
        val output = ArrayList<Byte>(12 + host.length + 6)
        output += 0x4c.toByte()
        output += 0x4d.toByte()
        output += 0x01.toByte()
        output += 0x00.toByte()
        output += 0x00.toByte()
        output += 0x01.toByte()
        repeat(6) { output += 0x00.toByte() }
        for (label in labels) {
            val bytes = label.encodeToByteArray()
            require(bytes.size in 1..63) { "invalid DNS label" }
            output += bytes.size.toByte()
            output.addAll(bytes.toList())
        }
        output += 0x00.toByte()
        output += 0x00.toByte()
        output += 0x01.toByte()
        output += 0x00.toByte()
        output += 0x01.toByte()
        return output.toByteArray()
    }

    private fun unsignedShort(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xff) shl 8) or (bytes[offset + 1].toInt() and 0xff)

    // A public resolver address guarantees that the probe follows the default
    // VPN route. sing-box sniffs the DNS payload and applies hijack-dns before
    // resolving it through the signed configuration's DNS transport.
    private const val PUBLIC_DNS = "1.1.1.1"

    // One public provider can be regionally filtered even when the VPN is
    // otherwise healthy. Prefer a DNS-backed endpoint that is reachable from
    // the device's current region, then retain the IP-literal probe as a
    // DNS-independent fallback. Either valid TLS response proves HTTPS through
    // the TUN; all failures remain visible when neither endpoint works.
    private val HTTPS_TARGETS = listOf("https://www.baidu.com/", "https://1.1.1.1/")
    private const val HTTPS_TIMEOUT_MS = 7_000
}
