package io.github.scisaga.loom.vpn

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.Closeable
import java.io.InputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URI
import java.security.SecureRandom
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

data class ProbeResult(
    val dns: String,
    val https: String,
    val target: String,
    val metricMillis: Long,
) {
    val healthy: Boolean get() = dns.startsWith("成功") && https.startsWith("成功")
}

class ProbeSession {
    private var cancelled = false
    private val sockets = mutableSetOf<Closeable>()

    @Synchronized
    internal fun attach(socket: Closeable): Boolean {
        if (cancelled) {
            socket.close()
            return false
        }
        sockets += socket
        return true
    }

    @Synchronized
    internal fun detach(socket: Closeable) { sockets -= socket }

    @Synchronized
    fun cancel() {
        cancelled = true
        sockets.forEach { runCatching { it.close() } }
        sockets.clear()
    }

    @Synchronized
    fun isCancelled(): Boolean = cancelled
}

/** Uses normal VPN-routed sockets. Only libbox underlay sockets use VpnService.protect. */
object NetworkProbe {
    suspend fun run(dnsServer: String, httpsTarget: String, session: ProbeSession = ProbeSession()): ProbeResult =
        withContext(Dispatchers.IO) {
            val target = URI(URI(httpsTarget).toASCIIString())
            require(target.scheme == "https" && !target.host.isNullOrBlank() &&
                target.rawUserInfo == null && target.rawFragment == null) { "业务探测需要认证 HTTPS 目标" }
            val resolver = probeDNSAddress(dnsServer)
            val started = System.nanoTime()
            val resolved = runCatching { resolveDNS(session, resolver, target.host) }
            if (session.isCancelled()) throw CancellationException("网络探测已取消")
            val dns = resolved.fold({ "成功（${it.hostAddress}）" }, { "失败：${it.message}" })
            val https = resolved.fold(
                { address -> runCatching { probeHTTPS(session, target, address) }.getOrElse { "失败：${it.message}" } },
                { "未执行：认证 DNS 查询失败" },
            )
            if (session.isCancelled()) throw CancellationException("网络探测已取消")
            ProbeResult(dns, https, httpsTarget, (System.nanoTime() - started) / 1_000_000)
        }

    private fun probeHTTPS(session: ProbeSession, target: URI, address: InetAddress): String {
        val port = if (target.port == -1) 443 else target.port
        require(port in 1..65535) { "HTTPS 端口无效" }
        val socket = Socket()
        check(session.attach(socket)) { "探测已取消" }
        try {
            socket.soTimeout = TIMEOUT_MS
            // A pre-resolved address prevents a host-resolver lookup. The original
            // certified hostname is preserved for SNI and HTTPS certificate checks.
            socket.connect(InetSocketAddress(address, port), TIMEOUT_MS)
            val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
            (factory.createSocket(socket, target.host, port, true) as SSLSocket).use { tls ->
                check(session.attach(tls)) { "探测已取消" }
                try {
                    tls.soTimeout = TIMEOUT_MS
                    tls.sslParameters = tls.sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
                    tls.startHandshake()
                    val path = target.rawPath.takeUnless { it.isNullOrEmpty() } ?: "/"
                    val requestTarget = path + (target.rawQuery?.let { "?$it" } ?: "")
                    val authority = target.rawAuthority
                    val request = "GET $requestTarget HTTP/1.1\r\nHost: $authority\r\nConnection: close\r\n\r\n"
                    tls.outputStream.write(request.toByteArray(Charsets.US_ASCII))
                    tls.outputStream.flush()
                    val status = readHTTPStatus(tls.inputStream)
                    check(status in 200..399) { "HTTP $status" }
                    return "成功（${target.host} HTTP $status）"
                } finally {
                    session.detach(tls)
                }
            }
        } finally {
            session.detach(socket)
            socket.close()
        }
    }

    private fun resolveDNS(session: ProbeSession, resolver: InetAddress, host: String): InetAddress {
        for (type in listOf(1, 28)) {
            val query = probeDNSQuery(host, type, SecureRandom().nextInt(65536))
            val response = ByteArray(4096)
            val packet = DatagramPacket(response, response.size)
            DatagramSocket().use { socket ->
                check(session.attach(socket)) { "探测已取消" }
                try {
                    socket.soTimeout = TIMEOUT_MS
                    socket.connect(resolver, 53)
                    socket.send(DatagramPacket(query, query.size))
                    socket.receive(packet)
                } finally {
                    session.detach(socket)
                }
            }
            val addresses = decodeProbeDNS(query, response.copyOf(packet.length), type)
            if (addresses.isNotEmpty()) return addresses.first()
        }
        error("认证 DNS 未返回目标地址")
    }

    private const val TIMEOUT_MS = 7_000
}

internal fun probeDNSAddress(value: String): InetAddress {
    if (value.contains(':')) {
        require(value.all { it in "0123456789abcdefABCDEF:." }) { "DNS 必须是认证 IP 地址" }
        return InetAddress.getByName(value) // A numeric IPv6 literal cannot invoke host DNS.
    }
    val octets = value.split('.')
    require(octets.size == 4 && octets.all {
        it.toIntOrNull()?.let { n -> n in 0..255 && n.toString() == it } == true
    }) { "DNS 必须是认证 IP 地址" }
    return InetAddress.getByAddress(octets.map { it.toInt().toByte() }.toByteArray())
}

internal fun probeDNSQuery(host: String, type: Int, id: Int): ByteArray {
    require(type == 1 || type == 28)
    val output = arrayListOf<Byte>((id shr 8).toByte(), id.toByte(), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0)
    for (label in host.split('.')) {
        val bytes = label.toByteArray(Charsets.US_ASCII)
        require(bytes.size in 1..63 && label.all { it.code in 33..126 }) { "DNS 名称无效" }
        output += bytes.size.toByte()
        output.addAll(bytes.toList())
    }
    output.addAll(listOf<Byte>(0, 0, type.toByte(), 0, 1))
    require(output.size <= 512) { "DNS 查询过长" }
    return output.toByteArray()
}

internal fun decodeProbeDNS(query: ByteArray, response: ByteArray, type: Int): List<InetAddress> {
    fun word(at: Int): Int {
        check(at >= 0 && at + 1 < response.size) { "DNS 响应截断" }
        return ((response[at].toInt() and 255) shl 8) or (response[at + 1].toInt() and 255)
    }
    check(response.size >= 12 && query.size >= 12 && response[0] == query[0] && response[1] == query[1]) {
        "DNS 事务不匹配"
    }
    val flags = word(2)
    check(flags and 0x8000 != 0 && flags and 0x0200 == 0 && flags and 0x000f == 0) { "DNS 响应失败或截断" }
    check(word(4) == 1 && response.size >= query.size &&
        response.copyOfRange(12, query.size).contentEquals(query.copyOfRange(12, query.size))) { "DNS 问题不匹配" }
    var at = query.size
    val result = mutableListOf<InetAddress>()
    repeat(word(6)) {
        while (true) {
            check(at < response.size) { "DNS 名称截断" }
            val length = response[at++].toInt() and 255
            if (length == 0) break
            if (length and 0xc0 == 0xc0) {
                check(at < response.size && ((length and 63) shl 8 or (response[at].toInt() and 255)) < response.size) {
                    "DNS 压缩指针无效"
                }
                at++
                break
            }
            check(length <= 63 && at + length <= response.size) { "DNS 标签无效" }
            at += length
        }
        val answerType = word(at)
        val answerClass = word(at + 2)
        val length = word(at + 8)
        at += 10
        check(at + length <= response.size) { "DNS 地址截断" }
        if (answerClass == 1 && answerType == type) {
            check(length == if (type == 1) 4 else 16) { "DNS 地址长度无效" }
            result += InetAddress.getByAddress(response.copyOfRange(at, at + length))
        }
        at += length
    }
    return result
}

internal fun readHTTPStatus(input: InputStream): Int {
    val line = StringBuilder()
    while (line.length < 4096) {
        val byte = input.read()
        check(byte != -1) { "HTTP 状态缺失" }
        if (byte == 10) {
            val fields = line.toString().trimEnd('\r').split(' ')
            check(fields.size >= 2 && fields[0] in setOf("HTTP/1.0", "HTTP/1.1")) { "HTTP 状态无效" }
            return checkNotNull(fields[1].toIntOrNull()) { "HTTP 状态码无效" }
        }
        line.append(byte.toChar())
    }
    error("HTTP 状态行过长")
}
