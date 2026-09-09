package io.github.scisaga.loom.route

import kotlinx.coroutines.delay
import org.json.JSONObject
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

internal class SelectorClient(routePlan: String) {
    private val root = JSONObject(routePlan)
    private val controller = root.getString("api").also {
        check(it == "127.0.0.1:61800") { "移动 selector 控制端点不是固定回环地址" }
    }
    private val secret = root.getString("api_secret").also {
        check(it.isNotBlank() && it.length <= MAX_SECRET && it.all { char -> char.code in 0x21..0x7e }) {
            "移动 selector 控制口令无效"
        }
    }

    suspend fun apply(targets: List<AppliedSelector>) {
        check(targets.isNotEmpty()) { "没有可应用的 selector" }
        val ordered = targets.sortedBy(AppliedSelector::selector)
        val current = readCurrent(ordered)
        val changed = mutableListOf<String>()
        try {
            ordered.forEach { target ->
                if (current.getValue(target.selector) == target.candidate) return@forEach
                request("PUT", target.selector, target.candidate)
                changed += target.selector
            }
            if (changed.isNotEmpty()) requestRaw("DELETE", "/connections/", null)
            ordered.forEach { target ->
                check(request("GET", target.selector) == target.candidate) {
                    "selector ${target.selector} 未读回目标候选"
                }
            }
        } catch (error: Throwable) {
            changed.asReversed().forEach { selector ->
                runCatching { request("PUT", selector, current.getValue(selector)) }
            }
            throw error
        }
    }

    /** §7.3.3：只读投影 libbox 的实际 selector 状态。 */
    suspend fun readCurrent(targets: List<AppliedSelector>): Map<String, String> {
        check(targets.isNotEmpty()) { "没有可读取的 selector" }
        return linkedMapOf<String, String>().apply {
            targets.sortedBy(AppliedSelector::selector).forEach { target ->
                put(target.selector, readCurrentWithStartupRetry(target.selector))
            }
        }
    }

    private suspend fun readCurrentWithStartupRetry(selector: String): String {
        var last: Throwable? = null
        repeat(20) {
            try {
                return request("GET", selector)
            } catch (error: Throwable) {
                last = error
                delay(100)
            }
        }
        throw IllegalStateException("本地 selector API 启动超时", last)
    }

    private fun request(method: String, selector: String, target: String? = null): String {
        val encoded = URLEncoder.encode(selector, StandardCharsets.UTF_8.name()).replace("+", "%20")
        val response = requestRaw(
            method,
            "/proxies/$encoded",
            target?.let { JSONObject().put("name", it).toString().encodeToByteArray() },
        )
        if (method != "GET") return ""
        return JSONObject(response.decodeToString()).getString("now").also {
            check(it.isNotBlank()) { "selector $selector 没有返回当前候选" }
        }
    }

    private fun requestRaw(method: String, path: String, body: ByteArray?): ByteArray {
        val response = loopbackHttpRequest(
            host = LOOPBACK_HOST,
            port = LOOPBACK_PORT,
            secret = secret,
            method = method,
            path = path,
            body = body,
            maximum = MAX_RESPONSE,
        )
        check(response.status in 200..299) { "本地 selector API 返回 HTTP ${response.status}" }
        return response.body
    }

    companion object {
        private const val LOOPBACK_HOST = "127.0.0.1"
        private const val LOOPBACK_PORT = 61800
        private const val MAX_RESPONSE = 4 * 1024
        private const val MAX_SECRET = 4 * 1024
    }
}

internal data class LoopbackHttpResponse(val status: Int, val body: ByteArray)

/**
 * Android's cleartext policy correctly blocks HttpURLConnection even for an
 * HTTP loopback controller. This deliberately tiny client cannot address the
 * network: production callers are pinned to 127.0.0.1 and all parsed input is
 * bounded before allocation.
 */
internal fun loopbackHttpRequest(
    host: String,
    port: Int,
    secret: String,
    method: String,
    path: String,
    body: ByteArray?,
    maximum: Int,
): LoopbackHttpResponse {
    require(host == "127.0.0.1") { "selector API 只允许 IPv4 回环" }
    require(port in 1..65535) { "selector API 端口无效" }
    require(method == "GET" || method == "PUT" || method == "DELETE") { "selector API 方法无效" }
    require(path.startsWith('/') && !path.contains('\r') && !path.contains('\n')) { "selector API 路径无效" }
    require(secret.isNotBlank() && secret.length <= 4 * 1024 && secret.all { it.code in 0x21..0x7e }) {
        "selector API 口令无效"
    }
    require(maximum in 1..64 * 1024) { "selector API 响应边界无效" }
    require(body == null || body.size <= maximum) { "selector API 请求过大" }

    Socket().use { socket ->
        socket.connect(InetSocketAddress(host, port), SOCKET_TIMEOUT_MS)
        socket.soTimeout = SOCKET_TIMEOUT_MS
        val header = buildString {
            append(method).append(' ').append(path).append(" HTTP/1.1\r\n")
            append("Host: ").append(host).append(':').append(port).append("\r\n")
            append("Authorization: Bearer ").append(secret).append("\r\n")
            append("Accept: application/json\r\n")
            append("Connection: close\r\n")
            if (body != null) {
                append("Content-Type: application/json\r\n")
                append("Content-Length: ").append(body.size).append("\r\n")
            }
            append("\r\n")
        }.toByteArray(StandardCharsets.US_ASCII)
        socket.getOutputStream().apply {
            write(header)
            if (body != null) write(body)
            flush()
        }

        val input = BufferedInputStream(socket.getInputStream())
        val statusLine = readHttpLine(input, MAX_HEADER_LINE)
        val status = statusLine.split(' ', limit = 3).let { parts ->
            check(parts.size >= 2 && parts[0].startsWith("HTTP/1.")) { "selector API 状态行无效" }
            parts[1].toIntOrNull()?.also { check(it in 100..599) } ?: error("selector API 状态码无效")
        }
        val headers = linkedMapOf<String, String>()
        var headerBytes = statusLine.length + 2
        while (true) {
            val line = readHttpLine(input, MAX_HEADER_LINE)
            headerBytes += line.length + 2
            check(headerBytes <= MAX_HEADERS) { "selector API 响应头过大" }
            if (line.isEmpty()) break
            val colon = line.indexOf(':')
            check(colon > 0) { "selector API 响应头无效" }
            val name = line.substring(0, colon).trim().lowercase()
            val value = line.substring(colon + 1).trim()
            check(name.isNotEmpty() && name.all { it in 'a'..'z' || it == '-' }) { "selector API 响应头名称无效" }
            headers[name] = headers[name]?.let { "$it,$value" } ?: value
        }
        val responseBody = when {
            headers["transfer-encoding"]?.split(',')?.any { it.trim().equals("chunked", true) } == true -> {
                readChunkedBody(input, maximum)
            }
            headers["content-length"] != null -> {
                val length = headers.getValue("content-length").toIntOrNull()
                check(length != null && length in 0..maximum) { "selector API Content-Length 无效" }
                readExactly(input, length)
            }
            else -> readUntilEOF(input, maximum)
        }
        return LoopbackHttpResponse(status, responseBody)
    }
}

private fun readHttpLine(input: InputStream, maximum: Int): String {
    val output = ByteArrayOutputStream()
    while (output.size() <= maximum) {
        val next = input.read()
        check(next >= 0) { "selector API 响应提前结束" }
        if (next == '\n'.code) {
            val bytes = output.toByteArray()
            val length = if (bytes.lastOrNull() == '\r'.code.toByte()) bytes.size - 1 else bytes.size
            return String(bytes, 0, length, StandardCharsets.ISO_8859_1)
        }
        output.write(next)
    }
    error("selector API 响应行过长")
}

private fun readExactly(input: InputStream, length: Int): ByteArray {
    val body = ByteArray(length)
    var offset = 0
    while (offset < length) {
        val read = input.read(body, offset, length - offset)
        check(read > 0) { "selector API 响应正文提前结束" }
        offset += read
    }
    return body
}

private fun readUntilEOF(input: InputStream, maximum: Int): ByteArray {
    val output = ByteArrayOutputStream()
    val buffer = ByteArray(1024)
    while (true) {
        val read = input.read(buffer)
        if (read < 0) break
        if (read == 0) continue
        check(output.size() + read <= maximum) { "selector API 响应过大" }
        output.write(buffer, 0, read)
    }
    return output.toByteArray()
}

private fun readChunkedBody(input: InputStream, maximum: Int): ByteArray {
    val output = ByteArrayOutputStream()
    while (true) {
        val sizeText = readHttpLine(input, MAX_HEADER_LINE).substringBefore(';').trim()
        val size = sizeText.toIntOrNull(16)
        check(size != null && size >= 0 && output.size() + size <= maximum) { "selector API chunk 大小无效" }
        if (size == 0) {
            var trailerBytes = 0
            while (true) {
                val trailer = readHttpLine(input, MAX_HEADER_LINE)
                trailerBytes += trailer.length + 2
                check(trailerBytes <= MAX_HEADERS) { "selector API trailer 过大" }
                if (trailer.isEmpty()) return output.toByteArray()
            }
        }
        output.write(readExactly(input, size))
        check(input.read() == '\r'.code && input.read() == '\n'.code) { "selector API chunk 结尾无效" }
    }
}

private const val SOCKET_TIMEOUT_MS = 3_000
private const val MAX_HEADER_LINE = 4 * 1024
private const val MAX_HEADERS = 16 * 1024
