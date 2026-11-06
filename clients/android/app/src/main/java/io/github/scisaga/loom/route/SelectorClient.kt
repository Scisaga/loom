package io.github.scisaga.loom.route

import kotlinx.coroutines.delay
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.TimeoutCancellationException
import io.github.scisaga.loom.enrollment.privateCall
import org.json.JSONObject
import org.json.JSONArray
import io.github.scisaga.loomcore.AndroidDeviceRequest
import io.github.scisaga.loomcore.Loomcore
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

/** Bounded bookkeeping owned only by one cancellable selector call. */
internal class SelectorCallScopes {
    private val remaining = linkedSetOf<String>()
    private val uncertain = linkedSetOf<String>()
    // A predecessor's unconfirmed PUT may still commit. Reads and local
    // preparation failures cannot discharge this call's CAS requirement.
    private val requiredCAS = linkedSetOf<String>()
    @Synchronized fun plan(scopes: Collection<String>, requireCAS: Collection<String> = emptyList()) {
        require(scopes.containsAll(requireCAS))
        remaining.addAll(scopes)
        requiredCAS.addAll(requireCAS)
    }
    @Synchronized fun mayWrite(scope: String): Boolean = scope in remaining
    @Synchronized fun requiresCAS(scope: String): Boolean = scope in requiredCAS
    @Synchronized fun wrote(scope: String) { uncertain.add(scope) }
    @Synchronized fun uncertain(): Set<String> = uncertain + requiredCAS
    @Synchronized fun finished(scope: String) { remaining.remove(scope) }
    @Synchronized fun confirmed(scope: String) { remaining.remove(scope); uncertain.remove(scope); requiredCAS.remove(scope) }
}

internal class SelectorClient(
    private val config: String,
    private val exchange: suspend (String, String, String, ByteArray?, Int, Socket) -> LoopbackHttpResponse =
        { secret, method, path, body, maximum, socket ->
            cancellableLoopbackHttpRequest(LOOPBACK_HOST, LOOPBACK_PORT, secret, method, path, body, maximum, socket)
        },
) {
    private val socketLock = Any()
    private var activeSocket: Socket? = null
    private var resourceRequest: AndroidDeviceRequest? = null
    private var cancelled = false
    private val scopes = SelectorCallScopes()

    fun planScopes(values: Collection<String>, requireCAS: Collection<String> = emptyList()) = scopes.plan(values, requireCAS)
    fun mayWrite(scope: String): Boolean = scopes.mayWrite(scope)
    fun requiresCAS(scope: String): Boolean = scopes.requiresCAS(scope)
    fun uncertainScopes(): Set<String> = scopes.uncertain()
    fun confirmed(scope: String) = scopes.confirmed(scope)
    fun finished(scope: String) = scopes.finished(scope)

    fun cancel() = synchronized(socketLock) {
        cancelled = true
        activeSocket?.close()
        resourceRequest?.cancel()
    }
    private val root = JSONObject(config).getJSONObject("experimental").getJSONObject("clash_api")
    private val controller = root.getString("external_controller").also {
        check(it == "127.0.0.1:61800") { "移动 selector 控制端点不是固定回环地址" }
    }
    private val secret = root.getString("secret").also {
        check(it.isNotBlank() && it.length <= MAX_SECRET && it.all { char -> char.code in 0x21..0x7e }) {
            "移动 selector 控制口令无效"
        }
    }

    var readbackTargets: Map<String,Map<String,String>> = emptyMap()
        private set

    var readbackRevisions: Map<String,String> = emptyMap()
        private set

    var readbackPolicies: Map<String,String> = emptyMap()
        private set
    var readbackChoices: Map<String,RouteChoices> = emptyMap()
        private set

    suspend fun apply(targets: List<AppliedSelector>) {
        if (targets.isEmpty()) { checkHealth(); return }
        planScopes(targets.map { it.selector })
        for (target in targets.sortedBy(AppliedSelector::selector)) {
            val current = request("GET", target.selector)
            val currentTargets = readbackTargets[target.selector].orEmpty()
            val currentPolicy = checkNotNull(readbackPolicies[target.selector])
            val currentChoices = checkNotNull(readbackChoices[target.selector])
            val explicit = target.expectedCandidate != null
            val expected = target.expectedCandidate ?: current
            val expectedTargets = if (explicit) target.expectedTargets else currentTargets
            val expectedPolicy = if (explicit) checkNotNull(target.expectedPolicyID) else currentPolicy
            val expectedChoices = if (explicit) target.expectedChoices else currentChoices
            val revision = checkNotNull(readbackRevisions[target.selector])
            val expectedRevision = target.expectedRevision ?: revision
            if (current != expected || currentTargets != expectedTargets || revision != expectedRevision || currentPolicy != expectedPolicy || currentChoices != expectedChoices) throw SelectionSuperseded()
            val changed = current != target.candidate || currentTargets != target.targets || currentPolicy != target.policyID || currentChoices != target.choices
            var appliedRevision = revision
            if (changed || target.forceCAS || scopes.requiresCAS(target.selector)) {
                prepareResources(target)
                synchronized(socketLock) {
                    if (cancelled) throw SelectionSuperseded()
                    // Record the possible write before its socket is opened.
                    // cancel() holds this same lock, so a cancelled call can
                    // neither start an unrecorded PUT nor add a later write.
                    scopes.wrote(target.selector)
                }
                check(request("PUT", target.selector, target.candidate, target.targets, expected, expectedTargets, expectedRevision,
                    target.policyID, target.choices, expectedPolicy, expectedChoices) == target.candidate &&
                    readbackTargets[target.selector] == target.targets && readbackPolicies[target.selector] == target.policyID && readbackChoices[target.selector] == target.choices) { "selector 未确认完整选择" }
                appliedRevision = checkNotNull(readbackRevisions[target.selector])
                check(appliedRevision != revision) { "selector 没有返回新的快照标识" }
            }
            check(request("GET",target.selector) == target.candidate && readbackTargets[target.selector] == target.targets &&
                readbackPolicies[target.selector] == target.policyID && readbackChoices[target.selector] == target.choices && readbackRevisions[target.selector] == appliedRevision) {
                "selector ${target.selector} 未读回完整选择"
            }
        }
    }

    private suspend fun prepareResources(target: AppliedSelector) {
        if (target.candidate == "reject") return
        currentCoroutineContext().ensureActive()
        val body = JSONObject().put("scope", target.selector).put("policy_id", target.policyID)
            .put("candidate_id", target.candidate).put("revision", "")
            .put("targets", JSONObject(target.targets)).put("choices", JSONObject(target.choices))
            .toString().encodeToByteArray()
        val pending = Loomcore.newAndroidSelectionResourcesRequest(config, body)
        synchronized(socketLock) {
            if (cancelled) { pending.cancel(); throw SelectionSuperseded() }
            check(activeSocket == null && resourceRequest == null) { "selector 客户端不允许并发资源准备" }
            resourceRequest = pending
        }
        val result = try {
            JSONObject(privateCall(pending::run, pending::cancel).decodeToString())
        } finally {
            pending.cancel()
            synchronized(socketLock) { if (resourceRequest === pending) resourceRequest = null }
        }
        currentCoroutineContext().ensureActive()
        synchronized(socketLock) { if (cancelled) throw SelectionSuperseded() }
        check(result.getBoolean("supported") && result.getBoolean("permission_current")) { "当前原生权限未确认" }
        if (!result.getBoolean("resources_ready")) throw RuntimeResourcesPending()
    }

    suspend fun readNativeObservations(): ByteArray = requestRaw("GET", "/loom/tcp-observations", null)

    /** §7.3.3：只读投影 libbox 的实际 selector 状态。 */
    suspend fun readCurrent(targets: List<AppliedSelector>): Map<String, String> = selectorStartupRead {
        if (targets.isEmpty()) {
            checkHealth()
            emptyMap()
        } else {
            linkedMapOf<String, String>().apply {
                targets.sortedBy(AppliedSelector::selector).forEach { target ->
                    put(target.selector, request("GET", target.selector))
                }
            }
        }
    }

    suspend fun closeServiceConnections(serviceID: String, scope: String) {
        val snapshot = requestRaw("GET", "/connections/", null)
        val ids = JSONArray(Loomcore.serviceConnectionIDs(snapshot, serviceID, scope).decodeToString())
        repeat(ids.length()) { index ->
            currentCoroutineContext().ensureActive()
            requestRaw("DELETE", "/connections/${ids.getString(index)}", null)
        }
    }

    private suspend fun checkHealth() {
        check(JSONObject(requestRaw("GET", "/version", null).decodeToString()).getString("version").isNotBlank()) {
            "本地运行时 API 未返回实际版本"
        }
    }


    private suspend fun request(method: String, selector: String, target: String? = null,
        targets: Map<String,String> = emptyMap(), expected: String? = null, expectedTargets: Map<String,String> = emptyMap(), expectedRevision: String? = null, policyID: String = "", choices: RouteChoices = emptyMap(),
        expectedPolicyID: String = "", expectedChoices: RouteChoices = emptyMap()): String {
        val encoded = URLEncoder.encode(selector, StandardCharsets.UTF_8.name()).replace("+", "%20")
        val response = requestRaw(method,"/proxies/$encoded",target?.let {
            JSONObject().put("name",it).put("targets",JSONObject(targets)).put("expected_name",checkNotNull(expected))
                .put("expected_targets",JSONObject(expectedTargets)).put("expected_revision",checkNotNull(expectedRevision))
                .put("policy_id",policyID).put("choices",JSONObject(choices)).put("expected_policy_id",expectedPolicyID)
                .put("expected_choices",JSONObject(expectedChoices)).toString().encodeToByteArray()
        })
        val value = JSONObject(response.decodeToString())
        val selected = value.getString("now").also { check(it.isNotBlank()) { "selector 没有返回当前候选" } }
        val choices = value.getJSONObject("targets").let { map -> map.keys().asSequence().associateWith(map::getString) }
        val revision = value.getString("revision").also {
            check(it.isNotBlank() && it.length <= 128 && it.all { char -> char.code in 0x21..0x7e }) { "selector 快照标识无效" }
        }
        val policy = value.getString("policy_id")
        val routes = value.getJSONObject("choices").routeChoices()
        check(if (selected == "reject") policy.isEmpty() && choices.isEmpty() && routes.isEmpty() else policy.isNotEmpty() && routes.keys == (choices.values + selected).toSet()) { "selector 连接上下文缺失" }
        readbackPolicies = readbackPolicies + (selector to policy)
        readbackChoices = readbackChoices + (selector to routes)
        readbackTargets = readbackTargets + (selector to choices)
        readbackRevisions = readbackRevisions + (selector to revision)
        return selected
    }

    private suspend fun requestRaw(method: String, path: String, body: ByteArray?): ByteArray {
        currentCoroutineContext().ensureActive()
        val socket = Socket()
        synchronized(socketLock) {
            if (cancelled) {
                socket.close()
                throw SelectionSuperseded()
            }
            check(activeSocket == null) { "selector 客户端不允许并发请求" }
            activeSocket = socket
        }
        val response = try {
            exchange(
                secret, method, path, body,
                if (path == "/connections/") 8 * 1024 * 1024 else if (path == "/loom/tcp-observations") 64 * 1024 else SELECTOR_READBACK_LIMIT, socket,
            )
        } catch (error: Throwable) {
            currentCoroutineContext().ensureActive()
            synchronized(socketLock) { if (cancelled) throw SelectionSuperseded() }
            throw error
        } finally {
            socket.close()
            synchronized(socketLock) { if (activeSocket === socket) activeSocket = null }
        }
        synchronized(socketLock) { if (cancelled) throw SelectionSuperseded() }
        if (response.status == 409) throw SelectionSuperseded()
        if (response.status == 503) throw IOException("本地 selector API 尚未就绪")
        check(response.status in 200..299) { "本地 selector API 返回 HTTP ${response.status}" }
        return response.body
    }

    companion object {
        private const val LOOPBACK_HOST = "127.0.0.1"
        private const val LOOPBACK_PORT = 61800
        private const val MAX_SECRET = 4 * 1024
    }
}

internal class RuntimeResourcesPending : IOException("当前按需传输资源尚未确认")

internal class SelectionSuperseded : IllegalStateException("选择已由其他操作更新；丢弃过时推荐")

internal data class LoopbackHttpResponse(val status: Int, val body: ByteArray)

/** One total startup deadline; conflicts and malformed replies are not retried. */
internal suspend fun <T> selectorStartupRead(read: suspend () -> T): T {
    var last: IOException? = null
    try {
        return withTimeout(SOCKET_TIMEOUT_MS.toLong()) {
            while (true) {
                currentCoroutineContext().ensureActive()
                try {
                    return@withTimeout read()
                } catch (error: IOException) {
                    last = error
                    delay(100)
                }
            }
            @Suppress("UNREACHABLE_CODE")
            error("selector startup ended without a response")
        }
    } catch (error: TimeoutCancellationException) {
        currentCoroutineContext().ensureActive()
        throw IllegalStateException("本地 selector API 启动超时", last ?: error)
    }
}

internal suspend fun cancellableLoopbackHttpRequest(
    host: String, port: Int, secret: String, method: String, path: String,
    body: ByteArray?, maximum: Int, socket: Socket = Socket(),
): LoopbackHttpResponse {
    try {
        return withTimeout(SOCKET_TIMEOUT_MS.toLong()) {
            privateCall(
                run = { loopbackHttpRequest(host, port, secret, method, path, body, maximum, socket) },
                cancel = socket::close,
            )
        }
    } catch (error: TimeoutCancellationException) {
        currentCoroutineContext().ensureActive()
        throw IOException("本地 selector API 响应超时", error)
    }
}

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
    socket: Socket = Socket(),
): LoopbackHttpResponse {
    require(host == "127.0.0.1") { "selector API 只允许 IPv4 回环" }
    require(port in 1..65535) { "selector API 端口无效" }
    require(method == "GET" || method == "PUT" || method == "DELETE") { "selector API 方法无效" }
    require(path.startsWith('/') && !path.contains('\r') && !path.contains('\n')) { "selector API 路径无效" }
    require(secret.isNotBlank() && secret.length <= 4 * 1024 && secret.all { it.code in 0x21..0x7e }) {
        "selector API 口令无效"
    }
    require(maximum in 1..8 * 1024 * 1024) { "selector API 响应边界无效" }
    require(body == null || body.size <= maximum) { "selector API 请求过大" }

    socket.use {
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
// A proxy reply contains every derived candidate ID, not just the current ID.
// Keep the same bounded readback allowance as the shared native selector.
internal const val SELECTOR_READBACK_LIMIT = 1024 * 1024
private const val MAX_HEADER_LINE = 4 * 1024
private const val MAX_HEADERS = 16 * 1024

internal typealias RouteChoices = Map<String,Map<String,String>>
internal fun JSONObject.routeChoices(): RouteChoices = keys().asSequence().associateWith { id ->
    val choice = getJSONObject(id)
    val fields = setOf("entry_node_id", "first_resource_id", "final_exit")
    check(choice.keys().asSequence().toSet() == fields) { "路径上下文字段不规范" }
    fields.associateWith(choice::getString)
}
