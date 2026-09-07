package io.github.scisaga.loom.route

import kotlinx.coroutines.delay
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.Proxy
import java.net.URLEncoder
import java.net.URL
import java.nio.charset.StandardCharsets

internal class SelectorClient(routePlan: String) {
    private val root = JSONObject(routePlan)
    private val controller = root.getString("api").also {
        check(it == "127.0.0.1:61800") { "移动 selector 控制端点不是固定回环地址" }
    }
    private val secret = root.getString("api_secret").also {
        check(it.isNotBlank()) { "移动 selector 控制口令为空" }
    }

    suspend fun apply(targets: List<AppliedSelector>) {
        check(targets.isNotEmpty()) { "没有可应用的 selector" }
        val ordered = targets.sortedBy(AppliedSelector::selector)
        val current = linkedMapOf<String, String>()
        ordered.forEach { target -> current[target.selector] = readCurrentWithStartupRetry(target.selector) }
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
        val connection = URL("http://$controller$path").openConnection(Proxy.NO_PROXY) as HttpURLConnection
        try {
            connection.requestMethod = method
            connection.connectTimeout = 3_000
            connection.readTimeout = 3_000
            connection.useCaches = false
            connection.setRequestProperty("Authorization", "Bearer $secret")
            if (body != null) {
                connection.doOutput = true
                connection.setFixedLengthStreamingMode(body.size)
                connection.setRequestProperty("Content-Type", "application/json")
                connection.outputStream.use { it.write(body) }
            }
            val status = connection.responseCode
            val stream = if (status in 200..299) connection.inputStream else connection.errorStream
            val response = stream?.use { input ->
                val output = ByteArrayOutputStream()
                val buffer = ByteArray(1024)
                while (output.size() <= MAX_RESPONSE) {
                    val read = input.read(buffer)
                    if (read < 0) break
                    if (read > 0) output.write(buffer, 0, read)
                }
                output.toByteArray()
            } ?: ByteArray(0)
            check(response.size <= MAX_RESPONSE) { "本地 selector API 响应过大" }
            check(status in 200..299) { "本地 selector API 返回 HTTP $status" }
            return response
        } finally {
            connection.disconnect()
        }
    }

    companion object {
        private const val MAX_RESPONSE = 4 * 1024
    }
}
