package io.github.scisaga.loom.enrollment

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

internal data class HttpResult(
    val status: Int,
    val contentType: String?,
    val body: ByteArray,
)

internal object HttpTransport {
    fun postJSON(context: Context, endpoint: String, body: ByteArray, maximum: Int): HttpResult = request(
        context = context,
        endpoint = endpoint,
        method = "POST",
        requestBody = body,
        maximum = maximum,
        accept = "application/json",
    )

    fun get(context: Context, endpoint: String, maximum: Int): HttpResult = request(
        context = context,
        endpoint = endpoint,
        method = "GET",
        requestBody = null,
        maximum = maximum,
        accept = "application/json, application/octet-stream",
    )

    private fun request(
        context: Context,
        endpoint: String,
        method: String,
        requestBody: ByteArray?,
        maximum: Int,
        accept: String,
    ): HttpResult {
        require(maximum in 1..MAXIMUM_RESPONSE) { "HTTP 响应边界无效" }
        val url = URL(endpoint)
        require(
            url.protocol == "https" && url.userInfo == null && url.host.isNotBlank() &&
                url.ref == null && url.query == null,
        ) { "控制通道必须是无凭据、无 query/fragment 的 HTTPS 地址" }
        val networks = underlyingNetworks(context)
        check(networks.isNotEmpty()) { "没有已验证且未被 VPN 接管的底层网络" }
        var lastFailure: Throwable? = null
        for (network in networks) {
            try {
                return requestOn(network, url, method, requestBody, maximum, accept)
            } catch (failure: IOException) {
                lastFailure = failure
            }
        }
        throw IllegalStateException("所有已验证的底层网络均无法访问控制通道", lastFailure)
    }

    private fun requestOn(
        network: Network,
        url: URL,
        method: String,
        requestBody: ByteArray?,
        maximum: Int,
        accept: String,
    ): HttpResult {
        val connection = network.openConnection(url) as HttpURLConnection
        try {
            connection.instanceFollowRedirects = false
            connection.useCaches = false
            connection.connectTimeout = CONNECT_TIMEOUT_MS
            connection.readTimeout = READ_TIMEOUT_MS
            connection.requestMethod = method
            connection.setRequestProperty("Accept", accept)
            connection.setRequestProperty("User-Agent", "Loom-Android/0.2")
            if (requestBody != null) {
                require(requestBody.size <= MAXIMUM_REQUEST) { "HTTP 请求体过大" }
                connection.doOutput = true
                connection.setFixedLengthStreamingMode(requestBody.size)
                connection.setRequestProperty("Content-Type", "application/json")
                connection.outputStream.use { it.write(requestBody) }
            }
            val status = connection.responseCode
            val stream = if (status in 200..299) connection.inputStream else connection.errorStream
            val response = stream?.use { input ->
                val output = ByteArrayOutputStream(minOf(maximum, 16 * 1024))
                val buffer = ByteArray(8192)
                var total = 0
                while (true) {
                    val read = input.read(buffer)
                    if (read < 0) break
                    total += read
                    require(total <= maximum) { "HTTP 响应超过 ${maximum}B 边界" }
                    output.write(buffer, 0, read)
                }
                output.toByteArray()
            } ?: ByteArray(0)
            return HttpResult(status, connection.contentType, response)
        } finally {
            connection.disconnect()
        }
    }

    private fun underlyingNetworks(context: Context): List<Network> {
        val connectivity = context.getSystemService(ConnectivityManager::class.java) ?: return emptyList()
        fun eligible(network: Network): Boolean {
            val capabilities = connectivity.getNetworkCapabilities(network) ?: return false
            return capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) &&
                capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) &&
                (Build.VERSION.SDK_INT < Build.VERSION_CODES.P ||
                    capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_SUSPENDED))
        }
        val active = connectivity.activeNetwork?.takeIf(::eligible)
        return buildList {
            active?.let(::add)
            connectivity.allNetworks
                .asSequence()
                .filter(::eligible)
                .filter { it != active }
                .sortedBy(Network::toString)
                .forEach(::add)
        }
    }

    private const val CONNECT_TIMEOUT_MS = 10_000
    private const val READ_TIMEOUT_MS = 20_000
    private const val MAXIMUM_REQUEST = 4 * 1024 * 1024
    private const val MAXIMUM_RESPONSE = 16 * 1024 * 1024
}
