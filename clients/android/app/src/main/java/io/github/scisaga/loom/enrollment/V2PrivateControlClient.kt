package io.github.scisaga.loom.enrollment

import io.github.scisaga.loom.security.DeviceKeyStore
import io.github.scisaga.loomcore.Loomcore
import org.json.JSONArray
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.InetAddress
import java.net.Proxy
import java.net.Socket
import java.net.URI
import java.security.KeyStore
import java.security.MessageDigest
import java.security.Principal
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509ExtendedKeyManager

internal data class V2PrivateControlPlan(
    val role: String,
    val serviceID: String,
    val overlayIP: String,
    val port: Int,
    val path: String,
    val certificateProfileRef: String,
    val serverSPKIPins: Set<String>,
    val internalCARoots: List<X509Certificate>,
    val clientCertificateChain: Array<X509Certificate>,
    val identitySPKIHash: String,
    val directoryGeneration: Long,
    val directoryHash: String,
)

internal data class V2ReportResponse(val statusCode: Int, val observations: ByteArray?)

/**
 * 只拨共享 verifier 投影的 exact overlay tuple。这个 socket 故意不
 * protect，因此进入同一个 VpnService 的 TUN/WG；只有 bootstrap/public socket 绕过 TUN。
 */
internal class V2PrivateControlClient(
    private val keys: DeviceKeyStore = DeviceKeyStore(),
) {
    fun getFirst(plans: List<V2PrivateControlPlan>, maximumBytes: Int = MAX_DEVICE_VIEW_BYTES): ByteArray =
        tryEach(plans) { get(it, maximumBytes) }

    fun postFirst(plans: List<V2PrivateControlPlan>, body: ByteArray): V2ReportResponse =
        tryEach(plans) { post(it, body) }

    private fun get(plan: V2PrivateControlPlan, maximumBytes: Int): ByteArray {
        check(plan.role == "device_config" && plan.path == DEVICE_CONFIG_PATH) { "[Android control] config plan 无效" }
        val connection = connection(plan, "GET")
        return try {
            connection.setRequestProperty("Accept", DEVICE_CONFIG_DELIVERY_MEDIA_TYPE)
            val status = connection.responseCode
            verifyPeerPin(connection, plan.serverSPKIPins)
            check(status == 200) { "[Android control] private device_config 被拒绝（HTTP $status）" }
            check(connection.contentEncoding.isNullOrEmpty()) { "[Android control] private device_config 禁止压缩" }
            check(connection.contentType?.substringBefore(';')?.trim() == DEVICE_CONFIG_DELIVERY_MEDIA_TYPE) {
                "[Android control] private device_config Content-Type 无效"
            }
            readBounded(connection.inputStream, connection.contentLengthLong, maximumBytes)
        } finally {
            connection.disconnect()
        }
    }

    private fun post(plan: V2PrivateControlPlan, body: ByteArray): V2ReportResponse {
        check(plan.role == "device_report" && plan.path == DEVICE_REPORT_PATH) { "[Android control] report plan 无效" }
        check(body.isNotEmpty() && body.size <= MAX_DEVICE_REPORT_BYTES) { "[Android report] envelope 大小无效" }
        val connection = connection(plan, "POST")
        return try {
            connection.doOutput = true
            connection.setFixedLengthStreamingMode(body.size)
            connection.setRequestProperty("Accept", DEVICE_REPORT_RECEIPT_MEDIA_TYPE)
            connection.setRequestProperty("Content-Type", "application/json")
            connection.outputStream.use { it.write(body) }
            val status = connection.responseCode
            verifyPeerPin(connection, plan.serverSPKIPins)
            check(connection.contentEncoding.isNullOrEmpty()) { "[Android report] private device_report 禁止压缩" }
            if (status == 204) {
                check(connection.inputStream.use { it.read() } == -1) { "[Android report] 204 携带正文" }
                V2ReportResponse(status, null)
            } else {
                check(status == 200) { "[Android report] private device_report 被拒绝（HTTP $status）" }
                check(connection.contentType?.substringBefore(';')?.trim() == DEVICE_REPORT_RECEIPT_MEDIA_TYPE) {
                    "[Android report] private receipt Content-Type 无效"
                }
                val receipt = readBounded(connection.inputStream, connection.contentLengthLong, MAX_DEVICE_REPORT_RECEIPT_BYTES)
                V2ReportResponse(status, Loomcore.androidV2ReportReceiptObservations(body, receipt))
            }
        } finally {
            connection.disconnect()
        }
    }

    private fun connection(plan: V2PrivateControlPlan, method: String): HttpsURLConnection {
        check(plan.port in 1..65535 && plan.overlayIP.isNotBlank()) { "[Android control] overlay tuple 无效" }
        val address = InetAddress.getByName(plan.overlayIP)
        check(address.hostAddress?.substringBefore('%') == plan.overlayIP) { "[Android control] overlay IP 不是 canonical literal" }
        val url = URI("https", null, plan.overlayIP, plan.port, plan.path, null, null).toURL()
        return (url.openConnection(Proxy.NO_PROXY) as HttpsURLConnection).apply {
            requestMethod = method
            instanceFollowRedirects = false
            useCaches = false
            connectTimeout = CONNECT_TIMEOUT_MS
            readTimeout = READ_TIMEOUT_MS
            sslSocketFactory = tlsSocketFactory(plan)
        }
    }

    private fun tlsSocketFactory(plan: V2PrivateControlPlan): SSLSocketFactory {
        val rootStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null)
            plan.internalCARoots.forEachIndexed { index, root -> setCertificateEntry("root-$index", root) }
        }
        val trustFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply {
            init(rootStore)
        }
        val keyManager = FixedDeviceKeyManager(keys.identityPrivateKey(), plan.clientCertificateChain)
        val context = SSLContext.getInstance("TLSv1.3").apply {
            init(arrayOf(keyManager), trustFactory.trustManagers, SecureRandom())
        }
        return TLS13SocketFactory(context.socketFactory)
    }

    private fun verifyPeerPin(connection: HttpsURLConnection, pins: Set<String>) {
        val leaf = connection.serverCertificates.firstOrNull() as? X509Certificate
            ?: error("[Android control] private service 缺 X.509 leaf")
        val digest = MessageDigest.getInstance("SHA-256").digest(leaf.publicKey.encoded)
        val pin = "sha256:" + digest.joinToString("") { "%02x".format(it.toInt() and 0xff) }
        check(pin in pins) { "[Android control] private service leaf SPKI 不在 certified pin set" }
    }

    private fun <T> tryEach(plans: List<V2PrivateControlPlan>, operation: (V2PrivateControlPlan) -> T): T {
        check(plans.isNotEmpty()) { "[Android control] private service plan 为空" }
        var failure: Exception? = null
        for (plan in plans) {
            try {
                return operation(plan)
            } catch (error: Exception) {
                failure?.addSuppressed(error) ?: run { failure = error }
            }
        }
        throw IllegalStateException("[Android control] 全部 certified private ${plans.first().role} 副本不可用", failure)
    }

    companion object {
        private const val DEVICE_CONFIG_PATH = "/private/v2/device/config"
        private const val DEVICE_REPORT_PATH = "/private/v2/device/report"
        private const val DEVICE_CONFIG_DELIVERY_MEDIA_TYPE =
            "application/vnd.loom.device-config-delivery.v1+json"
        private const val DEVICE_REPORT_RECEIPT_MEDIA_TYPE =
            "application/vnd.loom.device-report-receipt.v1+json"
        private const val CONNECT_TIMEOUT_MS = 15_000
        private const val READ_TIMEOUT_MS = 30_000
        private const val MAX_DEVICE_VIEW_BYTES = 32 shl 20
        private const val MAX_DEVICE_REPORT_BYTES = 4 shl 20
        private const val MAX_DEVICE_REPORT_RECEIPT_BYTES = (1 shl 20) + (16 shl 10)

        fun decodePlans(canonical: ByteArray, expectedRole: String): List<V2PrivateControlPlan> {
            val values = JSONArray(canonical.decodeToString())
            check(values.length() in 1..64)
            val factory = CertificateFactory.getInstance("X.509")
            return List(values.length()) { index -> decodePlan(values.getJSONObject(index), expectedRole, factory) }
        }

        private fun decodePlan(
            value: org.json.JSONObject,
            expectedRole: String,
            factory: CertificateFactory,
        ): V2PrivateControlPlan {
            check(value.getInt("schema") == 1 && value.getString("role") == expectedRole)
            val pins = value.getJSONArray("server_spki_pins").strings()
            val roots = decodeCertificates(value.getJSONArray("internal_ca_roots_der"), factory)
            val chain = decodeCertificates(value.getJSONArray("client_certificate_chain_der"), factory).toTypedArray()
            check(pins.isNotEmpty() && pins.distinct().size == pins.size && roots.isNotEmpty() && chain.isNotEmpty())
            return V2PrivateControlPlan(
                role = expectedRole,
                serviceID = value.getString("service_id"),
                overlayIP = value.getString("overlay_ip"),
                port = value.getInt("port"),
                path = value.getString("path"),
                certificateProfileRef = value.getString("certificate_profile_ref"),
                serverSPKIPins = pins.toSet(),
                internalCARoots = roots,
                clientCertificateChain = chain,
                identitySPKIHash = value.getString("identity_spki_hash"),
                directoryGeneration = value.getLong("directory_generation"),
                directoryHash = value.getString("directory_hash"),
            )
        }

        private fun decodeCertificates(values: JSONArray, factory: CertificateFactory): List<X509Certificate> =
            List(values.length()) { index ->
                val der = java.util.Base64.getUrlDecoder().decode(values.getString(index))
                factory.generateCertificate(der.inputStream()) as X509Certificate
            }

        private fun JSONArray.strings(): List<String> = List(length()) { index -> getString(index) }

        private fun readBounded(input: InputStream, contentLength: Long, maximumBytes: Int): ByteArray {
            check(maximumBytes > 0 && (contentLength < 0 || contentLength <= maximumBytes))
            return input.use { stream ->
                val output = ByteArrayOutputStream()
                val buffer = ByteArray(8192)
                while (true) {
                    val count = stream.read(buffer)
                    if (count < 0) break
                    check(output.size() + count <= maximumBytes) { "[Android control] private response 正文超限" }
                    output.write(buffer, 0, count)
                }
                output.toByteArray().also { check(it.isNotEmpty()) { "[Android control] private response 正文为空" } }
            }
        }
    }
}

private class FixedDeviceKeyManager(
    private val privateKey: PrivateKey,
    private val chain: Array<X509Certificate>,
) : X509ExtendedKeyManager() {
    override fun chooseClientAlias(
        keyType: Array<out String>?, issuers: Array<out Principal>?, socket: Socket?,
    ): String? = DEVICE_ALIAS.takeIf { keyType?.any { it.equals("EC", ignoreCase = true) } == true }

    override fun chooseEngineClientAlias(
        keyType: Array<out String>?, issuers: Array<out Principal>?, engine: SSLEngine?,
    ): String? = DEVICE_ALIAS.takeIf { keyType?.any { it.equals("EC", ignoreCase = true) } == true }

    override fun getClientAliases(keyType: String?, issuers: Array<out Principal>?): Array<String>? =
        arrayOf(DEVICE_ALIAS).takeIf { keyType.equals("EC", ignoreCase = true) }

    override fun getCertificateChain(alias: String?): Array<X509Certificate>? =
        chain.copyOf().takeIf { alias == DEVICE_ALIAS }

    override fun getPrivateKey(alias: String?): PrivateKey? = privateKey.takeIf { alias == DEVICE_ALIAS }
    override fun chooseServerAlias(keyType: String?, issuers: Array<out Principal>?, socket: Socket?): String? = null
    override fun chooseEngineServerAlias(
        keyType: String?, issuers: Array<out Principal>?, engine: SSLEngine?,
    ): String? = null

    override fun getServerAliases(keyType: String?, issuers: Array<out Principal>?): Array<String>? = null

    companion object {
        private const val DEVICE_ALIAS = "loom-device-identity"
    }
}

private class TLS13SocketFactory(private val delegate: SSLSocketFactory) : SSLSocketFactory() {
    override fun getDefaultCipherSuites(): Array<String> = delegate.defaultCipherSuites
    override fun getSupportedCipherSuites(): Array<String> = delegate.supportedCipherSuites
    override fun createSocket(socket: Socket, host: String, port: Int, autoClose: Boolean): Socket =
        constrain(delegate.createSocket(socket, host, port, autoClose))

    override fun createSocket(host: String, port: Int): Socket = constrain(delegate.createSocket(host, port))
    override fun createSocket(host: String, port: Int, localHost: InetAddress, localPort: Int): Socket =
        constrain(delegate.createSocket(host, port, localHost, localPort))

    override fun createSocket(host: InetAddress, port: Int): Socket = constrain(delegate.createSocket(host, port))
    override fun createSocket(
        address: InetAddress, port: Int, localAddress: InetAddress, localPort: Int,
    ): Socket = constrain(delegate.createSocket(address, port, localAddress, localPort))

    private fun constrain(socket: Socket): Socket = socket.also {
        check(it is SSLSocket)
        it.enabledProtocols = arrayOf("TLSv1.3")
    }
}
