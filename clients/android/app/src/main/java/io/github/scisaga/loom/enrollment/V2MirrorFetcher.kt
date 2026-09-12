package io.github.scisaga.loom.enrollment

import android.content.Context
import io.github.scisaga.loomcore.Loomcore
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.CookieHandler
import java.net.Proxy
import java.net.URL
import java.security.MessageDigest
import java.security.cert.X509Certificate
import javax.net.ssl.HttpsURLConnection

internal data class V2PublicArtifacts(
    val proofBundle: ByteArray,
    val bootstrapCatalog: ByteArray,
)

private data class V2Mirror(
    val endpointID: String,
    val baseURL: String,
    val pins: Set<String>,
    val hintRank: Long,
)

/** #14：公开 mirror 只收到 descriptor 中的 content-addressed GET，绝不收 token/cookie。 */
internal class V2MirrorFetcher(context: Context) {
    private val appContext = context.applicationContext

    fun fetch(descriptor: ByteArray, trustedTime: String): V2PublicArtifacts {
        val plan = JSONObject(Loomcore.prepareAndroidV2MirrorFetchPlan(descriptor, trustedTime).decodeToString())
        check(plan.getInt("schema") == 1) { "v2 mirror plan schema 无效" }
        val mirrors = parseMirrors(plan)
        val proof = fetchObject(mirrors, plan.getString("proof_hash"), PROOF_LIMIT) {
            Loomcore.verifyAndroidV2InviteProof(descriptor, it, trustedTime)
        }
        val catalog = fetchObject(mirrors, plan.getString("catalog_hash"), CATALOG_LIMIT) {
            Loomcore.verifyAndroidV2BootstrapCatalog(descriptor, proof, it, trustedTime, CLIENT_PROTOCOL)
        }
        return V2PublicArtifacts(proof.copyOf(), catalog.copyOf())
    }

    /** D130：resume mirror 请求仍只携带 content hash；APK root 验签发生在返回前。 */
    fun fetchResume(
        descriptor: ByteArray,
        pinnedPlatformKey: ByteArray,
        trustedTime: String,
    ): V2PublicArtifacts {
        val plan = JSONObject(
            Loomcore.prepareAndroidV2ResumeMirrorFetchPlan(descriptor, trustedTime).decodeToString(),
        )
        check(plan.getInt("schema") == 1) { "v2 resume mirror plan schema 无效" }
        val mirrors = parseMirrors(plan)
        val proof = fetchObject(mirrors, plan.getString("proof_hash"), PROOF_LIMIT) {
            Loomcore.verifyAndroidV2ResumeInviteProof(
                descriptor,
                it,
                pinnedPlatformKey,
                trustedTime,
            )
        }
        val catalog = fetchObject(mirrors, plan.getString("catalog_hash"), CATALOG_LIMIT) {
            Loomcore.verifyAndroidV2ResumeBootstrapCatalog(
                descriptor,
                proof,
                it,
                pinnedPlatformKey,
                trustedTime,
                CLIENT_PROTOCOL,
            )
        }
        return V2PublicArtifacts(proof.copyOf(), catalog.copyOf())
    }

    private fun parseMirrors(plan: JSONObject): List<V2Mirror> =
        plan.getJSONArray("mirrors").let { values ->
            (0 until values.length()).map { index ->
                val item = values.getJSONObject(index)
                V2Mirror(
                    endpointID = item.getString("endpoint_id"),
                    baseURL = item.getString("base_url"),
                    pins = item.getJSONArray("spki_pins").let { pins ->
                        (0 until pins.length()).map(pins::getString).toSet()
                    },
                    hintRank = item.getLong("hint_rank"),
                )
            }.sortedWith(compareBy(V2Mirror::hintRank, V2Mirror::endpointID))
        }

    private fun fetchObject(
        mirrors: List<V2Mirror>,
        expectedHash: String,
        maximum: Int,
        verify: (ByteArray) -> Unit,
    ): ByteArray {
        check(CookieHandler.getDefault() == null) { "v2 public mirror 路径禁止全局 CookieHandler" }
        check(expectedHash.startsWith("sha256:") && expectedHash.length == 71) { "v2 mirror object hash 无效" }
        val digest = expectedHash.removePrefix("sha256:")
        check(digest.all { it in '0'..'9' || it in 'a'..'f' }) { "v2 mirror digest 不规范" }
        val networks = HttpTransport.underlyingNetworks(appContext)
        check(networks.isNotEmpty()) { "没有可绑定的已验证底层 Network" }
        var lastFailure: Throwable? = null
        mirrors.forEach { mirror ->
            networks.forEach { network ->
                try {
                    val expectedURL = mirror.baseURL + digest
                    val body = requestObject(
                        network.openConnection(URL(expectedURL), Proxy.NO_PROXY) as HttpsURLConnection,
                        expectedURL,
                        mirror,
                        maximum,
                    )
                    verify(body)
                    return body
                } catch (failure: Exception) {
                    lastFailure = failure
                }
            }
        }
        throw IllegalStateException("所有认证 mirror/underlay 都未返回指定制品", lastFailure)
    }

    private fun requestObject(
        connection: HttpsURLConnection,
        expectedURL: String,
        mirror: V2Mirror,
        maximum: Int,
    ): ByteArray {
        try {
            connection.instanceFollowRedirects = false
            connection.useCaches = false
            connection.connectTimeout = CONNECT_TIMEOUT_MS
            connection.readTimeout = READ_TIMEOUT_MS
            connection.requestMethod = "GET"
            connection.setRequestProperty("Accept", "application/octet-stream")
            connection.setRequestProperty("Accept-Encoding", "identity")
            connection.setRequestProperty("User-Agent", "Loom-Android/0.3")
            val status = connection.responseCode
            val leaf = connection.serverCertificates.firstOrNull() as? X509Certificate
                ?: throw IOException("mirror TLS 没有 leaf certificate")
            val pin = "sha256:" + MessageDigest.getInstance("SHA-256")
                .digest(leaf.publicKey.encoded)
                .joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }
            if (pin !in mirror.pins) throw IOException("mirror SPKI pin 不匹配")
            if (status != 200 || connection.url.toString() != expectedURL) {
                throw IOException("mirror 响应状态无效: HTTP $status")
            }
            if (connection.headerFields.keys.filterNotNull().any { it.equals("set-cookie", ignoreCase = true) }) {
                throw IOException("mirror 响应禁止 Set-Cookie")
            }
            if (!connection.contentEncoding.isNullOrBlank() &&
                !connection.contentEncoding.equals("identity", ignoreCase = true)
            ) {
                throw IOException("mirror 响应禁止内容压缩")
            }
            if (connection.contentLengthLong > maximum) throw IOException("mirror 制品超过大小边界")
            return connection.inputStream.use { input ->
                val output = ByteArrayOutputStream(minOf(maximum, 16 * 1024))
                val buffer = ByteArray(8 * 1024)
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    if (output.size() + count > maximum) throw IOException("mirror 制品超过大小边界")
                    output.write(buffer, 0, count)
                }
                output.toByteArray()
            }
        } finally {
            connection.disconnect()
        }
    }

    private companion object {
        const val CLIENT_PROTOCOL = 2L
        const val PROOF_LIMIT = 16 * 1024 * 1024
        const val CATALOG_LIMIT = 16 * 1024 * 1024
        const val CONNECT_TIMEOUT_MS = 10_000
        const val READ_TIMEOUT_MS = 20_000
    }
}
