package io.github.scisaga.loom.vpn

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.Closeable
import io.github.scisaga.loomcore.Loomcore
import org.json.JSONObject

data class ProbeResult(
    val dns: String,
    val https: String,
    val target: String,
    val metricMillis: Long,
) {
    val healthy: Boolean get() = https.startsWith("成功")
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

/** Runs the original domain through the authenticated candidate entry. */
object NetworkProbe {
    suspend fun run(state: ByteArray, candidate: String, httpsTarget: String, session: ProbeSession = ProbeSession()): ProbeResult =
        withContext(Dispatchers.IO) {
            val request = Loomcore.newAndroidBusinessRequest(state, candidate, httpsTarget)
            val cancellation = Closeable { request.cancel() }
            check(session.attach(cancellation)) { "探测已取消" }
            try {
                val result = JSONObject(request.run().decodeToString())
                if (session.isCancelled()) throw CancellationException("网络探测已取消")
                ProbeResult(
                    dns = "由当前访问路径解析（未单独测量）",
                    https = if (result.getBoolean("available")) "成功（HTTPS 实际响应）" else "失败：${result.getString("description")}",
                    target = httpsTarget,
                    metricMillis = result.getLong("metric_millis"),
                )
            } finally {
                request.cancel()
                session.detach(cancellation)
            }
        }
}
