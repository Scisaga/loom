package io.github.scisaga.loom.route

import android.os.SystemClock
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.TimeUnit

private data class EntryTarget(val node: String, val address: String)
private data class EntryProbeValue(val rttMS: Long?, val error: String?)

/**
 * §16.1.2：在当前物理接口上对每个签名入口地址只发一个 ICMP echo。
 * ProcessBuilder 不经过 shell；Go 核心会按签名数据面复核每个 node/address。
 */
internal object AndroidEntryProbe {
    suspend fun measure(routingInputs: ByteArray, source: String): ByteArray = coroutineScope {
        val root = JSONObject(routingInputs.decodeToString())
        check(root.getInt("schema") == 1) { "入口探测输入 schema 无效" }
        val targets = root.getJSONArray("entries").objects().map {
            EntryTarget(node = it.getString("node"), address = it.getString("address"))
        }
        check(targets.map(EntryTarget::node).distinct().size == targets.size) { "入口探测输入含重复节点" }
        val semaphore = Semaphore(MAX_PARALLEL_PROBES)
        val byAddress = targets.groupBy(EntryTarget::address)
        val values = byAddress.toSortedMap().map { (address, _) ->
            async(Dispatchers.IO) { address to semaphore.withPermit { pingOnce(address, source) } }
        }.awaitAll().toMap()
        val timestamp = java.time.Instant.now().toString()
        JSONObject()
            .put("schema", 1)
            .apply { if (source.isNotBlank()) put("source", source) }
            .put(
                "measurements",
                JSONArray().apply {
                    targets.sortedBy(EntryTarget::node).forEach { target ->
                        val value = checkNotNull(values[target.address])
                        put(
                            JSONObject()
                                .put("node", target.node)
                                .put("address", target.address)
                                .put("ts", timestamp)
                                .apply {
                                    value.rttMS?.let { put("rtt_ms", it) }
                                    value.error?.let { put("error", it) }
                                },
                        )
                    }
                },
            )
            .toString()
            .encodeToByteArray()
    }

    private fun pingOnce(address: String, source: String): EntryProbeValue {
        if (source.isBlank()) return EntryProbeValue(null, "没有可绑定的底层网络")
        check(source.length <= 128 && source.none { it == '\r' || it == '\n' || it == '\u0000' }) {
            "底层网络接口名无效"
        }
        val arguments = buildList {
            add(PING)
            if (address.contains(':')) add("-6")
            addAll(listOf("-n", "-c", "1", "-W", "1", "-I", source, address))
        }
        var process: Process? = null
        return try {
            val started = SystemClock.elapsedRealtimeNanos()
            process = ProcessBuilder(arguments).redirectErrorStream(true).start()
            if (!process.waitFor(PROCESS_TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
                process.destroyForcibly()
                EntryProbeValue(null, "入口 ping 超时")
            } else if (process.exitValue() != 0) {
                EntryProbeValue(null, "入口 ping 未获响应")
            } else {
                val elapsed = (SystemClock.elapsedRealtimeNanos() - started) / 1_000_000L
                EntryProbeValue(elapsed.coerceAtLeast(0L), null)
            }
        } catch (cancelled: CancellationException) {
            process?.destroyForcibly()
            throw cancelled
        } catch (_: Throwable) {
            process?.destroyForcibly()
            EntryProbeValue(null, "入口 ping 不可用")
        }
    }

    private fun JSONArray.objects(): List<JSONObject> = (0 until length()).map(::getJSONObject)

    private const val MAX_PARALLEL_PROBES = 4
    private const val PROCESS_TIMEOUT_MS = 1_500L
    private const val PING = "/system/bin/ping"
}
