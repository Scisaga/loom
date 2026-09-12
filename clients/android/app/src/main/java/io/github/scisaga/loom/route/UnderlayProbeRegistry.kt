package io.github.scisaga.loom.route

import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.security.MessageDigest

/**
 * #14：registry 的生命周期与 Application 进程相同，而不是 Service/profile/config/连接相同。
 * 只有 ConnectivityManager 确认默认 Network identity 改变才清空本代冻结候选；Service 重建只复用。
 */
internal class UnderlayProbeRegistry {
    internal data class DebugState(
        val generation: Long,
        val frozenFingerprint: String,
    )

    private val lock = Mutex()
    private var networkIdentity: String? = null
    private var sourceInterface: String = ""
    private var generation: Long = 0
    private var frozen: Frozen? = null
    @Volatile private var debugState = DebugState(0, "")

    internal data class Snapshot(
        val generation: Long,
        val entries: ByteArray,
        val reused: Boolean,
    )

    private data class Frozen(
        val source: String,
        val entries: ByteArray,
    )

    suspend fun observeDefaultNetwork(identity: String?, source: String): Boolean = lock.withLock {
        if (networkIdentity == identity && sourceInterface == source) return@withLock false
        networkIdentity = identity
        sourceInterface = source
        generation++
        frozen = null
        debugState = DebugState(generation, "")
        true
    }

    /** #15：debug receiver 只导出脱敏指纹，用于证明同代重连没有再次测量。 */
    internal fun debugState(): DebugState = debugState

    suspend fun entriesIfEnabled(
        enabled: Boolean,
        inputs: ByteArray,
        source: String,
        measure: suspend (ByteArray, String) -> ByteArray,
        reuse: (ByteArray, ByteArray, String) -> ByteArray,
    ): Snapshot? {
        if (!enabled || source.isBlank()) return null
        return entries(inputs, source, measure, reuse)
    }

    suspend fun entries(
        inputs: ByteArray,
        source: String,
        measure: suspend (ByteArray, String) -> ByteArray,
        reuse: (ByteArray, ByteArray, String) -> ByteArray,
    ): Snapshot = withContext(NonCancellable) {
        lock.withLock {
            check(source.isNotBlank()) { "当前默认 Network 尚无可绑定源接口；不会消耗本代探测预算" }
            check(source == sourceInterface) { "入口探测源接口已变化；等待 ConnectivityManager 建立新代" }
            frozen?.let {
                return@withLock Snapshot(generation, reuse(inputs, it.entries, it.source), reused = true)
            }
            // 取消 profile/config/reconnect job 不能让同一代再次发主动 probe；本轮最多
            // 1.5 秒且继续到 exact 结果落入 process-lifetime registry。
            val measured = measure(inputs, source)
            frozen = Frozen(source, measured.copyOf())
            debugState = DebugState(
                generation,
                MessageDigest.getInstance("SHA-256").digest(measured)
                    .joinToString("") { "%02x".format(it.toInt() and 0xff) },
            )
            Snapshot(generation, measured, reused = false)
        }
    }
}
