package io.github.scisaga.loom.route

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.security.MessageDigest

/**
 * #14：registry 的生命周期与 Application 进程相同，而不是 Service/profile/config/连接相同。
 * 只有 ConnectivityManager 确认默认 Network identity 改变才清空本代冻结候选；Service 重建只复用。
 */
internal class UnderlayProbeRegistry(
    private val scope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.IO),
) {
    internal data class DebugState(
        val generation: Long,
        val activeProbeRounds: Int,
        val frozenFingerprint: String,
    )

    private val lock = Mutex()
    private var networkIdentity: String? = null
    private var sourceInterface: String = ""
    private var generation: Long = 0
    private var frozen: Frozen? = null
    @Volatile private var debugState = DebugState(0, 0, "")

    internal data class Snapshot(
        val generation: Long,
        val entries: ByteArray,
        val reused: Boolean,
    )

    internal class PendingSnapshot internal constructor(
        val generation: Long,
        private val entries: Deferred<ByteArray>,
        private val project: (ByteArray) -> ByteArray,
        private val reused: Boolean,
    ) {
        suspend fun await(): Snapshot = Snapshot(generation, project(entries.await()), reused)
    }

    private data class Frozen(
        val source: String,
        val entries: Deferred<ByteArray>,
    )

    suspend fun observeDefaultNetwork(identity: String?, source: String): Boolean = lock.withLock {
        if (networkIdentity == identity && sourceInterface == source) return@withLock false
        networkIdentity = identity
        sourceInterface = source
        generation++
        frozen?.entries?.cancel()
        frozen = null
        debugState = DebugState(generation, 0, "")
        true
    }

    /** #15：debug receiver 只导出脱敏指纹，用于证明同代重连没有再次测量。 */
    internal fun debugState(): DebugState = debugState

    suspend fun isCurrent(expectedGeneration: Long): Boolean = lock.withLock { generation == expectedGeneration }

    /** 冻结与消耗预算不等待网络；连接与模式切换立即继续，结果由宿主异步消费。 */
    suspend fun beginEntries(
        inputs: ByteArray,
        source: String,
        measure: suspend (ByteArray, String) -> ByteArray,
        reuse: (ByteArray, ByteArray, String) -> ByteArray,
    ): PendingSnapshot = lock.withLock {
        check(source.isNotBlank()) { "当前默认 Network 尚无可绑定源接口；不会消耗本代探测预算" }
        check(source == sourceInterface) { "入口探测源接口已变化；等待 ConnectivityManager 建立新代" }
        val requestedInputs = inputs.copyOf()
        frozen?.let {
            return@withLock PendingSnapshot(generation, it.entries,
                { measured -> reuse(requestedInputs, measured.copyOf(), it.source) }, reused = true)
        }
        val measuredGeneration = generation
        // Deferred 属于 Application，不属于等待结果的 profile/连接。失败结果同样
        // 保留在冻结槽中，取消等待或重连都不能重新获得主动探测预算。
        debugState = DebugState(generation, 1, "")
        val measured = scope.async {
            val result = measure(requestedInputs, source).copyOf()
            val fingerprint = MessageDigest.getInstance("SHA-256").digest(result)
                .joinToString("") { "%02x".format(it.toInt() and 0xff) }
            lock.withLock {
                if (generation == measuredGeneration) debugState = DebugState(generation, 1, fingerprint)
            }
            result
        }
        frozen = Frozen(source, measured)
        PendingSnapshot(generation, measured, { it.copyOf() }, reused = false)
    }
}
