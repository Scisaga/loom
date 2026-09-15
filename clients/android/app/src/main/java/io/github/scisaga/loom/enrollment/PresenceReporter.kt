package io.github.scisaga.loom.enrollment

import io.github.scisaga.loom.profiles.ProfileContext
import android.content.Context
import io.github.scisaga.loom.security.DeviceKeyStore
import io.github.scisaga.loomcore.Loomcore
import java.time.Instant

/** 在线心跳独立于完整健康报告，正文只能有 node、ts、signature。 */
internal class PresenceReporter(
    private val context: Context,
    private val keys: DeviceKeyStore = DeviceKeyStore(ProfileContext.keySuffix(context)),
) {
    fun send(profile: ManagedProfile): Int {
        check(profile.protocol == 1) { "[在线心跳] v1 入口拒绝其他协议" }
        val timestamp = Instant.now().toString()
        val message = Loomcore.preparePresenceHeartbeat(profile.nodeID, timestamp)
        val publicKey = keys.ensureIdentity()
        val body = Loomcore.assemblePresenceHeartbeat(
            profile.nodeID,
            timestamp,
            publicKey,
            keys.sign(message),
        )
        check(body.size <= 1024) { "[在线心跳] 三字段正文超过 1 KiB" }
        val result = HttpTransport.postPresence(context, profile.reportEndpoint, body)
        check(result.status == 204) { "[在线心跳] 服务端未接受（HTTP ${result.status}）" }
        check(result.body.isEmpty()) { "[在线心跳] 204 携带了意外正文" }
        return result.status
    }
}
