package io.github.scisaga.loom.vpn

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow

enum class ConnectionPhase { DISCONNECTED, STARTING, CONNECTED, STOPPING, ERROR }

data class VpnStatus(
    val phase: ConnectionPhase = ConnectionPhase.DISCONNECTED,
    val detail: String = "未连接",
    val dnsProbe: String = "未检查",
    val httpsProbe: String = "未检查",
    val trustedReport: String = "未上报",
    val alwaysOn: Boolean = false,
)

object VpnRuntime {
    private val mutable = MutableStateFlow(VpnStatus())
    val status = mutable.asStateFlow()

    fun update(value: VpnStatus) {
        mutable.value = value
    }

    fun transform(block: (VpnStatus) -> VpnStatus) {
        mutable.value = block(mutable.value)
    }
}
