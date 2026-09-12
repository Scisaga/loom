package io.github.scisaga.loom.vpn

import android.net.Network
import android.os.ParcelFileDescriptor
import io.github.scisaga.loomcore.AndroidBootstrapNetwork
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first

/**
 * #14：Go core 拥有 HY2/Trojan wire，Android 宿主只提供冻结 underlay 的
 * DNS、protect/bind 与加密 attempt journal callback。
 */
internal class AndroidBootstrapNetworkController(
    private val service: LoomVpnService,
    private val network: Network,
    private val recordAttempt: (String, Long) -> Unit,
) : AndroidBootstrapNetwork {
    override fun protectAndBindSocket(fd: Long) {
        require(fd in 0..Int.MAX_VALUE.toLong()) { "bootstrap socket fd 无效" }
        val descriptor = fd.toInt()
        check(service.protect(descriptor)) { "[D131 Android] VpnService.protect bootstrap socket 失败" }
        // fromFd 复制 descriptor；关闭副本不会夺走 Go net.Conn 的所有权。
        ParcelFileDescriptor.fromFd(descriptor).use { duplicate ->
            network.bindSocket(duplicate.fileDescriptor)
        }
    }

    override fun resolveHost(host: String): String {
        require(host.matches(Regex("[A-Za-z0-9.-]{1,253}"))) { "[D131 Android] bootstrap FQDN 无效" }
        val addresses = network.getAllByName(host)
            .mapNotNull { it.hostAddress?.substringBefore('%') }
            .distinct()
            .sorted()
        check(addresses.isNotEmpty()) { "[D131 Android] frozen underlay DNS 没有返回地址" }
        return addresses.joinToString("\n")
    }

    override fun recordConnectionAttempt(capabilityID: String, attempt: Long) {
        recordAttempt(capabilityID, attempt)
    }

    override fun underlayIdentity(): String = "network-handle:${network.networkHandle}"
}

/** 只保存同进程 Service 引用；任何 token/capability 都不进入这个 rendezvous。 */
internal object BootstrapServiceRegistry {
    private val active = MutableStateFlow<LoomVpnService?>(null)

    fun attach(service: LoomVpnService) {
        active.value = service
    }

    fun detach(service: LoomVpnService) {
        if (active.value === service) active.value = null
    }

    suspend fun await(): LoomVpnService = active.filterNotNull().first()
}
