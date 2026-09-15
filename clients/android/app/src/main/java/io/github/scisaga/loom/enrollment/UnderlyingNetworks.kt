package io.github.scisaga.loom.enrollment

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build

/** 只选择底层网络；公开传输由静态镜像 reader 负责，控制请求只走私有 v2。 */
internal object UnderlyingNetworks {
    fun available(context: Context): List<Network> {
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

}
