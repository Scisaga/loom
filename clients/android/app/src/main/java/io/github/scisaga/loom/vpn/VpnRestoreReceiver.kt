package io.github.scisaga.loom.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import androidx.core.content.ContextCompat

/** §8.3：首次解锁后的开机广播和覆盖升级只恢复用户此前保持的连接。 */
class VpnRestoreReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val desired = VpnConnectionPreference(context).desiredConnected()
        val prepared = VpnService.prepare(context) == null
        if (!shouldRestoreVpn(intent.action, desired, prepared)) return
        ContextCompat.startForegroundService(
            context,
            Intent(context, LoomVpnService::class.java).setAction(LoomVpnService.ACTION_CONNECT),
        )
    }
}

internal fun shouldRestoreVpn(action: String?, desiredConnected: Boolean, vpnPrepared: Boolean): Boolean =
    action in setOf(Intent.ACTION_BOOT_COMPLETED, Intent.ACTION_MY_PACKAGE_REPLACED) &&
        desiredConnected && vpnPrepared
