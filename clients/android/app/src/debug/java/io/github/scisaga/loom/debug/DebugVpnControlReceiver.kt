package io.github.scisaga.loom.debug

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import androidx.core.content.ContextCompat
import io.github.scisaga.loom.BuildConfig
import io.github.scisaga.loom.vpn.LoomVpnService

/** ADB-only control surface for physical-device data-plane acceptance. */
class DebugVpnControlReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        check(BuildConfig.DEBUG) { "debug VPN control is unavailable in release builds" }
        val serviceAction = when (intent.action) {
            ACTION_CONNECT -> LoomVpnService.ACTION_CONNECT
            ACTION_DISCONNECT -> LoomVpnService.ACTION_DISCONNECT
            else -> return
        }
        ContextCompat.startForegroundService(
            context,
            Intent(context, LoomVpnService::class.java).setAction(serviceAction),
        )
    }

    companion object {
        const val ACTION_CONNECT = "io.github.scisaga.loom.debug.CONNECT"
        const val ACTION_DISCONNECT = "io.github.scisaga.loom.debug.DISCONNECT"
    }
}
