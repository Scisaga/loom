package io.github.scisaga.loom.debug

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import androidx.core.content.ContextCompat
import io.github.scisaga.loom.BuildConfig
import io.github.scisaga.loom.enrollment.EnrollmentManager
import io.github.scisaga.loom.readBounded
import io.github.scisaga.loom.vpn.LoomVpnService
import java.io.File

/** ADB-only control surface for physical-device data-plane acceptance. */
class DebugVpnControlReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        check(BuildConfig.DEBUG) { "debug VPN control is unavailable in release builds" }
        if (intent.action == ACTION_IMPORT_INVITE) {
            importPendingInvite(context)
            return
        }
        if (intent.action == ACTION_RETRY_ENROLLMENT) {
            EnrollmentManager.get(context).retry()
            return
        }
        if (intent.action == ACTION_ABANDON_PENDING) {
            EnrollmentManager.get(context).abandonPending()
            return
        }
        if (intent.action == ACTION_ENROLLMENT_STATUS) {
            val status = EnrollmentManager.get(context).status.value
            resultData = buildString {
                append("phase=").append(status.phase.name)
                append(";abandonable=").append(status.canAbandonPending)
                append(";snapshot=").append(status.snapshot.isNotEmpty())
                append(";generation=").append(status.generation)
                append(";diagnostic=").append(status.diagnostic.ifEmpty { "none" })
            }
            return
        }
        val serviceAction = when (intent.action) {
            ACTION_CONNECT -> LoomVpnService.ACTION_CONNECT
            ACTION_ENROLLMENT_KEEPALIVE -> LoomVpnService.ACTION_ENROLLMENT_KEEPALIVE
            ACTION_DISCONNECT -> LoomVpnService.ACTION_DISCONNECT
            else -> return
        }
        ContextCompat.startForegroundService(
            context,
            Intent(context, LoomVpnService::class.java).setAction(serviceAction),
        )
    }

    private fun importPendingInvite(context: Context) {
        val manager = EnrollmentManager.get(context)
        var pending: File? = null
        val result = runCatching {
            pending = File(
                checkNotNull(context.getExternalFilesDir(null)) { "external app storage is unavailable" },
                PENDING_INVITE,
            )
            val file = checkNotNull(pending)
            require(file.isFile) { "pending debug invitation is missing" }
            val body = file.inputStream().use { readBounded(it, MAX_INVITE_BYTES) }
            require(body.isNotEmpty() && body.size <= MAX_INVITE_BYTES) {
                "debug invitation must be between 1 byte and 16 KiB"
            }
            val raw = body.decodeToString()
            check(file.delete()) { "cannot remove pending debug invitation" }
            raw
        }
        if (result.isFailure) pending?.delete()
        result.onSuccess(manager::importInvite).onFailure(manager::reportImportError)
    }

    companion object {
        const val ACTION_CONNECT = "io.github.scisaga.loom.debug.CONNECT"
        const val ACTION_ENROLLMENT_KEEPALIVE = "io.github.scisaga.loom.debug.ENROLLMENT_KEEPALIVE"
        const val ACTION_DISCONNECT = "io.github.scisaga.loom.debug.DISCONNECT"
        const val ACTION_IMPORT_INVITE = "io.github.scisaga.loom.debug.IMPORT_INVITE"
        const val ACTION_RETRY_ENROLLMENT = "io.github.scisaga.loom.debug.RETRY_ENROLLMENT"
        const val ACTION_ABANDON_PENDING = "io.github.scisaga.loom.debug.ABANDON_PENDING"
        const val ACTION_ENROLLMENT_STATUS = "io.github.scisaga.loom.debug.ENROLLMENT_STATUS"
        private const val PENDING_INVITE = "pending.loom-invite"
        private const val MAX_INVITE_BYTES = 16 * 1024
    }
}
