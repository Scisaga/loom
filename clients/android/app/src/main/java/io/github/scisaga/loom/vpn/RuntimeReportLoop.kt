package io.github.scisaga.loom.vpn

import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withTimeoutOrNull

/** The existing session report worker has one coalesced pending notification. */
internal suspend fun runtimeReportLoop(
    wakeups: Channel<Unit>, intervalMillis: Long, minimumIntervalMillis: Long, elapsedMillis: () -> Long,
    current: () -> Boolean, send: suspend () -> Unit,
) {
    require(intervalMillis > 0 && minimumIntervalMillis > 0)
    var lastSendStarted: Long? = null
    while (currentCoroutineContext().isActive && current()) {
        wakeups.tryReceive()
        lastSendStarted?.let { last ->
            val remaining = minimumIntervalMillis - (elapsedMillis() - last)
            if (remaining > 0) delay(remaining)
        }
        if (!currentCoroutineContext().isActive || !current()) break
        // Notifications received while waiting are included in the snapshot
        // captured by send(), not another URL-specific report request.
        wakeups.tryReceive()
        lastSendStarted = elapsedMillis()
        send()
        if (!current()) break
        withTimeoutOrNull(intervalMillis) { wakeups.receive() }
    }
}
