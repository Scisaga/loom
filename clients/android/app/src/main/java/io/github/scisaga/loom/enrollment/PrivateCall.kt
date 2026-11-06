package io.github.scisaga.loom.enrollment

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/** Cancellation reaches the blocking private socket call while it is running. */
internal suspend fun <T> privateCall(run: () -> T, cancel: () -> Unit): T = withContext(Dispatchers.IO) {
    suspendCancellableCoroutine { continuation ->
        continuation.invokeOnCancellation { cancel() }
        if (!continuation.isActive) return@suspendCancellableCoroutine
        try {
            continuation.resume(run())
        } catch (error: Throwable) {
            continuation.resumeWithException(error)
        } finally {
            cancel()
        }
    }
}
