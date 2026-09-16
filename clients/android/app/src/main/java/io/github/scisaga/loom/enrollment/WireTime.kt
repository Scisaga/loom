package io.github.scisaga.loom.enrollment

import java.time.Instant
import java.time.temporal.ChronoUnit

/** v2 verifier 要求秒精度的 UTC Z；Instant.toString() 默认会保留小数秒。 */
internal fun wireTime(instant: Instant = Instant.now()): String =
    instant.truncatedTo(ChronoUnit.SECONDS).toString()
