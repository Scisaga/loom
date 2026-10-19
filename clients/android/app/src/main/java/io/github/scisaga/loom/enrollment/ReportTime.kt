package io.github.scisaga.loom.enrollment

import java.time.Instant
import java.time.format.DateTimeFormatterBuilder
import java.util.Locale

private val reportTimeFormatter = DateTimeFormatterBuilder().appendInstant(3).toFormatter(Locale.ROOT)

internal fun reportTimestamp(at: Instant): String = reportTimeFormatter.format(at)
