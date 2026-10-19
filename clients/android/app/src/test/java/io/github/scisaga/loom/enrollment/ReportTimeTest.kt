package io.github.scisaga.loom.enrollment

import java.time.Instant
import org.junit.Assert.assertEquals
import org.junit.Test

class ReportTimeTest {
    @Test
    fun bridgeUsesFixedUtcMillisecondsWithoutRoundingOrTrimming() {
        listOf(
            "2030-01-01T00:00:00Z" to "2030-01-01T00:00:00.000Z",
            "2030-01-01T00:00:00.120Z" to "2030-01-01T00:00:00.120Z",
            "2030-01-01T00:00:00.123999999Z" to "2030-01-01T00:00:00.123Z",
            "2030-01-01T00:00:00.999999999Z" to "2030-01-01T00:00:00.999Z",
        ).forEach { (input, expected) ->
            val instant = Instant.parse(input)
            val encoded = reportTimestamp(instant)
            assertEquals(expected, encoded)
            assertEquals(instant.toEpochMilli(), Instant.parse(encoded).toEpochMilli())
        }
    }
}
