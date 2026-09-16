package io.github.scisaga.loom.enrollment

import java.time.Instant
import org.junit.Assert.assertEquals
import org.junit.Test

class WireTimeTest {
    @Test
    fun subsecondDeviceClocksProduceCanonicalProtocolTimeWithoutRoundingForward() {
        for (input in listOf(
            "2030-01-02T03:04:05Z",
            "2030-01-02T03:04:05.123Z",
            "2030-01-02T03:04:05.999999999Z",
            "2030-01-02T11:04:05.123456+08:00",
        )) {
            assertEquals("2030-01-02T03:04:05Z", wireTime(Instant.parse(input)))
        }
    }
}
