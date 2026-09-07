package io.github.scisaga.loom

import java.io.ByteArrayInputStream
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class InviteReadTest {
    @Test
    fun boundedReaderAcceptsExactLimit() {
        val input = ByteArray(16 * 1024) { (it and 0xff).toByte() }
        assertArrayEquals(input, readBounded(ByteArrayInputStream(input), input.size))
    }

    @Test
    fun boundedReaderRejectsOneExtraByte() {
        val input = ByteArray(16 * 1024 + 1)
        assertThrows(IllegalArgumentException::class.java) {
            readBounded(ByteArrayInputStream(input), 16 * 1024)
        }
    }
}
