package io.github.scisaga.loom.security

import java.util.Base64
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class TrustAnchorTest {
    private val pinned = ByteArray(32) { it.toByte() }
    private val encoded = Base64.getEncoder().encodeToString(pinned)

    @Test
    fun matchingBootstrapReturnsAPKKey() {
        assertArrayEquals(pinned, matchBootstrapPlatformKey(pinned, encoded))
    }

    @Test
    fun differentBootstrapKeyIsRejected() {
        val other = pinned.copyOf().also { it[0] = 99 }
        assertThrows(IllegalStateException::class.java) {
            matchBootstrapPlatformKey(pinned, Base64.getEncoder().encodeToString(other))
        }
    }

    @Test
    fun nonCanonicalBootstrapEncodingIsRejected() {
        assertThrows(IllegalStateException::class.java) {
            matchBootstrapPlatformKey(pinned, encoded.trimEnd('='))
        }
        assertThrows(IllegalStateException::class.java) {
            matchBootstrapPlatformKey(pinned, "$encoded\n")
        }
    }
}
