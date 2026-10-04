package io.github.scisaga.loom.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class NetworkProbeTest {
    @Test
    fun certifiedResolverMustBeAnAddressNotAHostLookup() {
        assertEquals("192.0.2.53", probeDNSAddress("192.0.2.53").hostAddress)
        assertThrows(IllegalArgumentException::class.java) { probeDNSAddress("resolver.example") }
        assertThrows(IllegalArgumentException::class.java) { probeDNSAddress("192.0.2.053") }
    }

    @Test
    fun dnsAnswerMustMatchActualQueryAndContainACompleteAddress() {
        val query = probeDNSQuery("web.example", 1, 0x1234)
        val response = query.copyOf().apply {
            this[2] = 0x81.toByte()
            this[3] = 0x80.toByte()
            this[7] = 1
        } + byteArrayOf(0xc0.toByte(), 12, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 192.toByte(), 0, 2, 8)
        assertEquals("192.0.2.8", decodeProbeDNS(query, response, 1).single().hostAddress)
        assertThrows(IllegalStateException::class.java) {
            decodeProbeDNS(query, response.copyOf().apply { this[0] = 0 }, 1)
        }
        assertThrows(IllegalStateException::class.java) { decodeProbeDNS(query, response.dropLast(1).toByteArray(), 1) }
        assertThrows(IllegalStateException::class.java) {
            decodeProbeDNS(query, response.copyOf().apply { this[2] = 0x83.toByte() }, 1)
        }
        assertThrows(IllegalStateException::class.java) {
            decodeProbeDNS(query, response.copyOf().apply { this[13] = 'x'.code.toByte() }, 1)
        }
    }

    @Test
    fun realHttpStatusIsRequiredAndResponseReadingIsBounded() {
        assertEquals(204, readHTTPStatus("HTTP/1.1 204 No Content\r\n".byteInputStream()))
        assertEquals(503, readHTTPStatus("HTTP/1.1 503 Unavailable\r\n".byteInputStream()))
        assertThrows(IllegalStateException::class.java) { readHTTPStatus("".byteInputStream()) }
        assertThrows(IllegalStateException::class.java) { readHTTPStatus("x".repeat(4096).byteInputStream()) }
    }
}
