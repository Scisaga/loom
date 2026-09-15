package io.github.scisaga.loom.route

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class IcmpEchoReplyTest {
    @Test
    fun readsTheReplyInsteadOfProcessOrSummaryTime() {
        val output = """
            PING demo-entry (192.0.2.1) 56(84) bytes of data.
            64 bytes from 192.0.2.1: icmp_seq=1 ttl=57 time=12.7 ms

            --- demo-entry ping statistics ---
            1 packets transmitted, 1 received, 0% packet loss, time 900ms
            rtt min/avg/max/mdev = 12.700/12.700/12.700/0.000 ms
        """.trimIndent()
        assertEquals(13L, icmpEchoReplyMillis(output))
        assertEquals(0L, icmpEchoReplyMillis("64 bytes from 2001:db8::1: icmp_seq=0 hlim=64 time=0.123 ms"))
    }

    @Test
    fun missingInexactOrAmbiguousRepliesStayUnknown() {
        listOf(
            "1 packets transmitted, 0 received, 100% packet loss, time 1000ms",
            "rtt min/avg/max/mdev = 12.700/12.700/12.700/0.000 ms",
            "64 bytes from 192.0.2.1: icmp_seq=1 ttl=57 time<1 ms",
            "64 bytes from 192.0.2.1: icmp_seq=1 ttl=57 time=NaN ms",
            "64 bytes from 192.0.2.1: icmp_seq=1 ttl=57 time=-1 ms",
            "64 bytes from 192.0.2.1: icmp_seq=1 ttl=57 time=999999999999999999999999999999999 ms",
            "time=12.7 ms",
            "From 192.0.2.1 icmp_seq=1 Destination Host Unreachable",
            "64 bytes from 192.0.2.1: icmp_seq=1 ttl=57 time=1 ms\n" +
                "64 bytes from 192.0.2.1: icmp_seq=2 ttl=57 time=2 ms",
        ).forEach { assertNull(it, icmpEchoReplyMillis(it)) }
    }
}
