package io.github.scisaga.loom.enrollment

import java.io.IOException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.net.ProtocolException
import java.net.SocketException
import javax.net.ssl.SSLHandshakeException
import org.junit.Assert.assertEquals
import org.junit.Test

class EnrollmentDiagnosticTest {
    @Test
    fun `classifies nested network causes without returning messages`() {
        assertEquals("dns", networkFailureKind(IllegalStateException("outer", UnknownHostException("private host"))))
        assertEquals("tls", networkFailureKind(IOException("outer", SSLHandshakeException("certificate detail"))))
        assertEquals("timeout", networkFailureKind(IOException("outer", SocketTimeoutException("address detail"))))
    }

    @Test
    fun `uses bounded categories for unrecognized failures`() {
        assertEquals("io", networkFailureKind(IOException("private detail")))
        assertEquals("protocol", networkFailureKind(ProtocolException("private detail")))
        assertEquals("socket-reset", networkFailureKind(SocketException("Connection reset by peer at private address")))
        assertEquals("unexpected", networkFailureKind(IllegalArgumentException("private detail")))
    }
}
