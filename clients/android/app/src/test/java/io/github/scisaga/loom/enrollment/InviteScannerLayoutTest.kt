package io.github.scisaga.loom.enrollment

import androidx.compose.ui.unit.dp
import org.junit.Assert.assertEquals
import org.junit.Test

class InviteScannerLayoutTest {
    @Test
    fun phoneViewportUsesAllAvailableWidth() {
        assertEquals(348.dp, scannerViewportEdge(348.dp))
    }

    @Test
    fun wideScreenViewportIsCappedAtReadableSquare() {
        assertEquals(420.dp, scannerViewportEdge(680.dp))
    }
}
