package io.github.scisaga.loom

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.github.scisaga.libbox.Libbox
import io.github.scisaga.loom.stage1.Stage1Config
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Stage1ConfigInstrumentedTest {
    @Test
    fun bundledConfigIsSignedAndAcceptedByPinnedLibbox() {
        val context = ApplicationProvider.getApplicationContext<LoomApplication>()
        assertTrue(Stage1Config.load(context).content.contains("\"type\": \"tun\""))
        assertEquals("1.11.4", Libbox.version())
    }
}
