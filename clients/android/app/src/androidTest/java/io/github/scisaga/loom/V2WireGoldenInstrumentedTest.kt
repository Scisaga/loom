package io.github.scisaga.loom

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.scisaga.loomcore.Loomcore
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class V2WireGoldenInstrumentedTest {
    @Test
    fun sharedGoldenAndMaliciousVectorsUseShippedGoVerifier() {
        val assets = InstrumentationRegistry.getInstrumentation().context.assets
        val body = assets.open("wire/v2/canonical.json").use { it.readBytes() }
        Loomcore.verifyCanonicalGolden(body)
    }
}
