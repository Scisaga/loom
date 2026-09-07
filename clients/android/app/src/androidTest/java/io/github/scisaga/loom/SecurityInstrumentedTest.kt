package io.github.scisaga.loom

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.github.scisaga.loom.security.DeviceKeyStore
import io.github.scisaga.loom.security.EncryptedStore
import io.github.scisaga.loomcore.Loomcore
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class SecurityInstrumentedTest {
    @Test
    fun keystoreIdentityAndProtectedStorageRejectTamper() {
        val keys = DeviceKeyStore()
        assertTrue(keys.proveBinding().contains("non-exportable"))
        val csr = keys.createCSR("demo-android-request")
        assertTrue(csr.decodeToString().startsWith("-----BEGIN CERTIFICATE REQUEST-----"))
        assertTrue(Loomcore.version().startsWith("android-stage2"))

        val context = ApplicationProvider.getApplicationContext<LoomApplication>()
        val store = EncryptedStore(context)
        val name = "instrumented-secret"
        val secret = "fixture credential".encodeToByteArray()
        store.put(name, secret)
        assertArrayEquals(secret, store.get(name))

        val file = store.fileForTest(name)
        val tampered = file.readBytes().also { it[it.lastIndex] = (it.last() + 1).toByte() }
        file.writeBytes(tampered)
        assertNull(runCatching { store.get(name) }.getOrNull())
    }
}
