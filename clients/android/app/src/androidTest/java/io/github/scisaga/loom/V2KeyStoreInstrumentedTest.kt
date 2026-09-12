package io.github.scisaga.loom

import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.github.scisaga.loom.security.DeviceKeyStore
import io.github.scisaga.loomcore.Loomcore
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class V2KeyStoreInstrumentedTest {
    @Test
    fun identityAndWrappingKeysUseDifferentKeystoreAliasesAndProfiles() {
        val keys = DeviceKeyStore()
        val identity = keys.ensureIdentity()
        val wrapping = keys.ensureWrapping()
        assertFalse(identity.contentEquals(wrapping.subjectPublicKeyInfo))
        assertFalse(keys.wrappingHasSigningPurpose())
        assertTrue(keys.proveBinding().contains("non-exportable"))
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            assertTrue(wrapping.profile == "p256-keystore-ecdh-v1")
        } else {
            assertTrue(wrapping.profile == "rsa2048-keystore-decrypt-v1")
        }
    }

    @Test
    fun identitySignatureStillVerifiesAfterWrappingKeyCreation() {
        val keys = DeviceKeyStore()
        keys.ensureWrapping()
        val message = "android-v2-identity-binding".encodeToByteArray()
        Loomcore.verifyP256Signature(keys.ensureIdentity(), message, keys.sign(message))
    }
}
