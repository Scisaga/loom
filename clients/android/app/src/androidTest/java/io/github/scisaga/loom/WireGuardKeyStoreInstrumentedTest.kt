package io.github.scisaga.loom

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.scisaga.loom.profiles.ProfileContext
import io.github.scisaga.loom.security.EncryptedStore
import io.github.scisaga.loom.security.WireGuardKeyStore
import io.github.scisaga.loomcore.Loomcore
import java.util.UUID
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class WireGuardKeyStoreInstrumentedTest {
    @Test
    fun localKeySurvivesReopenAndRejectsCorruptionWithoutReplacement() {
        val root = InstrumentationRegistry.getInstrumentation().targetContext
        val first = ProfileContext(root, UUID.randomUUID().toString().replace("-", ""))
        val second = ProfileContext(root, UUID.randomUUID().toString().replace("-", ""))
        try {
            assertNull(WireGuardKeyStore(first).existing())
            val public = WireGuardKeyStore(first).publicKeyForEnrollment()
            assertArrayEquals(public, WireGuardKeyStore(first).publicKeyForEnrollment())
            val private = requireNotNull(WireGuardKeyStore(first).existing())
            try {
                assertArrayEquals(public, Loomcore.localWireGuardPublicKey(private))
            } finally { private.fill(0) }
            assertFalse(public.contentEquals(WireGuardKeyStore(second).publicKeyForEnrollment()))
            val encrypted = EncryptedStore(first).fileForTest("wireguard-v2.key")
            encrypted.writeBytes(encrypted.readBytes().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() })
            val corrupt = encrypted.readBytes()
            assertThrows(Exception::class.java) { WireGuardKeyStore(first).publicKeyForEnrollment() }
            assertArrayEquals(corrupt, encrypted.readBytes())
        } finally {
            for (context in listOf(first, second)) {
                EncryptedStore(context).deleteStorageKey()
                context.filesDir.deleteRecursively()
            }
        }
    }
}
