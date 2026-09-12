package io.github.scisaga.loom

import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.github.scisaga.loom.security.DeviceKeyStore
import io.github.scisaga.loomcore.Loomcore
import java.security.KeyFactory
import java.security.interfaces.RSAPublicKey
import java.security.spec.MGF1ParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
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
        val identity = keys.ensureIdentity()
        Loomcore.verifyCSRIdentity(keys.createCSRDER("demo-android-request"), identity)

        val hash = "sha256:" + "00".repeat(32)
        val popBody = """
            {"challenge_hash":"$hash","claim_core_hash":"$hash","cluster_id":"demo-cluster","invite_id":"demo-invite","request_id":"demo-request","schema":2,"token_commitment":"$hash"}
        """.trimIndent().encodeToByteArray()
        val message = Loomcore.enrollmentPoPMessageV2(popBody)
        Loomcore.verifyP256Signature(identity, message, keys.signCanonicalV2(message))
    }

    @Test
    fun api26To30RsaFallbackUsesExactOaepProfile() {
        assumeTrue(Build.VERSION.SDK_INT in Build.VERSION_CODES.O until Build.VERSION_CODES.S)
        val keys = DeviceKeyStore()
        val wrapping = keys.ensureWrapping()
        assertTrue(wrapping.profile == "rsa2048-keystore-decrypt-v1")
        val publicKey = KeyFactory.getInstance("RSA")
            .generatePublic(X509EncodedKeySpec(wrapping.subjectPublicKeyInfo)) as RSAPublicKey
        assertTrue(publicKey.modulus.bitLength() == 2048)
        val plaintext = "android-api26-30-rsa-oaep".encodeToByteArray()
        val ciphertext = Cipher.getInstance("RSA/ECB/OAEPPadding").run {
            init(
                Cipher.ENCRYPT_MODE,
                publicKey,
                OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT),
            )
            doFinal(plaintext)
        }

        assertArrayEquals(plaintext, keys.decryptWrappingRSAOAEP(ciphertext))
    }
}
