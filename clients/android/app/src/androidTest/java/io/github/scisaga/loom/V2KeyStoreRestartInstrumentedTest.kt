package io.github.scisaga.loom

import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.scisaga.loom.security.DeviceKeyStore
import io.github.scisaga.loomcore.Loomcore
import java.security.KeyFactory
import java.security.interfaces.RSAPublicKey
import java.security.spec.MGF1ParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class V2KeyStoreRestartInstrumentedTest {
    @Test
    fun api26To30AliasesSurviveProcessStopAndSignedReplacement() {
        assumeTrue(Build.VERSION.SDK_INT in Build.VERSION_CODES.O until Build.VERSION_CODES.S)
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val phase = checkNotNull(InstrumentationRegistry.getArguments().getString("phase"))
        val evidence = instrumentation.targetContext.filesDir.resolve(EVIDENCE_FILE)
        val keys = DeviceKeyStore()
        val identity = keys.ensureIdentity()
        val wrapping = keys.ensureWrapping()
        assertEquals("rsa2048-keystore-decrypt-v1", wrapping.profile)

        when (phase) {
            "seed" -> evidence.writeText(
                JSONObject()
                    .put("identity", Base64.getEncoder().encodeToString(identity))
                    .put("wrapping", Base64.getEncoder().encodeToString(wrapping.subjectPublicKeyInfo))
                    .toString(),
            )
            "verify" -> {
                val before = JSONObject(evidence.readText())
                assertArrayEquals(Base64.getDecoder().decode(before.getString("identity")), identity)
                assertArrayEquals(
                    Base64.getDecoder().decode(before.getString("wrapping")),
                    wrapping.subjectPublicKeyInfo,
                )
                val message = "android-api26-30-restart-binding".encodeToByteArray()
                Loomcore.verifyP256Signature(identity, message, keys.sign(message))
                val publicKey = KeyFactory.getInstance("RSA")
                    .generatePublic(X509EncodedKeySpec(wrapping.subjectPublicKeyInfo)) as RSAPublicKey
                val plaintext = "android-api26-30-upgrade-oaep".encodeToByteArray()
                val ciphertext = Cipher.getInstance("RSA/ECB/OAEPPadding").run {
                    init(
                        Cipher.ENCRYPT_MODE,
                        publicKey,
                        OAEPParameterSpec(
                            "SHA-256",
                            "MGF1",
                            MGF1ParameterSpec.SHA1,
                            PSource.PSpecified.DEFAULT,
                        ),
                    )
                    doFinal(plaintext)
                }
                assertArrayEquals(plaintext, keys.decryptWrappingRSAOAEP(ciphertext))
                assertTrue(evidence.delete())
            }
            else -> error("phase 必须是 seed 或 verify")
        }
    }

    companion object {
        private const val EVIDENCE_FILE = "v2-keystore-restart-public.json"
    }
}
