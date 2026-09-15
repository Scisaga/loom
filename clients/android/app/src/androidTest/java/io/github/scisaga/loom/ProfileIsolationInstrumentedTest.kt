package io.github.scisaga.loom

import android.content.Intent
import android.net.VpnService
import androidx.core.content.ContextCompat
import androidx.test.platform.app.InstrumentationRegistry
import io.github.scisaga.loom.enrollment.EnrollmentManager
import io.github.scisaga.loom.profiles.ProfileCatalog
import io.github.scisaga.loom.profiles.ProfileContext
import io.github.scisaga.loom.security.DeviceKeyStore
import io.github.scisaga.loom.security.EncryptedStore
import io.github.scisaga.loom.vpn.ConnectionPhase
import io.github.scisaga.loom.vpn.LoomVpnService
import io.github.scisaga.loom.vpn.VpnRuntime
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.*
import org.junit.Test
import org.junit.Before
import org.junit.After
import androidx.activity.ComponentActivity

/** §7.2：仅使用临时本机配置，不替换真机既有身份，不请求新的业务路径探测。 */
class ProfileIsolationInstrumentedTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val catalog get() = ProfileCatalog.get(context)
    private lateinit var activity: ComponentActivity
    @Before fun launch() { activity = launchDeviceUi() }
    @After fun finish() {
        if (::activity.isInitialized) InstrumentationRegistry.getInstrumentation().runOnMainSync { activity.finish() }
    }

    @Test
    fun identitiesStorageAndSingleVpnStayBoundToTheirOwnProfiles() = runBlocking {
        check(VpnService.prepare(context) == null) { "真机尚未授权 VPN" }
        check(!VpnRuntime.status.value.alwaysOn) { "测试需要系统始终开启 VPN 关闭" }
        val original = catalog.state.value.selectedId
        val legacyContext = ProfileContext(context, ProfileContext.LEGACY_PROFILE)
        val originalIdentity = DeviceKeyStore().identityStatus()
        val originalPublicKey = if (originalIdentity.startsWith("non-exportable")) DeviceKeyStore().ensureIdentity() else null
        val originalRecord = EncryptedStore(legacyContext).get("managed-current")
        val a = catalog.create("demo-profile-a")
        val b = catalog.create("demo-profile-b")
        try {
            val ac = catalog.context(a.id)
            val bc = catalog.context(b.id)
            val ak = DeviceKeyStore(ProfileContext.keySuffix(ac))
            val bk = DeviceKeyStore(ProfileContext.keySuffix(bc))
            assertFalse(ak.ensureIdentity().contentEquals(bk.ensureIdentity()))
            val message = "demo-profile-isolation".encodeToByteArray()
            io.github.scisaga.loomcore.Loomcore.verifyP256Signature(ak.ensureIdentity(), message, ak.sign(message))
            assertTrue(runCatching {
                io.github.scisaga.loomcore.Loomcore.verifyP256Signature(bk.ensureIdentity(), message, ak.sign(message))
            }.isFailure)
            EncryptedStore(ac).put("route-preference", "demo-a".encodeToByteArray())
            EncryptedStore(bc).put("route-preference", "demo-b".encodeToByteArray())
            EncryptedStore(ac).put("join-pending", "demo-exact-pending".encodeToByteArray())
            assertEquals("demo-a", EncryptedStore(ac).get("route-preference")!!.decodeToString())
            assertEquals("demo-b", EncryptedStore(bc).get("route-preference")!!.decodeToString())
            val bFile = EncryptedStore(bc).fileForTest("route-preference")
            val bCiphertext = bFile.readBytes()
            try {
                bFile.writeBytes(EncryptedStore(ac).fileForTest("route-preference").readBytes())
                assertTrue(runCatching { EncryptedStore(bc).get("route-preference") }.isFailure)
            } finally { bFile.writeBytes(bCiphertext) }
            assertNull(EncryptedStore(bc).get("join-pending"))
            EncryptedStore(ac).remove("join-pending")
            send(LoomVpnService.ACTION_CONNECT, a.id)
            await(ConnectionPhase.CONNECTED, a.id)
            catalog.select(b.id)
            EnrollmentManager.get(bc).initialize()
            delay(300)
            assertEquals(a.id, VpnRuntime.status.value.profileId)
            assertEquals(ConnectionPhase.CONNECTED, VpnRuntime.status.value.phase)
            send(LoomVpnService.ACTION_CONNECT, b.id)
            await(ConnectionPhase.CONNECTED, b.id)
            assertTrue(VpnRuntime.status.value.dnsProbe.startsWith("未执行"))
            send(LoomVpnService.ACTION_DELETE_PROFILE, b.id)
            withTimeout(30_000) { while (catalog.contains(b.id)) delay(100) }
            assertEquals(ConnectionPhase.DISCONNECTED, VpnRuntime.status.value.phase)
            assertEquals("demo-a", EncryptedStore(ac).get("route-preference")!!.decodeToString())
            assertEquals(originalIdentity, DeviceKeyStore().identityStatus())
            if (originalPublicKey != null) assertArrayEquals(originalPublicKey, DeviceKeyStore().ensureIdentity())
            assertArrayEquals(originalRecord, EncryptedStore(legacyContext).get("managed-current"))
        } finally {
            send(LoomVpnService.ACTION_DISCONNECT)
            await(ConnectionPhase.DISCONNECTED)
            listOf(a, b).forEach { profile ->
                if (catalog.contains(profile.id)) {
                    send(LoomVpnService.ACTION_DELETE_PROFILE, profile.id)
                    withTimeout(30_000) { while (catalog.contains(profile.id)) delay(100) }
                }
            }
            catalog.select(original)
        }
    }

    private fun send(action: String, id: String? = null) {
        ContextCompat.startForegroundService(context, Intent(context, LoomVpnService::class.java)
            .setAction(action).apply { id?.let { putExtra(LoomVpnService.EXTRA_PROFILE_ID, it) } })
    }

    private suspend fun await(phase: ConnectionPhase, id: String? = null) = withTimeout(30_000) {
        while (VpnRuntime.status.value.phase != phase || (id != null && VpnRuntime.status.value.profileId != id)) {
            check(VpnRuntime.status.value.phase != ConnectionPhase.ERROR) { "测试配置的本机生命周期失败" }
            delay(100)
        }
    }
}
