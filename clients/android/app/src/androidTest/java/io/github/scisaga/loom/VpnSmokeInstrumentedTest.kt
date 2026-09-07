package io.github.scisaga.loom

import android.content.Intent
import android.net.VpnService
import androidx.core.content.ContextCompat
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.LargeTest
import androidx.test.platform.app.InstrumentationRegistry
import io.github.scisaga.loom.vpn.ConnectionPhase
import io.github.scisaga.loom.vpn.LoomVpnService
import io.github.scisaga.loom.vpn.VpnRuntime
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@LargeTest
@RunWith(AndroidJUnit4::class)
class VpnSmokeInstrumentedTest {
    @After
    fun disconnect() {
        send(LoomVpnService.ACTION_DISCONNECT)
    }

    @Test
    fun connectProbeDisconnectAndReconnect() = runBlocking {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        check(VpnService.prepare(context) == null) {
            "模拟器尚未授权 VPN；请通过 emulator-smoke.sh 执行可回滚的 ACTIVATE_VPN 授权"
        }
        send(LoomVpnService.ACTION_CONNECT)
        await(ConnectionPhase.CONNECTED)
        val probeDeadline = System.nanoTime() + 40_000_000_000
        while ((!VpnRuntime.status.value.dnsProbe.startsWith("成功") ||
                !VpnRuntime.status.value.httpsProbe.startsWith("成功")) &&
            System.nanoTime() < probeDeadline
        ) {
            delay(250)
        }
        check(VpnRuntime.status.value.dnsProbe.startsWith("成功") &&
            VpnRuntime.status.value.httpsProbe.startsWith("成功")) {
            "穿过 TUN 的探测失败: ${VpnRuntime.status.value}"
        }

        send(LoomVpnService.ACTION_DISCONNECT)
        await(ConnectionPhase.DISCONNECTED)
        send(LoomVpnService.ACTION_DISCONNECT)
        await(ConnectionPhase.DISCONNECTED)

        send(LoomVpnService.ACTION_CONNECT)
        await(ConnectionPhase.CONNECTED)
        send(LoomVpnService.ACTION_DISCONNECT)
        await(ConnectionPhase.DISCONNECTED)
        assertTrue(VpnRuntime.status.value.detail.contains("未连接"))
    }

    private suspend fun await(phase: ConnectionPhase) = withTimeout(30_000) {
        while (VpnRuntime.status.value.phase != phase) {
            val status = VpnRuntime.status.value
            check(status.phase != ConnectionPhase.ERROR) { status.detail }
            delay(100)
        }
    }

    private fun send(action: String) {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        val emulatorProxy = InstrumentationRegistry.getArguments().getString("emulatorProxy") == "true"
        ContextCompat.startForegroundService(
            context,
            Intent(context, LoomVpnService::class.java).setAction(action)
                .putExtra(LoomVpnService.EXTRA_EMULATOR_PROXY, emulatorProxy),
        )
    }
}
