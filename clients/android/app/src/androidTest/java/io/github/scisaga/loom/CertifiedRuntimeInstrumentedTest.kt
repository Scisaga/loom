package io.github.scisaga.loom

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertTextEquals
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextReplacement
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.BySelector
import androidx.test.uiautomator.StaleObjectException
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.Until
import io.github.scisaga.loom.enrollment.EnrollmentManager
import io.github.scisaga.loom.enrollment.EnrollmentPhase
import io.github.scisaga.loom.enrollment.ManagedProfileStore
import io.github.scisaga.loom.profiles.ProfileCatalog
import io.github.scisaga.loom.route.RouteManager
import io.github.scisaga.loom.vpn.ConnectionPhase
import io.github.scisaga.loom.vpn.VpnRuntime
import java.io.File
import java.net.InetSocketAddress
import java.net.InetAddress
import java.net.Socket
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/** Opt-in real daemon fixture; no fabricated View, identity, runtime or health. */
class CertifiedRuntimeInstrumentedTest {
    private var originalTLS: SSLContext? = null

    @After
    fun restoreFixtureTrust() {
        originalTLS?.let(SSLContext::setDefault)
    }

    @get:Rule
    val compose = createAndroidComposeRule<MainActivity>()

    @Test
    fun formalJoinVpnAndWithdrawal() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val args = InstrumentationRegistry.getArguments()
        assumeTrue("requires the isolated demo control fixture", args.getString("demoFixture") == "true")
        val device = UiDevice.getInstance(instrumentation)
        assertEquals("1", device.executeShellCommand("getprop ro.kernel.qemu").trim())
        val context = instrumentation.targetContext
        val directory = checkNotNull(context.getExternalFilesDir(null))
        val fixture = JSONObject(File(directory, "demo-runtime.json").readText())
        val resume = args.getString("demoResume") == "true"
        val independentServices = args.getString("demoServices") == "true"
        val serviceCount = if (independentServices) 2 else 1
        args.getString("demoNewProfile")?.let { name ->
            check(!resume)
            compose.onNodeWithTag("tab-configuration").performClick()
            compose.onNodeWithTag("add-profile").performScrollTo().performClick()
            compose.onNodeWithTag("profile-name-input").performTextReplacement(name)
            compose.onNodeWithText("保存").performClick()
            compose.waitUntil(10_000) {
                val catalog = ProfileCatalog.get(context).state.value
                catalog.profiles.any { it.id == catalog.viewedProfileId && it.name == name }
            }
        }
        val profileID = ProfileCatalog.get(context).state.value.viewedProfileId
        val enrollment = EnrollmentManager.get(context)
        val routing = RouteManager.get(context)
        fun click(tag: String) = compose.onNodeWithTag(tag).performScrollTo().performClick()
        fun await(label: String, seconds: Long = 60, condition: () -> Boolean) {
            val end = System.nanoTime() + TimeUnit.SECONDS.toNanos(seconds)
            var ready = condition()
            while (!ready && System.nanoTime() < end) {
                Thread.sleep(100)
                ready = condition()
            }
            assertTrue(label + "; enrollment=" + enrollment.status(profileID).value + "; runtime=" + VpnRuntime.status.value, ready)
        }
        fun clickSystem(selector: BySelector, label: String) {
            val end = System.nanoTime() + TimeUnit.SECONDS.toNanos(30)
            while (System.nanoTime() < end) {
                device.waitForIdle(1_000)
                val node = device.wait(Until.findObject(selector), 1_000) ?: continue
                try {
                    node.click()
                    return
                } catch (_: StaleObjectException) {
                    // DocumentsUI replaces its loading rows; resolve the real row again.
                }
            }
            error(label)
        }
        fun mark(name: String) {
            compose.waitForIdle()
            compose.onNodeWithTag("connection-toggle").assertTextEquals("断开")
            if (routing.status(profileID).value.currentPaths.isEmpty()) {
                compose.onNodeWithText("当前没有已选业务路径").assertIsDisplayed()
            }
            File(directory, name).writeText(JSONObject().put("view_digest", enrollment.status(profileID).value.viewDigest)
                .put("phase", VpnRuntime.status.value.phase.name).toString())
        }
        fun awaitConnected() {
            await("VPN must be backed by libbox and selector readback") {
                val runtime = VpnRuntime.status.value
                runtime.phase == ConnectionPhase.CONNECTED && runtime.viewDigest == enrollment.status(profileID).value.viewDigest &&
                    routing.status(profileID).value.running
            }
        }
        fun connect() {
            compose.onNodeWithTag("tab-connection").performClick()
            val phase = VpnRuntime.status.value.phase
            if (phase == ConnectionPhase.DISCONNECTED || phase == ConnectionPhase.ERROR || VpnRuntime.status.value.activeProfileId != profileID) {
                click("connection-toggle")
                // Consent is exercised on this disposable emulator's system UI.
                device.wait(Until.findObject(By.res("android:id/button1")), 3_000)?.click()
            }
            // The same profile can retain reconnect intent after an interrupted
            // test; a different active profile must use the normal switch button.
            awaitConnected()
        }
        val ca = CertificateFactory.getInstance("X.509").generateCertificate(File(directory, "demo-ca.pem").inputStream())
        val trust = KeyStore.getInstance(KeyStore.getDefaultType()).apply { load(null); setCertificateEntry("demo", ca) }
        val managers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(trust) }
        val tls = SSLContext.getInstance("TLS").apply { init(null, managers.trustManagers, null) }
        fun business(): Boolean = runCatching {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(fixture.getString("target_ip"), fixture.getInt("target_port")), 3_000)
                socket.soTimeout = 3_000
                (tls.socketFactory.createSocket(socket, "demo.example", fixture.getInt("target_port"), false) as SSLSocket).use { stream ->
                    stream.sslParameters = stream.sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
                    stream.startHandshake()
                    stream.outputStream.write("GET /demo-android-business HTTP/1.1\r\nHost: demo.example\r\nConnection: close\r\n\r\n".toByteArray())
                    val body = stream.inputStream.bufferedReader().readText()
                    body.startsWith("HTTP/1.0 200") && body.endsWith("demo-android-business")
                }
            }
        }.getOrElse {
            android.util.Log.w("LoomCertifiedFixture", "HTTPS failed: ${it.javaClass.simpleName}: ${it.message}")
            false
        }

        fun website() {
            if (!fixture.has("website_port")) return
            assertEquals(setOf("192.0.2.20"), InetAddress.getAllByName("control.loom").map { it.hostAddress }.toSet())
            val websiteCA = CertificateFactory.getInstance("X.509").generateCertificate(File(directory, "demo-website-root.pem").inputStream())
            val websiteTrust = KeyStore.getInstance(KeyStore.getDefaultType()).apply { load(null); setCertificateEntry("demo-website", websiteCA) }
            val websiteManagers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(websiteTrust) }
            val password = File(directory, "demo-admin.password").readText().trim().toCharArray()
            val identity = KeyStore.getInstance("PKCS12").apply { File(directory, "demo-admin.p12").inputStream().use { load(it, password) } }
            val keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(identity, password) }
            password.fill('\u0000')
            val websiteTLS = SSLContext.getInstance("TLS").apply { init(keyManagers.keyManagers, websiteManagers.trustManagers, null) }
            val port = fixture.getInt("website_port")
            // This ordinary application socket is intentionally not VPN-protected:
            // the active VPN's exact website exclusion must leave it on underlay.
            Socket().use { socket ->
                socket.connect(InetSocketAddress("control.loom", port), 5_000)
                socket.soTimeout = 5_000
                (websiteTLS.socketFactory.createSocket(socket, "control.loom", port, false) as SSLSocket).use { stream ->
                    stream.sslParameters = stream.sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
                    stream.startHandshake()
                    stream.outputStream.write("GET /api/control/ui/snapshot HTTP/1.1\r\nHost: control.loom:$port\r\nConnection: close\r\n\r\n".toByteArray())
                    val response = stream.inputStream.bufferedReader().readText()
                    assertTrue("website TLS did not reach authenticated control management: " + response.lineSequence().firstOrNull(), response.startsWith("HTTP/1.1 200") && response.contains("\"admin\":true"))
                }
            }
        }

        // The demo CA is trusted only in this instrumented process. Production
        // trust settings, certificate verification and hostname checks stay intact.
        if (independentServices) {
            originalTLS = SSLContext.getDefault()
            SSLContext.setDefault(tls)
        }
        if (!resume && args.getString("demoJoined") != "true") {
            compose.onNodeWithTag("tab-configuration").performClick()
            await("new profile must finish loading before file import", 15) {
                enrollment.status(profileID).value.phase == EnrollmentPhase.NOT_JOINED
            }
            compose.waitForIdle()
            click("import-invite")
            clickSystem(By.desc("Show roots"), "normal document picker did not open")
            assertTrue("document picker drawer did not open", device.wait(Until.hasObject(By.text("Open from")), 10_000))
            clickSystem(By.res("android:id/title").text("Downloads"), "Downloads root is absent")
            assertTrue("Downloads navigation did not finish", device.wait(Until.gone(By.text("Open from")), 10_000))
            clickSystem(By.res("android:id/title").text("demo-android.loom-invite"), "normal document picker did not expose the demo invitation")
        }
        await("private join or protected restart must restore the certified profile") { enrollment.status(profileID).value.phase == EnrollmentPhase.READY }
        connect()
        website()
        args.getString("demoResourceStep")?.let { step ->
            require(step in setOf("refresh", "restart", "recovery"))
            await("resource sample must follow the actual authorized selector") {
                routing.status(profileID).value.currentPaths.size == serviceCount
            }
            if (step == "recovery") {
                assertFalse("stopped first hop unexpectedly carried business", business())
                mark("demo-resource-failed.json")
                await("controller must restore the same first-hop execution inputs") {
                    File(directory, "demo-resource-restored").isFile
                }
                await("restored first hop must carry real application HTTPS") { business() }
                mark("demo-resource-recovered.json")
            } else {
                await("first hop must carry real application HTTPS") { business() }
                mark("demo-resource-$step.json")
                if (step == "refresh") {
                    val previous = enrollment.status(profileID).value.viewDigest
                    await("controller must publish unrelated configuration") {
                        File(directory, "demo-resource-refresh").isFile
                    }
                    compose.onNodeWithTag("tab-configuration").performClick()
                    click("refresh-config")
                    await("unrelated View must be accepted and applied") {
                        enrollment.status(profileID).value.viewDigest != previous &&
                            routing.status(profileID).value.currentPaths.size == serviceCount
                    }
                    compose.onNodeWithTag("tab-connection").performClick()
                    awaitConnected()
                    await("unrelated refresh must preserve authorized HTTPS") { business() }
                    mark("demo-resource-refreshed.json")
                }
            }
            // The normal report loop runs once a minute, after actual sampling
            // and loaded-component measurement. Allow a complete next cycle.
            await("controller must independently verify original resource reports", 120) {
                File(directory, "demo-resource-finish-$step").isFile
            }
            click("connection-toggle")
            await("normal disconnect must release the VPN") { VpnRuntime.status.value.phase == ConnectionPhase.DISCONNECTED }
            await("controller must read the signed stopped report") {
                File(directory, "demo-resource-stopped-$step").isFile
            }
            return
        }
        if (!resume) {
            if (independentServices) {
                await("only the failing Service must be rejected", 120) {
                    val paths = routing.status(profileID).value.currentPaths
                    paths.size == 1 && paths.single().service == "service:demo-service" && paths.single().state == "available"
                }
                assertTrue("other Service must still carry actual HTTPS", business())
                mark("demo-partial.json")
                await("controller must verify the independent signed outcomes") { File(directory, "demo-restored").isFile }
                await("failed Service must recover after observation expiry", 120) {
                    val paths = routing.status(profileID).value.currentPaths
                    paths.size == 2 && paths.all { it.state == "available" }
                }
            }
            await("authorized path must be consumed after protected restart") {
                routing.status(profileID).value.currentPaths.size == serviceCount
            }
            val path = routing.status(profileID).value.currentPaths.first()
            assertEquals("demo-exit", path.finalExit)
            assertEquals(listOf("demo-exit"), path.serverChain)
            if (!independentServices) assertEquals("unknown", path.state)
            // Runtime/selector readiness precedes a real business result. Wait
            // for that result within the fixture deadline; never synthesize it.
            await("real application TLS must traverse the VPN") { business() }
            if (args.getString("demoBlockedReport") == "true") {
                mark("demo-report-ready.json")
                await("controller must pause the authenticated control") { File(directory, "demo-report-paused").isFile }
                val sender = CoroutineScope(SupervisorJob() + Dispatchers.IO)
                try {
                    fun reportSequence() = JSONObject(checkNotNull(ManagedProfileStore(context, profileID).state()).decodeToString())
                        .getString("report_sequence").toLong()
                    val beforeReport = reportSequence()
                    val sending = sender.launch { runCatching { enrollment.postReport(profileID) } }
                    await("report sequence must be durably reserved before the network wait", 45) {
                        reportSequence() > beforeReport
                    }
                    Thread.sleep(1_000)
                    assertTrue("report must still be waiting on the stopped control", sending.isActive)
                    click("connection-toggle")
                    await("control network wait must not block normal disconnect", 10) {
                        VpnRuntime.status.value.phase == ConnectionPhase.DISCONNECTED
                    }
                    assertTrue("disconnect must finish before the blocked request", sending.isActive)
                    File(directory, "demo-report-disconnected.json").writeText("true")
                    await("controller must verify the stopped signed report after resuming") { File(directory, "demo-report-resumed").isFile }
                } finally {
                    sender.cancel()
                }
                connect()
                await("reconnected Service must carry real HTTPS") { business() }
            }
            val previous = enrollment.status(profileID).value.viewDigest
            mark("demo-allowed.json")
            await("formal control must publish withdrawal") { File(directory, "demo-withdrawn").isFile }
            compose.onNodeWithTag("tab-configuration").performClick()
            click("refresh-config")
            await("accepted withdrawal must replace the encrypted LKG") {
                enrollment.status(profileID).value.phase == EnrollmentPhase.READY &&
                    enrollment.status(profileID).value.viewDigest != previous &&
                    routing.status(profileID).value.currentPaths.isEmpty()
            }
            compose.onNodeWithTag("tab-connection").performClick()
            awaitConnected()
        }
        assertTrue("withdrawal left a selectable path", routing.status(profileID).value.currentPaths.isEmpty())
        website()
        assertFalse("withdrawn target remained reachable through the running VPN", business())
        mark(if (resume) "demo-restarted.json" else "demo-revoked.json")
        if (resume) {
            val previous = enrollment.status(profileID).value.viewDigest
            await("formal control must publish reauthorization") { File(directory, "demo-regranted").isFile }
            compose.onNodeWithTag("tab-configuration").performClick()
            click("refresh-config")
            await("new permission must replace the withdrawn LKG") {
                enrollment.status(profileID).value.phase == EnrollmentPhase.READY &&
                    enrollment.status(profileID).value.viewDigest != previous &&
                    routing.status(profileID).value.currentPaths.size == serviceCount
            }
            compose.onNodeWithTag("tab-connection").performClick()
            awaitConnected()
            assertEquals("demo-exit", routing.status(profileID).value.currentPaths.first().finalExit)
            await("reauthorization did not restore real VPN business") { business() }
            mark("demo-regranted.json")
        }
        // The controller reads the private signed report before allowing exit.
        await("private control report readback must finish") { File(directory, if (resume) "demo-resume-finish" else "demo-finish").isFile }
        click("connection-toggle")
        await("normal disconnect must release the VPN") { VpnRuntime.status.value.phase == ConnectionPhase.DISCONNECTED }
        if (args.getString("demoAwaitStoppedReport") == "true") {
            // Keep the ordinary app process alive until the controller has
            // independently read the signed stop result from the real daemon.
            await("private stopped report readback must finish") {
                File(directory, if (resume) "demo-resume-stop-readback" else "demo-stop-readback").isFile
            }
        }
    }
}
