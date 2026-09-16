package io.github.scisaga.loom

import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import androidx.test.platform.app.InstrumentationRegistry
import io.github.scisaga.loom.enrollment.EnrollmentManager
import io.github.scisaga.loom.profiles.ProfileCatalog
import org.json.JSONObject
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/** 仅由操作者显式发起；只检查当前私有控制承载的一个入口，不产生选路观测。 */
class UnderlayDNSDeviceInstrumentedTest {
    @Test
    fun compareCurrentCarrierResolvers() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("underlayDNS") == "true")
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val catalog = ProfileCatalog.get(context)
        val profile = checkNotNull(EnrollmentManager.get(catalog.context(catalog.state.value.selectedId)).currentProfile())
        check(profile.protocol == 2)
        val config = JSONObject(profile.config)
        val endpoints = config.getJSONArray("endpoints")
        val wg = (0 until endpoints.length()).map(endpoints::getJSONObject)
            .single { it.getString("tag") == "private-control-wg" }
        val outbounds = config.getJSONArray("outbounds")
        val byTag = (0 until outbounds.length()).map(outbounds::getJSONObject).associateBy { it.getString("tag") }
        val carrier = checkNotNull(byTag[wg.getString("detour")])
        val host = carrier.getString("server")
        check(host.matches(Regex("[A-Za-z0-9.-]{1,253}")))
        val resolver = config.getJSONObject("dns").getJSONArray("servers").getJSONObject(0).getString("address")
        check(resolver.matches(Regex("[0-9.]+"))) { "诊断只支持当前配置的 IP UDP resolver" }
        val connectivity = context.getSystemService(ConnectivityManager::class.java)
        @Suppress("DEPRECATION")
        val networks = connectivity.allNetworks.filter { network ->
            connectivity.getNetworkCapabilities(network)?.let {
                it.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) &&
                    it.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) &&
                    it.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            } == true
        }
        check(networks.size == 1) { "诊断需要唯一已验证底层网络，拒绝隐式选择" }
        val network = networks.single()
        val result = JSONObject()
        val executor = Executors.newSingleThreadExecutor()
        try {
            val lookup = executor.submit<Int> { network.getAllByName(host).size }
            result.put("network_resolver", runCatching { "answers:${lookup.get(10, TimeUnit.SECONDS)}" }
                .getOrElse { lookup.cancel(true); "failed:${it.javaClass.simpleName}" })
        } finally {
            executor.shutdownNow()
        }
        val query = ByteArrayOutputStream().also { bytes ->
            DataOutputStream(bytes).use { output ->
                output.writeShort(0x4c4d)
                output.writeShort(0x0100)
                output.writeShort(1)
                repeat(3) { output.writeShort(0) }
                host.trimEnd('.').split('.').forEach { label ->
                    val encoded = label.toByteArray(Charsets.US_ASCII)
                    check(encoded.size in 1..63)
                    output.writeByte(encoded.size)
                    output.write(encoded)
                }
                output.writeByte(0)
                output.writeShort(1)
                output.writeShort(1)
            }
        }.toByteArray()
        result.put("configured_resolver", runCatching {
            DatagramSocket(null).use { socket ->
                network.bindSocket(socket)
                socket.soTimeout = 5000
                socket.connect(InetAddress.getByName(resolver), 53)
                socket.send(DatagramPacket(query, query.size))
                val packet = DatagramPacket(ByteArray(4096), 4096)
                socket.receive(packet)
                check(packet.length >= 12 && packet.data[0] == query[0] && packet.data[1] == query[1])
                val flags = ((packet.data[2].toInt() and 255) shl 8) or (packet.data[3].toInt() and 255)
                check(flags and 0x8000 != 0 && flags and 15 == 0)
                val answers = ((packet.data[6].toInt() and 255) shl 8) or (packet.data[7].toInt() and 255)
                "answers:$answers"
            }
        }.getOrElse { "failed:${it.javaClass.simpleName}" })
        context.getExternalFilesDir(null)!!.resolve("underlay-dns-diagnostic.json").writeText(result.toString())
        println("underlay-dns-diagnostic=$result")
    }
}
