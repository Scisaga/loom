package io.github.scisaga.loom.vpn

import android.net.DnsResolver
import android.net.Network
import android.os.Build
import android.os.CancellationSignal
import androidx.annotation.RequiresApi
import io.github.scisaga.libbox.ExchangeContext
import io.github.scisaga.libbox.LocalDNSTransport
import java.net.Inet4Address
import java.net.Inet6Address
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.atomic.AtomicReference

/** local 解析必须绑定已选择的底层 Network，不能经默认 VPN 网络回到自身 FakeIP。 */
internal class AndroidLocalDNSTransport(private val selectedNetwork: () -> Network?) : LocalDNSTransport {
    override fun raw(): Boolean = Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q

    override fun lookup(ctx: ExchangeContext, network: String, domain: String) {
        val underlay = checkNotNull(selectedNetwork()) { "[Android DNS] 底层网络尚未就绪" }
        val addresses = underlay.getAllByName(domain).filter {
            when (network) {
                "ip4" -> it is Inet4Address
                "ip6" -> it is Inet6Address
                else -> true
            }
        }
        check(selectedNetwork() == underlay) { "[Android DNS] 解析期间底层网络已变化" }
        ctx.success(addresses.mapNotNull { it.hostAddress }.joinToString("\n"))
    }

    override fun exchange(ctx: ExchangeContext, message: ByteArray) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            exchangeRaw(ctx, message)
        } else {
            error("[Android DNS] 当前系统不支持原始 DNS 查询")
        }
    }

    @RequiresApi(Build.VERSION_CODES.Q)
    private fun exchangeRaw(ctx: ExchangeContext, message: ByteArray) {
        val underlay = checkNotNull(selectedNetwork()) { "[Android DNS] 底层网络尚未就绪" }
        val cancellation = CancellationSignal()
        val complete = CountDownLatch(1)
        val answer = AtomicReference<ByteArray?>()
        val failure = AtomicReference<DnsResolver.DnsException?>()
        ctx.onCancel { cancellation.cancel(); complete.countDown() }
        DnsResolver.getInstance().rawQuery(
            underlay, message, DnsResolver.FLAG_EMPTY, Executor { it.run() }, cancellation,
            object : DnsResolver.Callback<ByteArray> {
                override fun onAnswer(bytes: ByteArray, rcode: Int) {
                    answer.set(bytes)
                    complete.countDown()
                }

                override fun onError(error: DnsResolver.DnsException) {
                    failure.set(error)
                    complete.countDown()
                }
            },
        )
        complete.await()
        check(!cancellation.isCanceled) { "[Android DNS] 查询已取消" }
        check(selectedNetwork() == underlay) { "[Android DNS] 解析期间底层网络已变化" }
        check(failure.get() == null) { "[Android DNS] 底层网络解析失败" }
        ctx.rawSuccess(checkNotNull(answer.get()) { "[Android DNS] 底层网络未返回响应" })
    }
}
