package io.github.scisaga.loom.vpn

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class NetworkProbeTest {
    @Test
    fun businessOutcomeDoesNotInventASeparateDnsMeasurement() {
        val result = ProbeResult("由当前访问路径解析（未单独测量）", "成功（HTTPS 实际响应）", "https://demo.example/", 10)
        assertTrue(result.healthy)
        assertFalse(result.copy(https = "失败：HTTPS 未完成").healthy)
    }
}
