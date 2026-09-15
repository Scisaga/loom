package io.github.scisaga.loom.route

import kotlin.math.roundToLong

/** 只读取单包 ICMP 回复的精确 RTT；进程耗时、汇总和 time< 上界都不是测量值。 */
internal fun icmpEchoReplyMillis(output: String): Long? {
    val replies = ICMP_REPLY.findAll(output).toList()
    if (replies.size != 1) return null
    val millis = replies.single().groupValues[1].toDoubleOrNull() ?: return null
    if (!millis.isFinite() || millis < 0 || millis > 1_500) return null
    return millis.roundToLong()
}

private val ICMP_REPLY = Regex(
    "^\\s*\\d+ bytes from [^\\r\\n]+\\bicmp_seq[= ]\\d+\\b[^\\r\\n]*?\\btime=([0-9]+(?:\\.[0-9]+)?)\\s*ms(?:\\s|$)",
    RegexOption.MULTILINE,
)
