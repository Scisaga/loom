package io.github.scisaga.loom.enrollment

import java.time.Instant

internal data class EnrollmentAttemptWindow(
    val markFirstAttempt: Boolean,
    val recoveryDeadline: Instant,
)

internal fun enrollmentAttemptWindow(
    expiresAtText: String,
    firstAttemptedAtText: String?,
    now: Instant,
): EnrollmentAttemptWindow {
    val expiresAt = parseEnrollmentInstant(expiresAtText)
    val recoveryDeadline = expiresAt.plusSeconds(ENROLLMENT_RECOVERY_SECONDS)
    val firstAttemptedAt = firstAttemptedAtText?.takeIf(String::isNotBlank)?.let(::parseEnrollmentInstant)

    if (firstAttemptedAt == null) {
        check(now.isBefore(expiresAt)) { "加入二维码已过期；请放弃本机待加入事务并从中控重新获取" }
    } else {
        check(firstAttemptedAt.isBefore(expiresAt)) { "受保护的加入事务首次提交时间无效" }
    }
    check(now.isBefore(recoveryDeadline)) {
        "Device 加入恢复窗口已过期；请放弃本机待加入事务并在中控明确处理"
    }
    return EnrollmentAttemptWindow(firstAttemptedAt == null, recoveryDeadline)
}

private fun parseEnrollmentInstant(value: String): Instant = runCatching { Instant.parse(value) }
    .getOrElse { throw IllegalStateException("受保护的加入事务时间无效") }

private const val ENROLLMENT_RECOVERY_SECONDS = 60L * 60L
