package io.github.scisaga.loom.enrollment

import android.content.Context

internal class HealthReporter(context: Context, private val profileId: String) {
    private val enrollment = EnrollmentManager.get(context)
    suspend fun send() = enrollment.postReport(profileId)
}
