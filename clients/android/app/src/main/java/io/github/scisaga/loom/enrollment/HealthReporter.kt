package io.github.scisaga.loom.enrollment

import android.content.Context
import io.github.scisaga.loom.route.RouteManager
import io.github.scisaga.loomcore.Loomcore
import java.time.Instant
import java.time.temporal.ChronoUnit

internal class HealthReporter(context: Context, private val profileId: String) {
    private val enrollment = EnrollmentManager.get(context)
    private val routing = RouteManager.get(context)

    fun send() {
        Loomcore.postAndroidDeviceReport(
            enrollment.currentState(profileId),
            routing.reportObservations(profileId),
            routing.selectedCandidate(profileId),
            Instant.now().truncatedTo(ChronoUnit.SECONDS).toString(),
        )
    }
}
