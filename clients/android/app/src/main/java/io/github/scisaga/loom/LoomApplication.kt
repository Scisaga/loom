package io.github.scisaga.loom

import android.app.Application
import io.github.scisaga.libbox.Libbox
import io.github.scisaga.libbox.SetupOptions
import io.github.scisaga.loom.enrollment.EnrollmentManager
import io.github.scisaga.loom.enrollment.libboxWorkingDirectory
import io.github.scisaga.loom.route.UnderlayProbeRegistry

class LoomApplication : Application() {
    /** #14：同一进程内的 Service/profile 重建不得重置当前底层网络代的单次探测预算。 */
    internal val underlayProbeRegistry by lazy { UnderlayProbeRegistry() }

    override fun onCreate() {
        super.onCreate()
        val working = libboxWorkingDirectory(filesDir).apply { mkdirs() }
        val temporary = cacheDir.resolve("libbox").apply { mkdirs() }
        Libbox.setup(
            SetupOptions().apply {
                basePath = filesDir.absolutePath
                workingPath = working.absolutePath
                tempPath = temporary.absolutePath
                username = "android"
                fixAndroidStack = true
            },
        )
        EnrollmentManager.get(this).initialize()
    }
}
