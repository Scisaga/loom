package io.github.scisaga.loom

import android.app.Application
import io.github.scisaga.libbox.Libbox
import io.github.scisaga.libbox.SetupOptions
import io.github.scisaga.loom.enrollment.EnrollmentManager
import io.github.scisaga.loom.enrollment.libboxWorkingDirectory

class LoomApplication : Application() {
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
