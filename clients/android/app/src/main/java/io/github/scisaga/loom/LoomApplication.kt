package io.github.scisaga.loom

import android.app.Application
import io.github.scisaga.libbox.Libbox
import io.github.scisaga.libbox.SetupOptions
import io.github.scisaga.loom.enrollment.EnrollmentManager
import io.github.scisaga.loom.enrollment.libboxWorkingDirectory
import io.github.scisaga.loom.profiles.ProfileCatalog

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
        val viewedProfileId = ProfileCatalog.get(this).state.value.viewedProfileId
        EnrollmentManager.get(this).initialize(viewedProfileId)
    }
}
