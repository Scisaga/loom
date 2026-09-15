package io.github.scisaga.loom

import android.Manifest
import android.os.Build
import androidx.activity.ComponentActivity
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.runner.lifecycle.ActivityLifecycleMonitorRegistry
import androidx.test.runner.lifecycle.Stage

/** 厂商可能拦截测试进程的 Activity 启动；使用同一组件的正常 ADB 入口。 */
internal fun launchDeviceUi(): ComponentActivity {
    val instrumentation = InstrumentationRegistry.getInstrumentation()
    if (Build.VERSION.SDK_INT >= 33) {
        instrumentation.uiAutomation.grantRuntimePermission(
            instrumentation.targetContext.packageName, Manifest.permission.POST_NOTIFICATIONS,
        )
    }
    instrumentation.uiAutomation.executeShellCommand(
        "am start -W -a android.intent.action.MAIN -c android.intent.category.LAUNCHER " +
            "-f 0x10008000 -n io.github.scisaga.loom/.MainActivity",
    ).use { android.os.ParcelFileDescriptor.AutoCloseInputStream(it).readBytes() }
    var activity: ComponentActivity? = null
    instrumentation.runOnMainSync {
        activity = ActivityLifecycleMonitorRegistry.getInstance().getActivitiesInStage(Stage.RESUMED)
            .filterIsInstance<MainActivity>().singleOrNull()
    }
    return checkNotNull(activity) { "真机界面未成功启动" }
}
