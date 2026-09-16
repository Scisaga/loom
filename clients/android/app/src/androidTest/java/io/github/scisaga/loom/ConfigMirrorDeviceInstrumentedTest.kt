package io.github.scisaga.loom

import androidx.test.platform.app.InstrumentationRegistry
import io.github.scisaga.loom.enrollment.V2DeviceStateStore
import io.github.scisaga.loom.enrollment.V2MirrorFetcher
import io.github.scisaga.loom.profiles.ProfileCatalog
import io.github.scisaga.loom.profiles.ProfileContext
import io.github.scisaga.loom.security.DeviceKeyStore
import io.github.scisaga.loomcore.Loomcore
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assume.assumeTrue
import org.junit.Test

/** 显式诊断静态制品下载，不提交配置、身份或 floor，也不产生选路观测。 */
class ConfigMirrorDeviceInstrumentedTest {
    @Test
    fun fetchCertifiedConfigurationWithoutActivation() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("configMirror") == "true")
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val catalog = ProfileCatalog.get(context)
        val scoped = catalog.context(catalog.state.value.selectedId)
        val current = checkNotNull(V2DeviceStateStore(scoped).current())
        val identity = DeviceKeyStore(ProfileContext.keySuffix(scoped)).existingIdentity()
        val delivery = context.getExternalFilesDir(null)!!.resolve("diagnostic.loom-config").readBytes()
        val result = JSONObject()
        val plan = JSONObject(Loomcore.prepareAndroidV2PrivateDeviceConfigFetchPlan(current, delivery, identity).decodeToString())
        val mirrors = plan.getJSONArray("mirrors")
        val refs = plan.getJSONArray("refs")
        val runtime = (0 until refs.length()).map(refs::getJSONObject).single { it.getString("artifact_id") == "android-runtime" }
        val attempts = JSONArray()
        for (index in 0 until mirrors.length()) {
            val selected = JSONObject(plan.toString()).put("mirrors", JSONArray().put(mirrors.getJSONObject(index)))
                .put("refs", JSONArray().put(runtime))
            val fetched = runCatching {
                V2MirrorFetcher(scoped).fetchCompletionConfigs(Loomcore.canonicalizeV2(selected.toString().encodeToByteArray()))
            }
            val failures = JSONArray()
            generateSequence(fetched.exceptionOrNull()) { it.cause }.take(8).forEach {
                failures.put(JSONObject().put("type", it.javaClass.name).put("message", it.message))
            }
            attempts.put(JSONObject().put("mirror", index).put("verified", fetched.isSuccess).put("failures", failures))
        }
        result.put("attempts", attempts)
        context.getExternalFilesDir(null)!!.resolve("config-mirror-diagnostic.json").writeText(result.toString())
        println("config-mirror-attempts=${attempts.length()}")
    }
}
