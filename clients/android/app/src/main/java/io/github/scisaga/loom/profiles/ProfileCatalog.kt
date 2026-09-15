package io.github.scisaga.loom.profiles

import android.content.Context
import android.content.ContextWrapper
import io.github.scisaga.loom.security.DeviceKeyStore
import io.github.scisaga.loom.security.EncryptedStore
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.UUID

data class ConnectionProfile(val id: String, val name: String)

data class ProfileList(val profiles: List<ConnectionProfile>, val selectedId: String) {
    val selected: ConnectionProfile get() = profiles.first { it.id == selectedId }
}

/** 旧配置保留原目录和 Keystore alias，新增配置永远使用独立的命名空间。 */
class ProfileContext(context: Context, val profileId: String) : ContextWrapper(root(context)) {
    init { require(validProfileId(profileId)) { "配置标识无效" } }

    override fun getApplicationContext(): Context = this
    override fun getFilesDir(): File = if (profileId == LEGACY_PROFILE) super.getFilesDir()
        else super.getFilesDir().resolve("profiles/$profileId").apply { mkdirs() }
    override fun getCacheDir(): File = if (profileId == LEGACY_PROFILE) super.getCacheDir()
        else super.getCacheDir().resolve("profiles/$profileId").apply { mkdirs() }

    companion object {
        const val LEGACY_PROFILE = "legacy"
        fun root(context: Context): Context =
            if (context is ProfileContext) root(context.baseContext) else context.applicationContext
        fun id(context: Context): String = (context as? ProfileContext)?.profileId ?: LEGACY_PROFILE
        fun keySuffix(context: Context): String = id(context).let { if (it == LEGACY_PROFILE) "" else "-$it" }
    }
}

internal fun validProfileId(id: String): Boolean =
    id == ProfileContext.LEGACY_PROFILE || id.matches(Regex("[a-f0-9]{32}"))

class ProfileCatalog private constructor(context: Context) {
    private val root = ProfileContext.root(context)
    private val protected = EncryptedStore(root)
    private val mutable = MutableStateFlow(load())
    val state = mutable.asStateFlow()

    private fun load(): ProfileList {
        val bytes = protected.get(INDEX) ?: return ProfileList(
            listOf(ConnectionProfile(ProfileContext.LEGACY_PROFILE, "默认配置")),
            ProfileContext.LEGACY_PROFILE,
        ).also(::persist)
        val json = JSONObject(bytes.decodeToString())
        check(json.getInt("schema") == 1) { "配置目录版本无效" }
        val rows = json.getJSONArray("profiles")
        val profiles = (0 until rows.length()).map { index ->
            val row = rows.getJSONObject(index)
            ConnectionProfile(row.getString("id"), row.getString("name"))
        }
        check(profiles.isNotEmpty() && profiles.map { it.id }.distinct().size == profiles.size &&
            profiles.all { validProfileId(it.id) && it.name.isNotBlank() }) { "配置目录无效" }
        return ProfileList(profiles, json.getString("selected")).also {
            check(profiles.any { row -> row.id == it.selectedId }) { "所选配置不存在" }
        }
    }

    private fun persist(value: ProfileList) {
        val rows = JSONArray()
        value.profiles.forEach { rows.put(JSONObject().put("id", it.id).put("name", it.name)) }
        protected.put(INDEX, JSONObject().put("schema", 1).put("selected", value.selectedId)
            .put("profiles", rows).toString().encodeToByteArray())
    }

    private fun publish(value: ProfileList) { persist(value); mutable.value = value }

    @Synchronized
    fun create(name: String = "新配置"): ConnectionProfile {
        val profile = ConnectionProfile(UUID.randomUUID().toString().replace("-", ""), checkedName(name))
        publish(ProfileList(mutable.value.profiles + profile, profile.id))
        return profile
    }

    @Synchronized
    fun select(id: String) {
        requireContains(id)
        publish(mutable.value.copy(selectedId = id))
    }

    @Synchronized
    fun rename(id: String, name: String) {
        requireContains(id)
        publish(mutable.value.copy(profiles = mutable.value.profiles.map {
            if (it.id == id) it.copy(name = checkedName(name)) else it
        }))
    }

    @Synchronized
    fun context(id: String = mutable.value.selectedId): ProfileContext {
        requireContains(id)
        return ProfileContext(root, id)
    }

    @Synchronized
    fun contains(id: String): Boolean = mutable.value.profiles.any { it.id == id }

    /** 调用者先等宿主和此配置的任务停止；删除不影响其他配置的身份。 */
    @Synchronized
    internal fun removeStopped(id: String) {
        requireContains(id)
        val scoped = context(id)
        var remaining = mutable.value.profiles.filterNot { it.id == id }
        if (remaining.isEmpty()) {
            remaining = listOf(ConnectionProfile(UUID.randomUUID().toString().replace("-", ""), "默认配置"))
        }
        publish(ProfileList(remaining, mutable.value.selectedId.takeIf { selected ->
            remaining.any { it.id == selected }
        } ?: remaining.first().id))
        DeviceKeyStore(ProfileContext.keySuffix(scoped)).deleteIdentity()
        if (id == ProfileContext.LEGACY_PROFILE) {
            scoped.filesDir.resolve("protected").listFiles().orEmpty().filter { it.name != INDEX }.forEach {
                check(it.delete()) { "无法移除原配置数据" }
            }
            scoped.filesDir.resolve("libbox").listFiles().orEmpty().forEach {
                check(it.deleteRecursively()) { "无法移除原配置缓存" }
            }
        } else {
            EncryptedStore(scoped).deleteStorageKey()
            check(scoped.filesDir.deleteRecursively()) { "无法移除配置数据" }
            check(scoped.cacheDir.deleteRecursively()) { "无法移除配置缓存" }
        }
    }

    private fun requireContains(id: String) { check(contains(id)) { "配置已被删除" } }
    private fun checkedName(name: String): String = name.trim().also {
        require(it.isNotEmpty() && it.length <= 64 && it.none(Char::isISOControl)) { "配置名称需为 1–64 个字符" }
    }

    companion object {
        private const val INDEX = "connection-profiles"
        private val instances = mutableMapOf<String, ProfileCatalog>()
        @Synchronized
        fun get(context: Context): ProfileCatalog = ProfileContext.root(context).let { root ->
            instances.getOrPut(root.filesDir.absolutePath) { ProfileCatalog(root) }
        }
        fun scoped(context: Context): ProfileContext = if (context is ProfileContext)
            get(context).context(context.profileId) else get(context).context()
    }
}
