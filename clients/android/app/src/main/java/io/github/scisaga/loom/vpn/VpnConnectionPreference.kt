package io.github.scisaga.loom.vpn

import android.content.Context
import io.github.scisaga.loom.profiles.ProfileStorage
import io.github.scisaga.loom.profiles.validProfileId

/** §8.3：只保存非秘密的用户连接意图，身份和配置仍由 Keystore 保护。 */
class VpnConnectionPreference(context: Context) {
    private val preferences = context.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE)

    init {
        migrateLegacySingleProfileIntent()
    }

    fun desiredConnected(): Boolean = preferences.getBoolean(DESIRED_CONNECTED, false)
    fun profileId(): String = preferences.getString(PROFILE_ID, "").orEmpty().also { id ->
        require(id.isEmpty() || validProfileId(id)) { "已保存的连接配置标识无效" }
    }

    @Suppress("ApplySharedPref")
    fun save(desired: Boolean, profileId: String) {
        require(profileId.isEmpty() || validProfileId(profileId)) { "连接配置标识无效" }
        require(!desired || profileId.isNotEmpty()) { "连接意图缺少配置标识" }
        check(
            preferences.edit()
                .putBoolean(DESIRED_CONNECTED, desired)
                .putString(PROFILE_ID, profileId)
                .commit(),
        ) {
            "无法持久化 VPN 连接意图"
        }
    }

    /** One forward migration from the former single protected slot; it is never a fallback. */
    @Suppress("ApplySharedPref")
    private fun migrateLegacySingleProfileIntent() {
        if (preferences.getBoolean(PROFILE_MIGRATION_COMPLETE, false)) return
        val existing = preferences.getString(PROFILE_ID, "").orEmpty()
        require(existing.isEmpty() || validProfileId(existing)) { "已保存的连接配置标识无效" }
        val editor = preferences.edit()
        if (existing.isEmpty()) {
            editor.putString(PROFILE_ID, ProfileStorage.PRIMARY_ID)
        }
        check(editor.putBoolean(PROFILE_MIGRATION_COMPLETE, true).commit()) {
            "无法迁移 VPN 连接意图"
        }
    }

    private companion object {
        const val FILE = "vpn-lifecycle"
        const val DESIRED_CONNECTED = "desired-connected"
        const val PROFILE_ID = "profile-id"
        const val PROFILE_MIGRATION_COMPLETE = "profile-migration-v1"
    }
}
