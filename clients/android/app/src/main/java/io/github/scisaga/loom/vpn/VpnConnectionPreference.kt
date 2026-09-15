package io.github.scisaga.loom.vpn

import android.content.Context
import io.github.scisaga.loom.profiles.ProfileContext

/** §8.3：只保存非秘密的用户连接意图，身份和配置仍由 Keystore 保护。 */
class VpnConnectionPreference(context: Context) {
    private val preferences = ProfileContext.root(context).getSharedPreferences(FILE, Context.MODE_PRIVATE)

    fun desiredConnected(): Boolean = preferences.getBoolean(DESIRED_CONNECTED, false)

    fun profileId(): String = preferences.getString("profile-id", ProfileContext.LEGACY_PROFILE)!!

    @Suppress("ApplySharedPref")
    fun setProfileId(id: String) {
        check(preferences.edit().putString("profile-id", id).commit()) { "无法保存连接配置" }
    }

    @Suppress("ApplySharedPref")
    fun setDesiredConnected(desired: Boolean) {
        check(preferences.edit().putBoolean(DESIRED_CONNECTED, desired).commit()) {
            "无法持久化 VPN 连接意图"
        }
    }

    private companion object {
        const val FILE = "vpn-lifecycle"
        const val DESIRED_CONNECTED = "desired-connected"
    }
}
