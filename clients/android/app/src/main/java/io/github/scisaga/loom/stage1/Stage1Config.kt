package io.github.scisaga.loom.stage1

import android.content.Context
import android.util.Base64
import io.github.scisaga.libbox.Libbox
import io.github.scisaga.loomcore.Loomcore

data class VerifiedStage1Config(val content: String)

object Stage1Config {
    fun load(context: Context, emulatorProxy: Boolean = false): VerifiedStage1Config {
        val stem = if (emulatorProxy) "emulator-config" else "config"
        val config = context.assets.open("stage1/$stem.json").use { it.readBytes() }
        val signature = decodeAsset(context, "stage1/$stem.sig.b64")
        val publicKey = decodeAsset(context, "stage1/$stem.pub.b64")
        Loomcore.verifySignedConfig(config, signature, publicKey)
        val content = config.decodeToString()
        Libbox.checkConfig(content)
        return VerifiedStage1Config(content)
    }

    private fun decodeAsset(context: Context, name: String): ByteArray {
        val value = context.assets.open(name).bufferedReader().use { it.readText() }.trim()
        return Base64.decode(value, Base64.NO_WRAP)
    }
}
