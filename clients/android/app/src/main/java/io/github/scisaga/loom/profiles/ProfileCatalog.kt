package io.github.scisaga.loom.profiles

import android.content.Context
import io.github.scisaga.loom.security.EncryptedStore
import io.github.scisaga.loomcore.Loomcore
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.util.UUID

data class ConnectionProfile(val id: String, val name: String) {
    init {
        require(ProfileStorage.validId(id)) { "配置标识无效" }
        require(name == normalizeProfileName(name)) { "配置名称必须是规范值" }
    }
}

data class ProfileIndex(
    val profiles: List<ConnectionProfile>,
    val viewedProfileId: String,
) {
    init {
        require(profiles.isNotEmpty()) { "配置目录不能为空" }
        require(profiles.map(ConnectionProfile::id).distinct().size == profiles.size) { "配置标识重复" }
        require(profiles.any { it.id == viewedProfileId }) { "当前查看的配置不存在" }
    }

    val viewed: ConnectionProfile
        get() = profiles.first { it.id == viewedProfileId }
}

/** Local profile identifiers only namespace protected host state; they are never wire device IDs. */
object ProfileStorage {
    const val PRIMARY_ID = "primary"

    private val generatedID = Regex("[a-f0-9]{32}")

    fun validId(id: String): Boolean = id == PRIMARY_ID || generatedID.matches(id)

    fun state(profileId: String): String = key(profileId, "device-state-v2")

    fun candidate(profileId: String): String = key(profileId, "device-candidate-v2")

    fun routePreference(profileId: String): String = key(profileId, "route-preference-v2")

    fun observations(profileId: String): String = key(profileId, "route-observations-v2")

    fun networkGeneration(profileId: String): String = key(profileId, "network-generation-v2")

    fun networkIdentity(profileId: String): String = key(profileId, "network-identity-v2")

    private fun key(profileId: String, suffix: String): String {
        require(validId(profileId)) { "配置标识无效" }
        return "p.$profileId.$suffix"
    }
}

fun validProfileId(id: String): Boolean = ProfileStorage.validId(id)

fun checkedProfileName(name: String): String = normalizeProfileName(name)

/**
 * Stores only local profile names and the row currently viewed by the UI. Device authority,
 * route preference, observations and runtime readback remain in their explicitly scoped slots.
 */
class ProfileCatalog private constructor(context: Context) {
    private val storage = EncryptedProfileByteStore(EncryptedStore(context.applicationContext))
    private val mutableState = MutableStateFlow(
        loadOrMigrateProfileIndex(storage, Loomcore::validateAndroidDeviceState),
    )
    val state = mutableState.asStateFlow()

    @Synchronized
    fun create(name: String): ConnectionProfile {
        val profile = ConnectionProfile(newID(), normalizeProfileName(name))
        publish(ProfileIndex(mutableState.value.profiles + profile, profile.id))
        return profile
    }

    @Synchronized
    fun view(id: String) {
        requireContains(id)
        publish(mutableState.value.copy(viewedProfileId = id))
    }

    @Synchronized
    fun rename(id: String, name: String) {
        requireContains(id)
        val normalized = normalizeProfileName(name)
        publish(
            mutableState.value.copy(
                profiles = mutableState.value.profiles.map { profile ->
                    if (profile.id == id) profile.copy(name = normalized) else profile
                },
            ),
        )
    }

    /** Removes only the index row. The caller owns stopping runtime and deleting scoped bytes. */
    @Synchronized
    fun removeIndex(id: String): ProfileIndex {
        requireContains(id)
        var remaining = mutableState.value.profiles.filterNot { it.id == id }
        if (remaining.isEmpty()) {
            remaining = listOf(ConnectionProfile(newID(), DEFAULT_PROFILE_NAME))
        }
        val viewed = mutableState.value.viewedProfileId.takeIf { selected ->
            remaining.any { it.id == selected }
        } ?: remaining.first().id
        return ProfileIndex(remaining, viewed).also(::publish)
    }

    @Synchronized
    fun contains(id: String): Boolean = mutableState.value.profiles.any { it.id == id }

    @Synchronized
    fun name(id: String): String {
        requireContains(id)
        return mutableState.value.profiles.first { it.id == id }.name
    }

    private fun publish(value: ProfileIndex) {
        persistProfileIndex(storage, value)
        mutableState.value = value
    }

    private fun requireContains(id: String) {
        check(contains(id)) { "配置已不存在" }
    }

    private fun newID(): String {
        while (true) {
            val candidate = UUID.randomUUID().toString().replace("-", "")
            if (!contains(candidate)) return candidate
        }
    }

    companion object {
        private val instances = mutableMapOf<String, ProfileCatalog>()

        @Synchronized
        fun get(context: Context): ProfileCatalog {
            val root = context.applicationContext
            return instances.getOrPut(root.filesDir.absolutePath) { ProfileCatalog(root) }
        }
    }
}

private const val PROFILE_INDEX_KEY = "profile-index-v1"
private const val DEFAULT_PROFILE_NAME = "Loom A"

private data class LegacySlot(val oldKey: String, val newKey: String, val validatesDeviceState: Boolean = false)

private val legacySlots = listOf(
    LegacySlot("device-state-v2", ProfileStorage.state(ProfileStorage.PRIMARY_ID), validatesDeviceState = true),
    LegacySlot("device-candidate-v2", ProfileStorage.candidate(ProfileStorage.PRIMARY_ID), validatesDeviceState = true),
    LegacySlot("route-preference-v2", ProfileStorage.routePreference(ProfileStorage.PRIMARY_ID)),
    LegacySlot("route-observations-v2", ProfileStorage.observations(ProfileStorage.PRIMARY_ID)),
    LegacySlot("network-generation-v2", ProfileStorage.networkGeneration(ProfileStorage.PRIMARY_ID)),
    LegacySlot("network-identity-v2", ProfileStorage.networkIdentity(ProfileStorage.PRIMARY_ID)),
)

internal interface ProfileByteStore {
    fun get(key: String): ByteArray?
    fun put(key: String, value: ByteArray)
    fun remove(key: String)
}

private class EncryptedProfileByteStore(private val delegate: EncryptedStore) : ProfileByteStore {
    override fun get(key: String): ByteArray? = delegate.get(key)
    override fun put(key: String, value: ByteArray) = delegate.put(key, value)
    override fun remove(key: String) = delegate.remove(key)
}

internal fun loadOrMigrateProfileIndex(
    storage: ProfileByteStore,
    validateDeviceState: (ByteArray) -> Unit,
): ProfileIndex {
    storage.get(PROFILE_INDEX_KEY)?.let { body ->
        val index = decodeProfileIndex(body)
        // An index is the commit marker. Old keys are never read on this path; residual copies
        // from a crash after the commit can only be deleted.
        legacySlots.forEach { storage.remove(it.oldKey) }
        return index
    }

    val legacy = legacySlots.map { slot -> slot to storage.get(slot.oldKey) }
    legacy.forEach { (slot, body) ->
        if (body != null && slot.validatesDeviceState) validateDeviceState(body)
    }
    legacy.forEach { (slot, body) ->
        if (body == null) return@forEach
        storage.put(slot.newKey, body)
        check(storage.get(slot.newKey)?.contentEquals(body) == true) {
            "配置数据迁移回读不一致"
        }
    }

    val index = ProfileIndex(
        profiles = listOf(ConnectionProfile(ProfileStorage.PRIMARY_ID, DEFAULT_PROFILE_NAME)),
        viewedProfileId = ProfileStorage.PRIMARY_ID,
    )
    persistProfileIndex(storage, index)
    legacySlots.forEach { storage.remove(it.oldKey) }
    return index
}

private fun persistProfileIndex(storage: ProfileByteStore, index: ProfileIndex) {
    val previous = storage.get(PROFILE_INDEX_KEY)
    val body = encodeProfileIndex(index)
    try {
        storage.put(PROFILE_INDEX_KEY, body)
        val replay = checkNotNull(storage.get(PROFILE_INDEX_KEY)) { "配置目录未能持久保存" }
        check(replay.contentEquals(body)) { "配置目录持久化回读不一致" }
        check(decodeProfileIndex(replay) == index) { "配置目录持久化语义不一致" }
    } catch (error: Throwable) {
        runCatching {
            if (previous == null) {
                storage.remove(PROFILE_INDEX_KEY)
            } else {
                storage.put(PROFILE_INDEX_KEY, previous)
                check(storage.get(PROFILE_INDEX_KEY)?.contentEquals(previous) == true) {
                    "配置目录回滚回读不一致"
                }
            }
        }.onFailure(error::addSuppressed)
        throw error
    }
}

private fun normalizeProfileName(raw: String): String = raw.trim().also { name ->
    require(name.isNotEmpty() && name.length <= 64 && name.none(Char::isISOControl)) {
        "配置名称需为 1–64 个字符且不能包含控制字符"
    }
    require(wellFormedUnicode(name)) { "配置名称包含无效 Unicode" }
}

private fun wellFormedUnicode(value: String): Boolean {
    var index = 0
    while (index < value.length) {
        val current = value[index]
        when {
            Character.isHighSurrogate(current) -> {
                if (index + 1 >= value.length || !Character.isLowSurrogate(value[index + 1])) return false
                index += 2
            }
            Character.isLowSurrogate(current) -> return false
            else -> index++
        }
    }
    return true
}

internal fun encodeProfileIndex(index: ProfileIndex): ByteArray {
    val profiles = index.profiles.joinToString(separator = ",") { profile ->
        "{\"id\":${encodeJSONString(profile.id)},\"name\":${encodeJSONString(profile.name)}}"
    }
    return (
        "{\"schema\":1,\"viewed_profile_id\":${encodeJSONString(index.viewedProfileId)}," +
            "\"profiles\":[$profiles]}"
    ).encodeToByteArray()
}

internal fun decodeProfileIndex(body: ByteArray): ProfileIndex {
    require(body.isNotEmpty() && body.size <= 64 * 1024) { "配置目录大小无效" }
    val text = try {
        StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(body))
            .toString()
    } catch (error: CharacterCodingException) {
        throw IllegalArgumentException("配置目录 UTF-8 无效", error)
    }
    val root = StrictJSONParser(text).parse().asObject("配置目录")
    root.requireKeys(setOf("schema", "viewed_profile_id", "profiles"), "配置目录")
    require(root.values.getValue("schema").asInteger("schema") == 1L) { "配置目录 schema 无效" }
    val profiles = root.values.getValue("profiles").asArray("profiles").values.map { value ->
        val row = value.asObject("profile")
        row.requireKeys(setOf("id", "name"), "profile")
        ConnectionProfile(
            id = row.values.getValue("id").asString("profile.id"),
            name = row.values.getValue("name").asString("profile.name"),
        )
    }
    val decoded = ProfileIndex(
        profiles = profiles,
        viewedProfileId = root.values.getValue("viewed_profile_id").asString("viewed_profile_id"),
    )
    require(encodeProfileIndex(decoded).contentEquals(body)) { "配置目录不是规范 JSON" }
    return decoded
}

private fun encodeJSONString(value: String): String = buildString(value.length + 2) {
    append('"')
    value.forEach { character ->
        when (character) {
            '"' -> append("\\\"")
            '\\' -> append("\\\\")
            '\b' -> append("\\b")
            '\u000c' -> append("\\f")
            '\n' -> append("\\n")
            '\r' -> append("\\r")
            '\t' -> append("\\t")
            else -> if (character.code < 0x20) {
                append("\\u")
                append(character.code.toString(16).padStart(4, '0'))
            } else {
                append(character)
            }
        }
    }
    append('"')
}

private sealed interface JSONValue
private data class JSONObjectValue(val values: LinkedHashMap<String, JSONValue>) : JSONValue
private data class JSONArrayValue(val values: List<JSONValue>) : JSONValue
private data class JSONStringValue(val value: String) : JSONValue
private data class JSONNumberValue(val value: String) : JSONValue
private data class JSONLiteralValue(val value: String) : JSONValue

private fun JSONValue.asObject(label: String): JSONObjectValue = this as? JSONObjectValue
    ?: throw IllegalArgumentException("$label 必须是 object")

private fun JSONValue.asArray(label: String): JSONArrayValue = this as? JSONArrayValue
    ?: throw IllegalArgumentException("$label 必须是 array")

private fun JSONValue.asString(label: String): String = (this as? JSONStringValue)?.value
    ?: throw IllegalArgumentException("$label 必须是 string")

private fun JSONValue.asInteger(label: String): Long = (this as? JSONNumberValue)?.value
    ?.takeIf { it.matches(Regex("-?(0|[1-9][0-9]*)")) }
    ?.toLongOrNull()
    ?: throw IllegalArgumentException("$label 必须是 integer")

private fun JSONObjectValue.requireKeys(expected: Set<String>, label: String) {
    require(values.keys == expected) { "$label 含未知或缺失字段" }
}

/** A deliberately small strict parser for the protected profile-index JSON value. */
private class StrictJSONParser(private val source: String) {
    private var offset = 0

    fun parse(): JSONValue {
        skipWhitespace()
        val value = parseValue()
        skipWhitespace()
        require(offset == source.length) { "配置目录含尾随内容" }
        return value
    }

    private fun parseValue(): JSONValue {
        require(offset < source.length) { "配置目录 JSON 被截断" }
        return when (source[offset]) {
            '{' -> parseObject()
            '[' -> parseArray()
            '"' -> JSONStringValue(parseString())
            't' -> parseLiteral("true")
            'f' -> parseLiteral("false")
            'n' -> parseLiteral("null")
            '-', in '0'..'9' -> parseNumber()
            else -> throw IllegalArgumentException("配置目录 JSON token 无效")
        }
    }

    private fun parseObject(): JSONObjectValue {
        expect('{')
        skipWhitespace()
        val values = linkedMapOf<String, JSONValue>()
        if (consume('}')) return JSONObjectValue(values)
        while (true) {
            require(offset < source.length && source[offset] == '"') { "object key 必须是 string" }
            val key = parseString()
            require(key !in values) { "object key 重复" }
            skipWhitespace()
            expect(':')
            skipWhitespace()
            values[key] = parseValue()
            skipWhitespace()
            if (consume('}')) return JSONObjectValue(values)
            expect(',')
            skipWhitespace()
        }
    }

    private fun parseArray(): JSONArrayValue {
        expect('[')
        skipWhitespace()
        val values = mutableListOf<JSONValue>()
        if (consume(']')) return JSONArrayValue(values)
        while (true) {
            values += parseValue()
            skipWhitespace()
            if (consume(']')) return JSONArrayValue(values)
            expect(',')
            skipWhitespace()
        }
    }

    private fun parseString(): String {
        expect('"')
        val value = StringBuilder()
        while (offset < source.length) {
            val character = source[offset++]
            when {
                character == '"' -> return value.toString()
                character == '\\' -> value.append(parseEscape())
                character.code < 0x20 -> throw IllegalArgumentException("string 含未转义控制字符")
                else -> value.append(character)
            }
        }
        throw IllegalArgumentException("string 未闭合")
    }

    private fun parseEscape(): Char = when (requireCharacter("escape 被截断")) {
        '"' -> '"'
        '\\' -> '\\'
        '/' -> '/'
        'b' -> '\b'
        'f' -> '\u000c'
        'n' -> '\n'
        'r' -> '\r'
        't' -> '\t'
        'u' -> {
            require(offset + 4 <= source.length) { "unicode escape 被截断" }
            val raw = source.substring(offset, offset + 4)
            require(raw.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) {
                "unicode escape 无效"
            }
            offset += 4
            raw.toInt(16).toChar()
        }
        else -> throw IllegalArgumentException("string escape 无效")
    }

    private fun parseNumber(): JSONNumberValue {
        val start = offset
        if (source[offset] == '-') offset++
        require(offset < source.length) { "number 被截断" }
        if (source[offset] == '0') {
            offset++
        } else {
            require(source[offset] in '1'..'9') { "number 无效" }
            while (offset < source.length && source[offset].isDigit()) offset++
        }
        if (offset < source.length && source[offset] == '.') {
            offset++
            require(offset < source.length && source[offset].isDigit()) { "number fraction 无效" }
            while (offset < source.length && source[offset].isDigit()) offset++
        }
        if (offset < source.length && source[offset] in setOf('e', 'E')) {
            offset++
            if (offset < source.length && source[offset] in setOf('+', '-')) offset++
            require(offset < source.length && source[offset].isDigit()) { "number exponent 无效" }
            while (offset < source.length && source[offset].isDigit()) offset++
        }
        return JSONNumberValue(source.substring(start, offset))
    }

    private fun parseLiteral(expected: String): JSONLiteralValue {
        require(source.startsWith(expected, offset)) { "literal 无效" }
        offset += expected.length
        return JSONLiteralValue(expected)
    }

    private fun requireCharacter(message: String): Char {
        require(offset < source.length) { message }
        return source[offset++]
    }

    private fun expect(character: Char) {
        require(offset < source.length && source[offset] == character) { "期望 '$character'" }
        offset++
    }

    private fun consume(character: Char): Boolean {
        if (offset >= source.length || source[offset] != character) return false
        offset++
        return true
    }

    private fun skipWhitespace() {
        while (offset < source.length && source[offset] in setOf(' ', '\n', '\r', '\t')) offset++
    }
}
