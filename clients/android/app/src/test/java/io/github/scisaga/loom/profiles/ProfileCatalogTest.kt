package io.github.scisaga.loom.profiles

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class ProfileCatalogTest {
    @Test
    fun strictCodecRoundTripsNamesAndViewedProfile() {
        val index = ProfileIndex(
            profiles = listOf(
                ConnectionProfile(ProfileStorage.PRIMARY_ID, "Loom A"),
                ConnectionProfile("0123456789abcdef0123456789abcdef", "家庭网络"),
            ),
            viewedProfileId = "0123456789abcdef0123456789abcdef",
        )

        val encoded = encodeProfileIndex(index)

        assertEquals(index, decodeProfileIndex(encoded))
        assertEquals("家庭网络", decodeProfileIndex(encoded).viewed.name)
        assertEquals(
            "{\"schema\":1,\"viewed_profile_id\":\"0123456789abcdef0123456789abcdef\"," +
                "\"profiles\":[{\"id\":\"primary\",\"name\":\"Loom A\"}," +
                "{\"id\":\"0123456789abcdef0123456789abcdef\",\"name\":\"家庭网络\"}]}",
            encoded.decodeToString(),
        )
    }

    @Test
    fun strictCodecRejectsUnknownDuplicateDanglingAndNonCanonicalValues() {
        listOf(
            "{\"schema\":1,\"viewed_profile_id\":\"primary\",\"profiles\":[{\"id\":\"primary\",\"name\":\"Loom A\"}],\"extra\":0}",
            "{\"schema\":1,\"schema\":1,\"viewed_profile_id\":\"primary\",\"profiles\":[{\"id\":\"primary\",\"name\":\"Loom A\"}]}",
            "{\"schema\":1,\"viewed_profile_id\":\"missing\",\"profiles\":[{\"id\":\"primary\",\"name\":\"Loom A\"}]}",
            "{\"schema\":1,\"viewed_profile_id\":\"primary\",\"profiles\":[{\"id\":\"primary\",\"name\":\"Loom A\"},{\"id\":\"primary\",\"name\":\"Loom B\"}]}",
            "{\"schema\":1,\"viewed_profile_id\":\"bad-id\",\"profiles\":[{\"id\":\"bad-id\",\"name\":\"Loom A\"}]}",
            "{\"schema\":1,\"viewed_profile_id\":\"primary\",\"profiles\":[{\"id\":\"primary\",\"name\":\" Loom A \"}]}",
            "{ \"schema\":1,\"viewed_profile_id\":\"primary\",\"profiles\":[{\"id\":\"primary\",\"name\":\"Loom A\"}]}",
        ).forEach { body ->
            assertThrows(IllegalArgumentException::class.java) {
                decodeProfileIndex(body.encodeToByteArray())
            }
        }
    }

    @Test
    fun storageKeysAreExplicitlyNamespaced() {
        val id = "fedcba9876543210fedcba9876543210"

        assertEquals("p.$id.device-state-v2", ProfileStorage.state(id))
        assertEquals("p.$id.device-candidate-v2", ProfileStorage.candidate(id))
        assertEquals("p.$id.route-preference-v2", ProfileStorage.routePreference(id))
        assertEquals("p.$id.route-observations-v2", ProfileStorage.observations(id))
        assertEquals("p.$id.network-generation-v2", ProfileStorage.networkGeneration(id))
        assertEquals("p.$id.network-identity-v2", ProfileStorage.networkIdentity(id))
        assertTrue(ProfileStorage.validId(ProfileStorage.PRIMARY_ID))
        assertFalse(ProfileStorage.validId("PRIMARY"))
        assertThrows(IllegalArgumentException::class.java) { ProfileStorage.state("../escape") }
        assertEquals("Loom A", checkedProfileName("  Loom A  "))
        assertThrows(IllegalArgumentException::class.java) { checkedProfileName("line\nbreak") }
    }

    @Test
    fun oneSlotMigrationCopiesExactBytesBeforeCommittingIndex() {
        val storage = RecordingStore()
        val legacy = linkedMapOf(
            "device-state-v2" to byteArrayOf(1, 2, 3),
            "device-candidate-v2" to byteArrayOf(4, 5, 6),
            "route-preference-v2" to "preference".encodeToByteArray(),
            "route-observations-v2" to "observations".encodeToByteArray(),
            "network-generation-v2" to "generation".encodeToByteArray(),
            "network-identity-v2" to "identity".encodeToByteArray(),
        )
        legacy.forEach(storage::seed)
        val validated = mutableListOf<ByteArray>()

        val index = loadOrMigrateProfileIndex(storage) { validated += it.copyOf() }

        assertEquals(ProfileStorage.PRIMARY_ID, index.viewedProfileId)
        assertEquals("Loom A", index.viewed.name)
        assertEquals(2, validated.size)
        legacy.forEach { (oldKey, value) ->
            assertNull(storage.bytes(oldKey))
            val newKey = when (oldKey) {
                "device-state-v2" -> ProfileStorage.state(ProfileStorage.PRIMARY_ID)
                "device-candidate-v2" -> ProfileStorage.candidate(ProfileStorage.PRIMARY_ID)
                "route-preference-v2" -> ProfileStorage.routePreference(ProfileStorage.PRIMARY_ID)
                "route-observations-v2" -> ProfileStorage.observations(ProfileStorage.PRIMARY_ID)
                "network-generation-v2" -> ProfileStorage.networkGeneration(ProfileStorage.PRIMARY_ID)
                else -> ProfileStorage.networkIdentity(ProfileStorage.PRIMARY_ID)
            }
            assertArrayEquals(value, storage.bytes(newKey))
            assertTrue(storage.firstPut(newKey) < storage.firstPut("profile-index-v1"))
        }
    }

    @Test
    fun committedIndexNeverReadsLegacySlots() {
        val storage = RecordingStore()
        val index = ProfileIndex(
            listOf(ConnectionProfile(ProfileStorage.PRIMARY_ID, "Loom A")),
            ProfileStorage.PRIMARY_ID,
        )
        storage.seed("profile-index-v1", encodeProfileIndex(index))
        storage.seed("device-state-v2", byteArrayOf(9))

        assertEquals(index, loadOrMigrateProfileIndex(storage) { error("must not validate legacy") })

        assertFalse("device-state-v2" in storage.reads)
        assertNull(storage.bytes("device-state-v2"))
    }

    @Test
    fun invalidLegacyDeviceStateLeavesOldSlotAuthoritative() {
        val storage = RecordingStore()
        val legacyState = byteArrayOf(7, 8, 9)
        storage.seed("device-state-v2", legacyState)

        assertThrows(IllegalArgumentException::class.java) {
            loadOrMigrateProfileIndex(storage) { throw IllegalArgumentException("invalid state") }
        }

        assertArrayEquals(legacyState, storage.bytes("device-state-v2"))
        assertNull(storage.bytes(ProfileStorage.state(ProfileStorage.PRIMARY_ID)))
        assertNull(storage.bytes("profile-index-v1"))
    }

    @Test
    fun failedIndexReadbackDoesNotCommitMigration() {
        val storage = RecordingStore()
        val legacyState = byteArrayOf(3, 2, 1)
        storage.seed("device-state-v2", legacyState)
        storage.corruptNextIndexWrite = true

        assertThrows(IllegalStateException::class.java) {
            loadOrMigrateProfileIndex(storage) { }
        }

        assertArrayEquals(legacyState, storage.bytes("device-state-v2"))
        assertNull(storage.bytes("profile-index-v1"))
    }

    private class RecordingStore : ProfileByteStore {
        private val values = linkedMapOf<String, ByteArray>()
        private val puts = mutableListOf<String>()
        val reads = mutableListOf<String>()
        var corruptNextIndexWrite = false

        fun seed(key: String, value: ByteArray) {
            values[key] = value.copyOf()
        }

        fun bytes(key: String): ByteArray? = values[key]?.copyOf()

        fun firstPut(key: String): Int = puts.indexOf(key)

        override fun get(key: String): ByteArray? {
            reads += key
            return values[key]?.copyOf()
        }

        override fun put(key: String, value: ByteArray) {
            puts += key
            values[key] = if (key == "profile-index-v1" && corruptNextIndexWrite) {
                corruptNextIndexWrite = false
                value.copyOf().also { it[it.lastIndex] = (it.last() + 1).toByte() }
            } else {
                value.copyOf()
            }
        }

        override fun remove(key: String) {
            values.remove(key)
        }
    }
}
