package io.github.scisaga.loom.profiles

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
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
        assertEquals("家庭网络", decodeProfileIndex(encoded).viewed?.name)
        assertEquals(
            "{\"schema\":1,\"viewed_profile_id\":\"0123456789abcdef0123456789abcdef\"," +
                "\"profiles\":[{\"id\":\"primary\",\"name\":\"Loom A\"}," +
                "{\"id\":\"0123456789abcdef0123456789abcdef\",\"name\":\"家庭网络\"}]}",
            encoded.decodeToString(),
        )
    }

    @Test
    fun strictCodecRejectsNonCanonicalOrAmbiguousCatalogs() {
        listOf(
            "{\"schema\":1,\"viewed_profile_id\":\"primary\",\"profiles\":[]}",
            "{\"schema\":1,\"viewed_profile_id\":\"\",\"profiles\":[{\"id\":\"primary\",\"name\":\"Loom A\"}]}",
            "{\"schema\":1,\"viewed_profile_id\":\"primary\",\"profiles\":[{\"id\":\"primary\",\"name\":\"Loom A\"}],\"extra\":0}",
            "{\"schema\":1,\"schema\":1,\"viewed_profile_id\":\"primary\",\"profiles\":[{\"id\":\"primary\",\"name\":\"Loom A\"}]}",
            "{\"schema\":1,\"viewed_profile_id\":\"missing\",\"profiles\":[{\"id\":\"primary\",\"name\":\"Loom A\"}]}",
            "{\"schema\":1,\"viewed_profile_id\":\"primary\",\"profiles\":[{\"id\":\"primary\",\"name\":\"Loom A\"},{\"id\":\"primary\",\"name\":\"Loom B\"}]}",
            "{\"schema\":1,\"viewed_profile_id\":\"primary\",\"profiles\":[{\"id\":\"primary\",\"name\":\"Loom A\"},{\"id\":\"0123456789abcdef0123456789abcdef\",\"name\":\"Loom A\"}]}",
            "{ \"schema\":1,\"viewed_profile_id\":\"primary\",\"profiles\":[{\"id\":\"primary\",\"name\":\"Loom A\"}]}",
        ).forEach { body ->
            assertThrows(IllegalArgumentException::class.java) {
                decodeProfileIndex(body.encodeToByteArray())
            }
        }
    }

    @Test
    fun deletingFinalProfilePersistsEmptyCatalogWithoutResurrectingIdentity() {
        val original = ProfileIndex(listOf(ConnectionProfile(ProfileStorage.PRIMARY_ID, "Loom A")), ProfileStorage.PRIMARY_ID)
        val empty = original.withoutProfile(ProfileStorage.PRIMARY_ID)
        assertTrue(empty.profiles.isEmpty())
        assertEquals("", empty.viewedProfileId)
        assertNull(empty.viewed)
        val encoded = encodeProfileIndex(empty)
        assertEquals("{\"schema\":1,\"viewed_profile_id\":\"\",\"profiles\":[]}", encoded.decodeToString())
        val storage = RecordingStore().apply {
            seed("profile-index-v1", encoded)
            seed("device-state-v2", byteArrayOf(9))
            seed(ProfileStorage.state(ProfileStorage.PRIMARY_ID), byteArrayOf(1, 2, 3))
        }
        val replay = loadOrMigrateProfileIndex(storage) { error("空目录不得恢复已删除身份") }
        assertEquals(empty, replay)
        assertArrayEquals(encoded, encodeProfileIndex(replay))
        assertNull(storage.bytes("device-state-v2"))
        val added = ConnectionProfile("0123456789abcdef0123456789abcdef", "Loom A")
        val recreated = ProfileIndex(replay.profiles + added, added.id)
        assertEquals(added, decodeProfileIndex(encodeProfileIndex(recreated)).viewed)
    }

    @Test
    fun deletionKeepsExistingViewedProfileOrSelectsRemainingRow() {
        val first = ConnectionProfile(ProfileStorage.PRIMARY_ID, "Loom A")
        val second = ConnectionProfile("0123456789abcdef0123456789abcdef", "Loom B")
        val index = ProfileIndex(listOf(first, second), second.id)
        assertEquals(second, index.withoutProfile(first.id).viewed)
        assertEquals(first, index.withoutProfile(second.id).viewed)
        assertThrows(IllegalStateException::class.java) { index.withoutProfile("missing") }
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
        assertThrows(IllegalArgumentException::class.java) { ProfileStorage.state("../escape") }
        assertEquals("Loom A", checkedProfileName("  Loom A  "))
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
        assertEquals("Loom A", index.viewed?.name)
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

        val replay = RecordingStore().apply {
            seed("profile-index-v1", encodeProfileIndex(index))
            seed("device-state-v2", byteArrayOf(9))
        }
        assertEquals(index, loadOrMigrateProfileIndex(replay) { error("不得回读旧槽") })
        assertNull(replay.bytes("device-state-v2"))
    }

    private class RecordingStore : ProfileByteStore {
        private val values = linkedMapOf<String, ByteArray>()
        private val puts = mutableListOf<String>()
        fun seed(key: String, value: ByteArray) {
            values[key] = value.copyOf()
        }

        fun bytes(key: String): ByteArray? = values[key]?.copyOf()

        fun firstPut(key: String): Int = puts.indexOf(key)

        override fun get(key: String): ByteArray? {
            return values[key]?.copyOf()
        }

        override fun put(key: String, value: ByteArray) {
            puts += key
            values[key] = value.copyOf()
        }

        override fun remove(key: String) {
            values.remove(key)
        }
    }
}
