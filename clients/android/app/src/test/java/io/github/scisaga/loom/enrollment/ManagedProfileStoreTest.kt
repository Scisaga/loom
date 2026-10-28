package io.github.scisaga.loom.enrollment

import io.github.scisaga.loom.profiles.ProfileByteStore
import io.github.scisaga.loom.profiles.ProfileStorage
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

class ManagedProfileStoreTest {
    private val profileId = ProfileStorage.PRIMARY_ID
    private val stateKey = ProfileStorage.state(profileId)

    @Test
    fun unchangedReadsReuseProjectionButChangedDamagedAndRemovedBytesDoNot() {
        val storage = MemoryStorage()
        var validations = 0
        var projections = 0
        val handle = ManagedProfileStore(storage, profileId,
            validate = { validations++; check(it.decodeToString() != "demo-damaged") },
            checkAdvance = { _, _ -> }, authenticatedView = { it.decodeToString() },
            project = { bytes -> projections++; ManagedProfile("demo-device", "Demo", bytes.decodeToString(), "[]", "{}", "[]", "demo-record") },
        )
        storage.put(stateKey, "demo-first".encodeToByteArray())
        repeat(5) { handle.state(); handle.acceptedViewDigest(); handle.loadCurrent() }
        assertEquals(1, validations)
        assertEquals(1, projections)
        // Mutation of a returned byte array must not poison the cache key.
        handle.state()!!.fill(0)
        storage.put(stateKey, "demo-second".encodeToByteArray())
        assertEquals("demo-second", handle.loadCurrent()!!.viewDigest)
        assertEquals(2, projections)
        storage.put(stateKey, "demo-damaged".encodeToByteArray())
        repeat(2) { assertThrows(IllegalStateException::class.java) { handle.loadCurrent() } }
        storage.remove(stateKey)
        assertNull(handle.loadCurrent())
        storage.put(stateKey, "demo-second".encodeToByteArray())
        assertEquals("demo-second", handle.loadCurrent()!!.viewDigest)
        assertEquals(3, projections)
    }

    @Test
    fun currentCertifiedFileImportKeepsServiceChoicesAndDoesNotCreateMigrationEvidence() {
        val storage = MemoryStorage()
        val original = "demo-current-identity".encodeToByteArray()
        val next = "demo-forward-identity".encodeToByteArray()
        val choice = "demo-service-choice".encodeToByteArray()
        storage.put(stateKey, original)
        storage.put(ProfileStorage.routePreference(profileId), choice)
        var checked = false
        val handle = ManagedProfileStore(storage, profileId,
            validate = {}, checkAdvance = { after, before ->
                assertArrayEquals(next, after); assertArrayEquals(original, before); checked = true
            }, authenticatedView = { "demo-digest" },
            project = { bytes -> ManagedProfile("demo-device", "Demo", "demo-digest", "[]", "{}", "[]", bytes.decodeToString()) },
            acceptImportedView = { before, _ -> assertArrayEquals(original, before); next },
        )
        handle.importCertifiedView(byteArrayOf(1))
        assertEquals(true, checked)
        assertArrayEquals(next, handle.state())
        assertArrayEquals(choice, storage.get(ProfileStorage.routePreference(profileId)))
        assertNull(storage.get(ProfileStorage.policyIdentityEvidence(profileId)))
        assertNull(storage.get(ProfileStorage.policyPreferenceEvidence(profileId)))
    }

    @Test
    fun explicitTransportImportPreservesEvidenceBeforeReplacingSingleAuthority() {
        val storage = MemoryStorage()
        val original = "demo-signed-historical-state".encodeToByteArray()
        val replacement = "demo-forward-certified-state".encodeToByteArray()
        storage.put(stateKey, original)
        val handle = store(storage, validate = { check(!it.contentEquals(original)) }, replaceTransport = { before, next ->
            check(before.contentEquals(original))
            check(next.contentEquals(replacement))
            next
        })
        assertThrows(IllegalStateException::class.java) { handle.state() }
        storage.dropWrite = true
        assertThrows(IllegalStateException::class.java) { handle.replaceTransport(replacement) }
        assertArrayEquals(original, storage.get(stateKey))
        storage.dropWrite = false
        handle.replaceTransport(replacement)
        assertArrayEquals(original, storage.get(ProfileStorage.transportEvidence(profileId)))
        assertArrayEquals(replacement, store(storage).state())
    }

    @Test
    fun policyImportRetriesBetweenPreferenceAndIdentityWritesAndPreservesLaterChoice() {
        val storage = MemoryStorage()
        val original = "demo-historical-identity".encodeToByteArray()
        val legacy = "demo-old-preference".encodeToByteArray()
        val current = "demo-current-identity".encodeToByteArray()
        val converted = "demo-current-preference".encodeToByteArray()
        val preferenceKey = ProfileStorage.routePreference(profileId)
        storage.put(stateKey, original)
        storage.put(preferenceKey, legacy)
        val handle = ManagedProfileStore(storage, profileId,
            validate = { check(!it.contentEquals(original)) }, checkAdvance = { next, expected -> assertArrayEquals(expected, next) },
            authenticatedView = { "demo-digest" }, project = { bytes -> ManagedProfile("demo-device", "Demo", "demo-digest", "[]", "{}", "[]", bytes.decodeToString()) },
            replacePolicy = { before, _, preference -> assertArrayEquals(original, before); assertArrayEquals(legacy, preference); current },
            migratePreference = { _, _, _ -> converted },
        )
        storage.dropKey = stateKey
        assertThrows(IllegalStateException::class.java) { handle.replacePolicySelection(byteArrayOf(1)) }
        assertArrayEquals(original, storage.get(stateKey))
        assertArrayEquals(converted, storage.get(preferenceKey))
        storage.dropKey = null
        handle.replacePolicySelection(byteArrayOf(1))
        val laterChoice = "demo-user-choice-after-migration".encodeToByteArray()
        storage.put(preferenceKey, laterChoice)
        handle.replacePolicySelection(byteArrayOf(1))
        assertArrayEquals(laterChoice, storage.get(preferenceKey))
        assertArrayEquals(original, storage.get(ProfileStorage.policyIdentityEvidence(profileId)))
        assertArrayEquals(legacy, storage.get(ProfileStorage.policyPreferenceEvidence(profileId)))
        assertArrayEquals(current, handle.state())
    }

    @Test
    fun acceptedAuthorityPersistsWithoutNativeRuntimeAndRestartsFromSameBytes() {
        val storage = MemoryStorage()
        val bytes = "demo-authenticated-state-with-new-floor".encodeToByteArray()
        val store = store(storage)

        val accepted = store.acceptCertified(bytes)

        assertEquals("native-runtime-not-started", accepted.config)
        assertArrayEquals(bytes, storage.get(stateKey))
        assertNull(storage.get(ProfileStorage.candidate(profileId)))
        assertEquals(accepted, store(storage).loadCurrent())
        assertArrayEquals(bytes, store(storage).state())
    }

    @Test
    fun rejectedAuthenticationAndFailedWritePreservePreviousAuthority() {
        val storage = MemoryStorage()
        val before = "demo-accepted-floor".encodeToByteArray()
        store(storage).acceptCertified(before)
        val next = "demo-new-floor".encodeToByteArray()
        val rejecting = store(storage, validate = { if (it.contentEquals(next)) error("authentication rejected") })
        assertThrows(IllegalStateException::class.java) { rejecting.acceptCertified(next) }
        assertArrayEquals(before, storage.get(stateKey))

        storage.rejectWrite = true
        assertThrows(IllegalStateException::class.java) { store(storage).acceptCertified(next) }
        assertArrayEquals(before, storage.get(stateKey))
        assertEquals(before.decodeToString(), store(storage).loadCurrent()!!.recordID)
    }

    @Test
    fun missingLkgAndReadbackMismatchCannotReturnAcceptedProfile() {
        val storage = MemoryStorage()
        val incomplete = ManagedProfileStore(storage, profileId, {}, { _, _ -> }, { "" }, { null })
        assertThrows(IllegalStateException::class.java) { incomplete.acceptCertified(byteArrayOf(1)) }
        assertNull(storage.get(stateKey))

        storage.dropWrite = true
        assertThrows(IllegalStateException::class.java) {
            store(storage).acceptCertified("demo-new-state".encodeToByteArray())
        }
        assertNull(storage.get(stateKey))
    }

    @Test
    fun priorPendingCandidateIsPreservedAndNeverUsedAsAuthorityOrFallback() {
        val storage = MemoryStorage()
        val current = "demo-current".encodeToByteArray()
        val pending = "demo-pending-higher-floor".encodeToByteArray()
        storage.put(stateKey, current)
        storage.put(ProfileStorage.candidate(profileId), pending)

        assertThrows(IllegalStateException::class.java) { store(storage).loadCurrent() }
        assertThrows(IllegalStateException::class.java) { store(storage).acceptCertified(current) }
        assertArrayEquals(current, storage.get(stateKey))
        assertArrayEquals(pending, storage.get(ProfileStorage.candidate(profileId)))
    }

    @Test
    fun staleHandleCannotOverwriteReservedReportSequence() {
        val storage = MemoryStorage()
        val checkAdvance: (ByteArray, ByteArray) -> Unit = { next, previous ->
            check(next.decodeToString().toInt() >= previous.decodeToString().toInt()) { "sequence rollback" }
        }
        val first = store(storage, checkAdvance = checkAdvance)
        val stale = store(storage, checkAdvance = checkAdvance)
        first.acceptCertified("1".encodeToByteArray())
        val before = stale.state()!!
        val reserved = first.updateState { (it.decodeToString().toInt() + 1).toString().encodeToByteArray() }
        assertThrows(IllegalStateException::class.java) { stale.saveState(before) }
        assertArrayEquals(reserved, store(storage).state())
    }

    @Test
    fun removingAccessPersistsRevocationEvenWithoutRuntimeProjection() {
        val storage = MemoryStorage()
        val before = "demo-access".encodeToByteArray()
        store(storage).acceptCertified(before)
        val revoked = "demo-no-access".encodeToByteArray()
        val unexecutable = ManagedProfileStore(storage, profileId, {}, { _, _ -> }, { "demo-revoked" }, project = {
            error("access runtime is unavailable")
        })
        assertThrows(IllegalStateException::class.java) { unexecutable.acceptCertified(revoked) }
        assertArrayEquals(revoked, unexecutable.state())
        assertEquals("demo-revoked", unexecutable.acceptedViewDigest())
        assertThrows(IllegalStateException::class.java) { unexecutable.clearUncompletedIdentity() }
    }

    @Test
    fun resolverPreparationFailureKeepsAcceptedIdentityForSameProfileRepair() {
        val storage = MemoryStorage()
        val accepted = "demo-accepted-identity-without-resolver".encodeToByteArray()
        val repaired = "demo-same-identity-with-encrypted-resolver".encodeToByteArray()
        val handle = ManagedProfileStore(storage, profileId, {}, { _, _ -> }, { "demo-digest" }, project = { bytes ->
            check(!bytes.contentEquals(accepted)) { "resource hostname requires authenticated DNS" }
            ManagedProfile("demo-device", "Demo", "demo-digest", "[]", "{}", "[]", "demo-record")
        })
        assertThrows(IllegalStateException::class.java) { handle.acceptCertified(accepted) }
        assertArrayEquals(accepted, handle.state())
        assertThrows(IllegalStateException::class.java) { handle.clearUncompletedIdentity() }
        handle.acceptCertified(repaired)
        assertArrayEquals(repaired, handle.state())
        assertEquals("demo-device", handle.loadCurrent()!!.nodeID)
    }

    private fun store(
        storage: ProfileByteStore,
        validate: (ByteArray) -> Unit = {},
        checkAdvance: (ByteArray, ByteArray) -> Unit = { _, _ -> },
        replaceTransport: (ByteArray, ByteArray) -> ByteArray = { _, _ -> error("not an explicit migration") },
    ) =
        ManagedProfileStore(storage, profileId, validate, checkAdvance, { "demo-digest" }, project = { bytes ->
            ManagedProfile(
                "demo-device", "Demo", "demo-digest", "[]",
                "native-runtime-not-started", "[]", bytes.decodeToString(),
            )
        }, replaceTransport = replaceTransport)

    private class MemoryStorage : ProfileByteStore {
        private val records = mutableMapOf<String, ByteArray>()
        var rejectWrite = false
        var dropWrite = false
        var dropKey: String? = null
        override fun get(key: String) = records[key]?.copyOf()
        override fun put(key: String, value: ByteArray) {
            check(!rejectWrite) { "atomic write failed" }
            if (!dropWrite && key != dropKey) records[key] = value.copyOf()
        }
        override fun remove(key: String) { records.remove(key) }
    }
}
