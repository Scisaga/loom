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
        override fun get(key: String) = records[key]?.copyOf()
        override fun put(key: String, value: ByteArray) {
            check(!rejectWrite) { "atomic write failed" }
            if (!dropWrite) records[key] = value.copyOf()
        }
        override fun remove(key: String) { records.remove(key) }
    }
}
