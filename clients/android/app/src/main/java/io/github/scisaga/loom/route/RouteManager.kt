package io.github.scisaga.loom.route

import android.content.Context
import android.os.SystemClock
import android.util.Log
import io.github.scisaga.loom.enrollment.ManagedProfile
import io.github.scisaga.loom.enrollment.ManagedProfileStore
import io.github.scisaga.loom.enrollment.EnrollmentManager
import io.github.scisaga.loom.enrollment.privateCall
import io.github.scisaga.loom.profiles.ProfileCatalog
import io.github.scisaga.loom.profiles.ProfileStorage
import io.github.scisaga.loom.security.EncryptedStore
import io.github.scisaga.loom.vpn.ProbeResult
import io.github.scisaga.loom.vpn.LoomVpnService
import io.github.scisaga.loomcore.Loomcore
import io.github.scisaga.loomcore.AndroidDeviceRequest
import io.github.scisaga.loomcore.AndroidMeasurementObserver
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.json.JSONArray
import org.json.JSONObject
import java.time.Instant
import java.util.UUID
import java.io.IOException

data class ServicePolicyOption(val id: String, val name: String)
data class ServicePolicyStatus(val serviceID: String, val name: String, val policyID: String, val options: List<ServicePolicyOption>)

data class RouteStatus(
    val available: Boolean = false,
    val busy: Boolean = false,
    val services: List<ServicePolicyStatus> = emptyList(),
    val blocked: Boolean = false,
    val detail: String = "等待认证 DeviceView",
    val observationDetail: String = "尚无本机 TCP 建连观测",
    val currentPaths: List<RoutePathStatus> = emptyList(),
    val businessEvidence: List<RouteBusinessStatus> = emptyList(),
    val running: Boolean = false,
)

data class RoutePathStatus(
    val service: String,
    val candidate: String,
    val serverChain: List<String>,
    val finalExit: String,
    val state: String,
    val updatedAt: String,
)

internal data class AppliedRoute(
    val choices: Map<String, String>,
    val selectors: List<AppliedSelector>,
    val blockedScopes: List<String> = emptyList(),
    val selectionMemory: ByteArray = ByteArray(0),
    val nativeObservations: ByteArray = "[]".encodeToByteArray(),
    val nativeFixedExit: Boolean = false,
) {
    fun execution(): List<AppliedSelector> = selectors + blockedScopes.map {
        AppliedSelector(it, "reject", emptyList(), "", "unavailable")
    }
}

// Wake the existing sampler only when its domain scheduling proposal advances.
// The worker owns qualification, due times and the shared node budget.
internal fun tcpRecoveryProgressed(previous: Map<String, Pair<String, Int>>, current: Map<String, Pair<String, Int>>): Boolean =
    current.any { (target, proposal) -> previous[target] != proposal }

private fun tcpRecoveryProposals(body: ByteArray?): Map<String, Pair<String, Int>> {
    val decisions = body?.takeIf { it.isNotEmpty() }?.let {
        JSONObject(it.decodeToString()).optJSONObject("access")?.optJSONObject("decisions")
    } ?: return emptyMap()
    return buildMap {
        decisions.keys().forEach { target ->
            val value = decisions.getJSONObject(target)
            val pending = value.optString("pending")
            if (value.optBoolean("calibrate_tcp") && pending.isNotBlank()) put(target, pending to value.optInt("confirmations"))
        }
    }
}

internal fun tcpObservationDetail(action: String, target: String, result: String, metricMillis: Long, observedAt: String, validUntil: String): String {
    val source = when (action) {
        "tcp_connect" -> "TCP 建连观测"
        "tcp_calibration" -> "后台 TCP 试连"
        else -> return "尚无本机 TCP 建连观测"
    }
    val outcome = when (result) { "available" -> "成功"; "unavailable" -> "不可用"; else -> "未知" }
    return "$source · $target · $outcome · $metricMillis ms\n采样 $observedAt · 有效至 $validUntil"
}

internal fun AppliedRoute.matchesReadback(
    candidates: Map<String, String>,
    targets: Map<String, Map<String, String>>,
    policies: Map<String, String>,
    choices: Map<String, RouteChoices>,
): Boolean = execution().all {
    candidates[it.selector] == it.candidate && targets[it.selector] == it.targets &&
        policies[it.selector] == it.policyID && choices[it.selector] == it.choices
}

internal fun AppliedRoute.hasCompleteReadback(
    scopes: Set<String>, candidates: Map<String, String>, targets: Map<String, Map<String, String>>,
    policies: Map<String, String>, choices: Map<String, RouteChoices>,
): Boolean = execution().map { it.selector }.toSet() == scopes && matchesReadback(candidates, targets, policies, choices)

internal fun AppliedRoute.confirmedReportSelectors(
    preferredPolicies: Map<String, String>, pendingScopes: Set<String>,
    candidates: Map<String, String>, targets: Map<String, Map<String, String>>,
    policies: Map<String, String>, choices: Map<String, RouteChoices>, revisions: Map<String, String>,
): List<AppliedSelector> = selectors.filter { selected ->
    selected.selector !in pendingScopes && !revisions[selected.selector].isNullOrBlank() &&
        selected.policyID == preferredPolicies[selected.selector] &&
        copy(selectors = listOf(selected), blockedScopes = emptyList()).matchesReadback(candidates, targets, policies, choices)
}

internal fun AppliedRoute.blockedSelectedScopes(
    internetPolicyID: String, lanPolicyIDs: Map<String, String>, actual: Map<String, String>,
): Set<String> = blockedScopes.filterTo(linkedSetOf()) { scope ->
    actual[scope] == "reject" && if (scope == "access") internetPolicyID.isNotEmpty()
        else scope.startsWith("local_network:") && !lanPolicyIDs[scope.removePrefix("local_network:")].isNullOrEmpty()
}

internal fun <T> confirmScopeMemory(
    previous: Map<String, T>, proposals: Map<String, T>, scopes: Collection<String>, confirm: (String, T) -> T,
): Map<String, T> = previous + scopes.mapNotNull { scope -> proposals[scope]?.let { scope to confirm(scope, it) } }.toMap()

internal fun AppliedRoute.hasInitialSelection(
    internetPolicyID: String,
    candidates: Map<String, String>,
    targets: Map<String, Map<String, String>>,
    policies: Map<String, String>,
    choices: Map<String, RouteChoices>,
    selectionInFlight: Boolean = false,
    accessScopeExpected: Boolean = true,
): Boolean {
    if (selectionInFlight) return false
    val access = execution().singleOrNull { it.selector == "access" }
    if (accessScopeExpected && (access == null || !copy(selectors = listOf(access), blockedScopes = emptyList())
            .matchesReadback(candidates, targets, policies, choices))) return false
    // A waiting Internet preference may legitimately retain reject, including
    // when independently selected LAN services already run.
    if (internetPolicyID.isEmpty()) return !accessScopeExpected || access?.candidate == "reject"
    if (access == null) return false
    return access.policyID == internetPolicyID && access.candidate.isNotBlank() &&
        access.candidate != "reject" && access.choices.containsKey(access.candidate)
}

internal data class AppliedSelector(
    val selector: String,
    val candidate: String,
    val chain: List<String>,
    val finalExit: String,
    val state: String = "unknown",
    val targets: Map<String,String> = emptyMap(),
    val expectedCandidate: String? = null,
    val expectedRevision: String? = null,
    val expectedTargets: Map<String,String> = emptyMap(),
    val policyID: String = "",
    val choices: RouteChoices = emptyMap(),
    val expectedPolicyID: String? = null,
    val expectedChoices: RouteChoices = emptyMap(),
    val forceCAS: Boolean = false,
)

internal data class BusinessProbeInput(
    val selector: AppliedSelector,
    val networkGeneration: String,
    val target: String,
)

internal data class RuntimeReportData(
    val preference: ByteArray,
    val resourceObservations: ByteArray,
    val observations: ByteArray,
    val selections: ByteArray,
    val networkGeneration: String,
    val applicationComplete: Boolean = false,
)

internal suspend fun applyScopesIndependently(
    scopes: Collection<String>,
    apply: suspend (String) -> Unit,
    failed: suspend (String, IOException) -> Unit,
) {
    for (scope in scopes.sorted()) {
        try { apply(scope) } catch (error: IOException) {
            currentCoroutineContext().ensureActive()
            failed(scope, error)
        }
    }
}

internal fun serviceBusinessProbeInputs(
    profile: ManagedProfile,
    application: AppliedRoute?,
    networkGeneration: String,
): List<BusinessProbeInput> {
    val groups = profile.businessProbeTargets.associateBy { it.serviceID }
    return application?.selectors.orEmpty().sortedBy { it.selector }.flatMap { selected ->
        val group = groups.values.singleOrNull {
            application?.choices?.get(it.serviceID) == selected.policyID &&
                (selected.selector == "access" || selected.selector == "local_network:${it.serviceID}")
        } ?: return@flatMap emptyList()
        group.targets.map { target -> BusinessProbeInput(selected, networkGeneration, target) }
    }
}

/** Applies the shared pure selection and only publishes selector readback. */
class RouteManager private constructor(context: Context) {
    private val applicationContext = context.applicationContext
    private val protected = EncryptedStore(context.applicationContext)
    private val catalog = ProfileCatalog.get(context.applicationContext)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val operation = Mutex()
    private val profiles = mutableMapOf<String, ProfileRuntime>()

    // A disposable call owns its socket and a read-only identity snapshot, not
    // a persisted operation or a second source of authorization.
    private data class SelectorInput(
        val profile: ManagedProfile,
        val previousProfile: ManagedProfile?,
        val generation: String,
        val state: ByteArray,
        val preference: ByteArray,
        val client: SelectorClient,
        val hostCurrent: () -> Boolean,
    )

    private fun cancelSelector(runtime: ProfileRuntime) {
        val previous = runtime.selectorClient
        runtime.selectorClient = null
        previous?.cancel()
        if (previous != null) clearReadback(runtime, previous.uncertainScopes())
    }

    // Called only under operation. A replacement call's object identity also
    // fences an A→B→A user choice with byte-identical saved preferences.
    private fun selectorInput(profileId: String, runtime: ProfileRuntime, profile: ManagedProfile, hostCurrent: () -> Boolean = { true },
        plannedScopes: Collection<String> = JSONArray(profile.serviceScopes).strings()): SelectorInput {
        val identity = ManagedProfileStore.get(applicationContext, profileId)
        check(catalog.contains(profileId) && identity.acceptedViewDigest() == profile.viewDigest) { "运行配置已替换" }
        val state = checkNotNull(identity.state())
        cancelSelector(runtime)
        val client = SelectorClient(profile.config)
        planSelectorScopes(runtime, client, plannedScopes)
        runtime.selectorClient = client
        if (client.mayWrite("access")) runtime.mutableStatus.value = runtime.mutableStatus.value.copy(busy = true)
        return SelectorInput(profile, runtime.runningProfile, runtime.generation, state, Loomcore.androidPreference(state), client, hostCurrent)
    }

    // Called under operation, before this call's first GET can refill the
    // cache. A cancelled PUT can still reach native CAS after its socket was
    // closed; a GET of its old snapshot is not a successor's write fence.
    private fun planSelectorScopes(runtime: ProfileRuntime, client: SelectorClient, scopes: Collection<String>) {
        client.planScopes(scopes, requireCAS = scopes.filter { it !in runtime.actualRevisions })
    }

    private fun selectorInputCurrent(profileId: String, runtime: ProfileRuntime, input: SelectorInput): Boolean {
        if (!selectorOwnerCurrent(profileId, runtime, input)) return false
        return ManagedProfileStore.get(applicationContext, profileId).state()?.let {
            Loomcore.androidPreference(it).contentEquals(input.preference)
        } == true
    }

    private fun selectorOwnerCurrent(profileId: String, runtime: ProfileRuntime, input: SelectorInput): Boolean {
        if (!input.hostCurrent() || !catalog.contains(profileId) || synchronized(profiles) { profiles[profileId] !== runtime } ||
            runtime.selectorClient !== input.client ||
            runtime.runningProfile !== input.previousProfile && runtime.runningProfile !== input.profile ||
            runtime.generation != input.generation
        ) return false
        val identity = ManagedProfileStore.get(applicationContext, profileId)
        return identity.acceptedViewDigest() == input.profile.viewDigest
    }

    private fun requireSelectorInput(profileId: String, runtime: ProfileRuntime, input: SelectorInput) {
        if (!selectorInputCurrent(profileId, runtime, input)) throw SelectionSuperseded()
    }

    private suspend fun <T> selectorIO(
        profileId: String,
        runtime: ProfileRuntime,
        input: SelectorInput,
        apply: suspend () -> T,
    ): T {
        var completed = false
        var failure: Throwable? = null
        try {
            return runtime.selectorIO.withLock {
                operation.withLock {
                    if (!selectorOwnerCurrent(profileId, runtime, input)) throw SelectionSuperseded()
                }
                apply().also { completed = true }
            }
        } catch (error: Throwable) {
            failure = error
            throw error
        } finally {
            input.client.cancel()
            withContext(NonCancellable) {
                operation.withLock {
                    if (runtime.selectorClient === input.client) {
                        runtime.selectorClient = null
                        if (completed) {
                            // publish kept busy while this owner could still
                            // write. Its release is the existing completion
                            // notification used by the startup observer.
                            runtime.mutableStatus.value = runtime.mutableStatus.value.copy(busy = false)
                        } else {
                            // A timed-out PUT may already have taken effect. The
                            // previous GET cannot confirm the current selection.
                            clearReadback(runtime, input.client.uncertainScopes())
                            runtime.application?.let { publish(profileId, runtime, it, running = runtime.runningProfile != null) }
                            runtime.mutableStatus.value = runtime.mutableStatus.value.copy(
                                busy = false,
                                detail = "运行选择尚未确认：${failure?.message ?: "请求未完成"}；等待重新读回",
                            )
                        }
                    }
                }
            }
        }
    }

    private fun clearReadback(runtime: ProfileRuntime) {
        runtime.actual = linkedMapOf()
        runtime.actualTargets = emptyMap()
        runtime.actualRevisions = emptyMap()
        runtime.actualPolicies = emptyMap()
        runtime.actualChoices = emptyMap()
    }

    private fun clearReadback(runtime: ProfileRuntime, scopes: Set<String>) {
        if (scopes.isEmpty()) return
        runtime.actual.keys.removeAll(scopes)
        runtime.actualTargets = runtime.actualTargets - scopes
        runtime.actualRevisions = runtime.actualRevisions - scopes
        runtime.actualPolicies = runtime.actualPolicies - scopes
        runtime.actualChoices = runtime.actualChoices - scopes
        runtime.application = runtime.application?.let { it.copy(
            selectors = it.selectors.filterNot { selected -> selected.selector in scopes },
            blockedScopes = it.blockedScopes - scopes,
        ) }
    }

    // Retry only while this disposable call still owns the same runtime. A
    // native CAS conflict needs a fresh read, not a saved stale recommendation.
    private suspend fun <T> rereadSelector(
        profileId: String, runtime: ProfileRuntime, input: SelectorInput,
        acceptStartupPreference: Boolean = false,
        apply: suspend (SelectorInput) -> T,
    ): T {
        var current = input
        repeat(3) { attempt ->
            try {
                return apply(current)
            } catch (error: SelectionSuperseded) {
                currentCoroutineContext().ensureActive()
                current = operation.withLock {
                    if (!selectorOwnerCurrent(profileId, runtime, current) || attempt == 2) throw error
                    val state = checkNotNull(ManagedProfileStore.get(applicationContext, profileId).state())
                    val preference = Loomcore.androidPreference(state)
                    if (!preference.contentEquals(current.preference) && !acceptStartupPreference) throw error
                    current.copy(state = state, preference = preference)
                }
            }
        }
        error("selector reread exhausted")
    }

    private fun readbackScopes(runtime: ProfileRuntime,client: SelectorClient,current: Map<String,String>) {
        runtime.actual.putAll(current)
        runtime.actualTargets=runtime.actualTargets+client.readbackTargets.filterKeys { it in current }
        runtime.actualRevisions=runtime.actualRevisions+client.readbackRevisions.filterKeys { it in current }
        runtime.actualPolicies=runtime.actualPolicies+client.readbackPolicies.filterKeys { it in current }
        runtime.actualChoices=runtime.actualChoices+client.readbackChoices.filterKeys { it in current }
    }

    private fun actualSelector(input: SelectorInput, scope: String, current: Map<String, String>): AppliedSelector? {
        val client = input.client
        val id = current[scope] ?: return null
        if (id == "reject") return AppliedSelector(scope, id, emptyList(), "", "unknown")
        val preference = JSONObject(input.preference.decodeToString())
        val policy = if (scope == "access") preference.optString("policy_id")
            else preference.optJSONObject("lan_policy_ids")?.optString(scope.removePrefix("local_network:")).orEmpty()
        if (policy.isEmpty() || client.readbackPolicies[scope] != policy) return null
        val allowed = JSONArray(Loomcore.androidSelectedRoutes(input.state).decodeToString()).objects().filter {
            it.getString("policy_id") == policy &&
                (scope == "access" && it.getString("scope").startsWith("service:") || it.getString("scope") == scope)
        }.associateBy { it.getString("id") }
        val route = allowed[id] ?: return null
        val targets = client.readbackTargets[scope].orEmpty()
        if ((targets.values + id).any { it !in allowed }) return null
        return AppliedSelector(scope, id, route.optJSONArray("chain")?.strings().orEmpty(), route.getString("final_exit"),
            targets = targets, policyID = policy, choices = client.readbackChoices[scope].orEmpty())
    }

    private fun publishScope(profileId: String, runtime: ProfileRuntime, input: SelectorInput,
        proposal: AppliedRoute, selected: AppliedSelector, confirm: Boolean) {
        requireSelectorInput(profileId, runtime, input)
        val scope = selected.selector
        val previousMemory = runtime.selectionMemory
        if (confirm) confirmMemory(runtime, proposal.copy(selectors = proposal.selectors.filter { it.selector == scope }))
        runtime.selectionMemory?.takeIf { it.isNotEmpty() }?.let {
            val memory = JSONObject(it.decodeToString())
            val item = memory.optJSONObject(scope)
            if (selected.candidate == "reject" || item != null &&
                (item.optString("policy_id") != selected.policyID || item.optString("network_generation") != runtime.generation)) {
                memory.remove(scope)
                runtime.selectionMemory = memory.toString().encodeToByteArray()
            }
        }
        val prior = runtime.application ?: proposal.copy(selectors = emptyList(), blockedScopes = emptyList())
        runtime.application = prior.copy(choices = proposal.choices,
            selectors = prior.selectors.filterNot { it.selector == scope } + listOf(selected).filter { it.candidate != "reject" },
            blockedScopes = (prior.blockedScopes - scope) + listOf(scope).filter { selected.candidate == "reject" },
            selectionMemory = runtime.selectionMemory ?: ByteArray(0),
            nativeObservations = proposal.nativeObservations, nativeFixedExit = proposal.nativeFixedExit)
        runtime.nativeObservations = proposal.nativeObservations
        runtime.runningProfile = input.profile
        input.client.confirmed(scope)
        publish(profileId, runtime, checkNotNull(runtime.application), running = true, observation = businessObservationDetail(runtime))
        if (tcpRecoveryProgressed(tcpRecoveryProposals(previousMemory), tcpRecoveryProposals(runtime.selectionMemory))) {
            LoomVpnService.requestFirstHopMeasurement(profileId)
        }
    }

    private suspend fun applySelector(profileId: String, runtime: ProfileRuntime, input: SelectorInput,
        onlyScopes: Set<String>? = null): AppliedRoute {
        val scopes = JSONArray(input.profile.serviceScopes).strings().filter { onlyScopes == null || it in onlyScopes }
        operation.withLock {
            requireSelectorInput(profileId, runtime, input)
            planSelectorScopes(runtime, input.client, scopes)
            runtime.application?.let {
                val choices = evaluate(profileId, runtime, input.profile, runtime.actual, input.state).choices
                runtime.application = it.copy(choices = choices, selectors = it.selectors.filter { selected -> selected.policyID in choices.values })
            }
        }
        if (scopes.isEmpty()) {
            input.client.readCurrent(emptyList())
            return operation.withLock {
                requireSelectorInput(profileId, runtime, input)
                evaluate(profileId, runtime, input.profile, emptyMap(), input.state).also {
                    runtime.application = it; runtime.runningProfile = input.profile
                    publish(profileId, runtime, it, running = true)
                }
            }
        }
        var nativeEvents: ByteArray? = null
        applyScopesIndependently(scopes, apply = { scope ->
            val placeholder = AppliedSelector(scope, "reject", emptyList(), "")
            val current = input.client.readCurrent(listOf(placeholder))
            if (nativeEvents == null) nativeEvents = try { input.client.readNativeObservations() } catch (error: Exception) {
                currentCoroutineContext().ensureActive()
                if (error is SelectionSuperseded) throw error
                "{\"observations\":[]}".encodeToByteArray()
            }
            val desired = operation.withLock {
                requireSelectorInput(profileId, runtime, input)
                readbackScopes(runtime, input.client, current)
                evaluate(profileId, runtime, input.profile, runtime.actual, input.state, checkNotNull(nativeEvents))
            }
            val selected = desired.execution().single { it.selector == scope }
            input.client.apply(listOf(selected))
            val actual = input.client.readCurrent(listOf(selected))
            operation.withLock {
                requireSelectorInput(profileId, runtime, input)
                readbackScopes(runtime, input.client, actual)
                check(desired.copy(selectors = listOf(selected), blockedScopes = emptyList()).matchesReadback(
                    runtime.actual, runtime.actualTargets, runtime.actualPolicies, runtime.actualChoices)) { "selector scope 回读与完整选择不一致" }
                publishScope(profileId, runtime, input, desired, selected, confirm = true)
            }
        }, failed = { scope, error ->
            if (error is RuntimeResourcesPending) {
                LoomVpnService.runtimeResourcesPending(profileId, input.profile)
                // Preparation precedes PUT. Read the actual old/reject snapshot,
                // never manufacture a network failure from local preparation.
                var rejecting = false
                try {
                    var actual = input.client.readCurrent(listOf(AppliedSelector(scope, "reject", emptyList(), "")))
                    var retained = operation.withLock { requireSelectorInput(profileId, runtime, input); actualSelector(input, scope, actual) }
                    if (retained == null || input.client.requiresCAS(scope)) {
                        rejecting = retained == null
                        val selected = retained ?: AppliedSelector(scope, "reject", emptyList(), "", "unknown")
                        // Retaining a legal old path is allowed, but an
                        // inherited unconfirmed write still needs its own CAS
                        // fence. Preparation failure keeps this scope unknown.
                        input.client.apply(listOf(selected.copy(
                            expectedCandidate = checkNotNull(actual[scope]),
                            expectedRevision = checkNotNull(input.client.readbackRevisions[scope]),
                            expectedTargets = input.client.readbackTargets[scope].orEmpty(),
                            expectedPolicyID = checkNotNull(input.client.readbackPolicies[scope]),
                            expectedChoices = input.client.readbackChoices[scope].orEmpty(),
                        )))
                        actual = input.client.readCurrent(listOf(AppliedSelector(scope, "reject", emptyList(), "")))
                        retained = actualSelector(input, scope, actual)
                    }
                    operation.withLock {
                        requireSelectorInput(profileId, runtime, input)
                        readbackScopes(runtime, input.client, actual)
                        val proposal = evaluate(profileId, runtime, input.profile, runtime.actual, input.state,
                            nativeEvents ?: "{\"observations\":[]}".encodeToByteArray())
                        publishScope(profileId, runtime, input, proposal, checkNotNull(retained), confirm = false)
                        runtime.mutableStatus.value = runtime.mutableStatus.value.copy(detail = "已确认路径继续运行；$scope 资源准备中")
                    }
                    return@applyScopesIndependently
                } catch (readError: Throwable) {
                    currentCoroutineContext().ensureActive()
                    if (readError is SelectionSuperseded) throw readError
                    if (rejecting) {
                        LoomVpnService.stopUnverifiablePolicySelection(profileId) { commit ->
                            operation.withLock {
                                if (!selectorInputCurrent(profileId, runtime, input)) false else { commit(); true }
                            }
                        }
                        throw IllegalStateException("服务拒绝状态未确认", readError)
                    }
                    if (readError !is IOException) throw readError
                }
            }
            operation.withLock {
                requireSelectorInput(profileId, runtime, input)
                clearReadback(runtime, input.client.uncertainScopes().intersect(setOf(scope)))
                input.client.finished(scope)
                runtime.application?.let { publish(profileId, runtime, it, running = true) }
                runtime.mutableStatus.value = runtime.mutableStatus.value.copy(detail = "$scope 尚未确认；其他已确认路径继续运行")
            }
        })
        return operation.withLock {
            requireSelectorInput(profileId, runtime, input)
            runtime.application ?: evaluate(profileId, runtime, input.profile, runtime.actual, input.state).copy(selectors = emptyList(), blockedScopes = emptyList()).also {
                runtime.application = it; runtime.runningProfile = input.profile
                publish(profileId, runtime, it, running = true)
            }
        }
    }

    fun status(profileId: String): StateFlow<RouteStatus> = runtime(profileId).mutableStatus.asStateFlow()

    private fun hasInitialSelectionLocked(profileId: String, profile: ManagedProfile): Boolean {
        val runtime = runtime(profileId)
        val identity = ManagedProfileStore.get(applicationContext, profileId)
        if (runtime.runningProfile !== profile || !catalog.contains(profileId) ||
            identity.acceptedViewDigest() != profile.viewDigest) return false
        val state = identity.state() ?: return false
        val policyID = JSONObject(Loomcore.androidPreference(state).decodeToString()).optString("policy_id")
        return runtime.application?.hasInitialSelection(policyID, runtime.actual, runtime.actualTargets,
            runtime.actualPolicies, runtime.actualChoices,
            selectionInFlight = runtime.selectorClient?.mayWrite("access") == true,
            accessScopeExpected = "access" in JSONArray(profile.serviceScopes).strings()) == true
    }

    internal suspend fun hasInitialSelection(profileId: String, profile: ManagedProfile): Boolean = operation.withLock {
        hasInitialSelectionLocked(profileId, profile)
    }

    // Called under the VPN lifecycle lock. Recheck and publish under operation
    // too, so a concurrent Policy change cannot consume an older ready result.
    // This consumes cached readback and local preference, without selector or
    // measurement network I/O.
    internal suspend fun confirmInitialSelection(profileId: String, profile: ManagedProfile, connected: () -> Unit) = operation.withLock {
        if (hasInitialSelectionLocked(profileId, profile)) connected()
    }

    fun profileAvailable(profileId: String, profile: ManagedProfile): Job {
        val runtime = runtime(profileId)
        return scope.launch {
            operation.withLock {
                if (!catalog.contains(profileId)) return@withLock
                ensureNetworkGeneration(profileId, runtime)
                if (runtime.availableProfile?.executionDigest != profile.executionDigest || profile.executionDigest.isEmpty()) {
                    protected.put(ProfileStorage.observations(profileId), "[]".encodeToByteArray())
                    runtime.linkObservations = null
                    runtime.linkObservationViewDigest = ""
                }
                val previousAvailable = runtime.availableProfile
                runtime.availableProfile = profile
                // A same-View sync updates the catalog, not the in-flight
                // selector's completion or UI busy state.
                if (runtime.selectorClient != null &&
                    (runtime.runningProfile?.recordID == profile.recordID || runtime.runningProfile == null &&
                        previousAvailable?.viewDigest == profile.viewDigest)) return@withLock
                if (runtime.runningProfile?.recordID != profile.recordID) {
                    runtime.firstHopRequest?.cancel()
                    cancelSelector(runtime)
                }
                val current = if (runtime.runningProfile?.recordID == profile.recordID) runtime.actual else emptyMap()
                runCatching { evaluate(profileId, runtime, profile, current) }
                    .onSuccess { projected ->
                        publish(profileId, runtime, projected, running = runtime.runningProfile?.recordID == profile.recordID)
                    }
                    .onFailure { error ->
                        runtime.mutableStatus.value = runtime.mutableStatus.value.copy(
                            available = false, currentPaths = emptyList(), businessEvidence = emptyList(), running = false,
                            detail = "认证配置已保存；运行投影不可用：${error.message ?: error.javaClass.simpleName}",
                            observationDetail = "尚无本机 TCP 建连观测",
                        )
                    }
            }
        }
    }

    suspend fun beginNetworkGeneration(profileId: String, identity: String? = null, isCurrent: () -> Boolean = { true }): Boolean = operation.withLock {
        if (!isCurrent()) return@withLock false
        val runtime = runtime(profileId)
        ensureNetworkGeneration(profileId, runtime)
        if (identity == null || identity == runtime.networkIdentity) return@withLock false
        require(identity.isNotBlank()) { "底层网络身份不能为空" }
        runtime.firstHopRequest?.cancel()
        cancelSelector(runtime)
        runtime.generation = UUID.randomUUID().toString()
        runtime.networkIdentity = identity
        runtime.actual = linkedMapOf()
        runtime.actualTargets = emptyMap()
        runtime.actualRevisions = emptyMap()
        runtime.actualPolicies = emptyMap()
        runtime.actualChoices = emptyMap()
        runtime.selectionMemory = null
        runtime.nativeObservations = "[]".encodeToByteArray()
        runtime.application = null
        protected.put(ProfileStorage.networkGeneration(profileId), runtime.generation.encodeToByteArray())
        protected.put(ProfileStorage.networkIdentity(profileId), identity.encodeToByteArray())
        protected.put(ProfileStorage.observations(profileId), "[]".encodeToByteArray())
        runtime.mutableStatus.value = runtime.mutableStatus.value.copy(businessEvidence = emptyList())
        true
    }

    internal suspend fun checkConfiguration(profileId: String, profile: ManagedProfile) = operation.withLock {
        val runtime = runtime(profileId)
        ensureNetworkGeneration(profileId, runtime)
        evaluate(profileId, runtime, profile, emptyMap())
        runtime.availableProfile = profile
        Unit
    }

    internal suspend fun acceptRetainedRuntime(profileId: String, profile: ManagedProfile, isCurrent: () -> Boolean) {
        val starting = operation.withLock {
            if (!isCurrent()) return
            runtime(profileId).runningProfile == null
        }
        if (starting) {
            applyToRunning(profileId, profile, isCurrent)
            return
        }
        operation.withLock {
        if (!isCurrent()) return
        val runtime = runtime(profileId)
        val previous = checkNotNull(runtime.runningProfile)
        check(profile.nodeID == previous.nodeID)
        runtime.firstHopRequest?.cancel()
        cancelSelector(runtime)
        val candidates = JSONArray(profile.routes).objects().map { it.getString("id") }.toSet()
        val retained = observations(profileId).objects().filter {
            it.getString("scope") in JSONArray(profile.serviceScopes).strings() && it.getString("candidate_id") in candidates &&
                it.getString("network_generation") == runtime.generation
        }
        protected.put(ProfileStorage.observations(profileId), JSONArray(retained).toString().encodeToByteArray())
        if (previous.recordID != profile.recordID || previous.viewDigest != profile.viewDigest ||
            previous.executionDigest != profile.executionDigest || previous.config != profile.config) {
            // Native permission may already have removed an old choice. Its
            // earlier cached readback cannot confirm this retained projection.
            clearReadback(runtime)
        }
        runtime.runningProfile = profile
        runtime.availableProfile = profile
        runtime.linkObservations = null
        runtime.linkObservationViewDigest = ""
        runtime.application?.let { publish(profileId, runtime, it, running = true, observation = businessObservationDetail(runtime)) }
        }
        refreshFromMeasurements(profileId, profile)
    }

    internal suspend fun applyToRunning(profileId: String, profile: ManagedProfile, isCurrent: () -> Boolean = { true }): AppliedRoute {
        val runtime = runtime(profileId)
        val input = operation.withLock {
            if (!isCurrent()) throw SelectionSuperseded()
            ensureNetworkGeneration(profileId, runtime)
            runtime.firstHopRequest?.cancel()
            protected.put(ProfileStorage.observations(profileId), "[]".encodeToByteArray())
            runtime.mutableStatus.value = runtime.mutableStatus.value.copy(busy = true, detail = "正在应用候选并读回 selector…")
            selectorInput(profileId, runtime, profile, isCurrent).also { runtime.availableProfile = profile }
        }
        return selectorIO(profileId, runtime, input) {
            rereadSelector(profileId, runtime, input, acceptStartupPreference = input.previousProfile == null) {
                applySelector(profileId, runtime, it)
            }
        }
    }

    fun rebuildServiceConnections(profileId: String, serviceID: String) {
        scope.launch {
            val runtime = runtime(profileId)
            val captured = operation.withLock {
                if (!catalog.contains(profileId) || runtime.mutableStatus.value.busy) return@withLock null
                val profile = runtime.runningProfile ?: return@withLock null
                val selected = runtime.application?.selectors?.singleOrNull {
                    it.selector == "local_network:$serviceID" ||
                        it.selector == "access" && runtime.application?.choices?.containsKey(serviceID) == true
                } ?: return@withLock null
                selectorInput(profileId, runtime, profile, plannedScopes = emptyList()) to selected
            } ?: return@launch
            val (input, selected) = captured
            try {
                selectorIO(profileId, runtime, input) {
                    val result = runCatching {
                        withTimeout(5_000) {
                            check(input.client.readCurrent(listOf(selected))[selected.selector] == selected.candidate) { "服务路径已变化，请重试" }
                            operation.withLock { requireSelectorInput(profileId, runtime, input) }
                            input.client.closeServiceConnections(serviceID, selected.selector)
                        }
                    }
                    currentCoroutineContext().ensureActive()
                    operation.withLock {
                        requireSelectorInput(profileId, runtime, input)
                        runtime.mutableStatus.value = runtime.mutableStatus.value.copy(detail = if (result.isSuccess)
                            "已关闭该服务的现有连接；新连接使用当前优选路径" else "该服务连接未能全部重建，请重试")
                    }
                }
            } catch (error: SelectionSuperseded) {
                // A replaced rebuild never closes a newer selection's connections.
            }
        }
    }

    fun select(profileId: String, serviceID: String, policyID: String) {
        val runtime = runtime(profileId)
        scope.launch {
            val input = operation.withLock {
                if (!catalog.contains(profileId)) return@withLock null
                val profile = runtime.runningProfile ?: runtime.availableProfile ?: return@withLock null
                val service = JSONArray(profile.serviceCatalog).objects().singleOrNull { it.getString("id") == serviceID }
                    ?: return@withLock null
                if (JSONArray(profile.policyCatalog).objects().none { it.getString("id") == policyID && it.getString("service_id") == serviceID }) return@withLock null
                runtime.firstHopRequest?.cancel()
                ManagedProfileStore.get(applicationContext, profileId).updateState { state -> Loomcore.chooseAndroidPolicy(state, policyID) }
                if (runtime.runningProfile == null) {
                    if (runtime.selectorClient != null) {
                        // The current startup will re-read the newly persisted
                        // preference. Stop/removal still cancel its owner.
                        runtime.mutableStatus.value = runtime.mutableStatus.value.copy(busy = true,
                            detail = "已保存策略；正在应用到启动中的连接…")
                        return@withLock null
                    }
                    cancelSelector(runtime)
                    publish(profileId, runtime, evaluate(profileId, runtime, profile, emptyMap()), running = false)
                    return@withLock null
                }
                runtime.mutableStatus.value = runtime.mutableStatus.value.copy(busy = true, detail = "正在应用所选策略…")
                val changedScope = if (service.getString("kind") == "local_network") "local_network:$serviceID" else "access"
                selectorInput(profileId, runtime, profile, plannedScopes = listOf(changedScope)) to changedScope
            }
            if (input != null) {
                val (call, changedScope) = input
                try {
                    selectorIO(profileId, runtime, call) {
                        try {
                            rereadSelector(profileId, runtime, call) { current ->
                                current.client.apply(listOf(AppliedSelector(changedScope, "reject", emptyList(), "", "unknown")))
                                operation.withLock { requireSelectorInput(profileId, runtime, current) }
                                applySelector(profileId, runtime, current, setOf(changedScope))
                            }
                        } catch (error: Throwable) {
                            currentCoroutineContext().ensureActive()
                            val current = operation.withLock { selectorInputCurrent(profileId, runtime, call) }
                            if (!current) throw SelectionSuperseded()
                            // An unconfirmed explicit choice fails closed only in
                            // its affected selector. No fallback to old permission.
                            val rejection = runCatching {
                                call.client.apply(listOf(AppliedSelector(changedScope, "reject", emptyList(), "", "unavailable")))
                            }
                            if (rejection.isFailure) LoomVpnService.stopUnverifiablePolicySelection(profileId) { commit ->
                                operation.withLock {
                                    if (!selectorInputCurrent(profileId, runtime, call)) false else { commit(); true }
                                }
                            }
                            operation.withLock {
                                if (selectorInputCurrent(profileId, runtime, call)) {
                                    runtime.actual.remove(changedScope)
                                    runtime.application = runtime.application?.let {
                                        val retainedChoices = if (changedScope == "access") it.choices.filterKeys { id ->
                                            JSONArray(call.profile.serviceCatalog).objects().any { service ->
                                                service.getString("id") == id && service.getString("kind") == "local_network"
                                            }
                                        } else it.choices
                                        it.copy(choices = retainedChoices + (serviceID to policyID),
                                            selectors = it.selectors.filter { selected -> selected.selector != changedScope },
                                            blockedScopes = (it.blockedScopes + changedScope).distinct())
                                    }
                                    runtime.application?.let { publish(profileId, runtime, it, running = true) }
                                    runtime.mutableStatus.value = runtime.mutableStatus.value.copy(busy = false,
                                        detail = "服务策略未应用：${error.message}", blocked = true)
                                }
                            }
                            throw error
                        }
                    }
                } catch (error: CancellationException) {
                    throw error
                } catch (error: SelectionSuperseded) {
                    // A newer call owns status, selection and its connections.
                } catch (error: Throwable) {
                    Log.w("Loom", "服务策略未确认；保留认证身份和已接受选择", error)
                }
                LoomVpnService.requestFirstHopMeasurement(profileId)
            }
            EnrollmentManager.get(applicationContext).reportRuntimeOutcome(profileId)
        }
    }

    internal suspend fun refreshLinkObservations(profileId: String, profile: ManagedProfile) {
        val identity = ManagedProfileStore.get(applicationContext, profileId)
        val requestContext=currentCoroutineContext()
        val input=operation.withLock {
            requestContext.ensureActive()
            val owner=runtime(profileId)
            val running=owner.runningProfile ?: return@withLock null
            if(running.recordID!=profile.recordID || identity.acceptedViewDigest()!=profile.viewDigest)return@withLock null
            val body=identity.state() ?: return@withLock null
            Triple(owner,owner.generation,owner.measurementSnapshot) to (running to body)
        } ?: return
        val (ownership,requestData)=input
        val (owner,generation,base)=ownership
        val (running,body)=requestData
        val response = try {
            val request = Loomcore.newAndroidLinkObservationRequest(body, base ?: ByteArray(0))
            privateCall(request::run, request::cancel)
        } catch (error: CancellationException) {
            throw error
        } catch (error: Exception) {
            Log.w("Loom", "中继观测读取不可用；保留原样本截止时间")
            return
        }
        val received=JSONObject(response.decodeToString())
        val receivedSamples=received.getJSONArray("observations").toString().encodeToByteArray()
        val hidden=JSONObject(Loomcore.hiddenAndroidInternetPolicies(body,receivedSamples,System.currentTimeMillis()).decodeToString())
            .let { value -> value.keys().asSequence().associateWith(value::getLong) }
        operation.withLock {
            requestContext.ensureActive()
            val runtime = runtime(profileId)
            if (runtime !== owner || runtime.generation!=generation || runtime.measurementSnapshot !== base ||
                runtime.runningProfile !== running || runtime.runningProfile?.recordID != profile.recordID || identity.acceptedViewDigest() != profile.viewDigest) return@withLock
            val value = received
            check(value.getString("view_digest") == profile.viewDigest && value.getString("device_id") == profile.nodeID)
            runtime.linkObservationViewDigest = profile.viewDigest
            runtime.measurementSnapshot = response
            runtime.linkObservations = value.getJSONArray("observations").toString().encodeToByteArray()
            runtime.hiddenPolicies=hidden
            runtime.hiddenPolicyViewDigest=profile.viewDigest
            runtime.application?.let { publish(profileId,runtime,it,running=true) }
        }
    }

    private fun measurementProfileCurrent(runtime: ProfileRuntime, profile: ManagedProfile): Boolean =
        runtime.runningProfile?.recordID == profile.recordID ||
            runtime.runningProfile == null && runtime.availableProfile?.recordID == profile.recordID

    internal suspend fun sampleFirstHops(profileId: String, profile: ManagedProfile, onCompleted: () -> Unit): Long? {
        val identity = ManagedProfileStore.get(applicationContext, profileId)
        val ownerContext = currentCoroutineContext()
        val owner = ownerContext[Job]
        var completedAtElapsed: Long? = null
        lateinit var request: AndroidDeviceRequest
        val input = operation.withLock {
            val runtime = runtime(profileId)
            if (!measurementProfileCurrent(runtime, profile) || identity.acceptedViewDigest() != profile.viewDigest) return@withLock null
            val state = identity.state() ?: return@withLock null
            val generation = runtime.generation
            val selections = JSONArray(runtime.application?.selectors.orEmpty().filter {
                it.candidate != "reject" && runtime.actual[it.selector] == it.candidate
            }.sortedBy { it.selector }.map {
                JSONObject().put("scope", it.selector).put("candidate_id", it.candidate).put("targets",JSONObject(it.targets))
            }).toString().encodeToByteArray()
            val previous = runtime.resourceObservations ?: protected.get(ProfileStorage.resourceObservations(profileId)) ?: ByteArray(0)
            val preference=Loomcore.androidPreference(state)
            val expectedRevision=runtime.actualRevisions["access"]
            request = Loomcore.newAndroidFirstHopRequest(state, selections, previous, runtime.selectionMemory ?: ByteArray(0),
                currentBody(runtime,runtime.actual),runtime.nativeObservations,
                if(runtime.linkObservationViewDigest==profile.viewDigest) runtime.linkObservations ?: "[]".encodeToByteArray() else "[]".encodeToByteArray(),
                generation, object : AndroidMeasurementObserver {
                override fun diagnostic(line: String) {
                    emitEchoDiagnostic(line) { Log.d("Loom", it) }
                }
                override fun completed(body: ByteArray) = runBlocking(ownerContext) {
                    operation.withLock {
                        check(owner?.isActive != false && catalog.contains(profileId) && runtime.firstHopRequest === request &&
                            measurementProfileCurrent(runtime, profile) && runtime.generation == generation &&
                            identity.state()?.let { Loomcore.androidPreference(it).contentEquals(preference) } == true && identity.acceptedViewDigest() == profile.viewDigest) { "首跳测量输入已替换" }
                        runtime.resourceObservations = Loomcore.mergeAndroidResourceObservations(
                            runtime.resourceObservations ?: previous, body, profile.resourceCacheIdentity, generation)
                        completedAtElapsed = SystemClock.elapsedRealtime()
                    }
                    // Reporting consumes this already accepted batch without
                    // waiting for selector I/O or another measurement task.
                    onCompleted()
                    emitMeasurementCompletionDiagnostics(body,
                        emit = { Log.i("Loom", it) }, failed = { Log.w("Loom", "measurement-completed diagnostic unavailable") })
                    refreshFromMeasurements(profileId, profile)
                }
                override fun calibrated(body: ByteArray) = runBlocking(ownerContext) {
                    val changed=operation.withLock {
                        if(owner?.isActive==false||!catalog.contains(profileId)||runtime.firstHopRequest!==request||
                            !measurementProfileCurrent(runtime, profile)||runtime.generation!=generation||runtime.actualRevisions["access"]!=expectedRevision||
                            identity.acceptedViewDigest()!=profile.viewDigest||identity.state()?.let { !Loomcore.androidPreference(it).contentEquals(preference) }!=false) return@withLock false
                        val result=JSONObject(Loomcore.mergeAndroidTCPRecoveryObservations(currentBody(runtime,runtime.actual),
                            runtime.selectionMemory ?: ByteArray(0),runtime.nativeObservations,body,generation,System.currentTimeMillis()).decodeToString())
                        runtime.nativeObservations=result.getJSONArray("native_observations").toString().encodeToByteArray()
                        runtime.selectionMemory=result.getJSONObject("memory").toString().encodeToByteArray()
                        result.getBoolean("needs_routing")
                    }
                    if(changed) refreshFromMeasurements(profileId,profile)
                }
            })
            runtime.firstHopRequest?.cancel()
            runtime.firstHopRequest = request
            Triple(previous, generation, preference)
        } ?: return null
        try {
            val sampled = privateCall(request::run, request::cancel)
            operation.withLock {
                val runtime = runtime(profileId)
                if (owner?.isActive == false || runtime.firstHopRequest !== request || !measurementProfileCurrent(runtime, profile) ||
                    runtime.generation != input.second || identity.state()?.let { Loomcore.androidPreference(it).contentEquals(input.third) } != true ||
                    identity.acceptedViewDigest() != profile.viewDigest) return@withLock
                runtime.resourceObservations = sampled
                if (!sampled.contentEquals(input.first)) {
                    runCatching { protected.put(ProfileStorage.resourceObservations(profileId), sampled) }
                        .onFailure { Log.w("Loom", "首跳样本缓存写入失败；本进程保留原样本") }
                }
            }
        } catch (error: CancellationException) {
            throw error
        } catch (error: Exception) {
            Log.w("Loom", "首跳测量已停止；保留已完成样本及原截止时间")
        } finally {
            request.cancel()
            withContext(NonCancellable) {
                operation.withLock {
                    synchronized(profiles) { profiles[profileId] }?.let { runtime ->
                        if (runtime.firstHopRequest === request) runtime.firstHopRequest = null
                    }
                }
            }
        }
        return operation.withLock { completedAtElapsed }
    }

    internal suspend fun reportData(profileId: String, state: ByteArray, acceptedView: String, appliedView: String,
        permissionView: String): RuntimeReportData = operation.withLock {
        val runtime = runtime(profileId)
        ensureNetworkGeneration(profileId, runtime)
        val running = appliedView == acceptedView && runtime.runningProfile?.viewDigest == acceptedView
        val permissionCurrent = permissionView == acceptedView &&
            (runtime.availableProfile?.viewDigest == acceptedView || runtime.runningProfile?.viewDigest == acceptedView)
        val scopes = JSONArray(runtime.runningProfile?.serviceScopes ?: "[]").strings().toSet()
        val preferenceBytes = Loomcore.androidPreference(state)
        val preference = JSONObject(preferenceBytes.decodeToString())
        val policiesCurrent = runtime.application?.selectors?.all { selected ->
            val policy = if (selected.selector == "access") preference.optString("policy_id")
                else preference.optJSONObject("lan_policy_ids")?.optString(selected.selector.removePrefix("local_network:")).orEmpty()
            selected.policyID == policy
        } == true
        val complete = permissionCurrent && runtime.runningProfile?.viewDigest == acceptedView && runtime.selectorClient == null &&
            policiesCurrent &&
            runtime.application?.hasCompleteReadback(scopes, runtime.actual, runtime.actualTargets, runtime.actualPolicies, runtime.actualChoices) == true
        val selectionConfirmed = running && complete
        val preferredPolicies = scopes.associateWith { scope ->
            if (scope == "access") preference.optString("policy_id")
            else preference.optJSONObject("lan_policy_ids")?.optString(scope.removePrefix("local_network:")).orEmpty()
        }
        val pendingScopes = scopes.filterTo(linkedSetOf()) { runtime.selectorClient?.mayWrite(it) == true }
        val selected = if (permissionCurrent && runtime.runningProfile?.viewDigest == acceptedView)
            runtime.application?.confirmedReportSelectors(preferredPolicies, pendingScopes,
                runtime.actual, runtime.actualTargets, runtime.actualPolicies, runtime.actualChoices, runtime.actualRevisions).orEmpty()
            else emptyList()
        val selections = JSONArray(selected.sortedBy { it.selector }.map {
            JSONObject().put("scope", it.selector).put("candidate_id", it.candidate).put("targets",JSONObject(it.targets))
        }).toString().encodeToByteArray()
        val resources = if (permissionCurrent) runtime.resourceObservations
            ?: protected.get(ProfileStorage.resourceObservations(profileId)) ?: ByteArray(0) else ByteArray(0)
        val values = if (selectionConfirmed) observations(profileId).objects().filter { observation ->
            observation.getString("network_generation") == runtime.generation
        }.sortedBy { it.getString("candidate_id") } else emptyList()
        RuntimeReportData(
            preferenceBytes,
            resources,
            JSONArray(values).toString().encodeToByteArray(),
            selections,
            runtime.generation,
            complete,
        )
    }

    suspend fun tunnelStopped(profileId: String) = operation.withLock {
        val runtime = runtime(profileId)
        val previousRoute=runtime.application
        runtime.firstHopRequest?.cancel()
        cancelSelector(runtime)
        runtime.runningProfile = null
        runtime.application = null
        runtime.actual = linkedMapOf()
        runtime.actualTargets = emptyMap()
        runtime.actualRevisions = emptyMap()
        runtime.actualPolicies = emptyMap()
        runtime.actualChoices = emptyMap()
        runtime.selectionMemory = null
        runtime.linkObservations = null
        runtime.nativeObservations = "[]".encodeToByteArray()
        runtime.linkObservationViewDigest = ""
        runtime.hiddenPolicies=emptyMap()
        runtime.hiddenPolicyViewDigest=""
        previousRoute?.let { publish(profileId,runtime,it,running=false) }
        protected.put(ProfileStorage.observations(profileId), "[]".encodeToByteArray())
        runtime.mutableStatus.value = runtime.mutableStatus.value.copy(running = false, busy = false, currentPaths = emptyList(),
            businessEvidence = runtime.mutableStatus.value.businessEvidence.map { it.copy(current = false) }, observationDetail = "尚无本机 TCP 建连观测")
    }

    suspend fun removeProfile(profileId: String) = operation.withLock {
        require(ProfileStorage.validId(profileId)) { "配置标识无效" }
        synchronized(profiles) {
            check(profiles[profileId]?.runningProfile == null) { "运行中的配置不能删除" }
            profiles[profileId]?.let(::cancelSelector)
            profiles.remove(profileId)
        }
        protected.remove(ProfileStorage.routePreference(profileId))
        protected.remove(ProfileStorage.observations(profileId))
        protected.remove(ProfileStorage.resourceObservations(profileId))
        protected.remove(ProfileStorage.networkGeneration(profileId))
        protected.remove(ProfileStorage.networkIdentity(profileId))
    }

    internal suspend fun refreshFromMeasurements(profileId: String, profile: ManagedProfile, onlyScopes: Set<String>? = null) {
        val runtime = runtime(profileId)
        val input = operation.withLock {
            if (runtime.runningProfile !== profile || runtime.application == null ||
                runtime.selectorClient != null || runtime.mutableStatus.value.busy ||
                !catalog.contains(profileId) || ManagedProfileStore.get(applicationContext, profileId).acceptedViewDigest() != profile.viewDigest
            ) return@withLock null
            selectorInput(profileId, runtime, profile, plannedScopes = onlyScopes ?: JSONArray(profile.serviceScopes).strings())
        } ?: return
        try {
            selectorIO(profileId, runtime, input) {
                rereadSelector(profileId, runtime, input) { applySelector(profileId, runtime, it, onlyScopes) }
            }
        } catch (error: SelectionSuperseded) {
            // Cancellation/supersession cannot publish or close another choice.
        }
    }

    private fun confirmMemory(runtime: ProfileRuntime, route: AppliedRoute) {
        if (route.selectionMemory.isEmpty() || route.selectors.isEmpty()) return
        val previous = runtime.selectionMemory?.takeIf { it.isNotEmpty() }?.let { JSONObject(it.decodeToString()) } ?: JSONObject()
        val proposals = JSONObject(route.selectionMemory.decodeToString())
        val selectedByScope = route.selectors.associateBy { it.selector }
        val memory = confirmScopeMemory(previous.keys().asSequence().associateWith(previous::getJSONObject),
            proposals.keys().asSequence().associateWith(proposals::getJSONObject), selectedByScope.keys) { scope, proposal ->
            val selected = checkNotNull(selectedByScope[scope])
            val actual = JSONObject().put("scope",selected.selector).put("candidate_id",runtime.actual[selected.selector])
                .put("targets",JSONObject(runtime.actualTargets[selected.selector].orEmpty()))
                .put("revision",runtime.actualRevisions[selected.selector] ?: "0")
                .put("policy_id",runtime.actualPolicies[selected.selector] ?: "").put("choices",JSONObject(runtime.actualChoices[selected.selector].orEmpty()))
            val confirmed = JSONObject(Loomcore.confirmAndroidSelectionMemory(
                JSONObject().put(selected.selector, proposal).toString().encodeToByteArray(),
                actual.toString().encodeToByteArray(), SystemClock.elapsedRealtime()).decodeToString())
            confirmed.getJSONObject(selected.selector)
        }
        runtime.selectionMemory = JSONObject(memory).toString().encodeToByteArray()
    }

    internal suspend fun refreshNativeObservations(profileId: String,profile: ManagedProfile) {
        LoomVpnService.requestRuntimeResourceRetry(profileId)
        val repairScopes = operation.withLock {
            val runtime = runtime(profileId)
            val identity = ManagedProfileStore.get(applicationContext, profileId)
            if (runtime.runningProfile !== profile || runtime.application == null || runtime.selectorClient != null ||
                !catalog.contains(profileId) || identity.acceptedViewDigest() != profile.viewDigest) return@withLock null
            val application = checkNotNull(runtime.application)
            val scopes = JSONArray(profile.serviceScopes).strings().toSet()
            val selected = if (!application.hasCompleteReadback(scopes, runtime.actual, runtime.actualTargets, runtime.actualPolicies, runtime.actualChoices)) scopes
            else {
                val state = identity.state() ?: return@withLock null
                val preference = JSONObject(Loomcore.androidPreference(state).decodeToString())
                val lan = preference.optJSONObject("lan_policy_ids")
                application.blockedSelectedScopes(preference.optString("policy_id"),
                    lan?.let { choices -> choices.keys().asSequence().associateWith(choices::getString) }.orEmpty(), runtime.actual).intersect(scopes)
            }
            selected.takeIf { it.isNotEmpty() }
        }
        if (repairScopes != null) {
            // The same current facts can become unknown when their original
            // deadlines pass. This runs no probe and does not renew a sample.
            refreshFromMeasurements(profileId, profile, repairScopes)
            return
        }
        val runtime=runtime(profileId)
        val input=operation.withLock {
            if (runtime.runningProfile===profile&&runtime.hiddenPolicyViewDigest==profile.viewDigest&&
                runtime.hiddenPolicies.values.any { it<=System.currentTimeMillis() }) {
                val now=System.currentTimeMillis()
                runtime.hiddenPolicies=runtime.hiddenPolicies.filterValues { it>now }
                runtime.application?.let { publish(profileId,runtime,it,running=true) }
            }
            if (runtime.runningProfile !== profile || runtime.application==null || runtime.selectorClient!=null ||
                runtime.mutableStatus.value.busy || runtime.selectionMemory==null || !catalog.contains(profileId) ||
                runtime.actualPolicies["access"].isNullOrBlank() ||
                ManagedProfileStore.get(applicationContext,profileId).acceptedViewDigest()!=profile.viewDigest) return@withLock null
            selectorInput(profileId,runtime,profile,plannedScopes = emptyList())
        } ?: return
        try {
            selectorIO(profileId,runtime,input) {
                val read=try {
                    input.client.readCurrent(checkNotNull(runtime.application).execution().filter { it.selector=="access" }) to input.client.readNativeObservations()
                } catch(error: Exception) {
                    currentCoroutineContext().ensureActive()
                    if(error is SelectionSuperseded) throw error
                    Log.w("Loom","本机连接观测暂不可读；保持已确认选择")
                    return@selectorIO
                }
                val (current,events)=read
                val needsRouting=try { operation.withLock {
                    requireSelectorInput(profileId,runtime,input)
                    readbackScopes(runtime,input.client,current)
                    val result=JSONObject(Loomcore.refreshAndroidNativeObservations(
                        currentBody(runtime,current),checkNotNull(runtime.selectionMemory),runtime.nativeObservations,
                        events,runtime.generation,System.currentTimeMillis()).decodeToString())
                    runtime.nativeObservations=result.getJSONArray("native_observations").toString().encodeToByteArray()
                    runtime.selectionMemory=result.getJSONObject("memory").toString().encodeToByteArray()
                    runtime.mutableStatus.value=runtime.mutableStatus.value.copy(observationDetail=businessObservationDetail(runtime))
                    val route = !result.getBoolean("binding_current") || result.getBoolean("needs_routing") && !checkNotNull(runtime.application).nativeFixedExit
                    if (route) {
                        planSelectorScopes(runtime, input.client, listOf("access"))
                        runtime.mutableStatus.value = runtime.mutableStatus.value.copy(busy = true)
                    }
                    route
                } } catch(error: Exception) {
                    currentCoroutineContext().ensureActive()
                    if(error is SelectionSuperseded) throw error
                    Log.w("Loom","本机连接观测未接受；保持已确认选择")
                    return@selectorIO
                }
                if (needsRouting) rereadSelector(profileId,runtime,input) { applySelector(profileId,runtime,it,setOf("access")) }
            }
        } catch (error: SelectionSuperseded) {
            // An old network, runtime or user operation cannot publish facts.
        }
    }

    private fun evaluate(
        profileId: String,
        runtime: ProfileRuntime,
        profile: ManagedProfile,
        current: Map<String, String>,
        inputState: ByteArray? = null,
        nativeEvents: ByteArray = "{\"observations\":[]}".encodeToByteArray(),
    ): AppliedRoute {
        val state = inputState ?: checkNotNull(ManagedProfileStore.get(applicationContext, profileId).state())
        val currentBody = currentBody(runtime,current)
        val resources = runCatching {
            Loomcore.androidCachedResourceObservations(
                runtime.resourceObservations ?: protected.get(ProfileStorage.resourceObservations(profileId)) ?: ByteArray(0),
                profile.resourceCacheIdentity,
                runtime.generation.ifBlank { "startup" },
            )
        }.getOrElse {
            Log.w("Loom", "首跳样本缓存不可用；继续必要业务尝试")
            "[]".encodeToByteArray()
        }
        val body = Loomcore.evaluateAndroidRoutes(
            state,
            observations(profileId).toString().encodeToByteArray(),
            currentBody,
            runtime.generation.ifBlank { "startup" },
            System.currentTimeMillis(),
            resources,
            if (runtime.linkObservationViewDigest == profile.viewDigest) runtime.linkObservations ?: "[]".encodeToByteArray() else "[]".encodeToByteArray(),
            runtime.selectionMemory ?: ByteArray(0),
            SystemClock.elapsedRealtime(),
            runtime.nativeObservations,
            nativeEvents,
        )
        val root = JSONObject(body.decodeToString())
        return AppliedRoute(
            selectionMemory = root.getJSONObject("memory").toString().encodeToByteArray(),
            nativeObservations = root.getJSONArray("native_observations").toString().encodeToByteArray(),
            nativeFixedExit = root.getBoolean("native_fixed_exit"),
            choices = buildMap {
                JSONArray(profile.policyCatalog).objects().singleOrNull { it.getString("id") == root.optString("policy_id") }?.let { put(it.getString("service_id"), it.getString("id")) }
                root.optJSONObject("lan_policy_ids")?.let { lan -> lan.keys().forEach { service -> put(service, lan.getString(service)) } }
            },
            blockedScopes = root.getJSONArray("blocked_scopes").strings(),
            selectors = root.getJSONArray("selections").objects().map {
                AppliedSelector(
                    it.getString("selector"),
                    it.getString("candidate"),
                    it.optJSONArray("chain")?.strings().orEmpty(),
                    it.getString("final_exit"),
                    it.getString("state"),
                    targets = it.getJSONObject("targets").let { values -> values.keys().asSequence().associateWith(values::getString) },
                    expectedCandidate = it.optString("expected_candidate").ifBlank { null },
                    expectedRevision = it.getString("expected_revision"),
                    policyID = it.getString("policy_id"), choices = it.getJSONObject("choices").routeChoices(),
                    expectedPolicyID = it.getString("expected_policy_id"), expectedChoices = it.getJSONObject("expected_choices").routeChoices(),
                    expectedTargets = it.getJSONObject("expected_targets").let { values -> values.keys().asSequence().associateWith(values::getString) },
                    forceCAS = it.getBoolean("force_cas"),
                )
            },
        )
    }

    private fun currentBody(runtime: ProfileRuntime,current: Map<String,String>): ByteArray = JSONObject().apply {
        current.forEach { (selector,candidate) ->
            put(selector,JSONObject().put("policy_id",runtime.actualPolicies[selector] ?: "").put("choices",JSONObject(runtime.actualChoices[selector].orEmpty()))
                .put("candidate_id",candidate).put("revision",runtime.actualRevisions[selector] ?: "0").put("targets",JSONObject(runtime.actualTargets[selector].orEmpty())))
        }
    }.toString().encodeToByteArray()

    private fun observations(profileId: String): JSONArray = protected.get(ProfileStorage.observations(profileId))?.let {
        runCatching { JSONArray(it.decodeToString()) }.getOrNull()
    } ?: JSONArray()

    private fun businessObservationDetail(runtime: ProfileRuntime): String {
        val tcp = JSONArray(runtime.nativeObservations.decodeToString()).objects().filter {
            it.optString("action") in setOf("tcp_connect", "tcp_calibration") &&
                it.optString("network_generation") == runtime.generation && it.currentAt(Instant.now())
        }.maxByOrNull { Instant.parse(it.getString("observed_at")).minusMillis(it.optLong("metric_millis", 0L)) }
        return tcp?.let {
            tcpObservationDetail(it.getString("action"), it.getString("target"), it.getString("result"),
                it.optLong("metric_millis", 0L), it.getString("observed_at"), it.getString("valid_until"))
        } ?: "尚无本机 TCP 建连观测"
    }

    private fun ensureNetworkGeneration(profileId: String, runtime: ProfileRuntime) {
        if (runtime.generation.isNotBlank()) return
        runtime.generation = protected.get(ProfileStorage.networkGeneration(profileId))?.decodeToString().orEmpty()
        runtime.networkIdentity = protected.get(ProfileStorage.networkIdentity(profileId))?.decodeToString().orEmpty()
        if (runtime.generation.isNotBlank()) return
        runtime.generation = UUID.randomUUID().toString()
        protected.put(ProfileStorage.networkGeneration(profileId), runtime.generation.encodeToByteArray())
    }

    private fun publish(
        profileId: String,
        runtime: ProfileRuntime,
        route: AppliedRoute,
        running: Boolean,
        observation: String = runtime.mutableStatus.value.observationDetail,
    ) {
        val profile = runtime.runningProfile ?: runtime.availableProfile
        val policies = JSONArray(profile?.policyCatalog ?: "[]").objects()
        if (profile?.viewDigest!=runtime.hiddenPolicyViewDigest || !running) {
            runtime.hiddenPolicies=emptyMap()
            runtime.hiddenPolicyViewDigest=""
        }
        val hidden = if (profile!=null&&runtime.hiddenPolicyViewDigest==profile.viewDigest&&running) runtime.hiddenPolicies else emptyMap()
        val visibilityNow=System.currentTimeMillis()
        val services = JSONArray(profile?.serviceCatalog ?: "[]").objects().map { service ->
            val id = service.getString("id")
            val current=route.choices[id].orEmpty()
            ServicePolicyStatus(id, service.getString("name"), current, policies.filter {
                val policyID=it.getString("id")
                it.optString("service_id") == id && it.optString("action") == "allow" &&
                    (policyID==current || (hidden[policyID] ?: 0L)<=visibilityNow)
            }.map { ServicePolicyOption(it.getString("id"), it.getString("name")) })
        }.filter { it.options.isNotEmpty() }
        val now = Instant.now().toString()
        runtime.mutableStatus.value = RouteStatus(
            available = services.isNotEmpty(),
            busy = runtime.selectorClient?.mayWrite("access") == true,
            services = services,
            blocked = route.blockedScopes.isNotEmpty(),
            detail = (if (running) "服务策略已应用并读回" else "服务策略 · 等待连接") +
                if (route.blockedScopes.isEmpty()) "" else "；暂无可用路径：${route.blockedScopes.joinToString()}",
            observationDetail = observation,
            businessEvidence = businessEvidence(profileId, runtime, route, running, Instant.parse(now)),
            currentPaths = route.selectors.filter { running && runtime.actual[it.selector] == it.candidate }.map { selected ->
                RoutePathStatus(
                    service = selected.selector,
                    candidate = selected.candidate,
                    serverChain = selected.chain,
                    finalExit = selected.finalExit,
                    state = selected.state,
                    updatedAt = now,
                )
            },
            running = running,
        )
    }

    private fun businessEvidence(
        profileId: String,
        runtime: ProfileRuntime,
        route: AppliedRoute,
        running: Boolean,
        now: Instant,
    ): List<RouteBusinessStatus> {
        val profile = if (running) runtime.runningProfile else runtime.availableProfile
        if (profile == null) return emptyList()
        val candidates = JSONArray(profile.routes).objects().associate { it.getString("id") to "access" }
        val targets = mapOf("access" to profile.businessProbeTargets.filter { route.choices.containsKey(it.serviceID) }.flatMap { it.targets })
        val selected = route.selectors.filter { runtime.actual[it.selector] == it.candidate }.associate { it.selector to it.candidate }
        val samples = observations(profileId).objects().mapNotNull { sample ->
            runCatching {
                if (sample.getString("action") != "https_request") return@mapNotNull null
                val metric = if (sample.has("metric_millis")) {
                    val value = sample.get("metric_millis")
                    if (value !is Int && value !is Long) return@mapNotNull null
                    (value as Number).toLong()
                } else null
                RouteBusinessStatus(sample.getString("scope"), sample.getString("target"), sample.getString("candidate_id"),
                    sample.getString("network_generation"), sample.getString("result"), sample.getString("observed_at"),
                    sample.getString("valid_until"), metric)
            }.getOrNull()
        }
        return projectBusinessEvidence(targets, candidates, selected, samples, runtime.generation, now, running)
    }

    private fun runtime(profileId: String): ProfileRuntime {
        require(ProfileStorage.validId(profileId)) { "配置标识无效" }
        return synchronized(profiles) { profiles.getOrPut(profileId, ::ProfileRuntime) }
    }

    private class ProfileRuntime {
        val selectorIO = Mutex()
        var selectorClient: SelectorClient? = null
        val mutableStatus = MutableStateFlow(RouteStatus())
        @Volatile var availableProfile: ManagedProfile? = null
        @Volatile var runningProfile: ManagedProfile? = null
        @Volatile var generation: String = ""
        @Volatile var networkIdentity: String = ""
        @Volatile var actual = linkedMapOf<String, String>()
        var actualTargets: Map<String,Map<String,String>> = emptyMap()
        var actualRevisions: Map<String,String> = emptyMap()
        var actualPolicies: Map<String,String> = emptyMap()
        var actualChoices: Map<String,RouteChoices> = emptyMap()
        var selectionMemory: ByteArray? = null
        var nativeObservations: ByteArray = "[]".encodeToByteArray()
        @Volatile var application: AppliedRoute? = null
        var resourceObservations: ByteArray? = null
        var firstHopRequest: AndroidDeviceRequest? = null
        var linkObservations: ByteArray? = null
        var measurementSnapshot: ByteArray? = null
        var linkObservationViewDigest: String = ""
        var hiddenPolicies: Map<String,Long> = emptyMap()
        var hiddenPolicyViewDigest: String = ""
    }

    companion object {
        @Volatile private var instance: RouteManager? = null

        fun get(context: Context): RouteManager = instance ?: synchronized(this) {
            instance ?: RouteManager(context).also { instance = it }
        }
    }
}

private fun JSONArray.objects(): List<JSONObject> = (0 until length()).map(::getJSONObject)
private fun JSONArray.strings(): List<String> = (0 until length()).map(::getString)

private fun JSONObject.currentAt(now: Instant): Boolean = runCatching {
    !Instant.parse(getString("observed_at")).isAfter(now) && Instant.parse(getString("valid_until")).isAfter(now)
}.getOrDefault(false)
