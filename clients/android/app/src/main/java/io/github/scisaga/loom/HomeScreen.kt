package io.github.scisaga.loom

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.scisaga.loom.enrollment.EnrollmentPhase
import io.github.scisaga.loom.enrollment.EnrollmentStatus
import io.github.scisaga.loom.enrollment.InviteScanner
import io.github.scisaga.loom.profiles.ConnectionProfile
import io.github.scisaga.loom.profiles.ProfileIndex
import io.github.scisaga.loom.route.RouteMode
import io.github.scisaga.loom.route.RouteStatus
import io.github.scisaga.loom.vpn.ConnectionPhase
import io.github.scisaga.loom.vpn.VpnStatus

/** A read-only UI projection. It is never persisted and cannot update client authority. */
internal data class HomeUiState(
    val status: VpnStatus,
    val profiles: ProfileIndex,
    val join: EnrollmentStatus,
    val route: RouteStatus,
    val activeRoute: RouteStatus,
    val notificationsAllowed: Boolean,
    val diagnostics: String,
    val selectedTab: HomeTab,
    val scanning: Boolean = false,
)

/** User intents emitted by [LoomHomeScreen]; the route owns every side effect. */
internal data class HomeUiActions(
    val onTabSelected: (HomeTab) -> Unit = {},
    val onChooseProfile: () -> Unit = {},
    val onConnect: (String) -> Unit = {},
    val onDisconnect: () -> Unit = {},
    val onViewProfile: (String) -> Unit = {},
    val onAddProfile: () -> Unit = {},
    val onRenameProfile: (ConnectionProfile) -> Unit = {},
    val onDeleteProfile: (ConnectionProfile) -> Unit = {},
    val onScanned: (String) -> Unit = {},
    val onCancelScan: () -> Unit = {},
    val onStartScan: () -> Unit = {},
    val onImportFile: (String) -> Unit = {},
    val onRetryEnrollment: (String) -> Unit = {},
    val onRefreshEnrollment: (String) -> Unit = {},
    val onAbandonEnrollment: (String) -> Unit = {},
    val onSelectRoute: (String, RouteMode, String) -> Unit = { _, _, _ -> },
    val onOpenNotificationSettings: () -> Unit = {},
)

@Composable
internal fun LoomHomeScreen(state: HomeUiState, actions: HomeUiActions = HomeUiActions()) {
    val status = state.status
    val profiles = state.profiles
    val viewedProfile = profiles.viewed
    val activeProfile = profiles.profiles.firstOrNull { it.id == status.activeProfileId }
    val requestedProfile = profiles.profiles.firstOrNull { it.id == status.requestedProfileId }
    val headerProfile = activeProfile ?: requestedProfile ?: viewedProfile
    val hasManagedProfile = state.join.snapshot.isNotEmpty()
    val connectionScroll = rememberScrollState()
    val configurationScroll = rememberScrollState()
    val diagnosticsScroll = rememberScrollState()

    Scaffold(
        containerColor = Paper,
        bottomBar = { HomeTabBar(state.selectedTab, actions.onTabSelected) },
    ) { contentPadding ->
        Column(Modifier.fillMaxSize().padding(contentPadding)) {
            LoomHeader(headerProfile.name, status)
            when (state.selectedTab) {
                HomeTab.CONNECTION -> HomePage(
                    title = "连接",
                    subtitle = "连接状态与当前生效路径",
                    scrollState = connectionScroll,
                    modifier = Modifier.weight(1f),
                ) {
                    ConnectionCard(
                        status = status,
                        viewedProfile = viewedProfile,
                        activeProfile = activeProfile,
                        requestedProfile = requestedProfile,
                        hasManagedProfile = hasManagedProfile,
                        onChoose = actions.onChooseProfile,
                        onConnect = { actions.onConnect(viewedProfile.id) },
                        onDisconnect = actions.onDisconnect,
                    )
                    if (!hasManagedProfile) {
                        OutlinedButton(
                            onClick = { actions.onTabSelected(HomeTab.CONFIGURATION) },
                            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag("go-to-enrollment"),
                        ) {
                            Text("前往配置加入网络")
                        }
                    }
                    CurrentPathCard(
                        paths = state.activeRoute.currentPaths,
                        running = state.activeRoute.running && status.phase == ConnectionPhase.CONNECTED,
                        profileName = activeProfile?.name.orEmpty(),
                    )
                }

                HomeTab.CONFIGURATION -> HomePage(
                    title = "配置",
                    subtitle = enrollmentSummary(state.join),
                    scrollState = configurationScroll,
                    modifier = Modifier.weight(1f),
                ) {
                    ProfilesCard(
                        index = profiles,
                        vpn = status,
                        onView = actions.onViewProfile,
                        onAdd = actions.onAddProfile,
                        onRename = actions.onRenameProfile,
                        onDelete = actions.onDeleteProfile,
                    )
                    if (state.scanning) {
                        InviteScanner(onScanned = actions.onScanned, onCancel = actions.onCancelScan)
                    } else if (state.join.phase == EnrollmentPhase.READY) {
                        JoinedDeviceCard(viewedProfile, state.join) {
                            actions.onRefreshEnrollment(viewedProfile.id)
                        }
                    } else {
                        EnrollmentCard(
                            profile = viewedProfile,
                            status = state.join,
                            onScan = actions.onStartScan,
                            onImportFile = { actions.onImportFile(viewedProfile.id) },
                            onRetry = { actions.onRetryEnrollment(viewedProfile.id) },
                            onRefresh = { actions.onRefreshEnrollment(viewedProfile.id) },
                            onAbandonPending = { actions.onAbandonEnrollment(viewedProfile.id) },
                        )
                    }
                    RouteModeCard(state.route) { mode, exit ->
                        actions.onSelectRoute(viewedProfile.id, mode, exit)
                    }
                    Text(
                        "配置身份、签名运行配置与连接模式均保存在本机受保护存储中。",
                        color = Muted,
                        fontSize = 12.sp,
                    )
                    if (!state.notificationsAllowed) {
                        NotificationPermissionCard(actions.onOpenNotificationSettings)
                    }
                }

                HomeTab.DIAGNOSTICS -> HomePage(
                    title = "诊断",
                    subtitle = "网络证据、可信上报与本机组件",
                    scrollState = diagnosticsScroll,
                    modifier = Modifier.weight(1f),
                ) {
                    NetworkEvidenceCard(
                        status,
                        if (status.activeProfileId.isNotBlank()) state.activeRoute else state.route,
                        activeProfile?.name ?: viewedProfile.name,
                        status.deviceName.ifBlank { state.join.deviceName },
                        state.diagnostics,
                    )
                }
            }
        }
    }
}
