package io.github.scisaga.loom

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.android.tools.screenshot.PreviewTest
import io.github.scisaga.loom.enrollment.EnrollmentPhase
import io.github.scisaga.loom.enrollment.EnrollmentStatus
import io.github.scisaga.loom.profiles.ConnectionProfile
import io.github.scisaga.loom.profiles.ProfileIndex
import io.github.scisaga.loom.route.RouteMode
import io.github.scisaga.loom.route.RoutePathStatus
import io.github.scisaga.loom.route.RouteStatus
import io.github.scisaga.loom.vpn.ConnectionPhase
import io.github.scisaga.loom.vpn.VpnStatus

private const val secondProfileID = "00112233445566778899aabbccddeeff"

private val singleProfile = ProfileIndex(
    profiles = listOf(ConnectionProfile("primary", "Loom 演示网络")),
    viewedProfileId = "primary",
)

private val multipleProfiles = ProfileIndex(
    profiles = listOf(
        ConnectionProfile("primary", "Loom 演示网络"),
        ConnectionProfile(secondProfileID, "Loom 备用网络"),
    ),
    viewedProfileId = "primary",
)

private val demoPaths = listOf(
    RoutePathStatus(
        service = "demo-web",
        candidate = "demo-candidate-direct",
        serverChain = listOf("demo-cn", "demo-exit"),
        state = "available",
        updatedAt = "2026-01-02T03:04:05Z",
    ),
    RoutePathStatus(
        service = "demo-api",
        candidate = "demo-candidate-fallback",
        serverChain = listOf("demo-exit"),
        state = "unknown",
        updatedAt = "2026-01-02T03:04:06Z",
    ),
)

private val readyEnrollment = EnrollmentStatus(
    phase = EnrollmentPhase.READY,
    detail = "认证配置已验证",
    nodeID = "demo-node",
    deviceName = "demo-phone",
    snapshot = "demo-certified-lkg",
    generation = 7,
)

private val connectedStatus = VpnStatus(
    phase = ConnectionPhase.CONNECTED,
    detail = "已通过认证候选建立连接",
    requestedProfileId = "primary",
    activeProfileId = "primary",
    deviceName = "demo-phone",
    generation = 7,
    dnsProbe = "成功",
    httpsProbe = "成功",
    trustedReport = "已签名上报",
)

private val connectedRoute = RouteStatus(
    available = true,
    mode = RouteMode.AUTO,
    exits = listOf("demo-exit"),
    directAvailable = true,
    detail = "Auto · 当前 selector 已回读",
    observationDetail = "真实 DNS 与 HTTPS 业务成功",
    currentPaths = demoPaths,
    running = true,
)

private fun homeState(
    tab: HomeTab,
    status: VpnStatus = VpnStatus(),
    profiles: ProfileIndex = singleProfile,
    join: EnrollmentStatus = EnrollmentStatus(
        phase = EnrollmentPhase.NOT_JOINED,
        detail = "尚未导入一次性加入邀请",
    ),
    route: RouteStatus = RouteStatus(),
    activeRoute: RouteStatus = route,
    notificationsAllowed: Boolean = true,
): HomeUiState = HomeUiState(
    status = status,
    profiles = profiles,
    join = join,
    route = route,
    activeRoute = activeRoute,
    notificationsAllowed = notificationsAllowed,
    diagnostics = "libbox demo-1.11.4 · core demo-v2",
    selectedTab = tab,
)

@PreviewTest
@Preview(name = "connection-disconnected-unjoined", widthDp = 412, heightDp = 915, locale = "zh-rCN", fontScale = 1.0f)
@Composable
fun connectionDisconnectedUnjoined() {
    LoomTheme { LoomHomeScreen(homeState(HomeTab.CONNECTION)) }
}

@PreviewTest
@Preview(name = "connection-connected-auto", widthDp = 412, heightDp = 915, locale = "zh-rCN", fontScale = 1.0f)
@Composable
fun connectionConnectedAuto() {
    LoomTheme {
        LoomHomeScreen(
            homeState(
                tab = HomeTab.CONNECTION,
                status = connectedStatus,
                profiles = multipleProfiles,
                join = readyEnrollment,
                route = connectedRoute,
                activeRoute = connectedRoute,
            ),
        )
    }
}

@PreviewTest
@Preview(name = "connection-error", widthDp = 412, heightDp = 915, locale = "zh-rCN", fontScale = 1.0f)
@Composable
fun connectionError() {
    LoomTheme {
        LoomHomeScreen(
            homeState(
                tab = HomeTab.CONNECTION,
                status = VpnStatus(
                    phase = ConnectionPhase.ERROR,
                    detail = "demo-exit 的真实业务检查失败",
                    requestedProfileId = "primary",
                    deviceName = "demo-phone",
                ),
                join = readyEnrollment,
                route = connectedRoute.copy(running = false, blocked = true, detail = "当前没有可用候选"),
            ),
        )
    }
}

@PreviewTest
@Preview(name = "configuration-not-joined", widthDp = 412, heightDp = 915, locale = "zh-rCN", fontScale = 1.0f)
@Composable
fun configurationNotJoined() {
    LoomTheme { LoomHomeScreen(homeState(HomeTab.CONFIGURATION)) }
}

@PreviewTest
@Preview(name = "configuration-ready-multiple-profiles", widthDp = 412, heightDp = 915, locale = "zh-rCN", fontScale = 1.0f)
@Composable
fun configurationReadyMultipleProfiles() {
    LoomTheme {
        LoomHomeScreen(
            homeState(
                tab = HomeTab.CONFIGURATION,
                status = connectedStatus,
                profiles = multipleProfiles,
                join = readyEnrollment,
                route = connectedRoute,
                activeRoute = connectedRoute,
            ),
        )
    }
}

@PreviewTest
@Preview(name = "configuration-join-error", widthDp = 412, heightDp = 915, locale = "zh-rCN", fontScale = 1.0f)
@Composable
fun configurationJoinError() {
    LoomTheme {
        LoomHomeScreen(
            homeState(
                tab = HomeTab.CONFIGURATION,
                join = EnrollmentStatus(
                    phase = EnrollmentPhase.ERROR,
                    detail = "私有通道暂不可达；已保留同一加入事务",
                    nodeID = "demo-node",
                    deviceName = "demo-phone",
                    canAbandonPending = true,
                ),
            ),
        )
    }
}

@PreviewTest
@Preview(name = "diagnostics-connected", widthDp = 412, heightDp = 915, locale = "zh-rCN", fontScale = 1.0f)
@Composable
fun diagnosticsConnected() {
    LoomTheme {
        LoomHomeScreen(
            homeState(
                tab = HomeTab.DIAGNOSTICS,
                status = connectedStatus,
                profiles = multipleProfiles,
                join = readyEnrollment,
                route = connectedRoute,
                activeRoute = connectedRoute,
            ),
        )
    }
}

@PreviewTest
@Preview(name = "profile-picker", widthDp = 412, heightDp = 915, locale = "zh-rCN", fontScale = 1.0f)
@Composable
fun profilePicker() {
    LoomTheme {
        Surface(modifier = Modifier.fillMaxSize(), color = Paper) {
            Column(Modifier.padding(top = 520.dp)) {
                ProfilePickerContent(
                    index = multipleProfiles,
                    activeProfileId = "primary",
                    onSelect = {},
                    onDismiss = {},
                )
            }
        }
    }
}

@PreviewTest
@Preview(name = "notification-warning", widthDp = 412, heightDp = 915, locale = "zh-rCN", fontScale = 1.0f)
@Composable
fun notificationWarning() {
    LoomTheme {
        Surface(modifier = Modifier.fillMaxSize(), color = Paper) {
            Column(Modifier.padding(22.dp)) {
                NotificationPermissionCard(onOpenSettings = {})
            }
        }
    }
}
