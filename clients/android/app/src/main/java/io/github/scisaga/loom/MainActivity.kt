package io.github.scisaga.loom

import android.Manifest
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.Image
import androidx.compose.foundation.ScrollState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ColorFilter
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.scisaga.loom.enrollment.EnrollmentManager
import io.github.scisaga.loom.enrollment.EnrollmentPhase
import io.github.scisaga.loom.enrollment.EnrollmentStatus
import io.github.scisaga.loom.enrollment.InviteScanner
import io.github.scisaga.libbox.Libbox
import io.github.scisaga.loom.route.RouteManager
import io.github.scisaga.loom.route.RouteMode
import io.github.scisaga.loom.route.RoutePathStatus
import io.github.scisaga.loom.route.RouteStatus
import io.github.scisaga.loom.vpn.ConnectionPhase
import io.github.scisaga.loom.vpn.LoomVpnService
import io.github.scisaga.loom.vpn.VpnRuntime
import io.github.scisaga.loom.vpn.VpnStatus
import io.github.scisaga.loomcore.Loomcore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.io.InputStream

internal val LoomGreen = Color(0xFF239B68)
internal val Ink = Color(0xFF17211B)
internal val Muted = Color(0xFF647269)
internal val Paper = Color(0xFFF0F4F1)
internal val CardTint = Color(0xFFF7FBF8)

private enum class HomeTab(val label: String) {
    CONNECTION("连接"),
    CONFIGURATION("配置"),
    DIAGNOSTICS("诊断"),
}

class MainActivity : ComponentActivity() {
    private val enrollment by lazy { EnrollmentManager.get(this) }
    private var notificationsAllowed by mutableStateOf(true)

    private val vpnPermission = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        if (it.resultCode == RESULT_OK) {
            connect()
        } else {
            VpnRuntime.update(
                VpnStatus(
                    phase = ConnectionPhase.ERROR,
                    detail = "未获得 Android VPN 权限；请在系统确认页允许 Loom 建立 VPN",
                ),
            )
        }
    }

    private val notificationPermission = registerForActivityResult(ActivityResultContracts.RequestPermission()) {
        notificationsAllowed = notificationPermissionGranted()
    }

    private val inviteFile = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) return@registerForActivityResult
        lifecycleScope.launch(Dispatchers.IO) {
            runCatching {
                val body = contentResolver.openInputStream(uri)?.use { stream ->
                    readBounded(stream, MAX_INVITE_BYTES)
                } ?: error("无法读取加入文件")
                require(body.isNotEmpty() && body.size <= MAX_INVITE_BYTES) { "加入文件必须小于 16 KiB" }
                enrollment.importInvite(body.decodeToString())
            }.onFailure(enrollment::reportImportError)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        notificationsAllowed = notificationPermissionGranted()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            !notificationsAllowed
        ) {
            notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
        enrollment.initialize()
        setContent {
            LoomHome(
                enrollment = enrollment,
                onToggle = ::toggle,
                onImportFile = { inviteFile.launch(arrayOf("*/*")) },
                notificationsAllowed = notificationsAllowed,
                onOpenNotificationSettings = ::openNotificationSettings,
            )
        }
    }

    override fun onResume() {
        super.onResume()
        notificationsAllowed = notificationPermissionGranted()
        if (VpnRuntime.status.value.phase in setOf(ConnectionPhase.STARTING, ConnectionPhase.CONNECTED)) {
            ContextCompat.startForegroundService(
                this,
                Intent(this, LoomVpnService::class.java).setAction(LoomVpnService.ACTION_SYNC_SYSTEM_POLICY),
            )
        }
    }

    private fun toggle(phase: ConnectionPhase) {
        if (phase == ConnectionPhase.CONNECTED || phase == ConnectionPhase.STARTING) {
            ContextCompat.startForegroundService(
                this,
                Intent(this, LoomVpnService::class.java).setAction(LoomVpnService.ACTION_DISCONNECT),
            )
            return
        }
        val permission = VpnService.prepare(this)
        if (permission != null) vpnPermission.launch(permission) else connect()
    }

    private fun connect() {
        ContextCompat.startForegroundService(
            this,
            Intent(this, LoomVpnService::class.java).setAction(LoomVpnService.ACTION_CONNECT),
        )
    }

    private fun notificationPermissionGranted(): Boolean =
        NotificationManagerCompat.from(this).areNotificationsEnabled()

    private fun openNotificationSettings() {
        startActivity(
            Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS)
                .putExtra(Settings.EXTRA_APP_PACKAGE, packageName),
        )
    }

    companion object {
        private const val MAX_INVITE_BYTES = 16 * 1024
    }
}

@Composable
private fun LoomHome(
    enrollment: EnrollmentManager,
    onToggle: (ConnectionPhase) -> Unit,
    onImportFile: () -> Unit,
    notificationsAllowed: Boolean,
    onOpenNotificationSettings: () -> Unit,
) {
    val status by VpnRuntime.status.collectAsStateWithLifecycle()
    val join by enrollment.status.collectAsStateWithLifecycle()
    val context = LocalContext.current
    val routeManager = remember(context) { RouteManager.get(context) }
    val route by routeManager.status.collectAsStateWithLifecycle()
    val hasManagedProfile = join.snapshot.isNotEmpty()
    var diagnostics by remember { mutableStateOf("正在检查…") }
    var scanning by remember { mutableStateOf(false) }
    var selectedTab by rememberSaveable { mutableStateOf(HomeTab.CONNECTION) }
    val connectionScroll = rememberScrollState()
    val configurationScroll = rememberScrollState()
    val diagnosticsScroll = rememberScrollState()
    LaunchedEffect(Unit) {
        diagnostics = withContext(Dispatchers.IO) {
            runCatching {
                "libbox ${Libbox.version()} · core ${Loomcore.version()}"
            }.getOrElse { "自检失败：${it.message}" }
        }
    }
    MaterialTheme(
        colorScheme = lightColorScheme(
            primary = LoomGreen,
            onPrimary = Color.White,
            background = Paper,
            surface = Color.White,
            onSurface = Ink,
            onSurfaceVariant = Muted,
        ),
    ) {
        Scaffold(
            containerColor = Paper,
            bottomBar = {
                HomeTabBar(selectedTab) {
                    scanning = false
                    selectedTab = it
                }
            },
        ) { contentPadding ->
            Column(Modifier.fillMaxSize().padding(contentPadding)) {
                LoomHeader()
                when (selectedTab) {
                    HomeTab.CONNECTION -> HomePage(
                        title = "连接",
                        subtitle = "连接状态与当前生效路径",
                        scrollState = connectionScroll,
                        modifier = Modifier.weight(1f),
                    ) {
                        ConnectionCard(status, join, hasManagedProfile, onToggle)
                        if (!hasManagedProfile) {
                            OutlinedButton(
                                onClick = { selectedTab = HomeTab.CONFIGURATION },
                                modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag("go-to-enrollment"),
                            ) {
                                Text("前往配置加入网络")
                            }
                        }
                        CurrentPathCard(
                            paths = route.currentPaths,
                            running = route.running && status.phase == ConnectionPhase.CONNECTED,
                            profileName = join.profileName,
                        )
                    }

                    HomeTab.CONFIGURATION -> HomePage(
                        title = "配置",
                        subtitle = enrollmentSummary(join),
                        scrollState = configurationScroll,
                        modifier = Modifier.weight(1f),
                    ) {
                        if (scanning) {
                            InviteScanner(
                                onScanned = {
                                    scanning = false
                                    enrollment.importInvite(it)
                                },
                                onCancel = { scanning = false },
                            )
                        } else if (join.phase == EnrollmentPhase.READY) {
                            JoinedDeviceCard(join, enrollment::refreshConfiguration)
                        } else {
                            EnrollmentCard(
                                status = join,
                                onScan = { scanning = true },
                                onImportFile = onImportFile,
                                onRetry = enrollment::retry,
                                onRefresh = enrollment::refreshConfiguration,
                                onAbandonPending = enrollment::abandonPending,
                            )
                        }
                        RouteModeCard(route, routeManager::select)
                        Text(
                            "配置身份、签名运行配置与连接模式均保存在本机受保护存储中。",
                            color = Muted,
                            fontSize = 12.sp,
                        )
                        if (!notificationsAllowed) NotificationPermissionCard(onOpenNotificationSettings)
                    }

                    HomeTab.DIAGNOSTICS -> HomePage(
                        title = "诊断",
                        subtitle = "网络证据、可信上报与本机组件",
                        scrollState = diagnosticsScroll,
                        modifier = Modifier.weight(1f),
                    ) {
                        NetworkEvidenceCard(status, route, join.profileName, diagnostics)
                    }
                }
            }
        }
    }
}

@Composable
private fun LoomHeader() {
    Row(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 22.dp, vertical = 14.dp),
        verticalAlignment = Alignment.Top,
    ) {
        Image(
            painter = painterResource(R.drawable.ic_loom),
            contentDescription = "Loom",
            colorFilter = ColorFilter.tint(Ink),
            modifier = Modifier.size(32.dp).testTag("loom-mark"),
        )
        Column(Modifier.padding(start = 9.dp)) {
            Text(
                "LOOM",
                color = Ink,
                fontSize = 18.sp,
                lineHeight = 20.sp,
                fontWeight = FontWeight.Medium,
                letterSpacing = 2.sp,
                modifier = Modifier.testTag("loom-wordmark"),
            )
            Text(
                "ANDROID",
                color = Muted,
                fontSize = 9.sp,
                lineHeight = 12.sp,
                letterSpacing = 1.sp,
            )
        }
    }
}

@Composable
private fun HomePage(
    title: String,
    subtitle: String,
    scrollState: ScrollState,
    modifier: Modifier = Modifier,
    content: @Composable ColumnScope.() -> Unit,
) {
    Column(
        modifier = modifier
            .verticalScroll(scrollState)
            .padding(horizontal = 22.dp, vertical = 10.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text(title, color = Ink, fontSize = 26.sp, fontWeight = FontWeight.Bold)
        Text(subtitle, color = Muted, fontSize = 13.sp)
        content()
    }
}

@Composable
private fun HomeTabBar(selected: HomeTab, onSelect: (HomeTab) -> Unit) {
    NavigationBar(
        containerColor = Color.White,
        tonalElevation = 0.dp,
        modifier = Modifier.testTag("home-tabs"),
    ) {
        HomeTab.entries.forEach { tab ->
            NavigationBarItem(
                selected = selected == tab,
                onClick = { onSelect(tab) },
                icon = { HomeTabIcon(tab, selected == tab) },
                label = { Text(tab.label) },
                modifier = Modifier.testTag("tab-${tab.name.lowercase()}"),
                colors = NavigationBarItemDefaults.colors(
                    selectedIconColor = LoomGreen,
                    selectedTextColor = LoomGreen,
                    indicatorColor = Color(0xFFEAF6F0),
                    unselectedIconColor = Muted,
                    unselectedTextColor = Muted,
                ),
            )
        }
    }
}

@Composable
private fun HomeTabIcon(tab: HomeTab, selected: Boolean) {
    val color = if (selected) LoomGreen else Muted
    Canvas(Modifier.size(22.dp)) {
        val width = 1.8.dp.toPx()
        val line = Stroke(width = width, cap = StrokeCap.Round, join = StrokeJoin.Round)
        when (tab) {
            HomeTab.CONNECTION -> {
                drawCircle(color = color, radius = size.minDimension * 0.33f, style = line)
                drawLine(
                    color = color,
                    start = Offset(size.width * 0.5f, size.height * 0.08f),
                    end = Offset(size.width * 0.5f, size.height * 0.46f),
                    strokeWidth = width,
                    cap = StrokeCap.Round,
                )
            }

            HomeTab.CONFIGURATION -> {
                listOf(0.25f to 0.35f, 0.5f to 0.68f, 0.75f to 0.45f).forEach { (y, knob) ->
                    drawLine(
                        color = color,
                        start = Offset(size.width * 0.16f, size.height * y),
                        end = Offset(size.width * 0.84f, size.height * y),
                        strokeWidth = width,
                        cap = StrokeCap.Round,
                    )
                    drawCircle(
                        color = color,
                        radius = size.minDimension * 0.09f,
                        center = Offset(size.width * knob, size.height * y),
                    )
                }
            }

            HomeTab.DIAGNOSTICS -> {
                val path = Path().apply {
                    moveTo(size.width * 0.08f, size.height * 0.5f)
                    lineTo(size.width * 0.3f, size.height * 0.5f)
                    lineTo(size.width * 0.43f, size.height * 0.16f)
                    lineTo(size.width * 0.6f, size.height * 0.84f)
                    lineTo(size.width * 0.74f, size.height * 0.5f)
                    lineTo(size.width * 0.92f, size.height * 0.5f)
                }
                drawPath(path = path, color = color, style = line)
            }
        }
    }
}

internal fun enrollmentSummary(join: EnrollmentStatus): String = when {
    join.phase == EnrollmentPhase.READY -> "设备已加入 · 配置签名已验证"
    join.phase == EnrollmentPhase.PULLING -> "正在下载并验证配置更新"
    join.phase == EnrollmentPhase.ERROR && join.snapshot.isNotEmpty() -> "更新未完成 · 已安装配置保留"
    join.snapshot.isNotEmpty() -> "设备已加入 · 已安装配置保留"
    else -> "加入网络、管理配置与本机信息"
}

@Composable
private fun ConnectionCard(
    status: VpnStatus,
    join: EnrollmentStatus,
    hasManagedProfile: Boolean,
    onToggle: (ConnectionPhase) -> Unit,
) {
    val running = status.phase in setOf(ConnectionPhase.STARTING, ConnectionPhase.CONNECTED)
    Card(
        colors = CardDefaults.cardColors(containerColor = CardTint),
        shape = RoundedCornerShape(20.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Box(Modifier.size(11.dp).background(phaseColor(status.phase), CircleShape))
                Text(
                    phaseText(status.phase),
                    modifier = Modifier.padding(start = 9.dp).weight(1f).testTag("connection-status"),
                    color = Ink,
                    fontWeight = FontWeight.Bold,
                    fontSize = 20.sp,
                )
            }
            Text(
                if (hasManagedProfile) join.profileName.ifBlank { "认证配置" } else "尚未加入网络",
                color = Muted,
                fontSize = 13.sp,
                modifier = Modifier.testTag("connection-profile-name"),
            )
            if (status.detail.isNotBlank()) {
                Text(
                    status.detail,
                    color = if (status.phase == ConnectionPhase.ERROR) Color(0xFFB33A3A) else Muted,
                    fontSize = 12.sp,
                )
            }
            if (status.alwaysOn) {
                Text(
                    "Android 已开启“始终开启 VPN”，断开请在系统 VPN 设置中管理。",
                    color = Muted,
                    fontSize = 12.sp,
                    modifier = Modifier.testTag("always-on-guidance"),
                )
            }
            Button(
                onClick = { onToggle(status.phase) },
                enabled = status.phase != ConnectionPhase.STOPPING &&
                    !(status.alwaysOn && running) &&
                    (hasManagedProfile || running),
                modifier = Modifier.fillMaxWidth().heightIn(min = 50.dp).testTag("connection-toggle"),
                colors = ButtonDefaults.buttonColors(containerColor = LoomGreen),
                shape = RoundedCornerShape(14.dp),
            ) {
                Text(
                    when {
                        status.alwaysOn && running -> "由系统保持连接"
                        running -> "断开"
                        hasManagedProfile -> "连接"
                        else -> "请先加入网络"
                    },
                )
            }
        }
    }
}

@Composable
private fun JoinedDeviceCard(status: EnrollmentStatus, onRefresh: () -> Unit) {
    Card(
        colors = CardDefaults.cardColors(containerColor = Color.White),
        shape = RoundedCornerShape(16.dp),
        modifier = Modifier.fillMaxWidth().testTag("enrollment-card"),
    ) {
        Column(Modifier.padding(horizontal = 16.dp, vertical = 14.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                    Text("连接配置", color = Muted, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                    Text(
                        status.profileName.ifBlank { "认证配置" },
                        color = Ink,
                        fontSize = 17.sp,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.testTag("profile-name"),
                    )
                    Text(
                        if (status.generation > 0) "第 ${status.generation} 版 · 配置签名已验证" else "配置签名已验证",
                        color = Muted,
                        fontSize = 12.sp,
                    )
                }
                TextButton(onClick = onRefresh, modifier = Modifier.testTag("refresh-config")) {
                    Text("检查更新")
                }
            }
        }
    }
}

@Composable
private fun CurrentPathCard(paths: List<RoutePathStatus>, running: Boolean, profileName: String) {
    var showingDetails by rememberSaveable(profileName, running) { mutableStateOf(true) }
    var selectedDetail by rememberSaveable(profileName, running) { mutableStateOf(0) }
    LaunchedEffect(paths.size) {
        if (selectedDetail > paths.lastIndex) selectedDetail = 0
    }
    val summaries = remember(paths, running) { if (running) summarizeRoutePaths(paths) else emptyList() }
    Card(
        colors = CardDefaults.cardColors(containerColor = Color.White),
        shape = RoundedCornerShape(16.dp),
        modifier = Modifier.fillMaxWidth().testTag("route-summary-card"),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text("当前路径", color = Ink, fontSize = 17.sp, fontWeight = FontWeight.Bold)
                Surface(
                    color = if (running) Color(0xFFEAF6F0) else Color(0xFFF0F2F1),
                    shape = RoundedCornerShape(20.dp),
                ) {
                    Text(
                        if (running) "当前连接" else "未连接",
                        color = if (running) LoomGreen else Muted,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 5.dp),
                    )
                }
            }
            if (running && profileName.isNotBlank()) {
                Text(profileName, color = Muted, fontSize = 12.sp, modifier = Modifier.testTag("path-profile-name"))
            }
            if (summaries.isEmpty()) {
                Text(
                    if (running) "当前路径尚未确认" else "连接后显示各服务的实际路径",
                    color = Muted,
                    fontSize = 13.sp,
                )
            } else {
                if (!showingDetails) {
                    summaries.take(2).forEachIndexed { index, summary ->
                        if (index > 0) Box(Modifier.fillMaxWidth().height(1.dp).background(Color(0xFFE3E8E5)))
                        Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
                            Text(summary.servicesLabel, color = Ink, fontSize = 14.sp, fontWeight = FontWeight.Bold)
                            Text(summary.chainLabel, color = Ink, fontSize = 13.sp)
                            Text(summary.stateLabel, color = Muted, fontSize = 12.sp)
                        }
                    }
                    if (summaries.size > 2) {
                        Text("另有 ${summaries.size - 2} 组实际路径", color = Muted, fontSize = 12.sp)
                    }
                }
                if (showingDetails) {
                    Box(Modifier.fillMaxWidth().height(1.dp).background(Color(0xFFE3E8E5)))
                    Column(
                        modifier = Modifier.testTag("route-details-inline"),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Text(
                            "逐项详情 · ${selectedDetail + 1}/${paths.size}",
                            color = Muted,
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Bold,
                        )
                        RouteDetail(paths[selectedDetail.coerceIn(0, paths.lastIndex)])
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            OutlinedButton(
                                onClick = { selectedDetail -= 1 },
                                enabled = selectedDetail > 0,
                                modifier = Modifier.weight(1f).testTag("route-details-previous"),
                            ) { Text("上一项") }
                            TextButton(
                                onClick = { showingDetails = false },
                                modifier = Modifier.weight(1f).testTag("route-details-close"),
                            ) { Text("收起") }
                            OutlinedButton(
                                onClick = { selectedDetail += 1 },
                                enabled = selectedDetail < paths.lastIndex,
                                modifier = Modifier.weight(1f).testTag("route-details-next"),
                            ) { Text("下一项") }
                        }
                    }
                } else {
                    OutlinedButton(
                        onClick = {
                            selectedDetail = 0
                            showingDetails = true
                        },
                        modifier = Modifier.fillMaxWidth().testTag("route-details-open"),
                    ) {
                        Text("查看 ${paths.size} 项详情")
                    }
                }
            }
        }
    }
}

@Composable
private fun RouteDetail(path: RoutePathStatus) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(displayRouteService(path.service), color = Ink, fontSize = 15.sp, fontWeight = FontWeight.Bold)
        RouteChainDiagram(path)
        Text("当前结果：${displayRouteState(path.state)}", color = Muted, fontSize = 12.sp)
        Text("实际候选：${displayRouteCandidate(path.candidate)}", color = Muted, fontSize = 12.sp)
        if (path.updatedAt.isNotBlank()) Text("决策时间：${path.updatedAt}", color = Muted, fontSize = 11.sp)
    }
}

@Composable
private fun NetworkEvidenceCard(
    status: VpnStatus,
    route: RouteStatus,
    profileName: String,
    diagnostics: String,
) {
    Card(
        colors = CardDefaults.cardColors(containerColor = Color.White),
        shape = RoundedCornerShape(20.dp),
        modifier = Modifier.fillMaxWidth().testTag("network-evidence-card"),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
            Text("网络诊断", color = Ink, fontSize = 17.sp, fontWeight = FontWeight.Bold)
            if (profileName.isNotBlank()) Text(profileName, color = Muted, fontSize = 13.sp)
            Text(
                "业务 DNS/HTTPS\n${status.dnsProbe} / ${status.httpsProbe}\n" +
                    "可信上报：${status.trustedReport}\n服务器观测：${route.observationDetail}",
                color = Ink,
                fontSize = 13.sp,
            )
            Box(Modifier.fillMaxWidth().height(1.dp).background(Color(0xFFE3E8E5)))
            Text("信任边界", color = Muted, fontSize = 13.sp, fontWeight = FontWeight.Bold)
            Text(diagnostics, color = Ink, fontSize = 13.sp, modifier = Modifier.testTag("device-info-card"))
            Text(
                "每个底层网络代只测量授权入口一次；\n入口之后复用可信服务器观测，\n不探测完整业务路径。",
                color = Muted,
                fontSize = 12.sp,
            )
            Text("Loom ${BuildConfig.VERSION_NAME}", color = Muted, fontSize = 11.sp)
        }
    }
}

@Composable
private fun NotificationPermissionCard(onOpenSettings: () -> Unit) {
    Card(
        colors = CardDefaults.cardColors(containerColor = Color(0xFFFFF7E8)),
        shape = RoundedCornerShape(16.dp),
        modifier = Modifier.fillMaxWidth().testTag("notification-permission-card"),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text("连接通知已关闭", color = Ink, fontSize = 17.sp, fontWeight = FontWeight.Bold)
            Text(
                "VPN 可以继续运行，但连接状态和故障提醒可能不可见。请在系统设置中允许 Loom 通知。",
                color = Muted,
                fontSize = 13.sp,
            )
            OutlinedButton(
                onClick = onOpenSettings,
                modifier = Modifier.fillMaxWidth().testTag("open-notification-settings"),
            ) {
                Text("打开通知设置")
            }
        }
    }
}

@Composable
private fun EnrollmentCard(
    status: EnrollmentStatus,
    onScan: () -> Unit,
    onImportFile: () -> Unit,
    onRetry: () -> Unit,
    onRefresh: () -> Unit,
    onAbandonPending: () -> Unit,
) {
    var confirmAbandon by remember(status.canAbandonPending) { mutableStateOf(false) }
    if (confirmAbandon) {
        AlertDialog(
            onDismissRequest = { confirmAbandon = false },
            title = { Text("放弃本机待加入事务？") },
            text = {
                Text("这会删除手机保存的一次性加入凭据，但不会删除 Keystore 设备密钥，也不会撤销或修复中控中的 Device。")
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        confirmAbandon = false
                        onAbandonPending()
                    },
                ) { Text("确认放弃") }
            },
            dismissButton = {
                TextButton(onClick = { confirmAbandon = false }) { Text("继续保留") }
            },
        )
    }
    Card(
        colors = CardDefaults.cardColors(containerColor = Color.White),
        shape = RoundedCornerShape(16.dp),
        modifier = Modifier.fillMaxWidth().testTag("enrollment-card"),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text("加入网络", color = Muted, fontSize = 12.sp, fontWeight = FontWeight.Bold)
            Text(enrollmentTitle(status.phase), color = Ink, fontSize = 17.sp, fontWeight = FontWeight.Bold)
            Text(status.detail, color = Muted, fontSize = 13.sp, modifier = Modifier.testTag("enrollment-status"))
            if (status.profileName.isNotEmpty()) {
                Text(
                    buildString {
                        append(status.profileName)
                        if (status.generation > 0) append(" · 第 ${status.generation} 版")
                    },
                    color = Ink,
                    fontSize = 12.sp,
                    modifier = Modifier.testTag("profile-name"),
                )
            }
            when (status.phase) {
                EnrollmentPhase.NOT_JOINED -> Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Button(onClick = onScan, modifier = Modifier.weight(1f).testTag("scan-invite")) { Text("扫码加入") }
                    OutlinedButton(onClick = onImportFile, modifier = Modifier.weight(1f).testTag("import-invite")) { Text("导入文件") }
                }
                EnrollmentPhase.ERROR -> if (status.canAbandonPending) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Button(onClick = onRetry, modifier = Modifier.weight(1f)) { Text("安全重试") }
                        OutlinedButton(
                            onClick = { confirmAbandon = true },
                            modifier = Modifier.weight(1f).testTag("abandon-pending"),
                        ) { Text("放弃事务") }
                    }
                } else {
                    Button(onClick = onRetry, modifier = Modifier.fillMaxWidth()) { Text("重新检查") }
                }
                EnrollmentPhase.READY -> OutlinedButton(onClick = onRefresh, modifier = Modifier.fillMaxWidth()) { Text("检查签名配置更新") }
                else -> Unit
            }
        }
    }
}

internal fun readBounded(input: InputStream, maximum: Int): ByteArray {
    require(maximum > 0) { "读取边界无效" }
    val output = ByteArrayOutputStream(minOf(maximum, 8 * 1024))
    val buffer = ByteArray(4 * 1024)
    while (true) {
        val read = input.read(buffer)
        if (read < 0) break
        if (read == 0) {
            val one = input.read()
            if (one < 0) break
            require(output.size() < maximum) { "加入文件必须小于 16 KiB" }
            output.write(one)
            continue
        }
        require(output.size() + read <= maximum) { "加入文件必须小于 16 KiB" }
        output.write(buffer, 0, read)
    }
    return output.toByteArray()
}

private fun enrollmentTitle(phase: EnrollmentPhase): String = when (phase) {
    EnrollmentPhase.CHECKING -> "正在检查"
    EnrollmentPhase.NOT_JOINED -> "尚未加入"
    EnrollmentPhase.CLAIMING -> "正在验证身份"
    EnrollmentPhase.WAITING -> "已绑定，等待配置"
    EnrollmentPhase.PULLING -> "正在拉取签名配置"
    EnrollmentPhase.READY -> "正式入网就绪"
    EnrollmentPhase.ERROR -> "加入需要处理"
}

@Composable
private fun RouteModeCard(status: RouteStatus, onSelect: (RouteMode, String) -> Unit) {
    var choosingExit by remember { mutableStateOf(false) }
    if (choosingExit) {
        AlertDialog(
            onDismissRequest = { choosingExit = false },
            title = { Text("选择固定出口") },
            text = {
                Column(
                    modifier = Modifier.verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    status.exits.forEach { exit ->
                        TextButton(
                            onClick = {
                                choosingExit = false
                                onSelect(RouteMode.FIXED_EXIT, exit)
                            },
                            modifier = Modifier.fillMaxWidth().testTag("route-exit-$exit"),
                        ) { Text(exit) }
                    }
                }
            },
            confirmButton = {},
            dismissButton = {
                TextButton(onClick = { choosingExit = false }) { Text("取消") }
            },
        )
    }
    Card(
        colors = CardDefaults.cardColors(containerColor = Color.White),
        shape = RoundedCornerShape(16.dp),
        modifier = Modifier.fillMaxWidth().testTag("route-mode-card"),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text("流量模式", color = Muted, fontSize = 12.sp, fontWeight = FontWeight.Bold)
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                RouteModeButton(
                    label = "Direct",
                    selected = status.mode == RouteMode.DIRECT,
                    onClick = { onSelect(RouteMode.DIRECT, "") },
                    enabled = status.available && status.directAvailable && !status.busy,
                    modifier = Modifier.weight(1f).testTag("route-direct"),
                )
                RouteModeButton(
                    label = "Auto",
                    selected = status.mode == RouteMode.AUTO,
                    onClick = { onSelect(RouteMode.AUTO, "") },
                    enabled = status.available && !status.busy,
                    modifier = Modifier.weight(1f).testTag("route-auto"),
                )
                RouteModeButton(
                    label = "指定出口",
                    selected = status.mode == RouteMode.FIXED_EXIT,
                    onClick = { choosingExit = true },
                    enabled = status.available && status.exits.isNotEmpty() && !status.busy,
                    modifier = Modifier.weight(1f).testTag("route-fixed-exit"),
                )
            }
            Text(
                status.detail,
                color = if (status.blocked) Color(0xFFB33A3A) else Muted,
                fontSize = 12.sp,
            )
        }
    }
}

@Composable
private fun RouteModeButton(
    label: String,
    selected: Boolean,
    onClick: () -> Unit,
    enabled: Boolean,
    modifier: Modifier,
) {
    if (selected) {
        Button(
            onClick = onClick,
            enabled = enabled,
            modifier = modifier,
            shape = RoundedCornerShape(12.dp),
            colors = ButtonDefaults.buttonColors(containerColor = LoomGreen),
        ) { Text(label) }
    } else {
        OutlinedButton(
            onClick = onClick,
            enabled = enabled,
            modifier = modifier,
            shape = RoundedCornerShape(12.dp),
        ) { Text(label) }
    }
}

private fun phaseText(phase: ConnectionPhase): String = when (phase) {
    ConnectionPhase.DISCONNECTED -> "未连接"
    ConnectionPhase.STARTING -> "正在连接"
    ConnectionPhase.CONNECTED -> "已连接"
    ConnectionPhase.STOPPING -> "正在断开"
    ConnectionPhase.ERROR -> "连接失败"
}

private fun phaseColor(phase: ConnectionPhase): Color = when (phase) {
    ConnectionPhase.CONNECTED -> LoomGreen
    ConnectionPhase.ERROR -> Color(0xFFB33A3A)
    ConnectionPhase.STARTING, ConnectionPhase.STOPPING -> Color(0xFFE7A33E)
    ConnectionPhase.DISCONNECTED -> Color(0xFF98A29B)
}
