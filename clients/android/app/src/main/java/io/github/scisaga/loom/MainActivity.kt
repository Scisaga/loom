package io.github.scisaga.loom

import androidx.activity.compose.BackHandler
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.runtime.key
import io.github.scisaga.loom.profiles.ConnectionProfile
import io.github.scisaga.loom.profiles.ProfileCatalog
import io.github.scisaga.loom.profiles.ProfileContext
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
import androidx.compose.foundation.Image
import androidx.compose.foundation.ScrollState
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
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
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
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
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.rememberTextMeasurer
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
import io.github.scisaga.loom.security.DeviceKeyStore
import io.github.scisaga.loom.route.RouteManager
import io.github.scisaga.loom.route.RouteMode
import io.github.scisaga.loom.route.RoutePathStatus
import io.github.scisaga.loom.route.RouteStatus
import io.github.scisaga.loom.stage1.Stage1Config
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
    private val enrollment get() = EnrollmentManager.get(this)
    private var pendingConnectProfile: String? = null
    private var pendingImportProfile: String? = null
    private var importError by mutableStateOf<String?>(null)
    private var notificationsAllowed by mutableStateOf(true)

    private val vpnPermission = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        if (it.resultCode == RESULT_OK) {
            pendingConnectProfile?.let(::connect)
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
        val target = pendingImportProfile
        lifecycleScope.launch(Dispatchers.IO) {
            runCatching {
                val body = contentResolver.openInputStream(uri)?.use { stream ->
                    readBounded(stream, MAX_INVITE_BYTES)
                } ?: error("无法读取加入或配置文件")
                require(body.isNotEmpty() && body.size <= MAX_INVITE_BYTES) { "加入或配置文件必须不超过 1 MiB" }
                val catalog = ProfileCatalog.get(this@MainActivity)
                val id = target ?: catalog.create().id
                EnrollmentManager.get(catalog.context(id)).importInviteFile(body)
            }.onFailure { error -> withContext(Dispatchers.Main) { importError = error.message } }
        }
    }

    private var migrationExportProfile: String? = null
    private val migrationRequestFile = registerForActivityResult(
        ActivityResultContracts.CreateDocument("application/json"),
    ) { uri ->
        val profileID = migrationExportProfile ?: return@registerForActivityResult
        if (uri == null) return@registerForActivityResult
        lifecycleScope.launch(Dispatchers.IO) {
            runCatching {
                val catalog = ProfileCatalog.get(this@MainActivity)
                val request = EnrollmentManager.get(catalog.context(profileID)).exportMigrationRequest()
                checkNotNull(contentResolver.openOutputStream(uri)) { "无法写入迁移请求文件" }.use {
                    it.write(request)
                }
            }.onFailure { error -> withContext(Dispatchers.Main) { importError = error.message } }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        pendingConnectProfile = savedInstanceState?.getString("connect-profile")
        pendingImportProfile = savedInstanceState?.getString("import-profile")
        migrationExportProfile = savedInstanceState?.getString("migration-export-profile")
        notificationsAllowed = notificationPermissionGranted()
        val requestNotificationPermission =
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && !notificationsAllowed
        enrollment.initialize()
        setContent {
            LoomHome(
                onConnect = ::requestConnect,
                onDisconnect = ::disconnect,
                onImportFile = { profileId ->
                    pendingImportProfile = profileId
                    inviteFile.launch(arrayOf("*/*"))
                },
                onExportMigration = { profileID ->
                    migrationExportProfile = profileID
                    migrationRequestFile.launch("device.loom-migration-request")
                },
                importError = importError,
                onDismissImportError = { importError = null },
                notificationsAllowed = notificationsAllowed,
                onOpenNotificationSettings = ::openNotificationSettings,
            )
        }
        if (requestNotificationPermission) {
            window.decorView.post {
                if (!isFinishing && !notificationPermissionGranted()) {
                    notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
                }
            }
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

    override fun onSaveInstanceState(outState: Bundle) {
        outState.putString("connect-profile", pendingConnectProfile)
        outState.putString("import-profile", pendingImportProfile)
        outState.putString("migration-export-profile", migrationExportProfile)
        super.onSaveInstanceState(outState)
    }

    private fun disconnect() {
        ContextCompat.startForegroundService(this,
            Intent(this, LoomVpnService::class.java).setAction(LoomVpnService.ACTION_DISCONNECT))
    }

    private fun requestConnect(profileId: String) {
        pendingConnectProfile = profileId
        val permission = VpnService.prepare(this)
        if (permission != null) vpnPermission.launch(permission) else connect(profileId)
    }

    private fun connect(profileId: String) {
        ContextCompat.startForegroundService(this,
            Intent(this, LoomVpnService::class.java).setAction(LoomVpnService.ACTION_CONNECT)
                .putExtra(LoomVpnService.EXTRA_PROFILE_ID, profileId))
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
        private const val MAX_INVITE_BYTES = 1024 * 1024
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun LoomHome(
    onConnect: (String) -> Unit,
    onDisconnect: () -> Unit,
    onImportFile: (String?) -> Unit,
    onExportMigration: (String) -> Unit,
    importError: String?,
    onDismissImportError: () -> Unit,
    notificationsAllowed: Boolean,
    onOpenNotificationSettings: () -> Unit,
) {
    val context = LocalContext.current
    val catalog = remember(context) { ProfileCatalog.get(context) }
    val profiles by catalog.state.collectAsStateWithLifecycle()
    val scoped = remember(profiles.selectedId) { catalog.context(profiles.selectedId) }
    val enrollment = remember(scoped) { EnrollmentManager.get(scoped).also { it.initialize() } }
    val join by enrollment.status.collectAsStateWithLifecycle()
    val routeManager = remember(scoped) { RouteManager.get(scoped) }
    val selectedRoute by routeManager.status.collectAsStateWithLifecycle()
    val status by VpnRuntime.status.collectAsStateWithLifecycle()
    val active = profiles.profiles.firstOrNull { it.id == status.profileId }
    val activeManager = remember(status.profileId, scoped) {
        if (active != null) RouteManager.get(catalog.context(active.id)) else routeManager
    }
    val activeRoute by activeManager.status.collectAsStateWithLifecycle()
    val running = status.phase in setOf(ConnectionPhase.STARTING, ConnectionPhase.CONNECTED)
    var selectedTab by rememberSaveable { mutableStateOf(HomeTab.CONNECTION) }
    val connectionScroll = rememberScrollState()
    val configurationScroll = rememberScrollState()
    val diagnosticsScroll = rememberScrollState()
    var diagnostics by remember(scoped) { mutableStateOf("正在读取本机信息…") }
    var scanning by rememberSaveable { mutableStateOf(false) }
    var scanNew by rememberSaveable { mutableStateOf(false) }
    var scanProfile by rememberSaveable { mutableStateOf<String?>(null) }
    var scanError by remember { mutableStateOf<String?>(null) }
    var addSheet by remember { mutableStateOf(false) }
    var profileSheet by remember { mutableStateOf(false) }
    var rename by remember { mutableStateOf<ConnectionProfile?>(null) }
    var renameText by remember { mutableStateOf("") }
    var delete by remember { mutableStateOf<ConnectionProfile?>(null) }
    var switchTo by remember { mutableStateOf<ConnectionProfile?>(null) }
    var confirmJoin by remember { mutableStateOf(false) }
    var openAddAfterStop by remember { mutableStateOf(false) }
    val requestConnection: (ConnectionProfile) -> Unit = { target ->
        if (running && active?.id != target.id) switchTo = target else onConnect(target.id)
    }
    val requestAdd: () -> Unit = {
        if (running) confirmJoin = true else addSheet = true
    }
    BackHandler(scanning) { scanning = false }
    LaunchedEffect(status.phase, openAddAfterStop) {
        if (openAddAfterStop && status.phase == ConnectionPhase.DISCONNECTED) {
            openAddAfterStop = false
            addSheet = true
        }
    }
    LaunchedEffect(scoped) {
        diagnostics = withContext(Dispatchers.IO) {
            runCatching {
                "libbox ${Libbox.version()} · core ${Loomcore.version()}\nKeystore " +
                    DeviceKeyStore(ProfileContext.keySuffix(scoped)).identityStatus()
            }.getOrElse { "自检失败：${it.message}" }
        }
    }
    MaterialTheme(colorScheme = lightColorScheme(
        primary = LoomGreen, onPrimary = Color.White, background = Paper,
        surface = Color.White, onSurface = Ink, onSurfaceVariant = Muted,
    )) {
        Scaffold(containerColor = Paper, bottomBar = {
            HomeTabBar(selectedTab) { scanning = false; selectedTab = it }
        }) { padding ->
            Column(Modifier.fillMaxSize().padding(padding)) {
                LoomHeader()
                when (selectedTab) {
                    HomeTab.CONNECTION -> HomePage("连接", "连接状态与当前生效路径",
                        connectionScroll, Modifier.weight(1f)) {
                        ConnectionCard(status, join, profiles.selected, active,
                            onChoose = { profileSheet = true },
                            onConnect = { requestConnection(profiles.selected) }, onDisconnect = onDisconnect)
                        if (join.snapshot.isEmpty() && join.phase != EnrollmentPhase.TERMINAL) {
                            OutlinedButton(onClick = { selectedTab = HomeTab.CONFIGURATION },
                                modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag("go-to-enrollment")) {
                                Text("前往配置加入网络")
                            }
                        }
                        CurrentPathCard(activeRoute.currentPaths,
                            activeRoute.running && status.phase == ConnectionPhase.CONNECTED,
                            active?.name.orEmpty())
                    }
                    HomeTab.CONFIGURATION -> HomePage("配置", enrollmentSummary(join),
                        configurationScroll, Modifier.weight(1f)) {
                        ProfilesCard(profiles, status, catalog, onAdd = requestAdd,
                            onConnect = requestConnection,
                            onRename = { rename = it; renameText = it.name }, onDelete = { delete = it },
                            join = join, onRefresh = enrollment::refreshConfiguration,
                            onImportConfiguration = { profile -> catalog.select(profile.id); onImportFile(profile.id) })
                        Text("已选择：${profiles.selected.name} · 切换查看不会改变连接", color = Muted, fontSize = 12.sp)
                        if (scanning) {
                            InviteScanner(onScanned = { raw ->
                                scanning = false
                                runCatching {
                                    val id = if (scanNew) catalog.create().id else checkNotNull(scanProfile)
                                    EnrollmentManager.get(catalog.context(id)).importInvite(raw)
                                }.onFailure { scanError = it.message ?: "目标配置已不可用" }
                            }, onCancel = { scanning = false })
                        } else if (join.phase != EnrollmentPhase.READY) {
                            key(profiles.selectedId) {
                                EnrollmentCard(join,
                                    onScan = { scanNew = false; scanProfile = profiles.selectedId; scanning = true },
                                    onImportFile = { onImportFile(profiles.selectedId) },
                                    onExportMigration = { onExportMigration(profiles.selectedId) },
                                    onRetry = enrollment::retry, onRefresh = enrollment::refreshConfiguration,
                                    onAbandonPending = enrollment::abandonPending)
                            }
                        }
                        key(profiles.selectedId) { RouteModeCard(selectedRoute, routeManager::select) }
                        Text("每份配置分别保存身份、配置与连接模式。\n同一时间只运行一个连接。", color = Muted, fontSize = 12.sp)
                    }
                    HomeTab.DIAGNOSTICS -> HomePage("诊断", "网络证据、可信上报与本机组件",
                        diagnosticsScroll, Modifier.weight(1f)) {
                        NetworkEvidenceCard(if (status.profileId == profiles.selectedId) status else VpnStatus(),
                            selectedRoute, "${profiles.selected.name} · ${join.nodeID.ifBlank { "尚未加入" }}", diagnostics)
                        if (!notificationsAllowed) NotificationPermissionCard(false, onOpenNotificationSettings)
                        if (BuildConfig.DEBUG && join.snapshot.isEmpty() && join.phase != EnrollmentPhase.TERMINAL) {
                            DebugDirectCard(if (status.profileId == profiles.selectedId) status else VpnStatus()) { phase ->
                                if (phase in setOf(ConnectionPhase.STARTING, ConnectionPhase.CONNECTED)) onDisconnect()
                                else requestConnection(profiles.selected)
                            }
                        }
                    }
                }
            }
        }
        if (profileSheet) ModalBottomSheet(onDismissRequest = { profileSheet = false }) {
            Column(Modifier.verticalScroll(rememberScrollState()).padding(22.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("选择配置", fontSize = 20.sp, fontWeight = FontWeight.Bold)
                profiles.profiles.forEach { profile ->
                    ProfileChoice(profile, profiles.selectedId == profile.id) {
                        catalog.select(profile.id); profileSheet = false
                    }
                }
            }
        }
        if (addSheet) ModalBottomSheet(onDismissRequest = { addSheet = false }) {
            Column(Modifier.verticalScroll(rememberScrollState()).padding(22.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("添加配置", fontSize = 20.sp, fontWeight = FontWeight.Bold)
                TextButton(onClick = { addSheet = false; scanNew = true; scanning = true; selectedTab = HomeTab.CONFIGURATION },
                    modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("扫描二维码") }
                TextButton(onClick = { addSheet = false; onImportFile(null) },
                    modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("导入 .loom-invite 文件") }
            }
        }
        rename?.let { profile ->
            AlertDialog(onDismissRequest = { rename = null }, title = { Text("重命名配置") }, text = {
                OutlinedTextField(renameText, { renameText = it.take(64) }, singleLine = true,
                    label = { Text("配置名称") }, modifier = Modifier.testTag("profile-name-input"))
            }, confirmButton = { TextButton(enabled = renameText.isNotBlank() && renameText.none(Char::isISOControl), onClick = {
                catalog.rename(profile.id, renameText); rename = null
            }) { Text("保存") } }, dismissButton = { TextButton(onClick = { rename = null }) { Text("取消") } })
        }
        delete?.let { profile ->
            AlertDialog(onDismissRequest = { delete = null }, title = { Text("删除“${profile.name}”？") },
                text = { Text(if (running && active?.id == profile.id)
                    "将先断开连接，再移除此配置的本机身份与数据。" else "将移除此配置的本机身份与数据。") },
                confirmButton = { TextButton(enabled = !(status.alwaysOn && active?.id == profile.id), onClick = {
                    ContextCompat.startForegroundService(context, Intent(context, LoomVpnService::class.java)
                        .setAction(LoomVpnService.ACTION_DELETE_PROFILE).putExtra(LoomVpnService.EXTRA_PROFILE_ID, profile.id))
                    delete = null
                }) { Text("删除") } }, dismissButton = { TextButton(onClick = { delete = null }) { Text("取消") } })
        }
        switchTo?.let { profile ->
            AlertDialog(onDismissRequest = { switchTo = null }, title = { Text("切换连接？") },
                text = { Text("断开“${active?.name.orEmpty()}”，然后连接“${profile.name}”。") },
                confirmButton = { TextButton(onClick = { onConnect(profile.id); switchTo = null }) { Text("切换") } },
                dismissButton = { TextButton(onClick = { switchTo = null }) { Text("取消") } })
        }
        if (confirmJoin) AlertDialog(onDismissRequest = { confirmJoin = false }, title = { Text("添加新配置") },
            text = { Text("加入新网络可能需要临时注册隧道。先断开当前连接，再扫码或导入。") },
            confirmButton = { TextButton(enabled = !status.alwaysOn, onClick = {
                confirmJoin = false; openAddAfterStop = true; onDisconnect()
            }) { Text("断开并继续") } }, dismissButton = { TextButton(onClick = { confirmJoin = false }) { Text("取消") } })
        if (scanError != null) AlertDialog(onDismissRequest = { scanError = null },
            title = { Text("无法导入二维码") }, text = { Text(scanError.orEmpty()) },
            confirmButton = { TextButton(onClick = { scanError = null }) { Text("确定") } })
        if (importError != null) AlertDialog(onDismissRequest = onDismissImportError,
            title = { Text("无法导入文件") }, text = { Text(importError) },
            confirmButton = { TextButton(onClick = onDismissImportError) { Text("确定") } })
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
            modifier = Modifier.size(32.dp),
        )
        Column(Modifier.padding(start = 9.dp)) {
            Text(
                "LOOM",
                color = Ink,
                fontSize = 18.sp,
                lineHeight = 20.sp,
                fontWeight = FontWeight.Medium,
                letterSpacing = 2.sp,
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
                val levels = listOf(0.25f to 0.35f, 0.5f to 0.68f, 0.75f to 0.45f)
                levels.forEach { (y, knob) ->
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
    join.phase == EnrollmentPhase.TERMINAL -> "Device 已终止 · 数据连接已锁定关闭"
    join.phase == EnrollmentPhase.PULLING -> "正在下载并验证配置更新"
    join.phase == EnrollmentPhase.ERROR && join.snapshot.isNotEmpty() -> "更新未完成 · 原身份与已安装配置保留"
    join.snapshot.isNotEmpty() -> "设备已加入 · 已安装配置保留"
    else -> "加入网络、管理配置与本机信息"
}

@Composable
private fun ConnectionCard(
    status: VpnStatus, join: EnrollmentStatus, selected: ConnectionProfile, active: ConnectionProfile?,
    onChoose: () -> Unit, onConnect: () -> Unit, onDisconnect: () -> Unit,
) {
    val running = status.phase in setOf(ConnectionPhase.CONNECTED, ConnectionPhase.STARTING)
    val viewingActive = active?.id == selected.id
    Card(colors = CardDefaults.cardColors(containerColor = CardTint), shape = RoundedCornerShape(20.dp),
        modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Box(Modifier.size(11.dp).background(phaseColor(status.phase), CircleShape))
                Text(phaseText(status.phase), modifier = Modifier.padding(start = 9.dp).weight(1f).testTag("connection-status"),
                    color = Ink, fontWeight = FontWeight.Bold, fontSize = 20.sp)
                TextButton(onClick = onChoose, modifier = Modifier.testTag("choose-profile")) { Text("选择配置") }
            }
            Text("${selected.name} · ${join.nodeID.ifBlank { "尚未加入" }}", color = Muted, fontSize = 13.sp)
            if (running && !viewingActive) Text("当前连接：${active?.name.orEmpty()}", color = LoomGreen, fontSize = 13.sp)
            if (status.phase == ConnectionPhase.ERROR) Text(status.detail, color = Color(0xFFB33A3A), fontSize = 13.sp)
            if (status.alwaysOn) Text("Android 已开启“始终开启 VPN”，断开请在系统 VPN 设置中管理。",
                color = Muted, fontSize = 12.sp, modifier = Modifier.testTag("always-on-guidance"))
            Button(onClick = { if (running && viewingActive) onDisconnect() else onConnect() },
                enabled = status.phase != ConnectionPhase.STOPPING &&
                    !(status.alwaysOn && running && viewingActive) &&
                    ((running && viewingActive) || join.snapshot.isNotEmpty()),
                modifier = Modifier.fillMaxWidth().heightIn(min = 50.dp).testTag("connection-toggle"),
                shape = RoundedCornerShape(14.dp)) {
                Text(when {
                    status.alwaysOn && running && viewingActive -> "由系统保持连接"
                    running && viewingActive -> "断开"
                    join.phase == EnrollmentPhase.TERMINAL -> "配置已停用"
                    join.snapshot.isEmpty() -> "请先加入网络"
                    running -> "切换连接"
                    else -> "连接"
                })
            }
            if (running && !viewingActive) TextButton(onClick = onDisconnect, enabled = !status.alwaysOn,
                modifier = Modifier.fillMaxWidth()) { Text("断开当前连接") }
        }
    }
}

@Composable
private fun CurrentPathCard(paths: List<RoutePathStatus>, running: Boolean, profileName: String = "") {
    var showingDetails by rememberSaveable(profileName, running) { mutableStateOf(true) }
    var selectedDetail by rememberSaveable(profileName, running) { mutableStateOf(0) }
    LaunchedEffect(paths.size) { if (selectedDetail > paths.lastIndex) selectedDetail = 0 }
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
            if (running && profileName.isNotBlank()) Text(profileName, color = Muted, fontSize = 12.sp)
            if (summaries.isEmpty()) {
                Text(
                    if (running) "当前路径尚未确认" else "连接后显示各服务的实际路径",
                    color = Muted,
                    fontSize = 13.sp,
                )
            } else {
                if (!showingDetails) summaries.take(2).forEachIndexed { index, summary ->
                    if (index > 0) Box(Modifier.fillMaxWidth().height(1.dp).background(Color(0xFFE3E8E5)))
                    Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
                        Text(summary.servicesLabel, color = Ink, fontSize = 14.sp, fontWeight = FontWeight.Bold)
                        Text(summary.chain, color = Ink, fontSize = 13.sp)
                        Text(summary.evidenceLabel, color = Muted, fontSize = 12.sp)
                    }
                }
                if (!showingDetails && summaries.size > 2) {
                    Text("另有 ${summaries.size - 2} 组实际路径", color = Muted, fontSize = 12.sp)
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
        Text("实际候选：${path.candidate}", color = Muted, fontSize = 12.sp)
        Text("选路说明：${path.reason}", color = Muted, fontSize = 12.sp)
        if (path.updatedAt.isNotBlank()) Text("决策时间：${path.updatedAt}", color = Muted, fontSize = 11.sp)
    }
}

@Composable
private fun NetworkEvidenceCard(status: VpnStatus, route: RouteStatus, profile: String, diagnostics: String) {
    Card(colors = CardDefaults.cardColors(containerColor = Color.White), shape = RoundedCornerShape(20.dp),
        modifier = Modifier.fillMaxWidth().testTag("network-evidence-card")) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
            Text("网络诊断", color = Ink, fontSize = 17.sp, fontWeight = FontWeight.Bold)
            Text(profile, color = Muted, fontSize = 13.sp)
            Text("业务 DNS/HTTPS（不作为激活门禁）\n${status.dnsProbe} / ${status.httpsProbe}\n" +
                "可信上报：${status.trustedReport}\n服务器观测：${route.observationDetail}", color = Ink, fontSize = 13.sp)
            Box(Modifier.fillMaxWidth().height(1.dp).background(Color(0xFFE3E8E5)))
            Text("信任边界", color = Muted, fontSize = 13.sp, fontWeight = FontWeight.Bold)
            Text(diagnostics, color = Ink, fontSize = 13.sp, modifier = Modifier.testTag("device-info-card"))
            Text("每个底层网络代只测量授权入口一次；\n入口之后复用可信服务器观测，\n不探测完整业务路径。", color = Muted, fontSize = 12.sp)
            Text("Loom ${BuildConfig.VERSION_NAME}", color = Muted, fontSize = 11.sp)
        }
    }
}

@Composable
private fun NotificationPermissionCard(allowed: Boolean, onOpenSettings: () -> Unit) {
    Card(
        colors = CardDefaults.cardColors(containerColor = if (allowed) Color.White else Color(0xFFFFF7E8)),
        shape = RoundedCornerShape(16.dp),
        modifier = Modifier.fillMaxWidth().testTag("notification-permission-card"),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text("连接通知", color = Ink, fontSize = 17.sp, fontWeight = FontWeight.Bold)
            Text(
                if (allowed) "已允许显示连接状态和故障提醒。"
                else "通知已关闭，连接状态和故障提醒可能不可见。",
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
private fun DebugDirectCard(
    status: VpnStatus,
    onToggle: (ConnectionPhase) -> Unit,
) {
    val active = status.phase in setOf(ConnectionPhase.STARTING, ConnectionPhase.CONNECTED)
    Card(
        colors = CardDefaults.cardColors(containerColor = Color(0xFFFFF7E8)),
        shape = RoundedCornerShape(16.dp),
        modifier = Modifier.fillMaxWidth().testTag("debug-direct-card"),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text("开发诊断", color = Muted, fontSize = 12.sp, fontWeight = FontWeight.Bold)
            Text("Debug Direct TUN", color = Ink, fontSize = 17.sp, fontWeight = FontWeight.Bold)
            Text(
                "只验证本机 TUN 和路由启动；不会进行业务探测或可信健康上报。",
                color = Muted,
                fontSize = 13.sp,
            )
            OutlinedButton(
                onClick = { onToggle(status.phase) },
                enabled = status.phase != ConnectionPhase.STOPPING && !(active && status.alwaysOn),
                modifier = Modifier.fillMaxWidth().testTag("debug-direct-toggle"),
            ) {
                Text(
                    when {
                        active && status.alwaysOn -> "由系统保持连接"
                        active -> "断开 Debug Direct"
                        else -> "测试 Debug Direct"
                    },
                )
            }
        }
    }
}

@Composable
private fun EnrollmentCard(
    status: EnrollmentStatus,
    onScan: () -> Unit,
    onImportFile: () -> Unit,
    onExportMigration: () -> Unit,
    onRetry: () -> Unit,
    onRefresh: () -> Unit,
    onAbandonPending: () -> Unit,
) {
    var confirmAbandon by remember(status.canAbandonPending) { mutableStateOf(false) }
    Card(
        colors = CardDefaults.cardColors(containerColor = Color.White),
        shape = RoundedCornerShape(16.dp),
        modifier = Modifier.fillMaxWidth().testTag("enrollment-card"),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text("加入网络", color = Muted, fontSize = 12.sp, fontWeight = FontWeight.Bold)
            Text(enrollmentTitle(status.phase), color = Ink, fontSize = 17.sp, fontWeight = FontWeight.Bold)
            Text(status.detail, color = Muted, fontSize = 13.sp, modifier = Modifier.testTag("enrollment-status"))
            if (status.nodeID.isNotEmpty()) {
                Text(
                    buildString {
                        append("Device：${status.nodeID}")
                        if (status.generation > 0) append(" · generation ${status.generation}")
                    },
                    color = Ink,
                    fontSize = 12.sp,
                )
            }
            if (status.canImportResume && status.phase != EnrollmentPhase.NOT_JOINED) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Button(onClick = onScan, modifier = Modifier.weight(1f).testTag("scan-resume")) {
                        Text("扫码恢复")
                    }
                    OutlinedButton(
                        onClick = onImportFile,
                        modifier = Modifier.weight(1f).testTag("import-resume"),
                    ) { Text("导入 .loom-resume") }
                }
            }
            if (confirmAbandon) {
                AlertDialog(onDismissRequest = { confirmAbandon = false },
                    title = { Text("放弃待加入事务？") },
                    text = { Text("删除此配置的一次性加入凭据，保留设备密钥。中控中的设备不会被撤销。") },
                    confirmButton = { TextButton(onClick = { confirmAbandon = false; onAbandonPending() }) { Text("放弃") } },
                    dismissButton = { TextButton(onClick = { confirmAbandon = false }) { Text("取消") } })
            }
            when (status.phase) {
                EnrollmentPhase.NOT_JOINED -> Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Button(onClick = onScan, modifier = Modifier.weight(1f).testTag("scan-invite")) { Text("扫码加入") }
                    OutlinedButton(onClick = onImportFile, modifier = Modifier.weight(1f).testTag("import-invite")) { Text("导入文件") }
                }
                EnrollmentPhase.ERROR -> if (status.canMigrate) {
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(onClick = onExportMigration, modifier = Modifier.weight(1f)
                            .testTag("export-migration")) { Text("导出迁移请求") }
                        Button(onClick = onImportFile, modifier = Modifier.weight(1f)
                            .testTag("import-migration")) { Text("导入迁移文件") }
                    }
                } else if (status.canAbandonPending) {
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
                EnrollmentPhase.WAITING -> Button(onClick = onRetry, modifier = Modifier.fillMaxWidth()) { Text("继续加入") }
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
            require(output.size() < maximum) { "读取内容超过允许边界" }
            output.write(one)
            continue
        }
        require(output.size() + read <= maximum) { "读取内容超过允许边界" }
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
    EnrollmentPhase.TERMINAL -> "Device 已终止"
    EnrollmentPhase.ERROR -> "加入需要处理"
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun RouteModeCard(status: RouteStatus, onSelect: (RouteMode, String) -> Unit) {
    var choosingExit by remember(status.available, status.exits, status.mode) { mutableStateOf(false) }
    val labels = listOf("Direct", "Auto", "指定出口")
    val modes = listOf(RouteMode.DIRECT, RouteMode.AUTO, RouteMode.FIXED_EXIT)
    val tags = listOf("route-direct", "route-auto", "route-fixed-exit")
    val measurer = rememberTextMeasurer()
    val labelStyle = MaterialTheme.typography.labelLarge
    val minimumButtonWidth = with(LocalDensity.current) {
        labels.maxOf { measurer.measure(it, labelStyle, maxLines = 1).size.width }.toDp() + 20.dp
    }
    Card(
        colors = CardDefaults.cardColors(containerColor = Color.White),
        shape = RoundedCornerShape(16.dp),
        modifier = Modifier.fillMaxWidth().testTag("route-mode-card"),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text("流量模式", color = Ink, fontSize = 17.sp, fontWeight = FontWeight.Bold)
            // 按实际字体宽度分配三态操作；大字体时整组纵排，标签保持完整单行。
            BoxWithConstraints(Modifier.fillMaxWidth()) {
                val modeButton: @Composable (Int, Modifier) -> Unit = { index, modifier ->
                    val mode = modes[index]
                    RouteModeButton(
                        label = labels[index],
                        selected = status.mode == mode,
                        onClick = {
                            choosingExit = mode == RouteMode.FIXED_EXIT
                            if (!choosingExit) onSelect(mode, "")
                        },
                        enabled = status.available && !status.busy && when (mode) {
                            RouteMode.DIRECT -> status.directAvailable
                            RouteMode.AUTO -> true
                            RouteMode.FIXED_EXIT -> status.exits.isNotEmpty()
                        },
                        modifier = modifier.testTag(tags[index]),
                    )
                }
                if (maxWidth >= minimumButtonWidth * 3 + 16.dp) {
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        modes.indices.forEach { modeButton(it, Modifier.weight(1f)) }
                    }
                } else {
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        modes.indices.forEach { modeButton(it, Modifier.fillMaxWidth()) }
                    }
                }
            }
            Text(
                if (!status.available && !status.blocked) "加入网络后可选择连接模式" else status.detail,
                color = if (status.blocked) Color(0xFFB33A3A) else Muted,
                fontSize = 12.sp,
            )
            if (status.mode == RouteMode.FIXED_EXIT && status.exit.isNotBlank()) {
                Text("所选出口：${status.exit}", color = Ink, fontSize = 13.sp)
            }
            if (choosingExit && status.available) {
                ModalBottomSheet(onDismissRequest = { choosingExit = false },
                    modifier = Modifier.testTag("route-exits-sheet")) {
                    Column(
                        modifier = Modifier.verticalScroll(rememberScrollState()).padding(horizontal = 12.dp, vertical = 8.dp),
                        verticalArrangement = Arrangement.spacedBy(2.dp),
                    ) {
                        Text("选择已授权出口", color = Ink, fontSize = 13.sp, fontWeight = FontWeight.Bold)
                        status.exits.forEach { exit ->
                            TextButton(
                                onClick = {
                                    choosingExit = false
                                    onSelect(RouteMode.FIXED_EXIT, exit)
                                },
                                enabled = !status.busy,
                                modifier = Modifier.fillMaxWidth().testTag("route-exit-$exit"),
                            ) { Text(exit) }
                        }
                        TextButton(
                            onClick = { choosingExit = false },
                            modifier = Modifier.fillMaxWidth().testTag("route-exits-close"),
                        ) { Text("收起") }
                    }
                }
            }
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
            modifier = modifier.heightIn(min = 48.dp),
            contentPadding = PaddingValues(horizontal = 10.dp, vertical = 12.dp),
            shape = RoundedCornerShape(12.dp),
            colors = ButtonDefaults.buttonColors(containerColor = LoomGreen),
        ) { Text(label, style = MaterialTheme.typography.labelLarge, maxLines = 1, softWrap = false) }
    } else {
        OutlinedButton(
            onClick = onClick,
            enabled = enabled,
            modifier = modifier.heightIn(min = 48.dp),
            contentPadding = PaddingValues(horizontal = 10.dp, vertical = 12.dp),
            shape = RoundedCornerShape(12.dp),
        ) { Text(label, style = MaterialTheme.typography.labelLarge, maxLines = 1, softWrap = false) }
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
