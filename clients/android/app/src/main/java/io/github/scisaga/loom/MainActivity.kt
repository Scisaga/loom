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
import androidx.compose.foundation.layout.offset
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
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.MaterialTheme
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
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.scisaga.loom.enrollment.EnrollmentManager
import io.github.scisaga.loom.enrollment.EnrollmentPhase
import io.github.scisaga.loom.enrollment.EnrollmentStatus
import io.github.scisaga.libbox.Libbox
import io.github.scisaga.loom.profiles.ConnectionProfile
import io.github.scisaga.loom.profiles.ProfileCatalog
import io.github.scisaga.loom.profiles.checkedProfileName
import io.github.scisaga.loom.route.RouteManager
import io.github.scisaga.loom.route.RouteMode
import io.github.scisaga.loom.route.RoutePathStatus
import io.github.scisaga.loom.route.RouteStatus
import io.github.scisaga.loom.vpn.ConnectionPhase
import io.github.scisaga.loom.vpn.LoomVpnService
import io.github.scisaga.loom.vpn.VpnConnectionPreference
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

internal enum class HomeTab(val label: String) {
    CONNECTION("连接"),
    CONFIGURATION("配置"),
    DIAGNOSTICS("诊断"),
}

class MainActivity : ComponentActivity() {
    private val catalog by lazy { ProfileCatalog.get(this) }
    private val enrollment by lazy { EnrollmentManager.get(this) }
    private var notificationsAllowed by mutableStateOf(true)
    private var pendingConnectProfileId = ""
    private var pendingImportProfileId = ""
    private var profileError by mutableStateOf<String?>(null)

    private val vpnPermission = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        val profileId = pendingConnectProfileId
        pendingConnectProfileId = ""
        if (it.resultCode == RESULT_OK) {
            if (catalog.contains(profileId)) connect(profileId) else profileError = "原连接配置已不存在"
        } else {
            VpnRuntime.update(
                VpnStatus(
                    phase = ConnectionPhase.ERROR,
                    detail = "未获得 Android VPN 权限；请在系统确认页允许 Loom 建立 VPN",
                    requestedProfileId = profileId,
                ),
            )
        }
    }

    private val notificationPermission = registerForActivityResult(ActivityResultContracts.RequestPermission()) {
        notificationsAllowed = notificationPermissionGranted()
    }

    private val inviteFile = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        val profileId = pendingImportProfileId
        pendingImportProfileId = ""
        if (uri == null) return@registerForActivityResult
        if (!catalog.contains(profileId)) {
            profileError = "原导入配置已不存在"
            return@registerForActivityResult
        }
        lifecycleScope.launch(Dispatchers.IO) {
            runCatching {
                val body = contentResolver.openInputStream(uri)?.use { stream ->
                    readBounded(stream, MAX_INVITE_BYTES)
                } ?: error("无法读取加入文件")
                require(body.isNotEmpty() && body.size <= MAX_INVITE_BYTES) { "加入文件必须小于 16 KiB" }
                enrollment.importInvite(profileId, body.decodeToString())
            }.onFailure { enrollment.reportImportError(profileId, it) }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        pendingConnectProfileId = savedInstanceState?.getString(STATE_PENDING_CONNECT).orEmpty()
        pendingImportProfileId = savedInstanceState?.getString(STATE_PENDING_IMPORT).orEmpty()
        notificationsAllowed = notificationPermissionGranted()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            !notificationsAllowed
        ) {
            notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
        enrollment.initialize(catalog.state.value.viewedProfileId)
        setContent {
            LoomHomeRoute(
                catalog = catalog,
                enrollment = enrollment,
                onConnect = ::requestConnection,
                onDisconnect = ::disconnect,
                onImportFile = {
                    pendingImportProfileId = it
                    inviteFile.launch(arrayOf("*/*"))
                },
                onDeleteProfile = ::deleteProfile,
                notificationsAllowed = notificationsAllowed,
                onOpenNotificationSettings = ::openNotificationSettings,
                profileError = profileError,
                onDismissProfileError = { profileError = null },
            )
        }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        outState.putString(STATE_PENDING_CONNECT, pendingConnectProfileId)
        outState.putString(STATE_PENDING_IMPORT, pendingImportProfileId)
        super.onSaveInstanceState(outState)
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

    private fun requestConnection(profileId: String) {
        check(catalog.contains(profileId)) { "连接配置不存在" }
        pendingConnectProfileId = profileId
        val permission = VpnService.prepare(this)
        if (permission != null) vpnPermission.launch(permission) else connect(profileId)
    }

    private fun connect(profileId: String) {
        ContextCompat.startForegroundService(
            this,
            Intent(this, LoomVpnService::class.java)
                .setAction(LoomVpnService.ACTION_CONNECT)
                .putExtra(LoomVpnService.EXTRA_PROFILE_ID, profileId),
        )
    }

    private fun disconnect() {
        ContextCompat.startForegroundService(
            this,
            Intent(this, LoomVpnService::class.java).setAction(LoomVpnService.ACTION_DISCONNECT),
        )
    }

    private fun deleteProfile(profileId: String) {
        lifecycleScope.launch(Dispatchers.IO) {
            runCatching {
                check(catalog.state.value.profiles.size > 1) { "至少保留一个连接配置" }
                val runtime = VpnRuntime.status.value
                check(
                    runtime.phase !in setOf(
                        ConnectionPhase.STARTING,
                        ConnectionPhase.CONNECTED,
                        ConnectionPhase.STOPPING,
                    ) ||
                        profileId !in setOf(runtime.requestedProfileId, runtime.activeProfileId),
                ) { "当前连接配置必须先断开" }
                enrollment.quiesceProfile(profileId)
                val next = runCatching { catalog.removeIndex(profileId) }.getOrElse { error ->
                    enrollment.initialize(profileId)
                    throw error
                }
                val preference = VpnConnectionPreference(this@MainActivity)
                if (preference.profileId() == profileId) preference.save(false, next.viewedProfileId)
                VpnRuntime.transform { current ->
                    if (profileId in setOf(current.requestedProfileId, current.activeProfileId)) {
                        VpnStatus(alwaysOn = current.alwaysOn)
                    } else {
                        current
                    }
                }
                enrollment.removeProfile(profileId)
                RouteManager.get(this@MainActivity).removeProfile(profileId)
                enrollment.initialize(next.viewedProfileId)
            }.onFailure {
                withContext(Dispatchers.Main) {
                    profileError = it.message ?: it.javaClass.simpleName
                }
            }
        }
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
        private const val STATE_PENDING_CONNECT = "pending-connect-profile-id"
        private const val STATE_PENDING_IMPORT = "pending-import-profile-id"
    }
}

@Composable
private fun LoomHomeRoute(
    catalog: ProfileCatalog,
    enrollment: EnrollmentManager,
    onConnect: (String) -> Unit,
    onDisconnect: () -> Unit,
    onImportFile: (String) -> Unit,
    onDeleteProfile: (String) -> Unit,
    notificationsAllowed: Boolean,
    onOpenNotificationSettings: () -> Unit,
    profileError: String?,
    onDismissProfileError: () -> Unit,
) {
    val status by VpnRuntime.status.collectAsStateWithLifecycle()
    val profiles by catalog.state.collectAsStateWithLifecycle()
    val viewedProfile = profiles.viewed
    val enrollmentStatus = remember(viewedProfile.id) { enrollment.status(viewedProfile.id) }
    val join by enrollmentStatus.collectAsStateWithLifecycle()
    val context = LocalContext.current
    val routeManager = remember(context) { RouteManager.get(context) }
    val viewedRouteStatus = remember(viewedProfile.id) { routeManager.status(viewedProfile.id) }
    val route by viewedRouteStatus.collectAsStateWithLifecycle()
    val activeRouteId = status.activeProfileId.ifBlank { viewedProfile.id }
    val activeRouteStatus = remember(activeRouteId) { routeManager.status(activeRouteId) }
    val activeRoute by activeRouteStatus.collectAsStateWithLifecycle()
    var diagnostics by remember { mutableStateOf("正在检查…") }
    var scanning by remember { mutableStateOf(false) }
    var profileSheet by remember { mutableStateOf(false) }
    var addingProfile by remember { mutableStateOf(false) }
    var addName by remember { mutableStateOf(suggestedProfileName(profiles.profiles)) }
    var renaming by remember { mutableStateOf<ConnectionProfile?>(null) }
    var renameText by remember { mutableStateOf("") }
    var deleting by remember { mutableStateOf<ConnectionProfile?>(null) }
    var selectedTab by rememberSaveable { mutableStateOf(HomeTab.CONNECTION) }
    LaunchedEffect(viewedProfile.id) { enrollment.initialize(viewedProfile.id) }
    LaunchedEffect(Unit) {
        diagnostics = withContext(Dispatchers.IO) {
            runCatching {
                "libbox ${Libbox.version()} · core ${Loomcore.version()}"
            }.getOrElse { "自检失败：${it.message}" }
        }
    }
    LoomTheme {
        LoomHomeScreen(
            state = HomeUiState(
                status = status,
                profiles = profiles,
                join = join,
                route = route,
                activeRoute = activeRoute,
                notificationsAllowed = notificationsAllowed,
                diagnostics = diagnostics,
                selectedTab = selectedTab,
                scanning = scanning,
            ),
            actions = HomeUiActions(
                onTabSelected = {
                    scanning = false
                    selectedTab = it
                },
                onChooseProfile = { profileSheet = true },
                onConnect = onConnect,
                onDisconnect = onDisconnect,
                onViewProfile = catalog::view,
                onAddProfile = {
                    addName = suggestedProfileName(profiles.profiles)
                    addingProfile = true
                },
                onRenameProfile = {
                    renameText = it.name
                    renaming = it
                },
                onDeleteProfile = { deleting = it },
                onScanned = {
                    scanning = false
                    enrollment.importInvite(viewedProfile.id, it)
                },
                onCancelScan = { scanning = false },
                onStartScan = { scanning = true },
                onImportFile = onImportFile,
                onRetryEnrollment = enrollment::retry,
                onRefreshEnrollment = enrollment::refreshConfiguration,
                onAbandonEnrollment = enrollment::abandonPending,
                onSelectRoute = { profileID, mode, exit -> routeManager.select(profileID, mode, exit) },
                onOpenNotificationSettings = onOpenNotificationSettings,
            ),
        )

        if (profileSheet) {
            ProfilePickerSheet(
                index = profiles,
                activeProfileId = status.activeProfileId,
                onSelect = catalog::view,
                onDismiss = { profileSheet = false },
            )
        }
        if (addingProfile) {
            ProfileNameDialog(
                title = "添加配置",
                value = addName,
                valid = profileNameAvailable(addName, profiles.profiles),
                onValueChange = { addName = it.take(64) },
                onDismiss = { addingProfile = false },
                onConfirm = {
                    val created = catalog.create(addName)
                    enrollment.initialize(created.id)
                    addingProfile = false
                },
            )
        }
        renaming?.let { profile ->
            ProfileNameDialog(
                title = "重命名配置",
                value = renameText,
                valid = profileNameAvailable(renameText, profiles.profiles, profile.id),
                onValueChange = { renameText = it.take(64) },
                onDismiss = { renaming = null },
                onConfirm = {
                    catalog.rename(profile.id, renameText)
                    if (status.phase in setOf(ConnectionPhase.STARTING, ConnectionPhase.CONNECTED)) {
                        ContextCompat.startForegroundService(
                            context,
                            Intent(context, LoomVpnService::class.java)
                                .setAction(LoomVpnService.ACTION_SYNC_SYSTEM_POLICY),
                        )
                    }
                    renaming = null
                },
            )
        }
        deleting?.let { profile ->
            AlertDialog(
                onDismissRequest = { deleting = null },
                title = { Text("删除“${profile.name}”？") },
                text = { Text("这会删除该配置在本机保存的身份、认证配置和连接偏好，不影响其他配置。") },
                confirmButton = {
                    TextButton(onClick = {
                        deleting = null
                        onDeleteProfile(profile.id)
                    }) { Text("删除") }
                },
                dismissButton = { TextButton(onClick = { deleting = null }) { Text("取消") } },
            )
        }
        profileError?.let { error ->
            AlertDialog(
                onDismissRequest = onDismissProfileError,
                title = { Text("配置操作失败") },
                text = { Text(error) },
                confirmButton = { TextButton(onClick = onDismissProfileError) { Text("确定") } },
            )
        }
    }
}

@Composable
internal fun LoomTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = lightColorScheme(
            primary = LoomGreen,
            onPrimary = Color.White,
            background = Paper,
            surface = Color.White,
            onSurface = Ink,
            onSurfaceVariant = Muted,
        ),
        content = content,
    )
}

@Composable
private fun ProfileNameDialog(
    title: String,
    value: String,
    valid: Boolean,
    onValueChange: (String) -> Unit,
    onDismiss: () -> Unit,
    onConfirm: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            OutlinedTextField(
                value = value,
                onValueChange = onValueChange,
                singleLine = true,
                label = { Text("配置名称") },
                modifier = Modifier.testTag("profile-name-input"),
            )
        },
        confirmButton = { TextButton(enabled = valid, onClick = onConfirm) { Text("保存") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("取消") } },
    )
}

private fun profileNameAvailable(
    value: String,
    profiles: List<ConnectionProfile>,
    renamedProfileId: String = "",
): Boolean {
    val normalized = runCatching { checkedProfileName(value) }.getOrNull() ?: return false
    return profiles.none { it.id != renamedProfileId && it.name == normalized }
}

@Composable
internal fun LoomHeader(profileName: String, status: VpnStatus) {
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
        Column(Modifier.padding(start = 9.dp).offset(y = (-4).dp).weight(1f)) {
            Text(
                "LOOM · $profileName",
                color = Ink,
                fontSize = 18.sp,
                lineHeight = 20.sp,
                fontWeight = FontWeight.Medium,
                letterSpacing = 2.sp,
                modifier = Modifier.testTag("loom-wordmark"),
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                buildString {
                    append("ANDROID · ")
                    append(phaseText(status.phase))
                    if (status.deviceName.isNotBlank()) append(" · ${status.deviceName}")
                    if (status.generation > 0) append(" · 第 ${status.generation} 版")
                },
                color = Muted,
                fontSize = 9.sp,
                lineHeight = 12.sp,
                letterSpacing = 1.sp,
            )
        }
    }
}

@Composable
internal fun HomePage(
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
internal fun HomeTabBar(selected: HomeTab, onSelect: (HomeTab) -> Unit) {
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
internal fun ConnectionCard(
    status: VpnStatus,
    viewedProfile: ConnectionProfile,
    activeProfile: ConnectionProfile?,
    requestedProfile: ConnectionProfile?,
    hasManagedProfile: Boolean,
    onChoose: () -> Unit,
    onConnect: () -> Unit,
    onDisconnect: () -> Unit,
) {
    val running = status.phase in setOf(ConnectionPhase.STARTING, ConnectionPhase.CONNECTED)
    val viewedIsRuntime = status.activeProfileId == viewedProfile.id ||
        (status.phase == ConnectionPhase.STARTING && status.requestedProfileId == viewedProfile.id)
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
                when {
                    status.phase == ConnectionPhase.CONNECTED && activeProfile != null ->
                        "当前连接 · ${activeProfile.name}"
                    status.phase == ConnectionPhase.STARTING && requestedProfile != null ->
                        "正在连接 · ${requestedProfile.name}"
                    status.phase == ConnectionPhase.ERROR && requestedProfile != null ->
                        "连接失败 · ${requestedProfile.name}"
                    hasManagedProfile -> "待连接 · ${viewedProfile.name}"
                    else -> "${viewedProfile.name} · 尚未加入网络"
                },
                color = Muted,
                fontSize = 13.sp,
                modifier = Modifier.testTag("connection-profile-name"),
            )
            TextButton(onClick = onChoose, modifier = Modifier.testTag("choose-profile")) {
                Text(if (running && !viewedIsRuntime) "已选择 ${viewedProfile.name}" else "选择配置")
            }
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
                onClick = { if (running && viewedIsRuntime) onDisconnect() else onConnect() },
                enabled = status.phase != ConnectionPhase.STOPPING &&
                    !(status.alwaysOn && running && viewedIsRuntime) &&
                    (hasManagedProfile || (running && viewedIsRuntime)),
                modifier = Modifier.fillMaxWidth().heightIn(min = 50.dp).testTag("connection-toggle"),
                colors = ButtonDefaults.buttonColors(containerColor = LoomGreen),
                shape = RoundedCornerShape(14.dp),
            ) {
                Text(
                    when {
                        status.alwaysOn && running && viewedIsRuntime -> "由系统保持连接"
                        running && viewedIsRuntime -> "断开"
                        running -> "切换到 ${viewedProfile.name}"
                        hasManagedProfile -> "连接 ${viewedProfile.name}"
                        else -> "请先加入网络"
                    },
                )
            }
        }
    }
}

private fun suggestedProfileName(profiles: List<ConnectionProfile>): String {
    val names = profiles.map(ConnectionProfile::name).toSet()
    ('A'..'Z').firstOrNull { "Loom $it" !in names }?.let { return "Loom $it" }
    var number = profiles.size + 1
    while ("Loom $number" in names) number++
    return "Loom $number"
}

@Composable
internal fun JoinedDeviceCard(profile: ConnectionProfile, status: EnrollmentStatus, onRefresh: () -> Unit) {
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
                        profile.name,
                        color = Ink,
                        fontSize = 17.sp,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.testTag("profile-name"),
                    )
                    Text(
                        buildString {
                            if (status.deviceName.isNotBlank()) append("设备 ${status.deviceName} · ")
                            if (status.generation > 0) append("第 ${status.generation} 版 · ")
                            append("配置签名已验证")
                        },
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
internal fun CurrentPathCard(paths: List<RoutePathStatus>, running: Boolean, profileName: String) {
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
internal fun NetworkEvidenceCard(
    status: VpnStatus,
    route: RouteStatus,
    profileName: String,
    deviceName: String,
    diagnostics: String,
) {
    Card(
        colors = CardDefaults.cardColors(containerColor = Color.White),
        shape = RoundedCornerShape(20.dp),
        modifier = Modifier.fillMaxWidth().testTag("network-evidence-card"),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
            Text("网络诊断", color = Ink, fontSize = 17.sp, fontWeight = FontWeight.Bold)
            Text("配置：$profileName", color = Muted, fontSize = 13.sp)
            if (deviceName.isNotBlank()) Text("设备：$deviceName", color = Muted, fontSize = 13.sp)
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
internal fun NotificationPermissionCard(onOpenSettings: () -> Unit) {
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
internal fun EnrollmentCard(
    profile: ConnectionProfile,
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
            Text(
                "${profile.name} · ${enrollmentTitle(status.phase)}",
                color = Ink,
                fontSize = 17.sp,
                fontWeight = FontWeight.Bold,
            )
            Text(status.detail, color = Muted, fontSize = 13.sp, modifier = Modifier.testTag("enrollment-status"))
            if (status.deviceName.isNotEmpty()) {
                Text(
                    buildString {
                        append(profile.name)
                        if (status.generation > 0) append(" · 第 ${status.generation} 版")
                        append(" · 设备 ${status.deviceName}")
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
internal fun RouteModeCard(status: RouteStatus, onSelect: (RouteMode, String) -> Unit) {
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
