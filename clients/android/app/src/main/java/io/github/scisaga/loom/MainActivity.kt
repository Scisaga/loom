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
import androidx.compose.foundation.background
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
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
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ColorFilter
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

private val LoomGreen = Color(0xFF239B68)
private val Ink = Color(0xFF17211B)
private val Muted = Color(0xFF647269)
private val Paper = Color(0xFFFCFCFB)
private val CardTint = Color(0xFFF1F5F2)

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
                require(body.isNotEmpty() && body.size <= MAX_INVITE_BYTES) { "加入文件必须不超过 1 MiB" }
                enrollment.importInviteFile(body)
            }.onFailure(enrollment::reportImportError)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        notificationsAllowed = notificationPermissionGranted()
        val requestNotificationPermission =
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && !notificationsAllowed
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
        private const val MAX_INVITE_BYTES = 1024 * 1024
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
    LaunchedEffect(Unit) {
        diagnostics = withContext(Dispatchers.IO) {
            runCatching {
                Stage1Config.load(context)
                val key = DeviceKeyStore().identityStatus()
                "libbox ${Libbox.version()} · core ${Loomcore.version()}\nKeystore $key"
            }.getOrElse { "自检失败：${it.message}" }
        }
    }
    MaterialTheme {
        Surface(color = Paper, modifier = Modifier.fillMaxSize()) {
            Column(
                modifier = Modifier
                    .verticalScroll(rememberScrollState())
                    .padding(horizontal = 22.dp, vertical = 28.dp),
                verticalArrangement = Arrangement.spacedBy(18.dp),
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Image(
                        painter = painterResource(R.drawable.ic_loom),
                        contentDescription = "Loom",
                        colorFilter = ColorFilter.tint(Ink),
                        modifier = Modifier.size(36.dp),
                    )
                    Column(Modifier.padding(start = 10.dp)) {
                        Text("LOOM", color = Ink, fontWeight = FontWeight.Black, letterSpacing = 2.sp)
                        Text("ANDROID", color = Muted, fontSize = 10.sp, letterSpacing = 1.sp)
                    }
                }
                Text("移动网络", color = Ink, fontSize = 26.sp, fontWeight = FontWeight.Bold)
                Text(
                    when {
                        join.phase == EnrollmentPhase.READY -> "设备已加入 · 配置签名已验证"
                        join.phase == EnrollmentPhase.TERMINAL -> "Device 已终止；数据连接已锁定关闭"
                        join.snapshot.isNotEmpty() -> "候选已验签 · 连接后完成激活"
                        else -> "等待扫码完成正式入网"
                    },
                    color = Muted,
                )

                if (scanning) {
                    InviteScanner(
                        onScanned = {
                            scanning = false
                            enrollment.importInvite(it)
                        },
                        onCancel = { scanning = false },
                    )
                } else if (join.phase != EnrollmentPhase.READY) {
                    EnrollmentCard(
                        status = join,
                        onScan = { scanning = true },
                        onImportFile = onImportFile,
                        onRetry = enrollment::retry,
                        onRefresh = enrollment::refreshConfiguration,
                        onAbandonPending = enrollment::abandonPending,
                    )
                }

                ConnectionCard(
                    status = status,
                    join = join,
                    hasManagedProfile = hasManagedProfile,
                    onToggle = onToggle,
                )

                if (BuildConfig.DEBUG && !hasManagedProfile && join.phase != EnrollmentPhase.TERMINAL) {
                    DebugDirectCard(status = status, onToggle = onToggle)
                }

                if (!notificationsAllowed) {
                    NotificationPermissionCard(onOpenNotificationSettings)
                }

                RouteModeCard(route, routeManager::select)
                CurrentPathCard(
                    paths = route.currentPaths,
                    running = route.running,
                )
                if (!scanning && join.phase == EnrollmentPhase.READY) {
                    JoinedDeviceCard(join, enrollment::refreshConfiguration)
                }
                AdvancedInfoCard(status, route, diagnostics)
            }
        }
    }
}

@Composable
private fun ConnectionCard(
    status: VpnStatus,
    join: EnrollmentStatus,
    hasManagedProfile: Boolean,
    onToggle: (ConnectionPhase) -> Unit,
) {
    Card(
        colors = CardDefaults.cardColors(containerColor = CardTint),
        shape = RoundedCornerShape(20.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(Modifier.size(11.dp).background(phaseColor(status.phase), CircleShape))
                Text(
                    phaseText(status.phase),
                    modifier = Modifier.padding(start = 9.dp).testTag("connection-status"),
                    color = Ink,
                    fontWeight = FontWeight.Bold,
                    fontSize = 20.sp,
                )
            }
            Text(status.detail, color = Muted, fontSize = 13.sp)
            if (status.alwaysOn) {
                Text(
                    "Android 已开启“始终开启 VPN”；断开和关闭策略请在系统 VPN 设置中管理。",
                    color = Muted,
                    fontSize = 13.sp,
                    modifier = Modifier.testTag("always-on-guidance"),
                )
            }
            Button(
                onClick = { onToggle(status.phase) },
                enabled = status.phase != ConnectionPhase.STOPPING &&
                    !(status.alwaysOn && status.phase in setOf(
                        ConnectionPhase.STARTING,
                        ConnectionPhase.CONNECTED,
                    )) &&
                    (hasManagedProfile || status.phase in setOf(
                        ConnectionPhase.STARTING,
                        ConnectionPhase.CONNECTED,
                    )),
                modifier = Modifier.fillMaxWidth().height(50.dp).testTag("connection-toggle"),
                colors = ButtonDefaults.buttonColors(containerColor = LoomGreen),
                shape = RoundedCornerShape(14.dp),
            ) {
                Text(
                    when {
                        status.alwaysOn && status.phase in setOf(
                            ConnectionPhase.STARTING,
                            ConnectionPhase.CONNECTED,
                        ) -> "由系统保持连接"
                        status.phase in setOf(ConnectionPhase.CONNECTED, ConnectionPhase.STARTING) -> "断开"
                        join.phase == EnrollmentPhase.TERMINAL -> "Device 已停用"
                        hasManagedProfile -> "连接"
                        else -> "请先扫码加入"
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
                Column(modifier = Modifier.weight(1f)) {
                    Text("设备与配置", color = Muted, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                    Text(
                        buildString {
                            append("已加入")
                            if (status.generation > 0) append(" · generation ${status.generation}")
                        },
                        color = Ink,
                        fontSize = 15.sp,
                        fontWeight = FontWeight.Bold,
                    )
                    if (status.nodeID.isNotEmpty()) {
                        Text("Device ${status.nodeID}", color = Muted, fontSize = 12.sp)
                    }
                }
                TextButton(onClick = onRefresh, modifier = Modifier.testTag("refresh-config")) {
                    Text("检查更新")
                }
            }
        }
    }
}

@Composable
private fun CurrentPathCard(paths: List<RoutePathStatus>, running: Boolean) {
    var showingDetails by remember(paths) { mutableStateOf(false) }
    var selectedDetail by remember(paths) { mutableStateOf(0) }
    val summaries = remember(paths) { summarizeRoutePaths(paths) }
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
                        if (running) "当前连接" else "下次连接",
                        color = if (running) LoomGreen else Muted,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 5.dp),
                    )
                }
            }
            if (summaries.isEmpty()) {
                Text("尚无可验证的 selector 路径", color = Muted, fontSize = 13.sp)
            } else {
                summaries.take(2).forEachIndexed { index, summary ->
                    if (index > 0) Box(Modifier.fillMaxWidth().height(1.dp).background(Color(0xFFE3E8E5)))
                    Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
                        Text(summary.servicesLabel, color = Ink, fontSize = 14.sp, fontWeight = FontWeight.Bold)
                        Text(summary.chain, color = Ink, fontSize = 13.sp)
                        Text(summary.evidenceLabel, color = Muted, fontSize = 12.sp)
                    }
                }
                if (summaries.size > 2) {
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
                        RouteDetail(paths[selectedDetail])
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
        Text("实际路径：${path.chain}", color = Ink, fontSize = 13.sp)
        Text("实际候选：${path.candidate}", color = Muted, fontSize = 12.sp)
        if (path.links.isEmpty()) {
            Text(
                if (path.candidate == "direct") "Direct 不执行路径测量" else "分段证据尚未就绪",
                color = Muted,
                fontSize = 12.sp,
            )
        } else {
            path.links.forEach { link ->
                Text("${link.from} → ${link.to} · ${link.label}", color = Ink, fontSize = 12.sp)
                Text(link.detail, color = Muted, fontSize = 11.sp)
            }
        }
        Text("选路说明：${path.reason}", color = Muted, fontSize = 12.sp)
        if (path.updatedAt.isNotBlank()) Text("决策时间：${path.updatedAt}", color = Muted, fontSize = 11.sp)
    }
}

@Composable
private fun AdvancedInfoCard(status: VpnStatus, route: RouteStatus, diagnostics: String) {
    var expanded by remember { mutableStateOf(false) }
    Card(
        colors = CardDefaults.cardColors(containerColor = Color.White),
        shape = RoundedCornerShape(16.dp),
        modifier = Modifier.fillMaxWidth().testTag("advanced-info-card"),
    ) {
        Column(Modifier.padding(horizontal = 16.dp, vertical = 10.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text("诊断与信任", color = Ink, fontSize = 15.sp, fontWeight = FontWeight.Bold)
                    Text("网络证据、上报与本机组件", color = Muted, fontSize = 12.sp)
                }
                TextButton(onClick = { expanded = !expanded }, modifier = Modifier.testTag("advanced-info-toggle")) {
                    Text(if (expanded) "收起" else "展开")
                }
            }
            if (expanded) {
                Column(
                    modifier = Modifier.padding(bottom = 8.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Box(Modifier.fillMaxWidth().height(1.dp).background(Color(0xFFE3E8E5)))
                    Text("网络诊断", color = Muted, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                    Text(
                        "业务 DNS/HTTPS（不作为激活门禁）：${status.dnsProbe} / ${status.httpsProbe}\n" +
                            "可信上报：${status.trustedReport}\n服务器观测：${route.observationDetail}",
                        color = Ink,
                        fontSize = 13.sp,
                    )
                    Text("信任边界", color = Muted, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                    Text(diagnostics, color = Ink, fontSize = 13.sp)
                    Text(
                        "每个底层网络代只测量授权入口一次；入口之后复用可信服务器观测，不探测完整业务路径。",
                        color = Muted,
                        fontSize = 11.sp,
                    )
                }
            }
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
                "只验证本机 TUN、DNS 和 HTTPS；不代表已加入中控，也不会产生可信健康上报。",
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
