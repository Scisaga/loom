package io.github.scisaga.loom

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
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

    private val notificationPermission = registerForActivityResult(ActivityResultContracts.RequestPermission()) {}

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
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
        enrollment.initialize()
        setContent {
            LoomHome(
                enrollment = enrollment,
                onToggle = ::toggle,
                onImportFile = { inviteFile.launch(arrayOf("*/*")) },
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

    companion object {
        private const val MAX_INVITE_BYTES = 16 * 1024
    }
}

@Composable
private fun LoomHome(
    enrollment: EnrollmentManager,
    onToggle: (ConnectionPhase) -> Unit,
    onImportFile: () -> Unit,
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
                val key = DeviceKeyStore().proveBinding()
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
                Text("移动网络入口", color = Ink, fontSize = 30.sp, fontWeight = FontWeight.Bold)
                Text(
                    when {
                        join.phase == EnrollmentPhase.READY -> "已加入 · signed snapshot ${join.snapshot}"
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

                Card(
                    colors = CardDefaults.cardColors(containerColor = CardTint),
                    shape = RoundedCornerShape(22.dp),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Column(Modifier.padding(22.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Box(
                                Modifier.size(12.dp).background(phaseColor(status.phase), CircleShape),
                            )
                            Text(
                                phaseText(status.phase),
                                modifier = Modifier.padding(start = 10.dp).testTag("connection-status"),
                                color = Ink,
                                fontWeight = FontWeight.Bold,
                                fontSize = 20.sp,
                            )
                        }
                        Text(status.detail, color = Muted)
                        Button(
                            onClick = { onToggle(status.phase) },
                            enabled = status.phase != ConnectionPhase.STOPPING &&
                                (hasManagedProfile || status.phase in setOf(
                                    ConnectionPhase.STARTING,
                                    ConnectionPhase.CONNECTED,
                                )),
                            modifier = Modifier.fillMaxWidth().height(54.dp).testTag("connection-toggle"),
                            colors = ButtonDefaults.buttonColors(containerColor = LoomGreen),
                            shape = RoundedCornerShape(14.dp),
                        ) {
                            Text(
                                when {
                                    status.phase in setOf(ConnectionPhase.CONNECTED, ConnectionPhase.STARTING) -> "断开"
                                    hasManagedProfile -> "连接"
                                    else -> "请先扫码加入"
                                },
                            )
                        }
                    }
                }

                if (BuildConfig.DEBUG && !hasManagedProfile) {
                    DebugDirectCard(status = status, onToggle = onToggle)
                }

                RouteModeCard(route, routeManager::select)
                InfoCard(
                    "当前路径",
                    if (route.currentPaths.isNotEmpty()) {
                        buildString {
                            if (!route.running) append("上次/下次连接选择：\n")
                            append(
                                route.currentPaths.joinToString("\n\n") { path ->
                                    buildString {
                                        append("${path.service}\n")
                                        append("实际候选：${path.candidate}\n")
                                        append("实际路径：${path.chain}\n")
                                        if (path.links.isEmpty()) {
                                            append("连线观测：无服务器路径或证据尚未就绪\n")
                                        } else {
                                            append("连线观测：\n")
                                            path.links.forEach { link ->
                                                append("${link.from} → ${link.to}：${link.label}\n")
                                                append("  ${link.detail}\n")
                                            }
                                        }
                                        append("选路说明：${path.reason}")
                                        if (path.updatedAt.isNotBlank()) append("\n决策时间：${path.updatedAt}")
                                    }
                                },
                            )
                        }
                    } else {
                        "尚无可验证的 selector 路径"
                    },
                )
                InfoCard(
                    "网络诊断",
                    "DNS/HTTPS 激活门禁：${status.dnsProbe} / ${status.httpsProbe}\n" +
                        "可信上报：${status.trustedReport}\n服务器观测：${route.observationDetail}",
                )
                InfoCard("信任边界", diagnostics)
                Spacer(Modifier.height(6.dp))
                Text(
                    "Stage 3 只在每个底层网络代并行测量授权入口一次；入口之后复用可信服务器观测，不探测完整业务路径。",
                    color = Muted,
                    fontSize = 12.sp,
                )
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
                enabled = status.phase != ConnectionPhase.STOPPING,
                modifier = Modifier.fillMaxWidth().testTag("debug-direct-toggle"),
            ) {
                Text(if (active) "断开 Debug Direct" else "测试 Debug Direct")
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

@Composable
private fun InfoCard(title: String, value: String) {
    Card(
        colors = CardDefaults.cardColors(containerColor = Color.White),
        shape = RoundedCornerShape(16.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(title, color = Muted, fontSize = 12.sp, fontWeight = FontWeight.Bold)
            Text(value, color = Ink, fontSize = 14.sp)
        }
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
