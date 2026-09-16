package io.github.scisaga.loom

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.scisaga.loom.enrollment.EnrollmentManager
import io.github.scisaga.loom.enrollment.EnrollmentStatus
import io.github.scisaga.loom.profiles.ConnectionProfile
import io.github.scisaga.loom.profiles.ProfileCatalog
import io.github.scisaga.loom.profiles.ProfileList
import io.github.scisaga.loom.vpn.ConnectionPhase
import io.github.scisaga.loom.vpn.VpnStatus

@Composable
internal fun ProfileChoice(profile: ConnectionProfile, selected: Boolean, onSelect: () -> Unit) {
    Row(Modifier.fillMaxWidth().heightIn(min = 56.dp).selectable(selected, role = Role.RadioButton, onClick = onSelect),
        verticalAlignment = Alignment.CenterVertically) {
        RadioButton(selected, onClick = null)
        Text(profile.name, modifier = Modifier.padding(start = 12.dp), color = Ink)
    }
}

@Composable
internal fun ProfilesCard(
    profiles: ProfileList, vpn: VpnStatus, catalog: ProfileCatalog, onAdd: () -> Unit,
    onConnect: (ConnectionProfile) -> Unit, onRename: (ConnectionProfile) -> Unit,
    onDelete: (ConnectionProfile) -> Unit, join: EnrollmentStatus, onRefresh: () -> Unit,
    onImportConfiguration: (ConnectionProfile) -> Unit,
) {
    Card(colors = CardDefaults.cardColors(containerColor = Color.White), shape = RoundedCornerShape(20.dp),
        modifier = Modifier.fillMaxWidth().testTag("profiles-card")) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text("连接配置", fontSize = 17.sp, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
                TextButton(onClick = onAdd, modifier = Modifier.testTag("add-profile")) { Text("＋ 添加") }
            }
            profiles.profiles.forEach { profile -> key(profile.id) {
                val manager = remember(profile.id) { EnrollmentManager.get(catalog.context(profile.id)).also { it.initialize() } }
                val status by manager.status.collectAsStateWithLifecycle()
                var menu by remember { mutableStateOf(false) }
                val connected = profile.id == vpn.profileId && vpn.phase in
                    setOf(ConnectionPhase.STARTING, ConnectionPhase.CONNECTED)
                Row(Modifier.fillMaxWidth().heightIn(min = 72.dp), verticalAlignment = Alignment.CenterVertically) {
                    Row(Modifier.weight(1f).heightIn(min = 72.dp)
                        .testTag("profile-${profile.id}").selectable(profiles.selectedId == profile.id,
                            role = Role.RadioButton, onClick = { catalog.select(profile.id) }),
                        verticalAlignment = Alignment.CenterVertically) {
                        RadioButton(profiles.selectedId == profile.id, onClick = null)
                        Column(Modifier.padding(start = 12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                            Text(profile.name, color = Ink, fontSize = 15.sp,
                                fontWeight = if (profiles.selectedId == profile.id) FontWeight.Bold else FontWeight.Normal)
                            Text(listOf(status.nodeID.ifBlank { "尚未加入" }, if (connected) "已连接" else "未连接").joinToString(" · "),
                                color = if (connected) LoomGreen else Muted, fontSize = 12.sp)
                        }
                    }
                    Box {
                        IconButton(onClick = { menu = true }, modifier = Modifier.testTag("profile-menu-${profile.id}")) {
                            Canvas(Modifier.size(24.dp).semantics { contentDescription = "${profile.name}的操作" }) {
                                listOf(0.25f, 0.5f, 0.75f).forEach { y ->
                                    drawCircle(Muted, 1.8.dp.toPx(), Offset(size.width / 2, size.height * y))
                                }
                            }
                        }
                        DropdownMenu(menu, onDismissRequest = { menu = false }) {
                            DropdownMenuItem(text = { Text(if (connected) "已连接" else "连接") },
                                enabled = !connected && status.snapshot.isNotEmpty(), onClick = { menu = false; onConnect(profile) })
                            if (status.protocol == 2 && status.snapshot.isNotEmpty() &&
                                status.phase != io.github.scisaga.loom.enrollment.EnrollmentPhase.PULLING &&
                                vpn.phase !in setOf(ConnectionPhase.STARTING, ConnectionPhase.STOPPING) &&
                                (vpn.phase != ConnectionPhase.CONNECTED || connected)) {
                                DropdownMenuItem(text = { Text("导入配置更新") }, modifier = Modifier.testTag("import-config"),
                                    onClick = { menu = false; onImportConfiguration(profile) })
                            }
                            DropdownMenuItem(text = { Text("重命名") }, onClick = { menu = false; onRename(profile) })
                            DropdownMenuItem(text = { Text("删除") }, onClick = { menu = false; onDelete(profile) })
                        }
                    }
                }
            } }
            Box(Modifier.fillMaxWidth().height(1.dp).background(Color(0xFFE3E8E5)))
            Column {
                if (join.nodeID.isNotBlank()) Text("Device ${join.nodeID}", color = Muted, fontSize = 12.sp)
                TextButton(onClick = onRefresh, enabled = join.snapshot.isNotBlank(),
                    modifier = Modifier.align(Alignment.End).testTag("refresh-config")) { Text("检查更新") }
            }
        }
    }
}
