package io.github.scisaga.loom

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.IconButton
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.scisaga.loom.profiles.ConnectionProfile
import io.github.scisaga.loom.profiles.ProfileIndex
import io.github.scisaga.loom.vpn.ConnectionPhase
import io.github.scisaga.loom.vpn.VpnStatus

@Composable
internal fun ProfilesCard(
    index: ProfileIndex,
    vpn: VpnStatus,
    onView: (String) -> Unit,
    onAdd: () -> Unit,
    onRename: (ConnectionProfile) -> Unit,
    onDelete: (ConnectionProfile) -> Unit,
) {
    Card(
        colors = CardDefaults.cardColors(containerColor = Color.White),
        shape = RoundedCornerShape(20.dp),
        modifier = Modifier.fillMaxWidth().testTag("profiles-card"),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text("连接配置", color = Ink, fontSize = 17.sp, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
                TextButton(onClick = onAdd, modifier = Modifier.testTag("add-profile")) { Text("＋ 添加") }
            }
            index.profiles.forEach { profile ->
                var menu by remember(profile.id) { mutableStateOf(false) }
                val viewed = profile.id == index.viewedProfileId
                val active = profile.id == vpn.activeProfileId && vpn.phase == ConnectionPhase.CONNECTED
                val requested = profile.id == vpn.requestedProfileId &&
                    (vpn.phase == ConnectionPhase.STARTING ||
                        (vpn.phase == ConnectionPhase.CONNECTED && profile.id != vpn.activeProfileId))
                val stopping = vpn.phase == ConnectionPhase.STOPPING &&
                    profile.id in setOf(vpn.requestedProfileId, vpn.activeProfileId)
                val failed = vpn.phase == ConnectionPhase.ERROR && profile.id == vpn.requestedProfileId
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 62.dp)
                        .selectable(viewed, role = Role.RadioButton) { onView(profile.id) }
                        .testTag("profile-${profile.id}"),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    RadioButton(selected = viewed, onClick = null)
                    Column(
                        modifier = Modifier.padding(start = 10.dp).weight(1f),
                        verticalArrangement = Arrangement.spacedBy(3.dp),
                    ) {
                        Text(
                            profile.name,
                            color = Ink,
                            fontSize = 15.sp,
                            fontWeight = if (viewed) FontWeight.Bold else FontWeight.Normal,
                        )
                        Text(
                            when {
                                active -> "当前连接"
                                requested -> "正在连接/切换"
                                stopping -> "正在断开"
                                failed -> "上次连接失败"
                                viewed -> "已选择"
                                else -> "未选择"
                            },
                            color = when {
                                active -> LoomGreen
                                failed -> Color(0xFFB33A3A)
                                else -> Muted
                            },
                            fontSize = 12.sp,
                        )
                    }
                    Box {
                        IconButton(
                            onClick = { menu = true },
                            modifier = Modifier.testTag("profile-menu-${profile.id}"),
                        ) { Text("⋮", color = Muted, fontSize = 22.sp) }
                        DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                            DropdownMenuItem(
                                text = { Text("重命名") },
                                onClick = { menu = false; onRename(profile) },
                            )
                            DropdownMenuItem(
                                text = { Text("删除") },
                                enabled = !active && !requested && !stopping,
                                onClick = { menu = false; onDelete(profile) },
                            )
                        }
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun ProfilePickerSheet(
    index: ProfileIndex,
    activeProfileId: String,
    onSelect: (String) -> Unit,
    onDismiss: () -> Unit,
) {
    ModalBottomSheet(onDismissRequest = onDismiss) {
        Column(
            Modifier.fillMaxWidth().padding(horizontal = 22.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text("选择连接配置", color = Ink, fontSize = 20.sp, fontWeight = FontWeight.Bold)
            index.profiles.forEach { profile ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 56.dp)
                        .selectable(profile.id == index.viewedProfileId, role = Role.RadioButton) {
                            onSelect(profile.id)
                            onDismiss()
                        },
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    RadioButton(selected = profile.id == index.viewedProfileId, onClick = null)
                    Column(Modifier.padding(start = 12.dp)) {
                        Text(profile.name, color = Ink, fontSize = 15.sp)
                        if (profile.id == activeProfileId) Text("当前连接", color = LoomGreen, fontSize = 11.sp)
                    }
                }
            }
        }
    }
}
