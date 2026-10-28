package io.github.scisaga.loom

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
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
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
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
            if (index.profiles.isEmpty()) {
                Column(
                    Modifier.fillMaxWidth().padding(vertical = 18.dp).testTag("profiles-empty"),
                    verticalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    Text("还没有连接配置", color = Ink, fontSize = 15.sp)
                    Text("点击添加，然后扫码加入网络", color = Muted, fontSize = 13.sp)
                }
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
                val deleteBlockedByConnection = active || requested || stopping
                val canDelete = !deleteBlockedByConnection
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
                            modifier = Modifier.testTag("profile-menu-${profile.id}")
                                .semantics { contentDescription = "${profile.name}的更多操作" },
                        ) {
                            Canvas(Modifier.size(20.dp)) {
                                listOf(4f, 10f, 16f).forEach { y ->
                                    drawCircle(Muted, radius = 1.5.dp.toPx(), center = Offset(size.width / 2, y.dp.toPx()))
                                }
                            }
                        }
                        DropdownMenu(
                            expanded = menu,
                            onDismissRequest = { menu = false },
                            modifier = Modifier.widthIn(min = 180.dp, max = 240.dp),
                            shape = RoundedCornerShape(16.dp),
                            containerColor = Color.White,
                            tonalElevation = 0.dp,
                            shadowElevation = 8.dp,
                            border = BorderStroke(1.dp, Color(0xFFDDE7E0)),
                        ) {
                            DropdownMenuItem(
                                text = { Text("重命名", color = Ink, fontSize = 14.sp) },
                                leadingIcon = { ProfileActionIcon(delete = false, color = Muted) },
                                onClick = { menu = false; onRename(profile) },
                                modifier = Modifier.testTag("profile-rename-${profile.id}"),
                            )
                            HorizontalDivider(Modifier.padding(horizontal = 12.dp), color = Color(0xFFE8EEE9))
                            DropdownMenuItem(
                                text = {
                                    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                                        Text("删除", color = if (canDelete) Color(0xFFB33A3A) else Muted.copy(alpha = 0.55f), fontSize = 14.sp)
                                        if (deleteBlockedByConnection) Text("请先断开连接", color = Muted.copy(alpha = 0.55f), fontSize = 11.sp)
                                    }
                                },
                                leadingIcon = { ProfileActionIcon(delete = true, color = if (canDelete) Color(0xFFB33A3A) else Muted.copy(alpha = 0.55f)) },
                                enabled = canDelete,
                                onClick = { menu = false; onDelete(profile) },
                                modifier = Modifier.testTag("profile-delete-${profile.id}"),
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun ProfileActionIcon(delete: Boolean, color: Color) {
    Canvas(Modifier.size(20.dp)) {
        fun point(x: Float, y: Float) = Offset(x.dp.toPx(), y.dp.toPx())
        fun line(x1: Float, y1: Float, x2: Float, y2: Float) =
            drawLine(color, point(x1, y1), point(x2, y2), strokeWidth = 1.6.dp.toPx(), cap = StrokeCap.Round)
        if (delete) {
            line(4f, 5f, 16f, 5f)
            line(8f, 2.5f, 12f, 2.5f)
            line(6f, 5f, 6.7f, 17f)
            line(6.7f, 17f, 13.3f, 17f)
            line(13.3f, 17f, 14f, 5f)
            line(8.7f, 8.5f, 8.7f, 13.5f)
            line(11.3f, 8.5f, 11.3f, 13.5f)
        } else {
            line(4f, 12.5f, 12.5f, 4f)
            line(12.5f, 4f, 16f, 7.5f)
            line(16f, 7.5f, 7.5f, 16f)
            line(7.5f, 16f, 3.5f, 16.5f)
            line(3.5f, 16.5f, 4f, 12.5f)
            line(11f, 5.5f, 14.5f, 9f)
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
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        containerColor = Color.White,
        contentColor = Ink,
        tonalElevation = 0.dp,
    ) {
        ProfilePickerContent(index, activeProfileId, onSelect, onDismiss)
    }
}

@Composable
internal fun ProfilePickerContent(
    index: ProfileIndex,
    activeProfileId: String,
    onSelect: (String) -> Unit,
    onDismiss: () -> Unit,
) {
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
