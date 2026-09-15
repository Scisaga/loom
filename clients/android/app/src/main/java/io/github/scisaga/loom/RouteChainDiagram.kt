package io.github.scisaga.loom

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.material3.Text
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.scisaga.loom.route.RouteLinkStatus
import io.github.scisaga.loom.route.RoutePathStatus

/** 节点来自实际 chain，连线即使缺少观测也保留；读图不触发测量。 */
@Composable
internal fun RouteChainDiagram(path: RoutePathStatus) {
    Column(Modifier.fillMaxWidth().testTag("route-chain-diagram")) {
        RouteNode("本机", "Android", "phone")
        path.serverChain.forEachIndexed { index, node ->
            val evidence = path.links.firstOrNull { it.hop == index && it.kind != "target" }
            RouteEdge(evidence, path.protocols.getOrNull(index).orEmpty())
            RouteNode(node, when {
                path.serverChain.size == 1 -> "入口 · 出口"
                index == 0 -> "入口"
                index == path.serverChain.lastIndex -> "出口"
                else -> "服务器"
            }, "server")
        }
        val targets = path.links.filter { it.kind == "target" }
        if (targets.isEmpty()) {
            val direct = path.serverChain.isEmpty()
            RouteEdge(null, if (direct) "Direct · 本机直连" else "协议未确认", direct)
            RouteNode("目标地址", "按实际请求访问", "globe")
        } else {
            targets.forEachIndexed { index, target ->
                if (index > 0) {
                    Spacer(Modifier.height(12.dp))
                    RouteNode(target.from, "出口", "server")
                }
                RouteEdge(target, target.protocol)
                RouteNode(target.to, "目标地址 · 来自 ${target.from}", "globe")
            }
        }
    }
}

@Composable
private fun RouteNode(label: String, detail: String, type: String) {
    Row(Modifier.fillMaxWidth().heightIn(min = 48.dp), verticalAlignment = Alignment.CenterVertically) {
        RouteNodeIcon(type)
        Column(Modifier.padding(start = 12.dp).weight(1f)) {
            Text(label, color = Ink, fontSize = 14.sp, fontWeight = FontWeight.Medium)
            Text(detail, color = Muted, fontSize = 11.sp)
        }
    }
}

@Composable
private fun RouteEdge(link: RouteLinkStatus?, protocol: String, direct: Boolean = false) {
    Row(Modifier.fillMaxWidth().height(IntrinsicSize.Min)) {
        Canvas(Modifier.width(32.dp).fillMaxHeight().heightIn(min = 60.dp).semantics {
            contentDescription = "链路方向向下"
        }) {
            val x = size.width / 2
            val bottom = size.height - 5.dp.toPx()
            drawLine(LoomGreen, Offset(x, 2.dp.toPx()), Offset(x, bottom), 1.5.dp.toPx(), StrokeCap.Round)
            drawLine(LoomGreen, Offset(x - 4.dp.toPx(), bottom - 5.dp.toPx()), Offset(x, bottom), 1.5.dp.toPx())
            drawLine(LoomGreen, Offset(x + 4.dp.toPx(), bottom - 5.dp.toPx()), Offset(x, bottom), 1.5.dp.toPx())
        }
        Column(Modifier.padding(start = 12.dp, top = 6.dp, bottom = 10.dp).weight(1f)) {
            Text(protocol.ifBlank { link?.protocol?.ifBlank { "协议未确认" } ?: "协议未确认" }, color = Muted, fontSize = 11.sp)
            if (!direct) Text(link?.label ?: "—", color = Ink, fontSize = 13.sp)
            Text(if (direct) "不执行路径测量" else link?.detail ?: "暂无观测", color = Muted, fontSize = 11.sp)
        }
    }
}

@Composable
private fun RouteNodeIcon(type: String) {
    Canvas(Modifier.size(32.dp).semantics {
        contentDescription = when (type) { "phone" -> "本机图标"; "server" -> "服务器图标"; else -> "目标地址图标" }
    }) {
        val unit = size.width / 32f
        val stroke = Stroke(width = 1.5f * unit)
        when (type) {
            "phone" -> {
                drawRoundRect(Ink, Offset(9 * unit, 3 * unit), Size(14 * unit, 26 * unit), CornerRadius(3 * unit), style = stroke)
                drawLine(Ink, Offset(13 * unit, 24 * unit), Offset(19 * unit, 24 * unit), 1.5f * unit, StrokeCap.Round)
            }
            "server" -> listOf(6f, 18f).forEach { y ->
                drawRoundRect(Ink, Offset(3 * unit, y * unit), Size(26 * unit, 8 * unit), CornerRadius(2 * unit), style = stroke)
                drawCircle(Ink, unit, Offset(8 * unit, (y + 4) * unit))
                drawLine(Ink, Offset(15 * unit, (y + 4) * unit), Offset(24 * unit, (y + 4) * unit), unit)
            }
            else -> {
                drawCircle(Ink, 12 * unit, style = stroke)
                drawOval(Ink, Offset(10 * unit, 4 * unit), Size(12 * unit, 24 * unit), style = stroke)
                drawLine(Ink, Offset(4 * unit, 16 * unit), Offset(28 * unit, 16 * unit), 1.5f * unit)
            }
        }
    }
}
