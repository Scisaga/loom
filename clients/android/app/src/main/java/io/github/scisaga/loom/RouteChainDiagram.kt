package io.github.scisaga.loom

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Text
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.scisaga.loom.route.RoutePathStatus

/** Draws the applied chain only. A line is not a synthetic per-hop health observation. */
@Composable
internal fun RouteChainDiagram(path: RoutePathStatus) {
    Column(Modifier.fillMaxWidth().testTag("route-chain-diagram")) {
        RouteNode("本机", "Android", RouteNodeType.PHONE, "route-node-phone")
        path.serverChain.forEachIndexed { index, node ->
            RouteEdge(
                label = if (index == 0) "当前认证路径" else "继续中继",
                detail = "不提供逐跳健康结论",
                available = path.state == "available",
                tag = "route-edge-$index",
            )
            RouteNode(
                label = node,
                detail = when {
                    path.serverChain.size == 1 -> "入口 · 出口"
                    index == 0 -> "入口"
                    index == path.serverChain.lastIndex -> "出口"
                    else -> "中继"
                },
                type = RouteNodeType.SERVER,
                tag = "route-node-server-$index",
            )
        }
        RouteEdge(
            label = if (path.serverChain.isEmpty()) "Direct · 本机直连" else "前往目标地址",
            detail = if (path.serverChain.isEmpty()) "不执行路径测量" else "按实际请求访问",
            available = path.state == "available",
            tag = "route-edge-${path.serverChain.size}",
        )
        RouteNode("目标地址", "按实际请求访问", RouteNodeType.TARGET, "route-node-target")
    }
}

private enum class RouteNodeType { PHONE, SERVER, TARGET }

@Composable
private fun RouteNode(label: String, detail: String, type: RouteNodeType, tag: String) {
    Row(
        Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag(tag),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        RouteNodeIcon(type)
        Column(Modifier.padding(start = 12.dp).weight(1f)) {
            Text(label, color = Ink, fontSize = 14.sp, fontWeight = FontWeight.Medium)
            Text(detail, color = Muted, fontSize = 11.sp)
        }
    }
}

@Composable
private fun RouteEdge(label: String, detail: String, available: Boolean, tag: String) {
    Row(Modifier.fillMaxWidth().height(IntrinsicSize.Min).testTag(tag)) {
        Canvas(
            Modifier
                .width(32.dp)
                .fillMaxHeight()
                .heightIn(min = 60.dp)
                .semantics { contentDescription = "路径方向向下" },
        ) {
            val color = if (available) LoomGreen else Muted
            val x = size.width / 2
            val bottom = size.height - 5.dp.toPx()
            drawLine(color, Offset(x, 2.dp.toPx()), Offset(x, bottom), 1.5.dp.toPx(), StrokeCap.Round)
            drawLine(color, Offset(x - 4.dp.toPx(), bottom - 5.dp.toPx()), Offset(x, bottom), 1.5.dp.toPx())
            drawLine(color, Offset(x + 4.dp.toPx(), bottom - 5.dp.toPx()), Offset(x, bottom), 1.5.dp.toPx())
        }
        Column(Modifier.padding(start = 12.dp, top = 6.dp, bottom = 10.dp).weight(1f)) {
            Text(label, color = Ink, fontSize = 13.sp)
            Text(detail, color = Muted, fontSize = 11.sp)
        }
    }
}

@Composable
private fun RouteNodeIcon(type: RouteNodeType) {
    Canvas(
        Modifier.size(32.dp).semantics {
            contentDescription = when (type) {
                RouteNodeType.PHONE -> "本机图标"
                RouteNodeType.SERVER -> "服务器图标"
                RouteNodeType.TARGET -> "目标地址图标"
            }
        },
    ) {
        val unit = size.width / 32f
        val stroke = Stroke(width = 1.5f * unit)
        when (type) {
            RouteNodeType.PHONE -> {
                drawRoundRect(
                    Ink,
                    Offset(9 * unit, 3 * unit),
                    Size(14 * unit, 26 * unit),
                    CornerRadius(3 * unit),
                    style = stroke,
                )
                drawLine(
                    Ink,
                    Offset(13 * unit, 24 * unit),
                    Offset(19 * unit, 24 * unit),
                    1.5f * unit,
                    StrokeCap.Round,
                )
            }

            RouteNodeType.SERVER -> listOf(6f, 18f).forEach { y ->
                drawRoundRect(
                    Ink,
                    Offset(3 * unit, y * unit),
                    Size(26 * unit, 8 * unit),
                    CornerRadius(2 * unit),
                    style = stroke,
                )
                drawCircle(Ink, unit, Offset(8 * unit, (y + 4) * unit))
                drawLine(Ink, Offset(15 * unit, (y + 4) * unit), Offset(24 * unit, (y + 4) * unit), unit)
            }

            RouteNodeType.TARGET -> {
                drawCircle(Ink, 12 * unit, style = stroke)
                drawOval(Ink, Offset(10 * unit, 4 * unit), Size(12 * unit, 24 * unit), style = stroke)
                drawLine(Ink, Offset(4 * unit, 16 * unit), Offset(28 * unit, 16 * unit), 1.5f * unit)
            }
        }
    }
}
