//go:build windows

package main

import (
	"errors"
	"log"
	"math"
	"runtime"
	"strings"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/windows"
)

type misakaTextLayoutArgs struct {
	factory       *misakaCOMObject
	text          *uint16
	length        uintptr
	format        *misakaCOMObject
	width, height uintptr
	output        **misakaCOMObject
}

type misakaParagraphMetrics struct {
	left, top, width, trailingWidth, height, layoutWidth, layoutHeight float32
	bidiDepth, lines                                                   uint32
}

// §7.2：测量与绘制共用 DirectWrite 格式和可用宽度，不能按字符数猜测正常换行。
func (c *misakaCanvas) measureParagraph(text string, width, size int32) (int32, error) {
	if c == nil || c.closed || width <= 0 {
		return 0, errors.New("[§7.2] 段落测量缺少有效画布或宽度")
	}
	previousError := c.err
	defer func() { c.err = previousError }()
	format := c.textFormat(misakaTextStyle{size: size, weight: 400, wrap: true, cjk: misakaTextHasCJK(text)})
	if format == nil {
		return 0, c.err
	}
	characters, err := windows.UTF16FromString(text)
	if err != nil {
		return 0, err
	}
	var layout *misakaCOMObject
	args := misakaTextLayoutArgs{factory: c.writeFactory, text: &characters[0], length: uintptr(len(characters) - 1), format: format,
		width: uintptr(math.Float32bits(float32(width))), height: uintptr(math.Float32bits(1 << 20)), output: &layout}
	hr := misakaCreateTextLayout(misakaCOMMethod(c.writeFactory, 18), &args)
	runtime.KeepAlive(characters)
	defer misakaRelease(layout)
	if err := misakaHRESULT("[§7.2] 创建详情段落测量", hr); err != nil {
		return 0, err
	}
	var metrics misakaParagraphMetrics
	if err := misakaHRESULT("[§7.2] 读取详情段落高度", misakaCOMCall(layout, 60, uintptr(unsafe.Pointer(&metrics)))); err != nil {
		return 0, err
	}
	return max(1, int32(math.Ceil(float64(metrics.height)))), nil
}

func (app *portableGUI) misakaDetailParagraphHeight(text string, width, size int32) int32 {
	height, err := app.skin.canvas.measureParagraph(text, width, size)
	if err == nil {
		return height
	}
	// §7.2：系统度量失败时仍保留正文，按保守字符宽度增高，不用空白替代说明。
	log.Printf("[§7.2] 详情段落测量失败，使用保守高度保留正文：%v", err)
	lines := int32(0)
	for _, line := range strings.Split(text, "\n") {
		lines += max(1, (int32(utf8.RuneCountInString(line))*size*2+max(1, width)-1)/max(1, width))
	}
	return lines * (size + app.scale(6))
}

type misakaPathDetailLayout struct {
	best, reason, read, scope                         string
	bestBounds, reasonBounds, readBounds, scopeBounds portableRect
	height                                            int32
}

// §7.2：详情逐项顺排，读取时间紧接实际原因行；缺少 scope 时不保留占位行。
func (app *portableGUI) misakaPathDetails(row windowsPathDisplay, width int32) misakaPathDetailLayout {
	s := app.scale
	value := func(text string) string {
		if text == "" {
			return "未知"
		}
		return text
	}
	metrics := "当前测量：" + value(row.SelectedQuality) + "；已测候选：" + value(row.BestQuality)
	if row.LinkLabels != "" {
		metrics = row.LinkDetails
		if metrics == "" {
			metrics = "暂无对应连线的有效观测"
		}
	}
	if row.Comparison != "" {
		metrics += "\n" + row.Comparison
	}
	layout := misakaPathDetailLayout{best: metrics, reason: "原因：" + value(row.Reason), read: "读取：" + value(row.UpdatedAt)}
	line := func(height int32) portableRect {
		bounds := misakaRect(0, layout.height, width, height)
		layout.height += height
		return bounds
	}
	layout.bestBounds = line(app.misakaDetailParagraphHeight(layout.best, width, s(10)))
	layout.reasonBounds = line(app.misakaDetailParagraphHeight(layout.reason, width, s(10)))
	layout.readBounds = line(s(18))
	if row.DecisionScope != "" {
		layout.scope = "决策范围：" + row.DecisionScope
		layout.scopeBounds = line(app.misakaDetailParagraphHeight(layout.scope, width, s(9)))
	}
	return layout
}

func misakaPathNodeRows(row windowsPathDisplay) int32 {
	if row.Candidate == "" {
		return 1
	}
	return max(1, int32((len(strings.Split(row.Chain, " → "))+1)/3))
}

func (app *portableGUI) syncMisakaPathItemHeight() {
	height := uintptr(app.scale(app.misakaPathHeight()))
	current, _, _ := procSendMessage.Call(app.controls.pathsValue, 0x01A1, 0, 0) // LB_GETITEMHEIGHT
	if current != height {
		procSendMessage.Call(app.controls.pathsValue, portableLBSetItemHeight, 0, height)
		procInvalidateRect.Call(app.controls.pathsValue, 0, 0)
	}
}
