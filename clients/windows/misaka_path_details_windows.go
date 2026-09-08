//go:build windows

package main

import (
	"errors"
	"log"
	"math"
	"runtime"
	"strings"
	"time"
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
func (c *misakaCanvas) measureParagraph(text string, width, size int32, weights ...int32) (int32, error) {
	if c == nil || c.closed || width <= 0 {
		return 0, errors.New("[§7.2] 段落测量缺少有效画布或宽度")
	}
	previousError := c.err
	defer func() { c.err = previousError }()
	weight := int32(400)
	if len(weights) > 0 {
		weight = weights[0]
	}
	format := c.textFormat(misakaTextStyle{size: size, weight: weight, wrap: true, cjk: misakaTextHasCJK(text)})
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

func (app *portableGUI) misakaDetailParagraphHeight(text string, width, size int32, weight ...int32) int32 {
	height, err := app.skin.canvas.measureParagraph(text, width, size, weight...)
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

const (
	misakaDetailBodySize    int32 = 11
	misakaDetailTitleSize   int32 = 12
	misakaDetailTitleWeight int32 = 500
)

type misakaDetailBlock struct {
	title, body             string
	titleBounds, bodyBounds portableRect
}

type misakaPathDetailLayout struct {
	best, reason, read, scope                                            string
	bestBounds, reasonBounds, readBounds, scopeBounds, reasonTitleBounds portableRect
	blocks                                                               []misakaDetailBlock
	height                                                               int32
}

func windowsDetailTime(value string) string {
	at, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return value
	}
	return at.UTC().Format("2006-01-02 15:04:05 UTC")
}

// §7.2：测量逐段分组，标题与正文使用同一套实际字体度量，间距随 DPI 缩放。
func (app *portableGUI) misakaPathDetails(row windowsPathDisplay, width int32) misakaPathDetailLayout {
	s := app.scale
	layout := misakaPathDetailLayout{reason: row.Reason, read: "读取时间：" + windowsDetailTime(row.UpdatedAt)}
	if layout.reason == "" {
		layout.reason = "暂无选路说明"
	}
	if row.LinkLabels != "" && strings.HasPrefix(layout.reason, "入口") {
		if _, rest, ok := strings.Cut(layout.reason, "；"); ok {
			layout.reason = rest
		}
	}
	layout.reason = strings.ReplaceAll(layout.reason, "；未测整条业务路径", "")
	line := func(text string, size, weight int32) portableRect {
		height := app.misakaDetailParagraphHeight(text, width, s(size), weight)
		bounds := misakaRect(0, layout.height, width, height)
		layout.height += height
		return bounds
	}
	if row.LinkLabels != "" {
		for _, entry := range strings.Split(row.LinkDetails, "\n") {
			if entry == "" {
				continue
			}
			title, body, _ := strings.Cut(entry, "；")
			if source, tail, ok := strings.Cut(body, "；测量于 "); ok {
				ts, rest, _ := strings.Cut(tail, "；")
				body = source + " · " + windowsDetailTime(ts)
				if rest != "" {
					body += "；" + rest
				}
			}
			body = strings.ReplaceAll(body, "；", " · ")
			block := misakaDetailBlock{title: title, body: body}
			if len(layout.blocks) > 0 {
				layout.height += s(12)
			}
			block.titleBounds = line(title, misakaDetailTitleSize, misakaDetailTitleWeight)
			if body != "" {
				layout.height += s(4)
				block.bodyBounds = line(body, misakaDetailBodySize, 400)
			}
			layout.blocks = append(layout.blocks, block)
		}
	}
	if len(layout.blocks) == 0 {
		layout.best = "暂无对应连线的有效观测"
		if row.LinkLabels == "" {
			layout.best = "当前测量：" + row.SelectedQuality + "；已测候选：" + row.BestQuality
			if row.Comparison != "" {
				layout.best += "\n" + row.Comparison
			}
		}
		layout.bestBounds = line(layout.best, misakaDetailBodySize, 400)
	} else {
		layout.bestBounds = misakaRect(0, 0, width, layout.height)
	}
	layout.height += s(16)
	layout.reasonTitleBounds = line("选路说明", misakaDetailTitleSize, misakaDetailTitleWeight)
	layout.height += s(4)
	layout.reasonBounds = line(layout.reason, misakaDetailBodySize, 400)
	layout.height += s(8)
	layout.readBounds = line(layout.read, misakaDetailBodySize, 400)
	if row.DecisionScope != "" {
		scope := row.DecisionScope
		if len(scope) > 12 {
			scope = scope[:12] + "…"
		}
		layout.scope = "诊断标识：" + scope
		layout.height += s(4)
		layout.scopeBounds = line(layout.scope, misakaDetailBodySize, 400)
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
	count, _, _ := procSendMessage.Call(app.controls.pathsValue, 0x018B, 0, 0)
	if count == ^uintptr(0) {
		return
	}
	changed := false
	for index := uintptr(0); index < count; index++ {
		height := uintptr(app.scale(app.misakaPathHeightAt(int(index))))
		current, _, _ := procSendMessage.Call(app.controls.pathsValue, 0x01A1, index, 0)
		if current != height {
			procSendMessage.Call(app.controls.pathsValue, portableLBSetItemHeight, index, height)
			changed = true
		}
	}
	if changed {
		procInvalidateRect.Call(app.controls.pathsValue, 0, 0)
	}
}
