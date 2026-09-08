//go:build windows

package main

import (
	"runtime"
	"testing"
	"unsafe"
)

func misakaCanvasTestDC(t *testing.T, width, height int32) (uintptr, []byte) {
	t.Helper()
	dc, _, _ := procCreateCompatibleDC.Call(0)
	if dc == 0 {
		t.Fatal("[§7.2] 创建离屏画布 DC 失败")
	}
	t.Cleanup(func() { procDeleteDC.Call(dc) })
	header := portableBitmapInfoHeader{size: uint32(unsafe.Sizeof(portableBitmapInfoHeader{})), width: width, height: -height, planes: 1, bitCount: 32}
	var pixels unsafe.Pointer
	bitmap, _, _ := procCreateDIBSection.Call(dc, uintptr(unsafe.Pointer(&header)), portableDIBRGBColors, uintptr(unsafe.Pointer(&pixels)), 0, 0)
	if bitmap == 0 || pixels == nil {
		t.Fatal("[§7.2] 创建离屏画布位图失败")
	}
	previous, _, _ := procSelectObject.Call(dc, bitmap)
	t.Cleanup(func() {
		procSelectObject.Call(dc, previous)
		procDeleteObject.Call(bitmap)
	})
	return dc, unsafe.Slice((*byte)(pixels), int(width*height*4))
}

func misakaCanvasTestPixel(pixels []byte, width, x, y int32) uint32 {
	i := int((y*width + x) * 4)
	return uint32(pixels[i+2])<<16 | uint32(pixels[i+1])<<8 | uint32(pixels[i])
}

func misakaCanvasInkBounds(pixels []byte, width int32, area portableRect, background uint32) portableRect {
	ink := portableRect{left: area.right, top: area.bottom, right: area.left, bottom: area.top}
	for y := area.top; y < area.bottom; y++ {
		for x := area.left; x < area.right; x++ {
			if misakaCanvasTestPixel(pixels, width, x, y) == background {
				continue
			}
			ink.left, ink.top = min(ink.left, x), min(ink.top, y)
			ink.right, ink.bottom = max(ink.right, x+1), max(ink.bottom, y+1)
		}
	}
	return ink
}

func TestMisakaCanvasRenderAndRebind(t *testing.T) {
	runtime.LockOSThread()
	t.Cleanup(runtime.UnlockOSThread)
	dc, pixels := misakaCanvasTestDC(t, 320, 200)
	c, err := newMisakaCanvas()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	full := portableRect{right: 320, bottom: 200}
	if err := c.Begin(dc, full, 144); err != nil {
		t.Fatal(err)
	}
	c.Fill(full, 0xf8fafc, 0)
	if err := c.End(); err != nil {
		t.Fatal(err)
	}
	// §7.2：绑定非零起点的列表项，但绘图仍传入 HDC 坐标，验证平移既不遗漏也不重复。
	item := portableRect{left: 30, top: 20, right: 310, bottom: 180}
	if err := c.Begin(dc, item, 144); err != nil {
		t.Fatal(err)
	}
	c.Fill(item, 0xffffff, 0)
	c.Fill(portableRect{left: 50, top: 40, right: 110, bottom: 90}, 0x1c2541, 10)
	latin := portableRect{left: 130, top: 40, right: 300, bottom: 80}
	cjk := portableRect{left: 130, top: 100, right: 300, bottom: 150}
	c.Text("Loom", latin, 18, 600, 0x000000, 0)
	c.Text("正在连接", cjk, 22, 400, 0x000000, 0)
	if err := c.End(); err != nil {
		t.Fatal(err)
	}
	portableGDI32.NewProc("GdiFlush").Call()
	for _, check := range []struct {
		x, y int32
		rgb  uint32
	}{{0, 0, 0xf8fafc}, {35, 25, 0xffffff}, {50, 40, 0xffffff}, {80, 60, 0x1c2541}, {10, 60, 0xf8fafc}, {319, 199, 0xf8fafc}} {
		if got := misakaCanvasTestPixel(pixels, 320, check.x, check.y); got != check.rgb {
			t.Errorf("[§7.2] 像素 (%d,%d)=%06x，预期 %06x", check.x, check.y, got, check.rgb)
		}
	}
	for _, area := range []portableRect{latin, cjk} {
		ink := misakaCanvasInkBounds(pixels, 320, area, 0xffffff)
		if ink.right-ink.left < 20 || ink.bottom-ink.top < 8 {
			t.Errorf("[§7.2] DirectWrite 未在 %+v 内绘出可读字形：%+v", area, ink)
		}
	}
	// §7.2：丢弃设备资源不重建窗口，也不丢失文字格式；下一帧必须恢复绘制。
	c.releaseTarget()
	if c.target != nil || len(c.brushes) != 0 {
		t.Fatal("[§7.2] 绘制目标重置后仍保留设备资源")
	}
	for _, dpi := range []int32{96, 120, 144, 168, 192, 96} {
		if err := c.Begin(dc, full, dpi); err != nil {
			t.Fatal(err)
		}
		c.Fill(full, 0xffffff, 0)
		c.Text("Loom", full, dpi/4, 600, 0x000000, 1)
		if err := c.End(); err != nil {
			t.Fatal(err)
		}
	}
	c.Close()
	c.Close()
	if c.target != nil || c.factory != nil || c.writeFactory != nil || len(c.formats) != 0 || len(c.brushes) != 0 {
		t.Fatal("[§7.2] 关闭后仍保留 Direct2D/DirectWrite 资源")
	}
	if err := c.Begin(dc, full, 96); err == nil {
		t.Fatal("[§7.2] 已关闭的画布仍接受绘制")
	}
	t.Log("[§7.2] 系统 Direct2D/DirectWrite 的圆角像素、中文、坐标平移、DPI 和目标重建通过")
}

func TestMisakaCanvasTextSizeAlignmentAndClip(t *testing.T) {
	runtime.LockOSThread()
	t.Cleanup(runtime.UnlockOSThread)
	dc, pixels := misakaCanvasTestDC(t, 360, 180)
	c, err := newMisakaCanvas()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	full := portableRect{right: 360, bottom: 180}
	if err := c.Begin(dc, full, 96); err != nil {
		t.Fatal(err)
	}
	c.Fill(full, 0xffffff, 0)
	var aligned [3]portableRect
	for align := range uint32(3) {
		aligned[align] = portableRect{left: int32(align)*120 + 10, top: 10, right: int32(align)*120 + 110, bottom: 60}
		c.Text("LOOM", aligned[align], 18, 400, 0x000000, align)
	}
	small := portableRect{left: 10, top: 80, right: 150, bottom: 140}
	large := portableRect{left: 170, top: 80, right: 310, bottom: 140}
	c.Text("LOOM", small, 12, 400, 0x000000, 0)
	c.Text("LOOM", large, 24, 400, 0x000000, 0)
	clip := portableRect{left: 10, top: 150, right: 30, bottom: 175}
	c.Text("Long clipped text", clip, 18, 400, 0x000000, 0)
	if err := c.End(); err != nil {
		t.Fatal(err)
	}
	portableGDI32.NewProc("GdiFlush").Call()
	var offsets [3]int32
	for index, area := range aligned {
		ink := misakaCanvasInkBounds(pixels, 360, area, 0xffffff)
		if ink.right <= ink.left {
			t.Fatalf("[§7.2] 对齐方式 %d 没有文字像素", index)
		}
		offsets[index] = ink.left - area.left
	}
	if offsets[0] > 5 || offsets[1] < offsets[0]+10 || offsets[2] < offsets[1]+10 {
		t.Errorf("[§7.2] 左／中／右对齐的偏移不正确：%v", offsets)
	}
	smallInk := misakaCanvasInkBounds(pixels, 360, small, 0xffffff)
	largeInk := misakaCanvasInkBounds(pixels, 360, large, 0xffffff)
	smallHeight, largeHeight := smallInk.bottom-smallInk.top, largeInk.bottom-largeInk.top
	if smallHeight < 5 || largeHeight < smallHeight*3/2 || largeHeight > smallHeight*3 {
		t.Errorf("[§7.2] 12px／24px 字号未正确传入原生 ABI，字形高度 %d／%d", smallHeight, largeHeight)
	}
	outside := misakaCanvasInkBounds(pixels, 360, portableRect{left: 31, top: 150, right: 350, bottom: 175}, 0xffffff)
	if outside.right > outside.left {
		t.Errorf("[§7.2] 文字超出裁剪矩形：%+v", outside)
	}
	t.Logf("[§7.2] 原生 12px／24px 字号生成 %d／%dpx 字形；对齐偏移=%v；裁剪通过", smallHeight, largeHeight, offsets)
}

func TestMisakaCanvasNativeLayouts(t *testing.T) {
	if unsafe.Sizeof(misakaTargetProperties{}) != 28 || unsafe.Sizeof(misakaFloatRect{}) != 16 || unsafe.Sizeof(misakaRoundedRect{}) != 24 || unsafe.Sizeof(misakaTrimming{}) != 12 {
		t.Fatal("[§7.2] Direct2D 原生结构布局发生变化")
	}
	var args misakaTextFormatArgs
	if unsafe.Sizeof(args) != 72 || unsafe.Offsetof(args.size) != 48 || unsafe.Offsetof(args.locale) != 56 || unsafe.Offsetof(args.output) != 64 {
		t.Fatal("[§7.2] DirectWrite ABI 桥参数偏移发生变化")
	}
}

func TestMisakaCanvasEllipsisAndParagraph(t *testing.T) {
	runtime.LockOSThread()
	t.Cleanup(runtime.UnlockOSThread)
	dc, pixels := misakaCanvasTestDC(t, 260, 160)
	c, err := newMisakaCanvas()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	full := portableRect{right: 260, bottom: 160}
	if err := c.Begin(dc, full, 96); err != nil {
		t.Fatal(err)
	}
	c.Fill(full, 0xffffff, 0)
	line := portableRect{left: 10, top: 5, right: 125, bottom: 35}
	paragraph := portableRect{left: 10, top: 45, right: 125, bottom: 130}
	text := "Loom connection details contain a long explanation and 中文连接状态，换行后仍可阅读。"
	c.Text(text, line, 14, 400, 0x000000, 0)
	c.Paragraph(text, paragraph, 14, 400, 0x000000)
	if err := c.End(); err != nil {
		t.Fatal(err)
	}
	portableGDI32.NewProc("GdiFlush").Call()
	ink := misakaCanvasInkBounds(pixels, 260, paragraph, 0xffffff)
	if ink.bottom-ink.top < 40 || ink.top > paragraph.top+10 {
		t.Errorf("[§7.2] 段落未从矩形顶部换行：%+v", ink)
	}
	outside := misakaCanvasInkBounds(pixels, 260, portableRect{left: 126, right: 250, bottom: 155}, 0xffffff)
	if outside.right > outside.left {
		t.Errorf("[§7.2] 换行或省略后的文字超出矩形：%+v", outside)
	}
	for style, format := range c.formats {
		var trimming misakaTrimming
		var sign *misakaCOMObject
		hr := misakaCOMCall(format, 17, uintptr(unsafe.Pointer(&trimming)), uintptr(unsafe.Pointer(&sign)))
		if err := misakaHRESULT("读取原生文字截断设置", hr); err != nil {
			t.Fatal(err)
		}
		if trimming.granularity != 1 || sign == nil {
			t.Errorf("[§7.2] 原生格式未配置省略号截断：%+v", trimming)
		}
		misakaRelease(sign)
		wantParagraph, wantWrap := uintptr(2), uintptr(1)
		if style.wrap {
			wantParagraph, wantWrap = 0, 0
		}
		if misakaCOMCall(format, 12) != wantParagraph || misakaCOMCall(format, 13) != wantWrap {
			t.Errorf("[§7.2] 原生段落或换行属性与样式不符：%+v", style)
		}
	}
	t.Log("[§7.2] 两种格式均保留原生省略号；段落换行、顶部对齐及边界裁剪通过")
}
