//go:build windows

package main

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func misakaAlignmentInk(pixels []byte, width int32, area portableRect, accept func(uint32) bool) portableRect {
	ink := portableRect{left: area.right, top: area.bottom, right: area.left, bottom: area.top}
	for y := area.top; y < area.bottom; y++ {
		for x := area.left; x < area.right; x++ {
			if accept(misakaCanvasTestPixel(pixels, width, x, y)) {
				ink.left, ink.top = min(ink.left, x), min(ink.top, y)
				ink.right, ink.bottom = max(ink.right, x+1), max(ink.bottom, y+1)
			}
		}
	}
	return ink
}

func TestGUIMisakaChineseUsesSystemYaHeiInCanvasAndInputs(t *testing.T) {
	app := newProfileGUITestWindow(t)
	c := app.skin.canvas
	var collection *misakaCOMObject
	if err := misakaHRESULT("[§7.2] 读取系统字体集合", misakaCOMCall(c.writeFactory, 3, uintptr(unsafe.Pointer(&collection)), 0)); err != nil {
		t.Fatal(err)
	}
	defer misakaRelease(collection)
	family, _ := windows.UTF16FromString("Microsoft YaHei UI")
	var index, exists uint32
	if err := misakaHRESULT("[§7.2] 查询系统字体族", misakaCOMCall(collection, 5, uintptr(unsafe.Pointer(&family[0])), uintptr(unsafe.Pointer(&index)), uintptr(unsafe.Pointer(&exists)))); err != nil {
		t.Fatal(err)
	}
	if exists == 0 {
		t.Fatal("[§7.2] 系统字体集合没有所需的中文无衬线字体")
	}
	c.releaseFormats()
	dc, _ := misakaCanvasTestDC(t, 320, 100)
	bounds := portableRect{right: 320, bottom: 100}
	if err := c.Begin(dc, bounds, 96); err != nil {
		t.Fatal(err)
	}
	for _, label := range []string{"Loom", "当前选路", "demo 配置"} {
		c.Text(label, bounds, 14, 400, misakaText, 0)
	}
	if err := c.End(); err != nil {
		t.Fatal(err)
	}
	if len(c.formats) != 2 {
		t.Fatalf("[§7.2] 同字号的中英文错误复用了字体格式：%d", len(c.formats))
	}
	families := make(map[string]bool)
	for _, format := range c.formats {
		length := misakaCOMCall(format, 20)
		family := make([]uint16, length+1)
		if err := misakaHRESULT("[§7.2] 读取实际文字字体", misakaCOMCall(format, 21, uintptr(unsafe.Pointer(&family[0])), uintptr(len(family)))); err != nil {
			t.Fatal(err)
		}
		families[windows.UTF16ToString(family)] = true
	}
	if !families["Segoe UI"] || !families["Microsoft YaHei UI"] {
		t.Fatalf("[§7.2] 实际 DirectWrite 中英文字体未独立选择：%v", families)
	}
	for _, control := range []uintptr{app.controls.profileNameEdit, app.controls.draftName} {
		font, _, _ := procSendMessage.Call(control, portableWMGetFont, 0, 0)
		old, _, _ := procSelectObject.Call(dc, font)
		var actualFace [128]uint16
		portableGDI32.NewProc("GetTextFaceW").Call(dc, uintptr(len(actualFace)), uintptr(unsafe.Pointer(&actualFace[0])))
		procSelectObject.Call(dc, old)
		if face := windows.UTF16ToString(actualFace[:]); face != "Microsoft YaHei UI" {
			t.Fatalf("[§7.2] 原生名称输入实际字体发生回退：%q", face)
		}
		var logicalFont struct {
			height, width, escapement, orientation, weight int32
			styles                                         [8]byte
			face                                           [32]uint16
		}
		if size, _, _ := portableGDI32.NewProc("GetObjectW").Call(font, unsafe.Sizeof(logicalFont), uintptr(unsafe.Pointer(&logicalFont))); size != unsafe.Sizeof(logicalFont) {
			t.Fatal("[§7.2] 读取原生输入字体失败")
		}
		if family := windows.UTF16ToString(logicalFont.face[:]); family != "Microsoft YaHei UI" {
			t.Fatalf("[§7.2] 原生名称输入与自绘中文字体不同：%q", family)
		}
	}
}

func TestGUIMisakaAddAndPathSymbolsHaveVisibleGeometricCenters(t *testing.T) {
	app := newProfileGUITestWindow(t)
	const width, height int32 = 400, 240
	dc, pixels := misakaCanvasTestDC(t, width, height)
	for _, dpi := range []int32{96, 120, 144, 168, 192} {
		app.windowDPI = dpi
		s, c := app.scale, app.skin.canvas
		bounds := portableRect{right: width, bottom: height}
		if err := c.Begin(dc, bounds, dpi); err != nil {
			t.Fatal(err)
		}
		c.Fill(bounds, misakaWhite, 0)
		button := misakaRect(s(10), s(10), s(28), s(28))
		paintMisakaAdd(c, button, s, misakaText)
		for index := 0; index < 3; index++ {
			paintMisakaPathNode(c, s(35+int32(index)*60), s(80), index, 3, s, false)
		}
		if err := c.End(); err != nil {
			t.Fatal(err)
		}
		portableGDI32.NewProc("GdiFlush").Call()
		plus := misakaAlignmentInk(pixels, width, button, func(rgb uint32) bool { return rgb == misakaText })
		if plus.right <= plus.left || absMisakaAlignment(plus.left+plus.right-button.left-button.right) > 1 || absMisakaAlignment(plus.top+plus.bottom-button.top-button.bottom) > 1 {
			t.Errorf("[§7.2] DPI %d 加号实际像素未在按钮中居中：符号=%+v 按钮=%+v", dpi, plus, button)
		}
		for index := 0; index < 3; index++ {
			x, y := s(35+int32(index)*60), s(80)
			area := misakaCenteredRect(x, y, s(20), s(20))
			ink := misakaAlignmentInk(pixels, width, area, func(rgb uint32) bool { return rgb>>16 < 180 && rgb>>8&255 < 180 && rgb&255 < 180 })
			if ink.right <= ink.left || absMisakaAlignment(ink.left+ink.right-2*x) > 2 || absMisakaAlignment(ink.top+ink.bottom-2*y) > 2 {
				t.Errorf("[§7.2] DPI %d 路径位置 %d 的实际图标偏离圆心 (%d,%d)：%+v", dpi, index, x, y, ink)
			}
		}
	}
}

func TestGUIMisakaProfileSelectionHasSquareCornersAndContinuousRail(t *testing.T) {
	app := newProfileGUITestWindow(t)
	const width, height int32 = 400, 160
	dc, pixels := misakaCanvasTestDC(t, width, height)
	for _, dpi := range []int32{96, 120, 144, 168, 192} {
		app.windowDPI = dpi
		s := app.scale
		r := misakaRect(s(12), s(8), s(152), s(55))
		app.drawMisakaProfile(&portableDrawItem{hwndItem: app.controls.networkList, dc: dc, rect: r, itemID: 0, itemState: portableODSSelected})
		portableGDI32.NewProc("GdiFlush").Call()
		for y := r.top; y < r.bottom; y++ {
			if pixel := misakaCanvasTestPixel(pixels, width, r.left, y); pixel != misakaGreen {
				t.Fatalf("[§7.2] DPI %d 选中项竖线在 y=%d 中断：%06x", dpi, y, pixel)
			}
		}
		for _, point := range []portablePoint{{x: r.left + s(4), y: r.top}, {x: r.right - 1, y: r.top}, {x: r.left + s(4), y: r.bottom - 1}, {x: r.right - 1, y: r.bottom - 1}} {
			if pixel := misakaCanvasTestPixel(pixels, width, point.x, point.y); pixel != 0xE9F3ED {
				t.Errorf("[§7.2] DPI %d 选中项边角仍有裁切：(%d,%d)=%06x", dpi, point.x, point.y, pixel)
			}
		}
	}
}

func TestGUIMisakaPathLabelsStayUnderTheirNodesAtBothEdges(t *testing.T) {
	app := newProfileGUITestWindow(t)
	const width, height int32 = 1300, 300
	dc, pixels := misakaCanvasTestDC(t, width, height)
	for _, dpi := range []int32{96, 120, 144, 168, 192} {
		app.windowDPI = dpi
		s := app.scale
		for _, logicalWidth := range []int32{480, 640} {
			r := misakaRect(s(3), s(2), s(logicalWidth), s(128))
			app.drawMisakaPath(&portableDrawItem{hwndItem: app.controls.pathsValue, dc: dc, rect: r, itemID: 0})
			portableGDI32.NewProc("GdiFlush").Call()
			left, right, top := r.left+1, r.right-s(3)-1, r.top+1
			step := (right - left - s(84)) / 3
			for _, index := range []int32{0, 3} {
				x, y := left+s(42)+index*step, top+s(59)
				area := misakaRect(x-s(55), y+s(23), s(110), s(20))
				area.left, area.right = max(area.left, r.left+1), min(area.right, r.right-1)
				ink := misakaAlignmentInk(pixels, width, area, func(rgb uint32) bool { return rgb>>16 < 160 && rgb>>8&255 < 160 && rgb&255 < 160 })
				if ink.right <= ink.left || absMisakaAlignment(ink.left+ink.right-2*x) > 3 {
					t.Errorf("[§7.2] DPI %d、宽度 %d、路径端点 %d 的文字偏离节点竖轴 %d：%+v", dpi, logicalWidth, index, x, ink)
				}
			}
		}
	}
}

func TestGUIMisakaBrandUsesExistingFullMark(t *testing.T) {
	app := newProfileGUITestWindow(t)
	const width, height int32 = 360, 240
	dc, pixels := misakaCanvasTestDC(t, width, height)
	referenceDC, reference := misakaCanvasTestDC(t, width, height)
	instance, _, _ := procGetModuleHandle.Call(0)
	for _, dpi := range []int32{96, 120, 144, 168, 192} {
		app.windowDPI = dpi
		s := app.scale
		full := portableRect{right: width, bottom: height}
		for _, target := range []uintptr{dc, referenceDC} {
			procFillRect.Call(target, uintptr(unsafe.Pointer(&full)), app.misakaBrush(misakaSidebar))
		}
		app.drawMisakaBrand(dc, true)
		icon, _, err := procLoadImage.Call(instance, portableIconBrand, portableImageIcon, uintptr(s(40)), uintptr(s(40)), portableLRShared)
		if icon == 0 {
			t.Fatal(err)
		}
		procDrawIconEx.Call(referenceDC, uintptr(s(16)), uintptr(s(58)), icon, uintptr(s(40)), uintptr(s(40)), 0, 0, portableDrawIconNormal)
		portableGDI32.NewProc("GdiFlush").Call()
		for y := s(58); y < s(58)+s(40); y++ {
			for x := s(16); x < s(16)+s(40); x++ {
				if misakaCanvasTestPixel(pixels, width, x, y) != misakaCanvasTestPixel(reference, width, x, y) {
					t.Fatalf("[§7.2] DPI %d 品牌区与既有完整版图标不一致", dpi)
				}
			}
		}
	}
}

func TestGUIMisakaInlineEditorDoesNotCoverProfileStatus(t *testing.T) {
	app := newProfileGUITestWindow(t)
	for _, dpi := range []int32{96, 120, 144, 168, 192} {
		width, height := portableMinimumWindowSize(dpi)
		suggested := portableRect{left: 20, top: 20, right: 20 + width, bottom: 20 + height}
		procSendMessage.Call(app.hwnd, portableWMDPIChanged, uintptr(dpi)|uintptr(dpi)<<16, uintptr(unsafe.Pointer(&suggested)))
		before := readProfileGUITestWindow(t, app)
		var row portableRect
		procSendMessage.Call(app.controls.networkList, 0x0198, 0, uintptr(unsafe.Pointer(&row)))
		procMisakaMapPoints.Call(app.controls.networkList, app.hwnd, uintptr(unsafe.Pointer(&row)), 2)
		status := misakaRect(row.left+app.scale(29), row.top+app.scale(33), row.right-row.left-app.scale(35), app.scale(16))
		app.beginMisakaRename()
		after := readProfileGUITestWindow(t, app)
		editor := guiWindowRect(t, app.controls.profileNameEdit)
		procMisakaMapPoints.Call(0, app.hwnd, uintptr(unsafe.Pointer(&editor)), 2)
		if editor.bottom >= status.top {
			t.Fatalf("[§7.2] DPI %d 行内编辑框压住状态行：编辑框=%+v 状态=%+v", dpi, editor, status)
		}
		ink := 0
		for y := status.top; y < status.bottom; y++ {
			for x := status.left; x < status.right; x++ {
				pixel := before.NRGBAAt(int(x), int(y))
				if pixel.R < 180 && pixel.G < 180 && pixel.B < 180 {
					ink++
				}
				if after.NRGBAAt(int(x), int(y)) != pixel {
					t.Fatalf("[§7.2] DPI %d 重命名遮挡或改写了连接状态的实际像素", dpi)
				}
			}
		}
		if ink < 10 {
			t.Fatalf("[§7.2] DPI %d 状态行没有完整可读的实际文字", dpi)
		}
		app.finishMisakaRename(false)
	}
}

func absMisakaAlignment(value int32) int32 {
	if value < 0 {
		return -value
	}
	return value
}
