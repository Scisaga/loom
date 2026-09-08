//go:build windows

package main

import (
	"image"
	"testing"
	"unsafe"
)

func misakaProfileNameInk(picture *image.NRGBA, area portableRect) (portableRect, int) {
	bounds := portableRect{left: area.right, top: area.bottom, right: area.left, bottom: area.top}
	count := 0
	for y := area.top; y < area.bottom; y++ {
		for x := area.left; x < area.right; x++ {
			pixel := picture.NRGBAAt(int(x), int(y))
			if pixel.R >= 120 || pixel.G >= 120 || pixel.B >= 120 {
				continue
			}
			count++
			bounds.left, bounds.top = min(bounds.left, x), min(bounds.top, y)
			bounds.right, bounds.bottom = max(bounds.right, x+1), max(bounds.bottom, y+1)
		}
	}
	return bounds, count
}

func TestGUIMisakaRenameKeepsVisibleGlyphOriginSizeAndWeight(t *testing.T) {
	app := newProfileGUITestWindow(t)
	for _, dpi := range []int32{96, 120, 144, 168, 192} {
		width, height := portableMinimumWindowSize(dpi)
		suggested := portableRect{left: 20, top: 20, right: 20 + width, bottom: 20 + height}
		procSendMessage.Call(app.hwnd, portableWMDPIChanged, uintptr(dpi)|uintptr(dpi)<<16, uintptr(unsafe.Pointer(&suggested)))
		for _, name := range []string{"演示网络甲", "Loom 网络", "Agjp_demo"} {
			app.brokerProfiles[0].Name, app.profileName = name, name
			app.renderControls()
			var row portableRect
			procSendMessage.Call(app.controls.networkList, 0x0198, 0, uintptr(unsafe.Pointer(&row)))
			procMisakaMapPoints.Call(app.controls.networkList, app.hwnd, uintptr(unsafe.Pointer(&row)), 2)
			area := misakaRect(row.left+app.scale(29), row.top, row.right-row.left-app.scale(35), app.scale(32))
			before := readProfileGUITestWindow(t, app)
			app.beginMisakaRename()
			procSendMessage.Call(app.controls.profileNameEdit, 0x00B1, ^uintptr(0), ^uintptr(0))
			after := readProfileGUITestWindow(t, app)
			plainBounds, plainInk := misakaProfileNameInk(before, area)
			editBounds, editInk := misakaProfileNameInk(after, area)
			if plainInk < 10 || plainBounds != editBounds {
				t.Errorf("[§7.2] DPI %d、名称 %q 进入编辑后实际字形位置或尺寸变化：显示=%+v 编辑=%+v", dpi, name, plainBounds, editBounds)
			}
			if difference := absMisakaAlignment(int32(plainInk - editInk)); difference > int32(max(3, plainInk/20)) {
				t.Errorf("[§7.2] DPI %d、名称 %q 进入编辑后实际笔画字重变化：显示=%d 编辑=%d", dpi, name, plainInk, editInk)
			}
			app.finishMisakaRename(false)
		}
	}
}

func TestGUIMisakaProfileFocusDoesNotAddUnderline(t *testing.T) {
	app := newProfileGUITestWindow(t)
	const width, height int32 = 400, 140
	dc, pixels := misakaCanvasTestDC(t, width, height)
	for _, dpi := range []int32{96, 120, 144, 168, 192} {
		app.windowDPI = dpi
		s := app.scale
		rect := misakaRect(s(4), s(2), s(152), s(55))
		for _, focused := range []bool{true, false, true} {
			state := uint32(portableODSSelected)
			if focused {
				state |= portableODSFocus
			}
			app.drawMisakaProfile(&portableDrawItem{hwndItem: app.controls.networkList, dc: dc, rect: rect, itemID: 0, itemState: state})
			portableGDI32.NewProc("GdiFlush").Call()
			for y := rect.bottom - s(4); y < rect.bottom; y++ {
				for x := rect.left + s(6); x < rect.right-s(6); x++ {
					if pixel := misakaCanvasTestPixel(pixels, width, x, y); pixel != 0xE9F3ED {
						t.Fatalf("[§7.2] DPI %d、焦点 %t 在菜单项底部留下额外横线：(%d,%d)=%06x", dpi, focused, x, y, pixel)
					}
				}
			}
		}
	}
}
