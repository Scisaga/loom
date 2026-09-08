//go:build windows

package main

import (
	"strings"
	"testing"
	"unsafe"
)

// §7.3.3：实际像素应是连续面板与细分隔线，不能残留两张卡片之间的背景空隙。
func TestGUIMisakaPathsShareOnePanel(t *testing.T) {
	app := newProfileGUITestWindow(t)
	const width, height int32 = 1300, 600
	dc, pixels := misakaCanvasTestDC(t, width, height)
	for _, dpi := range []int32{96, 144, 192} {
		app.windowDPI = dpi
		s := app.scale
		rowHeight, rowWidth := s(app.misakaPathHeight()), s(640)
		for i := range 2 {
			app.drawMisakaPath(&portableDrawItem{dc: dc, rect: misakaRect(0, int32(i)*rowHeight, rowWidth, rowHeight), itemID: uint32(i)})
		}
		portableGDI32.NewProc("GdiFlush").Call()
		for y := rowHeight - s(3); y < rowHeight+s(3); y++ {
			want := uint32(misakaWhite)
			if y >= rowHeight-s(1) && y < rowHeight {
				want = misakaBorder
			}
			for _, x := range []int32{s(2), s(40), rowWidth - s(5)} {
				if got := misakaCanvasTestPixel(pixels, width, x, y); got != want {
					t.Fatalf("DPI %d divider does not span the panel at (%d,%d): %06x != %06x", dpi, x, y, got, want)
				}
			}
			if got := misakaCanvasTestPixel(pixels, width, 0, y); got != misakaBorder {
				t.Fatalf("DPI %d panel side is not continuous: %06x", dpi, got)
			}
		}
	}
}

func TestGUIMisakaExpandedServicesHaveIndependentHeights(t *testing.T) {
	app := newProfileGUITestWindow(t)
	app.pathsExpanded = true
	for _, dpi := range []int32{96, 144, 192} {
		width, height := portableMinimumWindowSize(dpi)
		suggested := portableRect{left: 20, top: 20, right: 20 + width, bottom: 20 + height}
		procSendMessage.Call(app.hwnd, portableWMDPIChanged, uintptr(dpi)|uintptr(dpi)<<16, uintptr(unsafe.Pointer(&suggested)))
		app.paths[0].Reason = strings.Repeat("说明较长的服务需要自身增加高度，不能让其他服务同步变高。", 8)
		app.renderControls()
		read := func(index uintptr) portableRect {
			var r portableRect
			procSendMessage.Call(app.controls.pathsValue, 0x0198, index, uintptr(unsafe.Pointer(&r)))
			return r
		}
		first, second := read(0), read(1)
		if first.bottom-first.top <= second.bottom-second.top || second.top != first.bottom {
			t.Fatalf("DPI %d service rows still share a height or leave a gap: first=%+v second=%+v", dpi, first, second)
		}
		app.paths[0].Reason = "保留当前路径"
		app.renderControls()
		shorter, unchanged := read(0), read(1)
		if shorter.bottom-shorter.top >= first.bottom-first.top || unchanged.bottom-unchanged.top != second.bottom-second.top || unchanged.top != shorter.bottom {
			t.Fatalf("DPI %d shortening one service changed another height or retained blank space", dpi)
		}
	}
}
