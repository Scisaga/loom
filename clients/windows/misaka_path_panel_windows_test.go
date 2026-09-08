//go:build windows

package main

import "testing"

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
