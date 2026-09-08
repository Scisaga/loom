//go:build windows

package main

import (
	"math"
	"runtime"
	"testing"
)

func TestMisakaCanvasGrayscaleTextKeepsNeutralEdges(t *testing.T) {
	runtime.LockOSThread()
	t.Cleanup(runtime.UnlockOSThread)
	const width, height int32 = 480, 120
	dc, pixels := misakaCanvasTestDC(t, width, height)
	c, err := newMisakaCanvas()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	full := portableRect{right: width, bottom: height}
	for _, dpi := range []int32{96, 120, 144, 168, 192} {
		var baseline portableRect
		var baselineColors int
		for _, grayscale := range []bool{false, true} {
			if err := c.Begin(dc, full, dpi); err != nil {
				t.Fatal(err)
			}
			if !grayscale {
				misakaCOMCall(c.target, 34, 1) // §7.2：只在合成 DC 上采集 ClearType 对照，不修改系统设置。
			}
			c.Fill(full, 0xffffff, 0)
			c.Text("当前选路 Loom 012345", full, 14*dpi/96, 400, 0, 0)
			if err := c.End(); err != nil {
				t.Fatal(err)
			}
			portableGDI32.NewProc("GdiFlush").Call()
			chromatic, solid := 0, 0
			shades := map[uint32]bool{}
			for y := int32(0); y < height; y++ {
				for x := int32(0); x < width; x++ {
					pixel := misakaCanvasTestPixel(pixels, width, x, y)
					r, g, b := pixel>>16, pixel>>8&255, pixel&255
					if r != g || g != b {
						chromatic++
					}
					if max(r, g, b) < 48 {
						solid++
					}
					if pixel != 0 && pixel != 0xffffff {
						shades[pixel] = true
					}
				}
			}
			ink := misakaCanvasInkBounds(pixels, width, full, 0xffffff)
			if !grayscale {
				baseline, baselineColors = ink, chromatic
				continue
			}
			if chromatic != 0 || solid < 20 || len(shades) < 4 {
				t.Fatalf("[§7.2] DPI=%d 文字仍有彩边或失去清晰抗锯齿：彩色=%d 实笔=%d 灰阶=%d", dpi, chromatic, solid, len(shades))
			}
			if absMisakaAlignment(ink.left-baseline.left) > 2 || absMisakaAlignment(ink.top-baseline.top) > 2 || absMisakaAlignment(ink.right-baseline.right) > 2 || absMisakaAlignment(ink.bottom-baseline.bottom) > 2 {
				t.Fatalf("[§7.2] 灰度抗锯齿改变文字布局：ClearType=%+v 灰度=%+v", baseline, ink)
			}
			t.Logf("[§7.2] DPI=%d ClearType彩边=%d → 灰度彩边=%d，保留%d实笔像素/%d灰阶", dpi, baselineColors, chromatic, solid, len(shades))
		}
		c.releaseTarget() // §7.2：设备重建后也必须重新应用灰度设置。
	}
}

func TestMisakaPathNodeOutlineRemainsConcentricAtFractionalDPI(t *testing.T) {
	runtime.LockOSThread()
	t.Cleanup(runtime.UnlockOSThread)
	const width, height, cx, cy int32 = 128, 128, 64, 64
	dc, pixels := misakaCanvasTestDC(t, width, height)
	c, err := newMisakaCanvas()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	full := portableRect{right: width, bottom: height}
	for _, dpi := range []int32{96, 120, 144, 168, 192} {
		scale := func(value int32) int32 { return value * dpi / 96 }
		for _, fixed := range []bool{false, true} {
			if err := c.Begin(dc, full, dpi); err != nil {
				t.Fatal(err)
			}
			c.Fill(full, misakaWhite, 0)
			paintMisakaPathNode(c, cx, cy, 1, 3, scale, fixed)
			if err := c.End(); err != nil {
				t.Fatal(err)
			}
			portableGDI32.NewProc("GdiFlush").Call()
			checked, maxDifference := 0, int32(0)
			for y := int32(0); y < height; y++ {
				for x := int32(0); x < width; x++ {
					distance := math.Hypot(float64(x-cx)+0.5, float64(y-cy)+0.5)
					if distance < float64(scale(12)) || distance > float64(scale(34))/2+2 {
						continue // §7.2：只检查圆环，中心服务器符号不参与圆环对称性判断。
					}
					pixel := misakaCanvasTestPixel(pixels, width, x, y)
					for _, reflected := range []uint32{misakaCanvasTestPixel(pixels, width, 2*cx-1-x, y), misakaCanvasTestPixel(pixels, width, x, 2*cy-1-y)} {
						for _, shift := range []uint{0, 8, 16} {
							maxDifference = max(maxDifference, absMisakaAlignment(int32(pixel>>shift&255)-int32(reflected>>shift&255)))
						}
					}
					checked++
				}
			}
			if checked < 100 || maxDifference > 2 {
				t.Fatalf("[§7.2] DPI=%d fixed=%t 节点边框形成不对称投影：镜像像素=%d 最大通道差=%d", dpi, fixed, checked, maxDifference)
			}
		}
	}
}
