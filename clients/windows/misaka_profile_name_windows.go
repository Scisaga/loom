//go:build windows

package main

import (
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

const misakaProfileNameSize = 13

// §7.2：同一名称在浏览和编辑时共用原生字体与排版基线，不能在两套字体度量之间跳动。
func createMisakaProfileNameFont(dpi, weight int32) (uintptr, error) {
	face, _ := windows.UTF16PtrFromString("Microsoft YaHei UI")
	height := -misakaProfileNameSize * dpi / 96
	font, _, err := procCreateFont.Call(uintptr(uint32(height)), 0, 0, 0, uintptr(weight), 0, 0, 0, 1, 0, 0, portableClearType, 0, uintptr(unsafe.Pointer(face)))
	if font == 0 {
		return 0, fmt.Errorf("[§7.2] 创建连接配置名称字体：%w", err)
	}
	return font, nil
}

func (app *portableGUI) misakaProfileNameFont(selected bool) uintptr {
	if len(app.fonts) >= 4 {
		if selected {
			return app.fonts[3]
		}
		return app.fonts[2]
	}
	font, _, _ := procSendMessage.Call(app.controls.profileNameEdit, portableWMGetFont, 0, 0)
	return font
}

func (app *portableGUI) misakaProfileNameBounds(row portableRect, font uintptr) portableRect {
	var metrics struct {
		height, ascent, descent, internalLeading, externalLeading int32
		averageWidth, maximumWidth, weight, overhang              int32
		aspectX, aspectY                                          int32
		first, last, defaultChar, breakChar                       uint16
		italic, underlined, struckOut, pitchAndFamily, charset    byte
	}
	dc, _, _ := procGetDC.Call(app.hwnd)
	if dc != 0 {
		previous, _, _ := procSelectObject.Call(dc, font)
		portableGDI32.NewProc("GetTextMetricsW").Call(dc, uintptr(unsafe.Pointer(&metrics)))
		procSelectObject.Call(dc, previous)
		procReleaseDC.Call(app.hwnd, dc)
	}
	height := metrics.height
	if height <= 0 {
		height = app.scale(23)
	}
	return misakaRect(row.left+app.scale(29), row.top+app.scale(4)+max(int32(0), (app.scale(23)-height)/2), row.right-row.left-app.scale(35), height)
}

func (app *portableGUI) drawMisakaProfileName(dc uintptr, row portableRect, name string, selected bool) {
	font := app.misakaProfileNameFont(selected)
	bounds := app.misakaProfileNameBounds(row, font)
	text, _ := windows.UTF16PtrFromString(name)
	previousFont, _, _ := procSelectObject.Call(dc, font)
	previousMode, _, _ := procSetBkMode.Call(dc, portableTransparent)
	previousColor, _, _ := procSetTextColor.Call(dc, uintptr(misakaColorRef(misakaText)))
	procDrawText.Call(dc, uintptr(unsafe.Pointer(text)), ^uintptr(0), uintptr(unsafe.Pointer(&bounds)), portableDTSingleLine|portableDTNoPrefix|portableDTEndEllipsis)
	procSetTextColor.Call(dc, previousColor)
	procSetBkMode.Call(dc, previousMode)
	procSelectObject.Call(dc, previousFont)
	runtime.KeepAlive(text)
}
