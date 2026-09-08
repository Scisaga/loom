//go:build windows

package main

import (
	"log"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

const misakaRetryPaintTimer = 4102

func (app *portableGUI) beginMisakaPaint(dc uintptr, bounds portableRect) bool {
	if err := app.skin.canvas.Begin(dc, bounds, app.dpi()); err != nil {
		app.misakaPaintFailed(dc, bounds, err)
		return false
	}
	return true
}

func (app *portableGUI) finishMisakaPaint(dc uintptr) {
	if err := app.skin.canvas.End(); err != nil {
		app.misakaPaintFailed(dc, app.skin.canvas.bounds, err)
	}
}

func (app *portableGUI) misakaPaintFailed(dc uintptr, bounds portableRect, err error) {
	// §7.2：设备重建失败应可见；限次重绘避免稳定错误变成空转的 WM_PAINT 循环。
	app.skin.paintError = err.Error()
	app.skin.paintFailures++
	log.Printf("[§7.2] 自绘窗口: %v", err)
	if app.skin.paintFailures <= 2 {
		procSetTimer.Call(app.hwnd, misakaRetryPaintTimer, 50, 0)
	}
	procFillRect.Call(dc, uintptr(unsafe.Pointer(&bounds)), app.misakaBrush(misakaBackground))
	label, _ := windows.UTF16PtrFromString("界面绘制暂不可用，请调整窗口后重试。")
	procSetBkMode.Call(dc, portableTransparent)
	procSetTextColor.Call(dc, uintptr(misakaColorRef(misakaRed)))
	procDrawText.Call(dc, uintptr(unsafe.Pointer(label)), ^uintptr(0), uintptr(unsafe.Pointer(&bounds)), portableDTCenter|portableDTVCenter|portableDTSingleLine)
	runtime.KeepAlive(label)
}
