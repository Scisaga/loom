//go:build windows

package main

import (
	"errors"
	"fmt"
	"image"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"loom/internal/clientenroll"
	"loom/internal/clientjoin"
)

const (
	windowsClipboardBitmap      = 2
	windowsClipboardUnicodeText = 13
	windowsDIBRGBColors         = 0
	windowsBIRGB                = 0
	windowsMaxClipboardText     = 128 << 10
)

type windowsBitmap struct {
	typeValue  int32
	width      int32
	height     int32
	widthBytes int32
	planes     uint16
	bitsPixel  uint16
	bits       unsafe.Pointer
}

type windowsBitmapInfoHeader struct {
	size          uint32
	width         int32
	height        int32
	planes        uint16
	bitCount      uint16
	compression   uint32
	sizeImage     uint32
	xPelsPerMeter int32
	yPelsPerMeter int32
	clrUsed       uint32
	clrImportant  uint32
}

type windowsBitmapInfo struct {
	header windowsBitmapInfoHeader
}

var (
	clipboardUser32   = windows.NewLazySystemDLL("user32.dll")
	clipboardGDI32    = windows.NewLazySystemDLL("gdi32.dll")
	clipboardKernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procOpenClipboard              = clipboardUser32.NewProc("OpenClipboard")
	procCloseClipboard             = clipboardUser32.NewProc("CloseClipboard")
	procIsClipboardFormatAvailable = clipboardUser32.NewProc("IsClipboardFormatAvailable")
	procGetClipboardData           = clipboardUser32.NewProc("GetClipboardData")
	procGetDC                      = clipboardUser32.NewProc("GetDC")
	procReleaseDC                  = clipboardUser32.NewProc("ReleaseDC")
	procGetObject                  = clipboardGDI32.NewProc("GetObjectW")
	procGetDIBits                  = clipboardGDI32.NewProc("GetDIBits")
	procGlobalLock                 = clipboardKernel32.NewProc("GlobalLock")
	procGlobalUnlock               = clipboardKernel32.NewProc("GlobalUnlock")
	procGlobalSize                 = clipboardKernel32.NewProc("GlobalSize")
)

// readWindowsClipboardInvite accepts the image produced by copying the QR in
// a browser, or the equivalent loom:// text. Clipboard bytes are decoded in
// memory and are never written to a temporary file.
func readWindowsClipboardInvite(owner uintptr) (clientenroll.Invite, error) {
	if err := openWindowsClipboard(owner); err != nil {
		return clientenroll.Invite{}, err
	}
	defer procCloseClipboard.Call()

	if available, _, _ := procIsClipboardFormatAvailable.Call(windowsClipboardBitmap); available != 0 {
		return readWindowsClipboardBitmap()
	}
	if available, _, _ := procIsClipboardFormatAvailable.Call(windowsClipboardUnicodeText); available != 0 {
		return readWindowsClipboardText()
	}
	return clientenroll.Invite{}, errors.New("剪贴板中没有二维码图片；请先在中控页面复制二维码，再按 Ctrl+V")
}

func openWindowsClipboard(owner uintptr) error {
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		opened, _, callErr := procOpenClipboard.Call(owner)
		if opened != 0 {
			return nil
		}
		lastErr = callErr
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Errorf("无法读取 Windows 剪贴板: %w", lastErr)
}

func readWindowsClipboardBitmap() (clientenroll.Invite, error) {
	handle, _, callErr := procGetClipboardData.Call(windowsClipboardBitmap)
	if handle == 0 {
		return clientenroll.Invite{}, fmt.Errorf("读取剪贴板二维码失败: %w", callErr)
	}
	var bitmap windowsBitmap
	written, _, callErr := procGetObject.Call(
		handle, unsafe.Sizeof(bitmap), uintptr(unsafe.Pointer(&bitmap)),
	)
	if written != unsafe.Sizeof(bitmap) || bitmap.width <= 0 || bitmap.height == 0 {
		return clientenroll.Invite{}, fmt.Errorf("读取剪贴板图片信息失败: %w", callErr)
	}
	height := bitmap.height
	if height < 0 {
		height = -height
	}
	if bitmap.width > 2048 || height > 2048 || int64(bitmap.width)*int64(height) > 4<<20 {
		return clientenroll.Invite{}, errors.New("剪贴板二维码图片过大；最大支持 2048×2048")
	}
	stride := int(bitmap.width) * 4
	pixels := make([]byte, stride*int(height))
	defer clear(pixels)
	info := windowsBitmapInfo{header: windowsBitmapInfoHeader{
		size: uint32(unsafe.Sizeof(windowsBitmapInfoHeader{})), width: bitmap.width,
		height: -height, planes: 1, bitCount: 32, compression: windowsBIRGB,
		sizeImage: uint32(len(pixels)),
	}}
	dc, _, dcErr := procGetDC.Call(0)
	if dc == 0 {
		return clientenroll.Invite{}, fmt.Errorf("读取剪贴板图片失败: %w", dcErr)
	}
	defer procReleaseDC.Call(0, dc)
	rows, _, dibErr := procGetDIBits.Call(
		dc, handle, 0, uintptr(height), uintptr(unsafe.Pointer(&pixels[0])),
		uintptr(unsafe.Pointer(&info)), windowsDIBRGBColors,
	)
	if rows != uintptr(height) {
		return clientenroll.Invite{}, fmt.Errorf("转换剪贴板二维码失败: %w", dibErr)
	}

	decoded := image.NewNRGBA(image.Rect(0, 0, int(bitmap.width), int(height)))
	for y := 0; y < int(height); y++ {
		for x := 0; x < int(bitmap.width); x++ {
			source := y*stride + x*4
			target := y*decoded.Stride + x*4
			decoded.Pix[target] = pixels[source+2]
			decoded.Pix[target+1] = pixels[source+1]
			decoded.Pix[target+2] = pixels[source]
			decoded.Pix[target+3] = 0xff
		}
	}
	runtime.KeepAlive(bitmap)
	return clientjoin.ReadImage(decoded)
}

func readWindowsClipboardText() (clientenroll.Invite, error) {
	handle, _, callErr := procGetClipboardData.Call(windowsClipboardUnicodeText)
	if handle == 0 {
		return clientenroll.Invite{}, fmt.Errorf("读取剪贴板文本失败: %w", callErr)
	}
	size, _, sizeErr := procGlobalSize.Call(handle)
	if size < 2 || size > windowsMaxClipboardText {
		return clientenroll.Invite{}, fmt.Errorf("剪贴板加入内容大小无效: %w", sizeErr)
	}
	address, _, lockErr := procGlobalLock.Call(handle)
	if address == 0 {
		return clientenroll.Invite{}, fmt.Errorf("锁定剪贴板文本失败: %w", lockErr)
	}
	defer procGlobalUnlock.Call(handle)
	units := unsafe.Slice((*uint16)(unsafe.Pointer(address)), int(size/2))
	end := 0
	for end < len(units) && units[end] != 0 {
		end++
	}
	if end == 0 || end == len(units) {
		return clientenroll.Invite{}, errors.New("剪贴板中的加入内容无效")
	}
	text := windows.UTF16ToString(units[:end])
	runtime.KeepAlive(units)
	return clientjoin.Read(text, nil)
}
