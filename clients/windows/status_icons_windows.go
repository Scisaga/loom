//go:build windows

package main

import (
	"fmt"
	"math"
	"runtime"
	"time"
	"unsafe"
)

const (
	portableStatusFrameCount    = 8
	portableStatusFrameInterval = 100 * time.Millisecond
)

type portableStatusIcons struct {
	stopped  uintptr
	failed   uintptr
	busy     [portableStatusFrameCount]uintptr
	stopping [portableStatusFrameCount]uintptr
}

func loadPortableStatusIcons(size int32) (*portableStatusIcons, error) {
	if size < 8 || size > 256 {
		return nil, fmt.Errorf("[§7.2] 连接状态图标尺寸无效：%d", size)
	}
	icons := &portableStatusIcons{}
	all := []*uintptr{&icons.stopped, &icons.failed}
	for index := range icons.busy {
		all = append(all, &icons.busy[index])
	}
	for index := range icons.stopping {
		all = append(all, &icons.stopping[index])
	}
	for index, handle := range all {
		icon, err := createPortableStatusIcon(size, index)
		if err != nil {
			icons.destroy()
			return nil, err
		}
		*handle = icon
	}
	return icons, nil
}

func portableStatusAnimated(state portableGUIState) bool {
	return state == guiLoading || state == guiJoining || state == guiStarting || state == guiStopping
}

func (icons *portableStatusIcons) icon(state portableGUIState, frame int, connectedIcon uintptr) uintptr {
	if state == guiConnected {
		return connectedIcon
	}
	if icons == nil {
		return 0
	}
	frame = ((frame % portableStatusFrameCount) + portableStatusFrameCount) % portableStatusFrameCount
	switch state {
	case guiLoading, guiJoining, guiStarting:
		return icons.busy[frame]
	case guiStopping:
		return icons.stopping[frame]
	case guiError:
		return icons.failed
	default:
		return icons.stopped
	}
}

func (icons *portableStatusIcons) destroy() {
	if icons == nil {
		return
	}
	all := []*uintptr{&icons.stopped, &icons.failed}
	for index := range icons.busy {
		all = append(all, &icons.busy[index])
	}
	for index := range icons.stopping {
		all = append(all, &icons.stopping[index])
	}
	for _, handle := range all {
		if *handle != 0 {
			procDestroyIcon.Call(*handle)
			*handle = 0
		}
	}
}

func createPortableStatusIcon(size int32, kind int) (uintptr, error) {
	header := portableBitmapInfoHeader{
		size: uint32(unsafe.Sizeof(portableBitmapInfoHeader{})), width: size, height: -size,
		planes: 1, bitCount: 32, compression: portableBIRGB, sizeImage: uint32(size * size * 4),
	}
	var pixels unsafe.Pointer
	bitmap, _, _ := procCreateDIBSection.Call(0, uintptr(unsafe.Pointer(&header)), portableDIBRGBColors,
		uintptr(unsafe.Pointer(&pixels)), 0, 0)
	if bitmap == 0 || pixels == nil {
		if bitmap != 0 {
			procDeleteObject.Call(bitmap)
		}
		return 0, fmt.Errorf("[§7.2] 无法创建连接状态图标位图")
	}
	defer procDeleteObject.Call(bitmap)
	data := unsafe.Slice((*byte)(pixels), int(size*size*4))
	paintPortableStatusIcon(data, int(size), kind)

	// §7.2：使用预乘 alpha 和全零 AND 蒙版，状态变化只需替换图标控件，保留透明背景。
	maskData := make([]byte, ((int(size)+15)/16)*2*int(size))
	mask, _, _ := procCreateBitmap.Call(uintptr(size), uintptr(size), 1, 1, uintptr(unsafe.Pointer(&maskData[0])))
	if mask == 0 {
		return 0, fmt.Errorf("[§7.2] 无法创建连接状态图标蒙版")
	}
	defer procDeleteObject.Call(mask)
	info := portableIconInfo{icon: 1, mask: mask, color: bitmap}
	icon, _, _ := procCreateIconIndirect.Call(uintptr(unsafe.Pointer(&info)))
	runtime.KeepAlive(header)
	runtime.KeepAlive(maskData)
	runtime.KeepAlive(info)
	if icon == 0 {
		return 0, fmt.Errorf("[§7.2] 无法创建连接状态图标")
	}
	return icon, nil
}

func paintPortableStatusIcon(pixels []byte, size, kind int) {
	const samples = 4
	for y := range size {
		for x := range size {
			var red, green, blue, alpha float64
			for sy := range samples {
				for sx := range samples {
					px := (float64(x)+(float64(sx)+0.5)/samples)/float64(size)*2 - 1
					py := (float64(y)+(float64(sy)+0.5)/samples)/float64(size)*2 - 1
					r, g, b, a := portableStatusPixel(px, py, kind)
					red += float64(r) * float64(a) / 255
					green += float64(g) * float64(a) / 255
					blue += float64(b) * float64(a) / 255
					alpha += float64(a)
				}
			}
			offset := (y*size + x) * 4
			pixels[offset] = byte(math.Round(blue / (samples * samples)))
			pixels[offset+1] = byte(math.Round(green / (samples * samples)))
			pixels[offset+2] = byte(math.Round(red / (samples * samples)))
			pixels[offset+3] = byte(math.Round(alpha / (samples * samples)))
		}
	}
}

func portableStatusPixel(x, y float64, kind int) (byte, byte, byte, byte) {
	if kind < 2 {
		if x*x+y*y > 0.82*0.82 {
			return 0, 0, 0, 0
		}
		if kind == 0 {
			if math.Abs(x) < 0.43 && math.Abs(y) < 0.10 {
				return 255, 255, 255, 255
			}
			return 122, 132, 142, 255
		}
		if math.Abs(x) < 0.38 && math.Abs(y) < 0.38 && (math.Abs(x-y) < 0.15 || math.Abs(x+y) < 0.15) {
			return 255, 255, 255, 255
		}
		return 202, 48, 48, 255
	}
	frame := (kind - 2) % portableStatusFrameCount
	for dot := range portableStatusFrameCount {
		angle := float64(dot)*2*math.Pi/portableStatusFrameCount - math.Pi/2
		dx, dy := x-0.64*math.Cos(angle), y-0.64*math.Sin(angle)
		if dx*dx+dy*dy > 0.155*0.155 {
			continue
		}
		age := (frame - dot + portableStatusFrameCount) % portableStatusFrameCount
		alpha := byte(255 - age*25)
		if kind >= 2+portableStatusFrameCount {
			return 108, 118, 128, alpha
		}
		return 0, 116, 204, alpha
	}
	return 0, 0, 0, 0
}
