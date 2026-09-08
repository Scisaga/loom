//go:build windows

package main

import (
	"bytes"
	"fmt"
	"testing"
	"unsafe"
)

func TestPortableStatusIconsStateAndDPI(t *testing.T) {
	getIconInfo := portableUser32.NewProc("GetIconInfo")
	for _, size := range []int32{16, 20, 24, 28, 32} {
		t.Run(fmt.Sprintf("size-%d", size), func(t *testing.T) {
			icons, err := loadPortableStatusIcons(size)
			if err != nil {
				t.Fatal(err)
			}
			defer icons.destroy()
			connected, err := loadPortableConnectedIcon(size)
			if err != nil || connected == 0 {
				t.Fatalf("connected icon: handle=%d err=%v", connected, err)
			}
			defer procDestroyIcon.Call(connected)
			for _, tc := range []struct {
				state    portableGUIState
				animated bool
				want     uintptr
			}{
				{guiLoading, true, icons.busy[3]},
				{guiNeedsJoin, false, icons.stopped},
				{guiJoining, true, icons.busy[3]},
				{guiNeedsElevation, false, icons.stopped},
				{guiStarting, true, icons.busy[3]},
				{guiConnected, false, connected},
				{guiStopping, true, icons.stopping[3]},
				{guiStopped, false, icons.stopped},
				{guiError, false, icons.failed},
			} {
				if got := icons.icon(tc.state, 3, connected); got == 0 || got != tc.want {
					t.Fatalf("state %d: icon=%d want=%d", tc.state, got, tc.want)
				}
				if portableStatusAnimated(tc.state) != tc.animated {
					t.Fatalf("state %d: wrong animation state", tc.state)
				}
			}
			if icons.icon(guiStarting, -1, connected) != icons.busy[7] || icons.icon(guiStarting, 8, connected) != icons.busy[0] {
				t.Fatal("animation frame does not wrap")
			}
			handles := []uintptr{icons.stopped, icons.failed}
			handles = append(handles, icons.busy[:]...)
			handles = append(handles, icons.stopping[:]...)
			seen := make(map[uintptr]bool)
			for _, handle := range handles {
				if handle == 0 || seen[handle] {
					t.Fatal("missing icon or repeated frame handle")
				}
				seen[handle] = true
				var info portableIconInfo
				if ok, _, _ := getIconInfo.Call(handle, uintptr(unsafe.Pointer(&info))); ok == 0 {
					t.Fatal("invalid icon handle")
				}
				var bitmap windowsBitmap
				n, _, _ := procGetObject.Call(info.color, unsafe.Sizeof(bitmap), uintptr(unsafe.Pointer(&bitmap)))
				procDeleteObject.Call(info.color)
				procDeleteObject.Call(info.mask)
				if n == 0 || bitmap.width != size || bitmap.height != size || bitmap.bitsPixel != 32 {
					t.Fatalf("wrong DPI bitmap: %+v", bitmap)
				}
			}
			icons.destroy()
			icons.destroy()
			for _, handle := range handles {
				var info portableIconInfo
				if ok, _, _ := getIconInfo.Call(handle, uintptr(unsafe.Pointer(&info))); ok != 0 {
					procDeleteObject.Call(info.color)
					procDeleteObject.Call(info.mask)
					t.Fatal("destroy retained a native icon")
				}
			}
			for state := guiLoading; state <= guiError; state++ {
				if state != guiConnected && icons.icon(state, 0, connected) != 0 {
					t.Fatal("destroy retained an icon reference")
				}
			}
			var info portableIconInfo
			if ok, _, _ := getIconInfo.Call(connected, uintptr(unsafe.Pointer(&info))); ok == 0 {
				t.Fatal("destroy released the externally owned connected icon")
			}
			procDeleteObject.Call(info.color)
			procDeleteObject.Call(info.mask)
		})
	}
	for _, size := range []int32{0, 7, 257} {
		if icons, err := loadPortableStatusIcons(size); err == nil || icons != nil {
			t.Fatalf("accepted invalid size %d", size)
		}
	}
}

func TestPortableStatusIconsTransparentAnimation(t *testing.T) {
	const size = 32
	var frames [][]byte
	for kind := range 2 + 2*portableStatusFrameCount {
		pixels := make([]byte, size*size*4)
		paintPortableStatusIcon(pixels, size, kind)
		if !bytes.Equal(pixels[:4], []byte{0, 0, 0, 0}) {
			t.Fatal("status icon has an opaque background")
		}
		visible := false
		for offset := 0; offset < len(pixels); offset += 4 {
			alpha := pixels[offset+3]
			visible = visible || alpha != 0
			for channel := range 3 {
				if pixels[offset+channel] > alpha {
					t.Fatal("status icon is not premultiplied alpha")
				}
			}
		}
		if !visible {
			t.Fatal("status icon is blank")
		}
		for _, previous := range frames {
			if bytes.Equal(previous, pixels) {
				t.Fatal("animation or status has identical pixels")
			}
		}
		frames = append(frames, pixels)
	}
}
