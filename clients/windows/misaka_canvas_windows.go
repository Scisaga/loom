//go:build windows

package main

import (
	"errors"
	"fmt"
	"math"
	"runtime"
	"syscall"
	"unicode"
	"unsafe"

	"golang.org/x/sys/windows"
)

// §7.2：画布仅使用系统 Direct2D/DirectWrite DLL，由界面线程持有。
// 坐标与字号均为 HDC 的物理像素；调用方先按当前 DPI 缩放。
type misakaCanvas struct {
	factory, writeFactory, target *misakaCOMObject
	brushes                       map[uint32]*misakaCOMObject
	formats                       map[misakaTextStyle]*misakaCOMObject
	bounds                        portableRect
	dpi                           int32
	drawing, closed               bool
	err                           error
}

type misakaTextStyle struct {
	size, weight int32
	align        uint32
	wrap         bool
	cjk          bool
}

type misakaFloatRect struct{ left, top, right, bottom float32 }
type misakaRoundedRect struct {
	rect             misakaFloatRect
	radiusX, radiusY float32
}
type misakaColor struct{ r, g, b, a float32 }
type misakaTrimming struct{ granularity, delimiter, delimiterCount uint32 }
type misakaTargetProperties struct {
	kind, format, alpha uint32
	dpiX, dpiY          float32
	usage, minimum      uint32
}

const misakaRecreateTarget = 0x8899000C

var (
	misakaD2DCreateFactory = windows.NewLazySystemDLL("d2d1.dll").NewProc("D2D1CreateFactory")
	misakaDWriteFactory    = windows.NewLazySystemDLL("dwrite.dll").NewProc("DWriteCreateFactory")
	misakaFactoryIID       = windows.GUID{Data1: 0x06152247, Data2: 0x6f50, Data3: 0x465a, Data4: [8]byte{0x92, 0x45, 0x11, 0x8b, 0xfd, 0x3b, 0x60, 0x07}}
	misakaWriteIID         = windows.GUID{Data1: 0xb859ee5a, Data2: 0xd838, Data3: 0x4b5b, Data4: [8]byte{0xa2, 0xe8, 0x1a, 0xdc, 0x7d, 0x93, 0xdb, 0x48}}
)

func newMisakaCanvas() (*misakaCanvas, error) {
	if err := misakaD2DCreateFactory.Find(); err != nil {
		return nil, fmt.Errorf("[§7.2] 加载系统 Direct2D: %w", err)
	}
	if err := misakaDWriteFactory.Find(); err != nil {
		return nil, fmt.Errorf("[§7.2] 加载系统 DirectWrite: %w", err)
	}
	c := &misakaCanvas{brushes: make(map[uint32]*misakaCOMObject), formats: make(map[misakaTextStyle]*misakaCOMObject)}
	hr, _, _ := misakaD2DCreateFactory.Call(0, uintptr(unsafe.Pointer(&misakaFactoryIID)), 0, uintptr(unsafe.Pointer(&c.factory)))
	if err := misakaHRESULT("[§7.2] 创建 Direct2D 工厂", hr); err != nil {
		c.Close()
		return nil, err
	}
	hr, _, _ = misakaDWriteFactory.Call(0, uintptr(unsafe.Pointer(&misakaWriteIID)), uintptr(unsafe.Pointer(&c.writeFactory)))
	if err := misakaHRESULT("[§7.2] 创建 DirectWrite 工厂", hr); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

func (c *misakaCanvas) Close() {
	if c == nil || c.closed {
		return
	}
	if c.drawing {
		_ = c.End()
	}
	c.releaseTarget()
	c.releaseFormats()
	misakaRelease(c.writeFactory)
	misakaRelease(c.factory)
	c.writeFactory, c.factory, c.closed = nil, nil, true
}

func (c *misakaCanvas) releaseTarget() {
	for color, brush := range c.brushes {
		misakaRelease(brush)
		delete(c.brushes, color)
	}
	misakaRelease(c.target)
	c.target = nil
}

func (c *misakaCanvas) releaseFormats() {
	for style, format := range c.formats {
		misakaRelease(format)
		delete(c.formats, style)
	}
}

func (c *misakaCanvas) Begin(dc uintptr, bounds portableRect, dpi int32) error {
	if c == nil || c.closed {
		return errors.New("[§7.2] Direct2D 画布已关闭")
	}
	if c.drawing {
		return errors.New("[§7.2] Direct2D 绘制已开始")
	}
	if dc == 0 || bounds.right <= bounds.left || bounds.bottom <= bounds.top || dpi <= 0 {
		return errors.New("[§7.2] Direct2D 绘制的 HDC、边界或 DPI 无效")
	}
	c.err = nil
	if c.dpi != dpi {
		c.releaseFormats()
		c.dpi = dpi
	}
	if c.target == nil {
		// §7.2：GDI DC 目标显式使用 BGRA 并忽略透明通道。固定 96 DPI，
		// 使绘制单位等于 HDC 物理像素，显示缩放统一由 Win32 界面处理。
		properties := misakaTargetProperties{format: 87, alpha: 3, dpiX: 96, dpiY: 96}
		hr := misakaCOMCall(c.factory, 16, uintptr(unsafe.Pointer(&properties)), uintptr(unsafe.Pointer(&c.target)))
		if err := misakaHRESULT("[§7.2] 创建 Direct2D DC 绘制目标", hr); err != nil {
			c.releaseTarget()
			return err
		}
	}
	if err := misakaHRESULT("[§7.2] 绑定 Direct2D HDC", misakaCOMCall(c.target, 57, dc, uintptr(unsafe.Pointer(&bounds)))); err != nil {
		c.releaseTarget()
		return err
	}
	c.bounds = bounds
	misakaCOMCall(c.target, 48) // §7.2：开始本次绘制。
	c.drawing = true
	return nil
}

func (c *misakaCanvas) End() error {
	if c == nil || c.closed || !c.drawing {
		return errors.New("[§7.2] Direct2D 绘制尚未开始")
	}
	hr := misakaCOMCall(c.target, 49, 0, 0) // §7.2：一次性提交到绑定的 HDC。
	c.drawing = false
	if uint32(hr) == misakaRecreateTarget {
		c.releaseTarget()
	}
	return errors.Join(c.err, misakaHRESULT("[§7.2] 提交 Direct2D 绘制", hr))
}

func (c *misakaCanvas) Fill(rect portableRect, rgb uint32, radius int32) {
	if !c.canDraw(rect) {
		return
	}
	brush := c.brush(rgb)
	if brush == nil {
		return
	}
	area := c.relativeRect(rect)
	if radius <= 0 {
		misakaCOMCall(c.target, 17, uintptr(unsafe.Pointer(&area)), uintptr(unsafe.Pointer(brush)))
		return
	}
	radius = min(radius, (rect.right-rect.left)/2, (rect.bottom-rect.top)/2)
	rounded := misakaRoundedRect{rect: area, radiusX: float32(radius), radiusY: float32(radius)}
	misakaCOMCall(c.target, 19, uintptr(unsafe.Pointer(&rounded)), uintptr(unsafe.Pointer(brush)))
}

// §7.2：单行文字垂直居中，超长时显示省略号，中文回退使用系统字体。
// align：0 左对齐、1 居中、2 右对齐。
func (c *misakaCanvas) Text(text string, rect portableRect, size, weight int32, rgb uint32, align uint32) {
	c.drawText(text, rect, misakaTextStyle{size: size, weight: weight, align: align}, rgb)
}

// §7.2：段落在矩形内换行并靠左上对齐，空间不足时显示省略号。
func (c *misakaCanvas) Paragraph(text string, rect portableRect, size, weight int32, rgb uint32) {
	c.drawText(text, rect, misakaTextStyle{size: size, weight: weight, wrap: true}, rgb)
}

func (c *misakaCanvas) drawText(text string, rect portableRect, style misakaTextStyle, rgb uint32) {
	if !c.canDraw(rect) || text == "" {
		return
	}
	if style.size <= 0 || style.size > 1024 || style.weight < 1 || style.weight > 999 || style.align > 2 {
		c.err = errors.New("[§7.2] DirectWrite 文字样式无效")
		return
	}
	characters, err := windows.UTF16FromString(text)
	if err != nil {
		c.err = fmt.Errorf("[§7.2] DirectWrite 文字编码： %w", err)
		return
	}
	// §7.2：Segoe UI 的默认中文回退可能是宋体；中文明确使用系统雅黑界面字体。
	// 字体族参与格式缓存，不能把同字号的中文与拉丁文字错误地复用成一种格式。
	style.cjk = misakaTextHasCJK(text)
	format := c.textFormat(style)
	brush := c.brush(rgb)
	if format == nil || brush == nil {
		return
	}
	area := c.relativeRect(rect)
	misakaCOMCall(c.target, 27, uintptr(unsafe.Pointer(&characters[0])), uintptr(len(characters)-1), uintptr(unsafe.Pointer(format)),
		uintptr(unsafe.Pointer(&area)), uintptr(unsafe.Pointer(brush)), 2, 0) // §7.2：裁剪到文字矩形。
	runtime.KeepAlive(characters)
}

func misakaTextHasCJK(text string) bool {
	for _, character := range text {
		if unicode.Is(unicode.Han, character) || character >= 0x3000 && character <= 0x30FF || character >= 0xFF00 && character <= 0xFFEF {
			return true
		}
	}
	return false
}

func (c *misakaCanvas) canDraw(rect portableRect) bool {
	if c == nil || c.closed {
		return false
	}
	if !c.drawing {
		c.err = errors.New("[§7.2] Direct2D 绘制前必须调用 Begin")
		return false
	}
	return c.err == nil && rect.right > rect.left && rect.bottom > rect.top
}

func (c *misakaCanvas) relativeRect(rect portableRect) misakaFloatRect {
	return misakaFloatRect{float32(rect.left - c.bounds.left), float32(rect.top - c.bounds.top),
		float32(rect.right - c.bounds.left), float32(rect.bottom - c.bounds.top)}
}

func (c *misakaCanvas) brush(rgb uint32) *misakaCOMObject {
	if c.err != nil {
		return nil
	}
	rgb &= 0xffffff
	if brush := c.brushes[rgb]; brush != nil {
		return brush
	}
	color := misakaColor{r: float32(rgb>>16) / 255, g: float32((rgb>>8)&255) / 255, b: float32(rgb&255) / 255, a: 1}
	var brush *misakaCOMObject
	hr := misakaCOMCall(c.target, 8, uintptr(unsafe.Pointer(&color)), 0, uintptr(unsafe.Pointer(&brush)))
	if c.err = misakaHRESULT("[§7.2] 创建 Direct2D 画刷", hr); c.err != nil {
		misakaRelease(brush)
		return nil
	}
	c.brushes[rgb] = brush
	return brush
}

func (c *misakaCanvas) textFormat(style misakaTextStyle) *misakaCOMObject {
	if format := c.formats[style]; format != nil {
		return format
	}
	familyName := "Segoe UI"
	if style.cjk {
		familyName = "Microsoft YaHei UI"
	}
	family, _ := windows.UTF16FromString(familyName)
	locale, _ := windows.UTF16FromString("zh-CN")
	var format *misakaCOMObject
	args := misakaTextFormatArgs{
		factory: c.writeFactory, family: &family[0], weight: uintptr(style.weight), stretch: 5,
		size: uintptr(math.Float32bits(float32(style.size))), locale: &locale[0], output: &format,
	}
	hr := misakaCreateTextFormat(misakaCOMMethod(c.writeFactory, 15), &args)
	runtime.KeepAlive(family)
	runtime.KeepAlive(locale)
	if c.err = misakaHRESULT("[§7.2] 创建 DirectWrite 文字格式", hr); c.err != nil {
		misakaRelease(format)
		return nil
	}
	align := [...]uintptr{0, 2, 1}[style.align]   // §7.2：左、中、右对齐。
	paragraph, wrapping := uintptr(2), uintptr(1) // §7.2：垂直居中，不换行。
	if style.wrap {
		paragraph, wrapping = 0, 0 // §7.2：靠上对齐，允许换行。
	}
	for _, option := range [][2]uintptr{{3, align}, {4, paragraph}, {5, wrapping}} {
		if c.err = misakaHRESULT("[§7.2] 设置 DirectWrite 文字格式", misakaCOMCall(format, option[0], option[1])); c.err != nil {
			misakaRelease(format)
			return nil
		}
	}
	var ellipsis *misakaCOMObject
	hr = misakaCOMCall(c.writeFactory, 20, uintptr(unsafe.Pointer(format)), uintptr(unsafe.Pointer(&ellipsis)))
	if c.err = misakaHRESULT("[§7.2] 创建 DirectWrite 省略号", hr); c.err != nil {
		misakaRelease(ellipsis)
		misakaRelease(format)
		return nil
	}
	trimming := misakaTrimming{granularity: 1} // §7.2：按字符截断。
	hr = misakaCOMCall(format, 9, uintptr(unsafe.Pointer(&trimming)), uintptr(unsafe.Pointer(ellipsis)))
	misakaRelease(ellipsis) // §7.2：文字格式已持有自己的引用。
	if c.err = misakaHRESULT("[§7.2] 设置 DirectWrite 文字截断", hr); c.err != nil {
		misakaRelease(format)
		return nil
	}
	c.formats[style] = format
	return format
}

// §7.2：使用指针字段，使 Go 参数在 ARM64 原生 ABI 桥接期间保持存活。
// 两种支持架构的指针与参数槽宽度均为八字节。
type misakaTextFormatArgs struct {
	factory    *misakaCOMObject
	family     *uint16
	collection uintptr
	weight     uintptr
	style      uintptr
	stretch    uintptr
	size       uintptr
	locale     *uint16
	output     **misakaCOMObject
}

type misakaCOMObject struct{ vtable *[58]uintptr }

func misakaCOMMethod(object *misakaCOMObject, index uintptr) uintptr {
	return object.vtable[index]
}

//go:uintptrescapes
func misakaCOMCall(object *misakaCOMObject, index uintptr, args ...uintptr) uintptr {
	parameters := append([]uintptr{uintptr(unsafe.Pointer(object))}, args...)
	result, _, _ := syscall.SyscallN(misakaCOMMethod(object, index), parameters...)
	return result
}

func misakaRelease(object *misakaCOMObject) {
	if object != nil {
		misakaCOMCall(object, 2)
	}
}

func misakaHRESULT(operation string, result uintptr) error {
	if int32(result) < 0 {
		return fmt.Errorf("%s: HRESULT 0x%08x", operation, uint32(result))
	}
	return nil
}
