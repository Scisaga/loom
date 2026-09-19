// Package clientjoin adapts user-facing join-code inputs to the private v2
// bootstrap capability. The QR is edition-neutral across Windows adapters.
package clientjoin

import (
	"bufio"
	"bytes"
	"errors"
	"image"
	_ "image/png"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"

	"loom/internal/control"
)

const (
	maxJoinInputBytes = 64 << 10
	maxQRImageBytes   = 4 << 20
	maxQRImageSide    = 2048
	maxQRImagePixels  = 4 << 20
)

// Read accepts one of the equivalent artifacts exposed by the control plane:
// a QR image path, a .loom-invite path, or the decoded loom:// URI. source may
// be empty to read one line from stdin, which keeps the one-time secret out of
// command history and process listings.
func Read(source string, stdin io.Reader) (control.BootstrapInvite, error) {
	if strings.TrimSpace(source) == "" {
		if stdin == nil {
			return control.BootstrapInvite{}, invalidJoinInput()
		}
		body, err := bufio.NewReader(io.LimitReader(stdin, maxJoinInputBytes+1)).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return control.BootstrapInvite{}, invalidJoinInput()
		}
		if len(body) == 0 || len(body) > maxJoinInputBytes {
			return control.BootstrapInvite{}, invalidJoinInput()
		}
		source = body
	}

	source = trimDroppedPath(source)
	if strings.HasPrefix(source, "loom://") {
		invite, err := control.DecodeInvite(source)
		if err != nil {
			return control.BootstrapInvite{}, invalidJoinInput()
		}
		return invite, nil
	}
	if source == "" || len(source) > maxJoinInputBytes || strings.ContainsRune(source, '\x00') {
		return control.BootstrapInvite{}, invalidJoinInput()
	}
	return readArtifact(filepath.Clean(source))
}

func readArtifact(path string) (control.BootstrapInvite, error) {
	absolute, err := filepath.Abs(path)
	if err != nil || !localArtifactPath(absolute) {
		return control.BootstrapInvite{}, invalidJoinInput()
	}
	before, err := os.Lstat(absolute)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 ||
		before.Size() <= 0 || before.Size() > maxQRImageBytes {
		return control.BootstrapInvite{}, invalidJoinInput()
	}
	file, err := os.Open(absolute)
	if err != nil {
		return control.BootstrapInvite{}, invalidJoinInput()
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) ||
		after.Size() <= 0 || after.Size() > maxQRImageBytes {
		return control.BootstrapInvite{}, invalidJoinInput()
	}
	body, err := io.ReadAll(io.LimitReader(file, maxQRImageBytes+1))
	if err != nil || len(body) == 0 || len(body) > maxQRImageBytes ||
		int64(len(body)) != after.Size() {
		clear(body)
		return control.BootstrapInvite{}, invalidJoinInput()
	}
	defer clear(body)

	// The small text artifact is an accessibility/offline fallback for the QR.
	// Trying it first avoids passing secret-bearing text through an image parser.
	if len(body) <= maxJoinInputBytes {
		if invite, parseErr := control.DecodeInvite(strings.TrimSpace(string(body))); parseErr == nil {
			return invite, nil
		}
	}
	return decodeQR(body)
}

// ReadImage decodes a QR image supplied by a native client surface, such as
// the Windows clipboard. The image stays in memory; callers do not need to
// write the one-time bearer credential to a temporary file.
func ReadImage(source image.Image) (control.BootstrapInvite, error) {
	if source == nil {
		return control.BootstrapInvite{}, invalidJoinInput()
	}
	bounds := source.Bounds()
	width, height := bounds.Dx(), bounds.Dy()
	if width <= 0 || height <= 0 || width > maxQRImageSide || height > maxQRImageSide ||
		width > maxQRImagePixels/height {
		return control.BootstrapInvite{}, invalidJoinInput()
	}
	return decodeQRImage(source)
}

func decodeQR(body []byte) (control.BootstrapInvite, error) {
	config, format, err := image.DecodeConfig(bytes.NewReader(body))
	if err != nil || format != "png" || config.Width <= 0 || config.Height <= 0 ||
		config.Width > maxQRImageSide || config.Height > maxQRImageSide ||
		config.Width > maxQRImagePixels/config.Height {
		return control.BootstrapInvite{}, invalidJoinInput()
	}
	decoded, format, err := image.Decode(bytes.NewReader(body))
	if err != nil || format != "png" {
		return control.BootstrapInvite{}, invalidJoinInput()
	}
	return decodeQRImage(decoded)
}

func decodeQRImage(decoded image.Image) (control.BootstrapInvite, error) {
	bitmap, err := gozxing.NewBinaryBitmapFromImage(decoded)
	if err != nil {
		return control.BootstrapInvite{}, invalidJoinInput()
	}
	result, err := qrcode.NewQRCodeReader().Decode(bitmap, nil)
	if err != nil || result == nil {
		return control.BootstrapInvite{}, invalidJoinInput()
	}
	invite, err := control.DecodeInvite(result.GetText())
	if err != nil {
		return control.BootstrapInvite{}, invalidJoinInput()
	}
	return invite, nil
}

func localArtifactPath(path string) bool {
	if runtime.GOOS != "windows" {
		return true
	}
	// Do not turn an explicit local import into SMB authentication or a device
	// namespace operation. The control plane emits a small local PNG.
	lower := strings.ToLower(filepath.Clean(path))
	return !strings.HasPrefix(lower, `\\`) && !strings.HasPrefix(lower, `//`) &&
		!strings.HasPrefix(lower, `\\?\`) && !strings.HasPrefix(lower, `\\.\`)
}

func trimDroppedPath(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 {
		first, last := value[0], value[len(value)-1]
		if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
			value = strings.TrimSpace(value[1 : len(value)-1])
		}
	}
	return value
}

func invalidJoinInput() error {
	// Never include the source: it may be the still-valid one-time secret.
	return errors.New("加入二维码或加入文件无效；请从中控为该 Device 重新获取")
}
