package windowsv2

import (
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

	"loom/internal/clientv2"
	"loom/internal/wire"
)

const (
	maximumWindowsCarrierBytes = 1 << 20
	maximumWindowsQRBytes      = 4 << 20
	maximumWindowsQRSide       = 2048
)

type EnrollmentCarrier struct {
	Invite    *wire.InviteBootstrapDescriptorV2
	Resume    *wire.EnrollmentResumeDescriptorV1
	Migration *wire.RuntimeDeviceMigrationPackageV1
}

func (carrier EnrollmentCarrier) ValidateShape() error {
	count := 0
	if carrier.Invite != nil {
		count++
	}
	if carrier.Resume != nil {
		count++
	}
	if carrier.Migration != nil {
		count++
	}
	if count != 1 {
		return invalidCarrier()
	}
	return nil
}

// DecodeEnrollmentCarrierText 接受 compact v2 QR URI 或 exact canonical
// `.loom-invite` / `.loom-resume`。它只解 carrier，不把自报字段当作 authority。
func DecodeEnrollmentCarrierText(raw string) (EnrollmentCarrier, error) {
	if strings.HasPrefix(raw, clientv2.InviteURIPrefix) {
		descriptor, err := clientv2.DecodeInviteURI(raw)
		if err != nil {
			return EnrollmentCarrier{}, invalidCarrier()
		}
		return EnrollmentCarrier{Invite: &descriptor}, nil
	}
	body := []byte(raw)
	if len(body) == 0 || len(body) > maximumWindowsCarrierBytes {
		return EnrollmentCarrier{}, invalidCarrier()
	}
	if descriptor, err := decodeWindowsInviteDescriptor(body); err == nil {
		return EnrollmentCarrier{Invite: &descriptor}, nil
	}
	if descriptor, err := decodeWindowsResumeDescriptor(body); err == nil {
		return EnrollmentCarrier{Resume: &descriptor}, nil
	}
	var migration wire.RuntimeDeviceMigrationPackageV1
	canonical, err := wire.DecodeStrict(body, maximumWindowsCarrierBytes, &migration)
	if err == nil && bytes.Equal(canonical, body) && migration.Schema == 1 && migration.Migration.Schema == 1 {
		return EnrollmentCarrier{Migration: &migration}, nil
	}
	return EnrollmentCarrier{}, invalidCarrier()
}

func ReadEnrollmentCarrier(source string) (EnrollmentCarrier, error) {
	source = trimWindowsDroppedPath(source)
	if strings.HasPrefix(source, clientv2.InviteURIPrefix) || strings.HasPrefix(source, "{") {
		return DecodeEnrollmentCarrierText(source)
	}
	if source == "" || len(source) > maximumWindowsQRBytes || strings.ContainsRune(source, 0) {
		return EnrollmentCarrier{}, invalidCarrier()
	}
	path, err := filepath.Abs(filepath.Clean(source))
	if err != nil || !localWindowsCarrierPath(path) {
		return EnrollmentCarrier{}, invalidCarrier()
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 ||
		before.Size() < 1 || before.Size() > maximumWindowsQRBytes {
		return EnrollmentCarrier{}, invalidCarrier()
	}
	file, err := os.Open(path)
	if err != nil {
		return EnrollmentCarrier{}, invalidCarrier()
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) ||
		after.Size() < 1 || after.Size() > maximumWindowsQRBytes {
		return EnrollmentCarrier{}, invalidCarrier()
	}
	body, err := io.ReadAll(io.LimitReader(file, maximumWindowsQRBytes+1))
	if err != nil || int64(len(body)) != after.Size() {
		clear(body)
		return EnrollmentCarrier{}, invalidCarrier()
	}
	defer clear(body)
	if len(body) <= maximumWindowsCarrierBytes {
		if carrier, decodeErr := DecodeEnrollmentCarrierText(string(body)); decodeErr == nil {
			return carrier, nil
		}
	}
	decoded, err := decodeWindowsQR(bytes.NewReader(body))
	if err != nil {
		return EnrollmentCarrier{}, invalidCarrier()
	}
	return DecodeEnrollmentCarrierText(decoded)
}

func ReadEnrollmentCarrierImage(source image.Image) (EnrollmentCarrier, error) {
	if source == nil {
		return EnrollmentCarrier{}, invalidCarrier()
	}
	bounds := source.Bounds()
	width, height := bounds.Dx(), bounds.Dy()
	if width < 1 || height < 1 || width > maximumWindowsQRSide || height > maximumWindowsQRSide ||
		width > maximumWindowsQRSide*maximumWindowsQRSide/height {
		return EnrollmentCarrier{}, invalidCarrier()
	}
	text, err := decodeWindowsQRImage(source)
	if err != nil {
		return EnrollmentCarrier{}, invalidCarrier()
	}
	return DecodeEnrollmentCarrierText(text)
}

func decodeWindowsInviteDescriptor(raw []byte) (wire.InviteBootstrapDescriptorV2, error) {
	var descriptor wire.InviteBootstrapDescriptorV2
	canonical, err := wire.DecodeStrict(raw, maximumWindowsCarrierBytes, &descriptor)
	if err != nil || !bytes.Equal(canonical, raw) || descriptor.Schema != 2 {
		return wire.InviteBootstrapDescriptorV2{}, invalidCarrier()
	}
	return descriptor, nil
}

func decodeWindowsResumeDescriptor(raw []byte) (wire.EnrollmentResumeDescriptorV1, error) {
	var descriptor wire.EnrollmentResumeDescriptorV1
	canonical, err := wire.DecodeStrict(raw, maximumWindowsCarrierBytes, &descriptor)
	if err != nil || !bytes.Equal(canonical, raw) || descriptor.Schema != 1 {
		return wire.EnrollmentResumeDescriptorV1{}, invalidCarrier()
	}
	return descriptor, nil
}

func decodeWindowsQR(source io.Reader) (string, error) {
	config, format, err := image.DecodeConfig(source)
	if err != nil || format != "png" || config.Width < 1 || config.Height < 1 ||
		config.Width > maximumWindowsQRSide || config.Height > maximumWindowsQRSide ||
		config.Width > maximumWindowsQRSide*maximumWindowsQRSide/config.Height {
		return "", invalidCarrier()
	}
	// DecodeConfig 消耗 reader；调用方使用 bytes.Reader 时重建一次。
	seeker, ok := source.(io.Seeker)
	if !ok {
		return "", invalidCarrier()
	}
	if _, err := seeker.Seek(0, io.SeekStart); err != nil {
		return "", invalidCarrier()
	}
	decoded, format, err := image.Decode(source)
	if err != nil || format != "png" {
		return "", invalidCarrier()
	}
	return decodeWindowsQRImage(decoded)
}

func decodeWindowsQRImage(source image.Image) (string, error) {
	bitmap, err := gozxing.NewBinaryBitmapFromImage(source)
	if err != nil {
		return "", err
	}
	result, err := qrcode.NewQRCodeReader().Decode(bitmap, nil)
	if err != nil || result == nil {
		return "", invalidCarrier()
	}
	return result.GetText(), nil
}

func localWindowsCarrierPath(path string) bool {
	if runtime.GOOS != "windows" {
		return true
	}
	lower := strings.ToLower(filepath.Clean(path))
	return !strings.HasPrefix(lower, `\\`) && !strings.HasPrefix(lower, `//`) &&
		!strings.HasPrefix(lower, `\\?\`) && !strings.HasPrefix(lower, `\\.\`)
}

func trimWindowsDroppedPath(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 {
		first, last := value[0], value[len(value)-1]
		if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
			value = strings.TrimSpace(value[1 : len(value)-1])
		}
	}
	return value
}

func invalidCarrier() error {
	return errors.New("Windows v2 加入码、续传文件或设备迁移文件无效")
}
