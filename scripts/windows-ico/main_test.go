package main

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"testing"
)

func TestRoundPNGAddsAntialiasedCornersWithoutChangingInterior(t *testing.T) {
	const size = 40
	source := image.NewNRGBA(image.Rect(0, 0, size, size))
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			source.SetNRGBA(x, y, color.NRGBA{R: uint8(x), G: uint8(y), B: 180, A: 255})
		}
	}
	var encoded bytes.Buffer
	if err := png.Encode(&encoded, source); err != nil {
		t.Fatal(err)
	}

	data, err := roundPNG(encoded.Bytes(), 0.125)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}

	if alpha := color.NRGBAModel.Convert(decoded.At(0, 0)).(color.NRGBA).A; alpha != 0 {
		t.Fatalf("[§7.2] 左上角应完全透明，实际 alpha=%d", alpha)
	}
	if alpha := color.NRGBAModel.Convert(decoded.At(1, 1)).(color.NRGBA).A; alpha == 0 || alpha == 255 {
		t.Fatalf("[§7.2] 圆角边缘应抗锯齿，实际 alpha=%d", alpha)
	}
	for _, point := range []image.Point{{5, 5}, {20, 20}, {39, 20}} {
		got := color.NRGBAModel.Convert(decoded.At(point.X, point.Y)).(color.NRGBA)
		want := source.NRGBAAt(point.X, point.Y)
		if got != want {
			t.Fatalf("[§7.2] 圆角不应改写品牌图内部像素 %v：got=%v want=%v", point, got, want)
		}
	}
}

func TestRoundedSquareCoverageIsSymmetric(t *testing.T) {
	const size = 40
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			got := roundedSquareCoverage(x, y, size, 5)
			mirrors := []uint8{
				roundedSquareCoverage(size-1-x, y, size, 5),
				roundedSquareCoverage(x, size-1-y, size, 5),
				roundedSquareCoverage(size-1-x, size-1-y, size, 5),
			}
			for _, mirror := range mirrors {
				if mirror != got {
					t.Fatalf("[§7.2] 圆角遮罩在 (%d,%d) 不对称：%d != %d", x, y, got, mirror)
				}
			}
		}
	}
}
