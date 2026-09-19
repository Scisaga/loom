// Command windows-ico packs PNG images into a multi-resolution Windows icon.
package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"image"
	"image/draw"
	"image/png"
	"math"
	"os"
)

type iconImage struct {
	width  int
	height int
	data   []byte
}

func main() {
	flags := flag.NewFlagSet("windows-ico", flag.ContinueOnError)
	cornerRadius := flags.Float64("corner-radius", 0, "rounded-corner radius as a fraction of icon width")
	flags.SetOutput(os.Stderr)
	if err := flags.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	args := flags.Args()
	if len(args) < 3 {
		fatalf("usage: windows-ico [-corner-radius FRACTION] OUTPUT.ico INPUT.png INPUT.png ...")
	}
	if *cornerRadius < 0 || *cornerRadius > 0.5 {
		fatalf("corner radius must be between 0 and 0.5")
	}
	images := make([]iconImage, 0, len(args)-1)
	for _, path := range args[1:] {
		file, err := os.Open(path)
		if err != nil {
			fatalf("open %s: %v", path, err)
		}
		config, _, err := image.DecodeConfig(file)
		_ = file.Close()
		if err != nil {
			fatalf("decode %s: %v", path, err)
		}
		if config.Width != config.Height || config.Width < 1 || config.Width > 256 {
			fatalf("%s must be a square PNG between 1 and 256 pixels", path)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			fatalf("read %s: %v", path, err)
		}
		if *cornerRadius > 0 {
			data, err = roundPNG(data, *cornerRadius)
			if err != nil {
				fatalf("round %s: %v", path, err)
			}
		}
		images = append(images, iconImage{width: config.Width, height: config.Height, data: data})
	}

	file, err := os.Create(args[0])
	if err != nil {
		fatalf("create %s: %v", args[0], err)
	}
	defer file.Close()
	write := func(value any) {
		if err := binary.Write(file, binary.LittleEndian, value); err != nil {
			fatalf("write %s: %v", args[0], err)
		}
	}
	write(uint16(0))
	write(uint16(1))
	write(uint16(len(images)))
	offset := uint32(6 + 16*len(images))
	for _, icon := range images {
		write(iconDimension(icon.width))
		write(iconDimension(icon.height))
		write(uint8(0))
		write(uint8(0))
		write(uint16(1))
		write(uint16(32))
		write(uint32(len(icon.data)))
		write(offset)
		offset += uint32(len(icon.data))
	}
	for _, icon := range images {
		if _, err := file.Write(icon.data); err != nil {
			fatalf("write %s: %v", args[0], err)
		}
	}
	if err := file.Close(); err != nil {
		fatalf("close %s: %v", args[0], err)
	}
}

func roundPNG(data []byte, radiusRatio float64) ([]byte, error) {
	source, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	bounds := source.Bounds()
	if bounds.Dx() != bounds.Dy() {
		return nil, fmt.Errorf("PNG must be square")
	}
	result := image.NewNRGBA(image.Rect(0, 0, bounds.Dx(), bounds.Dy()))
	draw.Draw(result, result.Bounds(), source, bounds.Min, draw.Src)
	radius := float64(bounds.Dx()) * radiusRatio
	if radius > 0 {
		for y := 0; y < bounds.Dy(); y++ {
			for x := 0; x < bounds.Dx(); x++ {
				coverage := roundedSquareCoverage(x, y, bounds.Dx(), radius)
				pixel := result.NRGBAAt(x, y)
				pixel.A = uint8((uint16(pixel.A)*uint16(coverage) + 127) / 255)
				result.SetNRGBA(x, y, pixel)
			}
		}
	}
	var output bytes.Buffer
	if err := png.Encode(&output, result); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func roundedSquareCoverage(pixelX, pixelY, size int, radius float64) uint8 {
	const samples = 8
	inside := 0
	for sampleY := 0; sampleY < samples; sampleY++ {
		for sampleX := 0; sampleX < samples; sampleX++ {
			x := float64(pixelX) + (float64(sampleX)+0.5)/samples
			y := float64(pixelY) + (float64(sampleY)+0.5)/samples
			nearestX := math.Max(radius, math.Min(float64(size)-radius, x))
			nearestY := math.Max(radius, math.Min(float64(size)-radius, y))
			if math.Hypot(x-nearestX, y-nearestY) <= radius {
				inside++
			}
		}
	}
	return uint8((inside*255 + samples*samples/2) / (samples * samples))
}

func iconDimension(size int) uint8 {
	if size == 256 {
		return 0
	}
	return uint8(size)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
