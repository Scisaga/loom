// Command windows-ico packs PNG images into a multi-resolution Windows icon.
package main

import (
	"encoding/binary"
	"fmt"
	"image"
	_ "image/png"
	"os"
)

type iconImage struct {
	width  int
	height int
	data   []byte
}

func main() {
	if len(os.Args) < 4 {
		fatalf("usage: windows-ico OUTPUT.ico INPUT.png INPUT.png ...")
	}
	images := make([]iconImage, 0, len(os.Args)-2)
	for _, path := range os.Args[2:] {
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
		images = append(images, iconImage{width: config.Width, height: config.Height, data: data})
	}

	file, err := os.Create(os.Args[1])
	if err != nil {
		fatalf("create %s: %v", os.Args[1], err)
	}
	defer file.Close()
	write := func(value any) {
		if err := binary.Write(file, binary.LittleEndian, value); err != nil {
			fatalf("write %s: %v", os.Args[1], err)
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
			fatalf("write %s: %v", os.Args[1], err)
		}
	}
	if err := file.Close(); err != nil {
		fatalf("close %s: %v", os.Args[1], err)
	}
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
