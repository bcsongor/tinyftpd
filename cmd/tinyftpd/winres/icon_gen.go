//go:build ignore

// icon_gen writes the application icon to icon.ico: 8-bit paletted PNGs at
// 16, 32, 48 and 256 pixels. The art lives in internal/pixelart; the larger
// sizes are nearest-neighbour scales of the hand-drawn 16 and 32, so pixels
// stay crisp.
//
//	go run icon_gen.go [preview.png]
package main

import (
	"bytes"
	"encoding/binary"
	"image"
	"log"
	"os"

	"tinyftpd/internal/pixelart"
)

func main() {
	small, large := pixelart.Parse(pixelart.App16), pixelart.Parse(pixelart.App32)
	images := []*image.Paletted{small, large, pixelart.Scale(small, 3), pixelart.Scale(large, 8)}

	var ico bytes.Buffer
	binary.Write(&ico, binary.LittleEndian, [3]uint16{0, 1, uint16(len(images))})
	offset := 6 + 16*len(images)
	var data []byte
	for _, img := range images {
		b := pixelart.PNG(img)
		size := uint8(img.Bounds().Dx()) // 256 wraps to 0, as ICO expects
		binary.Write(&ico, binary.LittleEndian, struct {
			W, H, Colors, Reserved uint8
			Planes, Bits           uint16
			Size, Offset           uint32
		}{size, size, 0, 0, 1, 8, uint32(len(b)), uint32(offset + len(data))})
		data = append(data, b...)
	}
	ico.Write(data)
	if err := os.WriteFile("icon.ico", ico.Bytes(), 0o644); err != nil {
		log.Fatal(err)
	}

	// An optional preview of every icon at 8x, for eyeballing.
	if len(os.Args) > 1 {
		big := pixelart.Scale(large, 8)
		preview := image.NewPaletted(image.Rect(0, 0, 256+32+128, 256+32+128), big.Palette)
		paste(preview, big, 0, 0)
		paste(preview, pixelart.Scale(small, 8), 256+32, 0)
		x := 0
		for _, name := range []string{"up", "folder", "file", "text", "image", "archive", "audio", "video"} {
			paste(preview, pixelart.Scale(pixelart.Parse(pixelart.Icons[name]), 3), x, 256+32+40)
			x += 52
		}
		if err := os.WriteFile(os.Args[1], pixelart.PNG(preview), 0o644); err != nil {
			log.Fatal(err)
		}
	}
}

func paste(dst, src *image.Paletted, ox, oy int) {
	for y := range src.Bounds().Dy() {
		for x := range src.Bounds().Dx() {
			dst.SetColorIndex(ox+x, oy+y, src.ColorIndexAt(x, y))
		}
	}
}
