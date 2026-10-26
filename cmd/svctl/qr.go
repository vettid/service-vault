package main

import (
	"strings"

	"rsc.io/qr"
)

// qrQuiet is the quiet zone around the code, in modules.
const qrQuiet = 2

// renderQR draws text as a QR code (error correction M) with half-block
// characters, two module rows per line. By default dark modules are
// spaces and light ones blocks, for a terminal with a dark background;
// invert is for a light one.
func renderQR(text string, invert bool) (string, error) {
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		return "", err
	}
	// lit: drawn in the terminal's foreground colour. Outside the code
	// (the quiet zone) Black is false: light.
	lit := func(x, y int) bool { return code.Black(x, y) == invert }
	var b strings.Builder
	lo, hi := -qrQuiet, code.Size+qrQuiet
	for y := lo; y < hi; y += 2 {
		for x := lo; x < hi; x++ {
			top, bottom := lit(x, y), y+1 < hi && lit(x, y+1)
			switch {
			case top && bottom:
				b.WriteRune('█')
			case top:
				b.WriteRune('▀')
			case bottom:
				b.WriteRune('▄')
			default:
				b.WriteByte(' ')
			}
		}
		b.WriteByte('\n')
	}
	return b.String(), nil
}
