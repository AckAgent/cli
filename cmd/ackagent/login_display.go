package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/skip2/go-qrcode"
)

// displayQRCode prints an ASCII QR code to the terminal with AckAgent branding in center.
func displayQRCode(data string) {
	// Use High error correction (30% recoverable) to allow center logo overlay
	qr, err := qrcode.New(data, qrcode.High)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate QR code: %v\n", err)
		fmt.Println("Manual entry: " + data)
		return
	}

	// Logo to display in center
	logo := []string{"✓"}
	fmt.Print(renderQRWithLogo(qr.Bitmap(), logo))
}

// renderQRWithLogo renders a QR bitmap with a logo overlay in the center.
// Uses Unicode half-blocks (▀, ▄, █, space) for compact display.
// The bitmap uses true=black, false=white (QR convention).
func renderQRWithLogo(bitmap [][]bool, logo []string) string {
	if len(bitmap) == 0 {
		return ""
	}

	size := len(bitmap)

	// Calculate logo dimensions in QR modules
	// Each character = 1 module width, each line = 2 modules tall (half-block rendering)
	logoWidth := 0
	for _, line := range logo {
		lineLen := len([]rune(line))
		if lineLen > logoWidth {
			logoWidth = lineLen
		}
	}
	logoHeight := len(logo) * 2

	// Add padding around logo (2 modules each side for visibility)
	paddedWidth := logoWidth + 4
	paddedHeight := logoHeight + 4

	// Center position for logo area
	startX := (size - paddedWidth) / 2
	startY := (size - paddedHeight) / 2
	endX := startX + paddedWidth
	endY := startY + paddedHeight

	// Clamp to valid range
	if startX < 0 {
		startX = 0
	}
	if startY < 0 {
		startY = 0
	}
	if endX > size {
		endX = size
	}
	if endY > size {
		endY = size
	}

	var sb strings.Builder

	// Process two rows at a time (half-block rendering)
	for y := 0; y < size; y += 2 {
		for x := 0; x < size; x++ {
			// Check if this position is in the logo area
			inLogoArea := x >= startX && x < endX && y >= startY && y < endY

			if inLogoArea {
				// Render white space in logo area
				sb.WriteRune(' ')
			} else {
				// Get top and bottom module values
				top := bitmap[y][x]
				bottom := false
				if y+1 < size {
					bottom = bitmap[y+1][x]
				}

				// Render using half-blocks
				// true = black, false = white
				switch {
				case top && bottom:
					sb.WriteRune('█') // Both black
				case top && !bottom:
					sb.WriteRune('▀') // Top black, bottom white
				case !top && bottom:
					sb.WriteRune('▄') // Top white, bottom black
				default:
					sb.WriteRune(' ') // Both white
				}
			}
		}
		sb.WriteRune('\n')
	}

	// Now we need to overlay the logo text on the rendered output
	// The logo should appear in the center of the cleared area
	output := sb.String()
	lines := strings.Split(output, "\n")

	// Calculate where to place logo text in the output
	// Output line = QR row / 2 (since we combine 2 rows per line)
	logoStartLine := (startY+paddedHeight/2)/2 - len(logo)/2
	logoStartCol := startX + (paddedWidth-logoWidth)/2

	for i, logoLine := range logo {
		lineIdx := logoStartLine + i
		if lineIdx < 0 || lineIdx >= len(lines) {
			continue
		}

		// Convert line to runes for proper Unicode handling
		lineRunes := []rune(lines[lineIdx])
		logoRunes := []rune(logoLine)

		// Place logo characters (1 char = 1 position)
		for j, r := range logoRunes {
			col := logoStartCol + j
			if col >= 0 && col < len(lineRunes) {
				lineRunes[col] = r
			}
		}
		lines[lineIdx] = string(lineRunes)
	}

	return strings.Join(lines, "\n")
}

func printLoginSuccess(deviceCount, syncedKeys int) {
	fmt.Println()
	fmt.Println("Login successful!")
	fmt.Println()
	fmt.Printf("You are now logged in with %d device(s).\n", deviceCount)
	if syncedKeys > 0 {
		fmt.Printf("Synced %d signing key(s) from your device(s).\n", syncedKeys)
	}

	fmt.Println()
	fmt.Println("Signing requests will be sent to all devices.")
	fmt.Println()
	fmt.Println("You can now use:")
	fmt.Println("  - SSH with SecurityKeyProvider")
	fmt.Println("  - Git signing with 'ackagent gpg'")
}
