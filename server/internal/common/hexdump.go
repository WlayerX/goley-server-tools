package common

import (
	"fmt"
	"strings"
)

// HexDump returns a canonical hex+ASCII dump of data, limited to maxBytes.
func HexDump(data []byte, maxBytes int) string {
	if len(data) > maxBytes {
		data = data[:maxBytes]
	}
	var sb strings.Builder
	for i := 0; i < len(data); i += 16 {
		end := i + 16
		if end > len(data) {
			end = len(data)
		}
		line := data[i:end]

		// offset
		sb.WriteString(fmt.Sprintf("  %04x  ", i))

		// hex bytes
		for j := 0; j < 16; j++ {
			if j < len(line) {
				sb.WriteString(fmt.Sprintf("%02x ", line[j]))
			} else {
				sb.WriteString("   ")
			}
			if j == 7 {
				sb.WriteByte(' ')
			}
		}

		// ASCII
		sb.WriteString(" |")
		for _, b := range line {
			if b >= 32 && b < 127 {
				sb.WriteByte(b)
			} else {
				sb.WriteByte('.')
			}
		}
		sb.WriteString("|\n")
	}
	return sb.String()
}
