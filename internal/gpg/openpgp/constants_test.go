package openpgp

import (
	"testing"
)

func TestKeyBlockSize(t *testing.T) {
	tests := []struct {
		algo byte
		want int
	}{
		{SymAlgoAES128, 16},
		{SymAlgoAES192, 16},
		{SymAlgoAES256, 16},
		{0x00, 0}, // Unknown
		{0xFF, 0}, // Unknown
	}

	for _, tt := range tests {
		got := KeyBlockSize(tt.algo)
		if got != tt.want {
			t.Errorf("KeyBlockSize(%d) = %d, want %d", tt.algo, got, tt.want)
		}
	}
}

func TestKeySize(t *testing.T) {
	tests := []struct {
		algo byte
		want int
	}{
		{SymAlgoAES128, 16},
		{SymAlgoAES192, 24},
		{SymAlgoAES256, 32},
		{0x00, 0}, // Unknown
		{0xFF, 0}, // Unknown
	}

	for _, tt := range tests {
		got := KeySize(tt.algo)
		if got != tt.want {
			t.Errorf("KeySize(%d) = %d, want %d", tt.algo, got, tt.want)
		}
	}
}
