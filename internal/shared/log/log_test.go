package log

import (
	"bytes"
	"strings"
	"testing"
)

func TestSetLevelFromString(t *testing.T) {
	tests := []struct {
		input    string
		expected Level
	}{
		{"debug", LevelDebug},
		{"DEBUG", LevelDebug},
		{"info", LevelInfo},
		{"INFO", LevelInfo},
		{"warn", LevelWarn},
		{"WARN", LevelWarn},
		{"warning", LevelWarn},
		{"error", LevelError},
		{"ERROR", LevelError},
		{"invalid", LevelInfo}, // defaults to info
		{"", LevelInfo},        // defaults to info
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			SetLevelFromString(tt.input)
			if got := GetLevel(); got != tt.expected {
				t.Errorf("SetLevelFromString(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestLogLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	SetOutput(&buf)
	defer SetOutput(nil)

	// Set to warn level
	SetLevel(LevelWarn)

	// Debug and Info should not appear
	Debug("debug message")
	Info("info message")
	if buf.Len() > 0 {
		t.Errorf("Debug/Info logged when level is Warn: %s", buf.String())
	}

	// Warn and Error should appear
	Warn("warn message")
	if !strings.Contains(buf.String(), "warn message") {
		t.Error("Warn message not logged")
	}

	buf.Reset()
	Error("error message")
	if !strings.Contains(buf.String(), "error message") {
		t.Error("Error message not logged")
	}
}

func TestLogFormat(t *testing.T) {
	var buf bytes.Buffer
	SetOutput(&buf)
	defer SetOutput(nil)
	SetLevel(LevelDebug)

	// Test package-level logging
	buf.Reset()
	Info("test message")
	output := buf.String()
	if !strings.Contains(output, "[INFO]") {
		t.Errorf("Missing [INFO] in output: %s", output)
	}
	if !strings.Contains(output, "test message") {
		t.Errorf("Missing message in output: %s", output)
	}

	// Test component logger
	buf.Reset()
	logger := New("http")
	logger.Debug("request sent")
	output = buf.String()
	if !strings.Contains(output, "[DEBUG]") {
		t.Errorf("Missing [DEBUG] in output: %s", output)
	}
	if !strings.Contains(output, "[http]") {
		t.Errorf("Missing [http] component in output: %s", output)
	}
	if !strings.Contains(output, "request sent") {
		t.Errorf("Missing message in output: %s", output)
	}
}

func TestLoggerComponent(t *testing.T) {
	var buf bytes.Buffer
	SetOutput(&buf)
	defer SetOutput(nil)
	SetLevel(LevelDebug)

	logger := New("crypto")
	logger.Debug("encrypting data=%d bytes", 128)

	output := buf.String()
	if !strings.Contains(output, "[crypto]") {
		t.Errorf("Missing component in output: %s", output)
	}
	if !strings.Contains(output, "encrypting data=128 bytes") {
		t.Errorf("Format args not applied: %s", output)
	}
}

func TestIsDebug(t *testing.T) {
	SetLevel(LevelDebug)
	if !IsDebug() {
		t.Error("IsDebug() should return true when level is debug")
	}

	SetLevel(LevelInfo)
	if IsDebug() {
		t.Error("IsDebug() should return false when level is info")
	}
}
