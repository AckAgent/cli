package crypto

import (
	"strings"
	"testing"
)

func TestEmojiFromIndex_SingleEmoji(t *testing.T) {
	// Index 0: first entry
	words, emojis := EmojiFromIndex(0)
	if words == "" || emojis == "" {
		t.Error("EmojiFromIndex(0) returned empty strings")
	}
	if words != SASWords[0] {
		t.Errorf("EmojiFromIndex(0) words = %q, want %q", words, SASWords[0])
	}
	if emojis != SASEmojis[0] {
		t.Errorf("EmojiFromIndex(0) emojis = %q, want %q", emojis, SASEmojis[0])
	}

	// Index 255: last single-emoji entry
	words, emojis = EmojiFromIndex(255)
	if words == "" || emojis == "" {
		t.Error("EmojiFromIndex(255) returned empty strings")
	}
	if words != SASWords[255] {
		t.Errorf("EmojiFromIndex(255) words = %q, want %q", words, SASWords[255])
	}
	// Single emoji should not contain a space or hyphen
	if strings.Contains(words, "-") {
		t.Errorf("EmojiFromIndex(255) words should not contain hyphen: %q", words)
	}
	if strings.Contains(emojis, " ") {
		t.Errorf("EmojiFromIndex(255) emojis should not contain space: %q", emojis)
	}
}

func TestEmojiFromIndex_TwoEmojis(t *testing.T) {
	// Index 256: first two-emoji entry
	words, emojis := EmojiFromIndex(256)
	if words == "" || emojis == "" {
		t.Error("EmojiFromIndex(256) returned empty strings")
	}
	// Two-emoji format: "word1-word2" and "emoji1 emoji2"
	wordParts := strings.Split(words, "-")
	if len(wordParts) != 2 {
		t.Errorf("EmojiFromIndex(256) expected 2 word parts, got %d: %q", len(wordParts), words)
	}
	emojiParts := strings.Split(emojis, " ")
	if len(emojiParts) != 2 {
		t.Errorf("EmojiFromIndex(256) expected 2 emoji parts, got %d: %q", len(emojiParts), emojis)
	}

	// Index 256 should decompose to adj=0 -> [SASWords[0], SASWords[0]]
	expectedWords := SASWords[0] + "-" + SASWords[0]
	if words != expectedWords {
		t.Errorf("EmojiFromIndex(256) words = %q, want %q", words, expectedWords)
	}

	// Index 65791: last two-emoji entry (256 + 256*256 - 1)
	words, emojis = EmojiFromIndex(65791)
	if words == "" || emojis == "" {
		t.Error("EmojiFromIndex(65791) returned empty strings")
	}
	wordParts = strings.Split(words, "-")
	if len(wordParts) != 2 {
		t.Errorf("EmojiFromIndex(65791) expected 2 word parts, got %d: %q", len(wordParts), words)
	}
	// adj = 65791 - 256 = 65535 -> [SASWords[255], SASWords[255]]
	expectedWords = SASWords[255] + "-" + SASWords[255]
	if words != expectedWords {
		t.Errorf("EmojiFromIndex(65791) words = %q, want %q", words, expectedWords)
	}
}

func TestEmojiFromIndex_ThreeEmojis(t *testing.T) {
	// Index 65792: first three-emoji entry
	words, emojis := EmojiFromIndex(65792)
	if words == "" || emojis == "" {
		t.Error("EmojiFromIndex(65792) returned empty strings")
	}
	wordParts := strings.Split(words, "-")
	if len(wordParts) != 3 {
		t.Errorf("EmojiFromIndex(65792) expected 3 word parts, got %d: %q", len(wordParts), words)
	}
	emojiParts := strings.Split(emojis, " ")
	if len(emojiParts) != 3 {
		t.Errorf("EmojiFromIndex(65792) expected 3 emoji parts, got %d: %q", len(emojiParts), emojis)
	}

	// adj = 0 -> [SASWords[0], SASWords[0], SASWords[0]]
	expectedWords := SASWords[0] + "-" + SASWords[0] + "-" + SASWords[0]
	if words != expectedWords {
		t.Errorf("EmojiFromIndex(65792) words = %q, want %q", words, expectedWords)
	}
}

func TestEmojiFromIndex_Deterministic(t *testing.T) {
	// Same index should always return the same result
	for _, idx := range []int{0, 42, 255, 256, 1000, 65791, 65792, 100000} {
		w1, e1 := EmojiFromIndex(idx)
		w2, e2 := EmojiFromIndex(idx)
		if w1 != w2 || e1 != e2 {
			t.Errorf("EmojiFromIndex(%d) not deterministic: (%q,%q) vs (%q,%q)", idx, w1, e1, w2, e2)
		}
	}
}

func TestEmojiFromIndex_Uniqueness(t *testing.T) {
	// All indices in the single-emoji range should produce unique results
	seen := make(map[string]int)
	for i := 0; i < 256; i++ {
		words, _ := EmojiFromIndex(i)
		if prev, ok := seen[words]; ok {
			t.Errorf("EmojiFromIndex(%d) and EmojiFromIndex(%d) both produce %q", i, prev, words)
		}
		seen[words] = i
	}
}
