package crypto

import "strings"

// EmojiFromIndex converts a sequential emoji index to word and emoji strings.
// The encoding scheme uses base-256 with SAS dictionary entries as digits:
//   - Index 0-255: 1 emoji (256 values)
//   - Index 256-65791: 2 emojis (256² = 65,536 values)
//   - Index 65792+: 3 emojis (256³ = 16,777,216 values)
//
// This provides unique, human-friendly identifiers for organizations.
func EmojiFromIndex(index int) (words string, emojis string) {
	if index < 256 {
		return SASWords[index], SASEmojis[index]
	}
	if index < 256+256*256 {
		adj := index - 256
		w := []string{SASWords[adj/256], SASWords[adj%256]}
		e := []string{SASEmojis[adj/256], SASEmojis[adj%256]}
		return strings.Join(w, "-"), strings.Join(e, " ")
	}
	adj := index - 256 - 256*256
	w := []string{SASWords[adj/(256*256)], SASWords[(adj/256)%256], SASWords[adj%256]}
	e := []string{SASEmojis[adj/(256*256)], SASEmojis[(adj/256)%256], SASEmojis[adj%256]}
	return strings.Join(w, "-"), strings.Join(e, " ")
}
