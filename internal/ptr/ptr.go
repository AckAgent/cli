package ptr

// DerefString safely dereferences a string pointer, returning empty string if nil.
func DerefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
