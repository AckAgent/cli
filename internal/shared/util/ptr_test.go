package util

import "testing"

func TestPtr(t *testing.T) {
	tests := []struct {
		name string
	}{
		{"int"},
		{"string"},
		{"bool"},
		{"struct"},
	}

	t.Run("int", func(t *testing.T) {
		v := 42
		p := Ptr(v)
		if *p != v {
			t.Errorf("Ptr(%d) = %d, want %d", v, *p, v)
		}
		// Modifying original shouldn't affect pointer
		v = 99
		if *p == v {
			t.Error("Ptr should return pointer to copy, not original")
		}
	})

	t.Run("string", func(t *testing.T) {
		v := "hello"
		p := Ptr(v)
		if *p != v {
			t.Errorf("Ptr(%q) = %q, want %q", v, *p, v)
		}
	})

	t.Run("bool", func(t *testing.T) {
		p := Ptr(true)
		if !*p {
			t.Error("Ptr(true) should be true")
		}
		p = Ptr(false)
		if *p {
			t.Error("Ptr(false) should be false")
		}
	})

	t.Run("struct", func(t *testing.T) {
		type S struct{ X int }
		v := S{X: 10}
		p := Ptr(v)
		if p.X != 10 {
			t.Errorf("Ptr(S{X: 10}).X = %d, want 10", p.X)
		}
	})

	t.Run("zero values", func(t *testing.T) {
		p := Ptr(0)
		if *p != 0 {
			t.Errorf("Ptr(0) = %d, want 0", *p)
		}
		sp := Ptr("")
		if *sp != "" {
			t.Errorf("Ptr(\"\") = %q, want \"\"", *sp)
		}
	})

	_ = tests // suppress unused
}
