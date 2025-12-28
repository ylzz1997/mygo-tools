package magic

import "testing"

func TestFixSrc_CommaIndex_Get(t *testing.T) {
	in := []byte(`package p

func f(m any) {
	_ = m[0, 0]
	_ = m[1:2, 3:4]
	_ = m [ 5 , 6 ] // spaces
}
`)
	out, ok := FixSrc("x.go", in)
	if !ok {
		t.Fatalf("FixSrc ok=false")
	}
	s := string(out)
	if want := `_ = m._getitem([]int{0}, []int{0})`; !contains(s, want) {
		t.Fatalf("missing rewrite: %q\nout:\n%s", want, s)
	}
	if want := `_ = m._getitem([]int{1, 2}, []int{3, 4})`; !contains(s, want) {
		t.Fatalf("missing rewrite: %q\nout:\n%s", want, s)
	}
	if want := `_ = m._getitem([]int{5}, []int{6})`; !contains(s, want) {
		t.Fatalf("missing rewrite: %q\nout:\n%s", want, s)
	}
}

func TestFixSrc_CommaIndex_Set(t *testing.T) {
	in := []byte(`package p

func f(m any, v int) {
	m[1:2, 3] = v
}
`)
	out, ok := FixSrc("x.go", in)
	if !ok {
		t.Fatalf("FixSrc ok=false")
	}
	s := string(out)
	if want := `m._setitem(v, []int{1, 2}, []int{3})`; !contains(s, want) {
		t.Fatalf("missing rewrite: %q\nout:\n%s", want, s)
	}
}

func TestFixSrc_DoesNotTouch_GenericInstantiationCall(t *testing.T) {
	in := []byte(`package p

func f[T any](x T) {}

func g() {
	f[int](1)
}
`)
	out, ok := FixSrc("x.go", in)
	if ok {
		// It may still return ok=true if other rewrites exist, but it must not rewrite f[int](1).
		if contains(string(out), "._getitem(") || contains(string(out), "._setitem(") {
			t.Fatalf("unexpected indexing rewrite:\n%s", string(out))
		}
	}
}

func TestFixSrc_DoesNotTouch_GenericInstantiationValue(t *testing.T) {
	in := []byte(`package p

func f[T any, U any](x T, y U) int { return 0 }

func g() {
	_ = f[int, string]          // instantiation used as value
	h := f[int, string]         // assigned
	_ = h(1, "x")               // call later
}
`)
	out, ok := FixSrc("x.go", in)
	if ok {
		if contains(string(out), "._getitem(") || contains(string(out), "._setitem(") {
			t.Fatalf("unexpected indexing rewrite:\n%s", string(out))
		}
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	// tiny helper to avoid importing strings in tests
	n := len(sub)
	if n == 0 {
		return 0
	}
	for i := 0; i+n <= len(s); i++ {
		if s[i:i+n] == sub {
			return i
		}
	}
	return -1
}


