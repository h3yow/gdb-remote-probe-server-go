package target

import (
	"errors"
	"testing"
)

func TestParseCondValid(t *testing.T) {
	cases := []string{
		"r1 == 5",
		"r1==5 && r2 > 3",
		"pc != 0x1000",
		"u32[0x2000] == 0x2a",
		"u32[8192] <= r3",
		"r4 >= 10 && r5 < 0xff && r6 != 0",
	}
	for _, src := range cases {
		c, err := ParseCond(src)
		if err != nil {
			t.Fatalf("ParseCond(%q): %v", src, err)
		}
		if c.String() != src {
			t.Fatalf("String()=%q want %q", c.String(), src)
		}
		t.Logf("parse ok: %q", src)
	}
}

func TestParseCondInvalid(t *testing.T) {
	cases := []string{
		"",             // empty
		"   ",          // whitespace only
		"r1",           // no operator
		"r1 = 5",       // single = is not an operator
		"r16 == 1",     // register out of range
		"r1 == ",       // missing operand
		"== 5",         // missing left operand
		"u32[2001] == 1", // unaligned memory address (hex 0x2001? no: decimal 2001)
		"u32[0x2002] == 1", // unaligned memory address
		"u32[0x2000 == 1",  // unterminated
		"r1 == zzz",        // bad operand
		"r1 == 1 && ",      // trailing conjunction
	}
	for _, src := range cases {
		_, err := ParseCond(src)
		if !errors.Is(err, ErrBPBadCond) {
			t.Fatalf("ParseCond(%q): want ErrBPBadCond, got %v", src, err)
		}
		t.Logf("parse rejected as expected: %q -> %v", src, err)
	}
}

func TestCondEvalRegistersAndMemory(t *testing.T) {
	// r1 = 7, then halt; also seed ram[0x2000] = 42 before running.
	code := []uint32{
		Encode(OpMOVI, 1, 0, 7),
		Encode(OpHALT, 0, 0, 0),
	}
	tg := newTarget(t, code)
	if err := tg.WriteMem(ramAddr, []byte{42, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	if _, err := tg.Continue(); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		src  string
		want bool
	}{
		{"r1 == 7", true},
		{"r1 == 8", false},
		{"r1 != 7", false},
		{"r1 > 6 && r1 < 8", true},
		{"r1 > 6 && r1 < 7", false},
		{"u32[0x2000] == 42", true},
		{"u32[0x2000] == 0x2a", true},
		{"u32[0x2000] != 42", false},
		{"r1 == 7 && u32[0x2000] == 42", true},
		{"pc == 0x1004", true}, // HALT stops at its own pc
		{"u32[0x9000] == 1", false}, // unmapped memory -> false, no panic
	}
	for _, tc := range cases {
		c, err := ParseCond(tc.src)
		if err != nil {
			t.Fatalf("parse %q: %v", tc.src, err)
		}
		tg.mu.Lock()
		got := c.evalLocked(tg)
		tg.mu.Unlock()
		if got != tc.want {
			t.Fatalf("eval %q = %v want %v", tc.src, got, tc.want)
		}
		t.Logf("eval %q = %v (want %v)", tc.src, got, tc.want)
	}
}
