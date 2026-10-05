package target

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/h3yow/gdb-remote-probe-server-go/pkg/image"
)

// cond.go: breakpoint condition expressions.
//
// Grammar (whitespace tolerant):
//
//	expr        := cmp ( "&&" cmp )*
//	cmp         := term ( "==" | "!=" | "<" | "<=" | ">" | ">=" ) term
//	term        := "r" <dec 0..15> | "pc" | "u32[" <addr> "]" | <number>
//	number      := decimal | 0x<hex>
//
// A condition reads registers and memory of the target at hit time. It is
// parsed once at configure time; evaluation happens under the target lock.
// Evaluation errors (unmapped/unreadable memory) make the condition false.

// condKind tags how a term resolves to a u32 value.
type termKind uint8

const (
	termImm termKind = iota // constant
	termReg                 // register file
	termMem                 // u32[addr] memory word
)

// condTerm is one operand of a comparison.
type condTerm struct {
	kind termKind
	val  uint32 // termImm: literal; termReg: register number; termMem: address
}

// condOp is a comparison operator.
type condOp uint8

const (
	opEq condOp = iota
	opNe
	opLt
	opLe
	opGt
	opGe
)

// condCmp is one "term op term" comparison.
type condCmp struct {
	left, right condTerm
	op          condOp
}

// Cond is a parsed breakpoint condition: a conjunction of comparisons.
type Cond struct {
	src  string
	cmps []condCmp
}

// ParseCond compiles src into a Cond. Empty/whitespace source is invalid;
// callers that want "no condition" pass a nil *Cond.
func ParseCond(src string) (*Cond, error) {
	trimmed := strings.TrimSpace(src)
	if trimmed == "" {
		return nil, fmt.Errorf("%w: empty condition", ErrBPBadCond)
	}
	parts := strings.Split(trimmed, "&&")
	c := &Cond{src: trimmed}
	for _, p := range parts {
		cmp, err := parseCmp(strings.TrimSpace(p))
		if err != nil {
			return nil, err
		}
		c.cmps = append(c.cmps, cmp)
	}
	return c, nil
}

// String returns the original source.
func (c *Cond) String() string { return c.src }

// cmpOps lists operators longest-first so "<=" wins over "<".
var cmpOps = []struct {
	tok string
	op  condOp
}{
	{"==", opEq},
	{"!=", opNe},
	{"<=", opLe},
	{">=", opGe},
	{"<", opLt},
	{">", opGt},
}

func parseCmp(s string) (condCmp, error) {
	for _, o := range cmpOps {
		if i := strings.Index(s, o.tok); i >= 0 {
			l, err := parseTerm(strings.TrimSpace(s[:i]))
			if err != nil {
				return condCmp{}, err
			}
			r, err := parseTerm(strings.TrimSpace(s[i+len(o.tok):]))
			if err != nil {
				return condCmp{}, err
			}
			return condCmp{left: l, right: r, op: o.op}, nil
		}
	}
	return condCmp{}, fmt.Errorf("%w: %q has no comparison operator", ErrBPBadCond, s)
}

func parseTerm(s string) (condTerm, error) {
	if s == "" {
		return condTerm{}, fmt.Errorf("%w: empty operand", ErrBPBadCond)
	}
	if s == "pc" {
		return condTerm{kind: termReg, val: RegPC}, nil
	}
	if strings.HasPrefix(s, "r") && len(s) > 1 && s[1] >= '0' && s[1] <= '9' {
		n, err := strconv.ParseUint(s[1:], 10, 8)
		if err != nil || n >= NumRegs {
			return condTerm{}, fmt.Errorf("%w: bad register %q", ErrBPBadCond, s)
		}
		return condTerm{kind: termReg, val: uint32(n)}, nil
	}
	if strings.HasPrefix(s, "u32[") {
		if !strings.HasSuffix(s, "]") {
			return condTerm{}, fmt.Errorf("%w: unterminated %q", ErrBPBadCond, s)
		}
		addr, err := parseNumber(s[4 : len(s)-1])
		if err != nil {
			return condTerm{}, fmt.Errorf("%w: bad address in %q", ErrBPBadCond, s)
		}
		if addr%4 != 0 {
			return condTerm{}, fmt.Errorf("%w: u32 address %#x not 4-aligned", ErrBPBadCond, addr)
		}
		return condTerm{kind: termMem, val: addr}, nil
	}
	v, err := parseNumber(s)
	if err != nil {
		return condTerm{}, fmt.Errorf("%w: bad operand %q", ErrBPBadCond, s)
	}
	return condTerm{kind: termImm, val: v}, nil
}

func parseNumber(s string) (uint32, error) {
	base := 10
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		base = 0
	}
	v, err := strconv.ParseUint(s, base, 32)
	if err != nil {
		return 0, err
	}
	return uint32(v), nil
}

// resolveLocked evaluates a term. Caller holds t.mu.
func (tm condTerm) resolveLocked(t *Target) (uint32, error) {
	switch tm.kind {
	case termImm:
		return tm.val, nil
	case termReg:
		return t.regs[tm.val], nil
	case termMem:
		rg, err := t.findRegionLocked(tm.val, 4)
		if err != nil {
			return 0, err
		}
		if !rg.Perm.Has(image.PermRead) {
			return 0, ErrBadPerm
		}
		off := int(tm.val - rg.Addr)
		d := rg.Data
		return uint32(d[off]) | uint32(d[off+1])<<8 |
			uint32(d[off+2])<<16 | uint32(d[off+3])<<24, nil
	}
	return 0, ErrBPBadCond
}

// evalLocked evaluates the condition against the current target state.
// Caller holds t.mu. Any resolution error yields false.
func (c *Cond) evalLocked(t *Target) bool {
	for _, cmp := range c.cmps {
		l, err := cmp.left.resolveLocked(t)
		if err != nil {
			return false
		}
		r, err := cmp.right.resolveLocked(t)
		if err != nil {
			return false
		}
		var ok bool
		switch cmp.op {
		case opEq:
			ok = l == r
		case opNe:
			ok = l != r
		case opLt:
			ok = l < r
		case opLe:
			ok = l <= r
		case opGt:
			ok = l > r
		case opGe:
			ok = l >= r
		}
		if !ok {
			return false
		}
	}
	return true
}
