package target

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/h3yow/gdb-remote-probe-server-go/pkg/image"
)

// Breakpoint conditions are small comparison expressions evaluated against
// the live register file and memory each time the breakpoint is reached.
//
// Grammar (single comparison, no boolean combinators):
//
//	<operand> <cmp> <operand>
//	operand := "r"<0-15> | "pc" | "[" <addr> "]" | <uint literal>
//	cmp     := "==" | "!=" | "<" | "<=" | ">" | ">="
//
// Literals accept decimal or 0x-prefixed hex. "[addr]" reads the u32 at a
// 4-aligned address; an unreadable address makes the condition false (never
// a target fault). An empty condition string means "always true".

// condOp is the comparison operator of a compiled condition.
type condOp uint8

const (
	condEQ condOp = iota
	condNE
	condLT
	condLE
	condGT
	condGE
)

// condOperand resolves to a u32 at evaluation time.
type condOperand struct {
	kind uint8 // operandReg | operandMem | operandConst
	n    uint32
}

const (
	operandReg uint8 = iota
	operandMem
	operandConst
)

// condition is a compiled breakpoint condition. The zero value (with text
// "") is the always-true condition.
type condition struct {
	text string
	op   condOp
	lhs  condOperand
	rhs  condOperand
}

// cmpTokens in longest-first order so "<=" wins over "<".
var cmpTokens = []struct {
	tok string
	op  condOp
}{
	{"==", condEQ},
	{"!=", condNE},
	{"<=", condLE},
	{">=", condGE},
	{"<", condLT},
	{">", condGT},
}

// parseCondition compiles expr; an empty string yields the always-true
// condition. Syntax errors are wrapped in ErrBPBadCond.
func parseCondition(expr string) (condition, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return condition{}, nil
	}
	bad := func(format string, args ...any) (condition, error) {
		return condition{}, fmt.Errorf("%w: %s", ErrBPBadCond, fmt.Sprintf(format, args...))
	}
	var (
		op   condOp
		l, r string
	)
	found := false
	for _, ct := range cmpTokens {
		if i := strings.Index(expr, ct.tok); i >= 0 {
			op = ct.op
			l, r = strings.TrimSpace(expr[:i]), strings.TrimSpace(expr[i+len(ct.tok):])
			found = true
			break
		}
	}
	if !found {
		return bad("missing comparison operator in %q", expr)
	}
	lhs, err := parseOperand(l)
	if err != nil {
		return bad("left operand: %v", err)
	}
	rhs, err := parseOperand(r)
	if err != nil {
		return bad("right operand: %v", err)
	}
	return condition{text: expr, op: op, lhs: lhs, rhs: rhs}, nil
}

// parseOperand parses one operand token.
func parseOperand(s string) (condOperand, error) {
	if s == "" {
		return condOperand{}, fmt.Errorf("empty operand")
	}
	if s == "pc" {
		return condOperand{kind: operandReg, n: RegPC}, nil
	}
	if s[0] == 'r' && len(s) > 1 {
		n, err := strconv.ParseUint(s[1:], 10, 8)
		if err != nil || n >= NumRegs {
			return condOperand{}, fmt.Errorf("bad register %q", s)
		}
		return condOperand{kind: operandReg, n: uint32(n)}, nil
	}
	if s[0] == '[' {
		if !strings.HasSuffix(s, "]") {
			return condOperand{}, fmt.Errorf("unterminated memory operand %q", s)
		}
		a, err := parseUint(s[1 : len(s)-1])
		if err != nil {
			return condOperand{}, fmt.Errorf("bad address in %q", s)
		}
		if a%4 != 0 {
			return condOperand{}, fmt.Errorf("memory operand %#x not 4-aligned", a)
		}
		return condOperand{kind: operandMem, n: uint32(a)}, nil
	}
	v, err := parseUint(s)
	if err != nil {
		return condOperand{}, fmt.Errorf("bad literal %q", s)
	}
	return condOperand{kind: operandConst, n: uint32(v)}, nil
}

// parseUint accepts decimal or 0x-hex.
func parseUint(s string) (uint64, error) {
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		return strconv.ParseUint(s[2:], 16, 32)
	}
	return strconv.ParseUint(s, 10, 32)
}

// evalLocked evaluates the condition against the target's current registers
// and memory. Caller holds t.mu. Unreadable memory operands yield false.
func (c condition) evalLocked(t *Target) bool {
	if c.text == "" {
		return true
	}
	l, ok := c.lhs.resolveLocked(t)
	if !ok {
		return false
	}
	r, ok := c.rhs.resolveLocked(t)
	if !ok {
		return false
	}
	switch c.op {
	case condEQ:
		return l == r
	case condNE:
		return l != r
	case condLT:
		return l < r
	case condLE:
		return l <= r
	case condGT:
		return l > r
	case condGE:
		return l >= r
	}
	return false
}

// resolveLocked reads one operand. Caller holds t.mu.
func (o condOperand) resolveLocked(t *Target) (uint32, bool) {
	switch o.kind {
	case operandReg:
		return t.regs[o.n], true
	case operandMem:
		rg, err := t.findRegionLocked(o.n, 4)
		if err != nil || !rg.Perm.Has(image.PermRead) {
			return 0, false
		}
		off := int(o.n - rg.Addr)
		v := uint32(rg.Data[off]) | uint32(rg.Data[off+1])<<8 |
			uint32(rg.Data[off+2])<<16 | uint32(rg.Data[off+3])<<24
		return v, true
	default:
		return o.n, true
	}
}
