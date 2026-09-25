package target

import "fmt"

// Opcodes of the virtual machine. Two instruction forms share the 4-byte
// word [opcode, b1, b2, b3]:
//
//	register form:  b1=dst, b2=src1, b3=src0
//	immediate form: b1=reg/dst, b2:b3 = uint16 LE immediate
type Opcode byte

const (
	OpNop  Opcode = 0x00
	OpHalt Opcode = 0x01
	OpMovi Opcode = 0x02 // b1=dst, imm16
	OpAdd  Opcode = 0x03 // b1=dst, b2=src1, b3=src0
	OpLd   Opcode = 0x04 // b1=dst, imm16 = address
	OpSt   Opcode = 0x05 // b1=src0, imm16 = address
	OpJmp  Opcode = 0x06 // imm16 = absolute target
	OpBz   Opcode = 0x07 // b1=src0, imm16 = absolute target
	OpJmpi Opcode = 0x08 // b1=src0, imm16 = absolute base
	OpIll  Opcode = 0x09 // illegal instruction -> fault
	OpSub  Opcode = 0x0A // b1=dst, b2=src1, b3=src0
)

// Instr constructs a 4-byte register-form instruction word.
func Instr(op Opcode, dst, src1, src0 byte) [InstSize]byte {
	return [InstSize]byte{byte(op), dst, src1, src0}
}

// ImmInstr constructs an immediate-form instruction, b2:b3 = imm LE.
func ImmInstr(op Opcode, b1 byte, imm uint16) [InstSize]byte {
	return [InstSize]byte{byte(op), b1, byte(imm), byte(imm >> 8)}
}

// Program is a label-based program built with the fluent assembler.
type Program struct {
	words  [][InstSize]byte
	labels map[string]uint32
	fixups []fixup
}

type fixup struct {
	word  int
	label string
}

// NewProgram creates an empty program.
func NewProgram() *Program {
	return &Program{labels: make(map[string]uint32)}
}

func (p *Program) emit(w [InstSize]byte) *Program {
	p.words = append(p.words, w)
	return p
}

const duplicateLabel = ^uint32(0)

// Label binds a name to the address of the next emitted instruction.
func (p *Program) Label(name string) *Program {
	if _, exists := p.labels[name]; exists {
		p.labels[name] = duplicateLabel
		return p
	}
	p.labels[name] = uint32(len(p.words)) * InstSize
	return p
}

func (p *Program) Nop() *Program                      { return p.emit(Instr(OpNop, 0, 0, 0)) }
func (p *Program) Halt() *Program                     { return p.emit(Instr(OpHalt, 0, 0, 0)) }
func (p *Program) Movi(dst byte, imm uint16) *Program { return p.emit(ImmInstr(OpMovi, dst, imm)) }
func (p *Program) Add(dst, src1, src0 byte) *Program  { return p.emit(Instr(OpAdd, dst, src1, src0)) }
func (p *Program) Sub(dst, src1, src0 byte) *Program  { return p.emit(Instr(OpSub, dst, src1, src0)) }
func (p *Program) Ld(dst byte, addr uint16) *Program  { return p.emit(ImmInstr(OpLd, dst, addr)) }
func (p *Program) St(addr uint16, src0 byte) *Program { return p.emit(ImmInstr(OpSt, src0, addr)) }
func (p *Program) Ill() *Program                      { return p.emit(Instr(OpIll, 0, 0, 0)) }
func (p *Program) Raw(w [InstSize]byte) *Program      { return p.emit(w) }

func (p *Program) Jmp(label string) *Program {
	p.fixups = append(p.fixups, fixup{word: len(p.words), label: label})
	return p.emit(ImmInstr(OpJmp, 0, 0))
}

func (p *Program) Bz(src0 byte, label string) *Program {
	p.fixups = append(p.fixups, fixup{word: len(p.words), label: label})
	return p.emit(ImmInstr(OpBz, src0, 0))
}

func (p *Program) Jmpi(baseLabel string, src0 byte) *Program {
	p.fixups = append(p.fixups, fixup{word: len(p.words), label: baseLabel})
	return p.emit(ImmInstr(OpJmpi, src0, 0))
}

// Link resolves labels and returns the assembled code and its entry.
func (p *Program) Link(codeAddr uint32) (code []byte, entry uint32, err error) {
	const op = "Program.Link"
	out := make([][InstSize]byte, len(p.words))
	copy(out, p.words)
	for name, off := range p.labels {
		if off == duplicateLabel {
			return nil, 0, newError(CodeImageCorrupt, op, "duplicate label: "+name)
		}
		if uint64(codeAddr)+uint64(off) > 0xFFFF {
			return nil, 0, newError(CodeImageCorrupt, op, fmt.Sprintf("label %q out of 16-bit range", name))
		}
	}
	for _, f := range p.fixups {
		off, ok := p.labels[f.label]
		if !ok {
			return nil, 0, newError(CodeImageCorrupt, op, "undefined label: "+f.label)
		}
		if off == duplicateLabel {
			return nil, 0, newError(CodeImageCorrupt, op, "duplicate label: "+f.label)
		}
		abs := codeAddr + off
		if abs > 0xFFFF {
			return nil, 0, newError(CodeImageCorrupt, op, fmt.Sprintf("label %q out of 16-bit range", f.label))
		}
		out[f.word][2] = byte(abs)
		out[f.word][3] = byte(abs >> 8)
	}
	flat := make([]byte, 0, len(out)*int(InstSize))
	for _, w := range out {
		flat = append(flat, w[:]...)
	}
	return flat, codeAddr, nil
}

// BuildImage assembles code and data into a validated Image. The code
// segment is R+X, the data segment R+W. Stripped images carry no symbols
// but remain fully debuggable through addresses.
func BuildImage(p *Program, codeAddr uint32, dataAddr uint32, data []byte, stripped bool) (*Image, error) {
	const op = "BuildImage"
	if p == nil {
		return nil, newError(CodeImageCorrupt, op, "nil program")
	}
	code, entry, err := p.Link(codeAddr)
	if err != nil {
		return nil, err
	}
	segs := []Segment{{Name: ".text", Addr: codeAddr, Perm: PermRead | PermExec, Data: code}}
	if len(data) > 0 {
		segs = append(segs, Segment{Name: ".data", Addr: dataAddr, Perm: PermRead | PermWrite, Data: data})
	}
	img := &Image{Entry: entry, Segments: segs, Stripped: stripped}
	if !stripped {
		img.Symbols = []Symbol{{Name: "_entry", Addr: entry, Size: uint32(len(code))}}
		for name, off := range p.labels {
			if off == duplicateLabel {
				continue
			}
			img.Symbols = append(img.Symbols, Symbol{Name: name, Addr: entry + off})
		}
	}
	if err := img.validate(op); err != nil {
		return nil, err
	}
	return img, nil
}
