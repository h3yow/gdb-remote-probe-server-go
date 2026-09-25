// Package target implements a reproducible local debug target: a small
// register machine, its executable image format and breakpoint semantics.
package target

import (
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"sort"
)

// Code is a stable, wire-safe error classification. Every failure produced
// by the target packages carries one of these codes so callers (including
// the remote protocol layer and tests) can distinguish failure classes
// without string matching.
type Code int

const (
	CodeOK Code = iota
	CodeImageTooShort
	CodeBadMagic
	CodeUnsupportedVersion
	CodeBadChecksum
	CodeImageCorrupt
	CodeSegmentOverlap
	CodeAddressOutOfRange
	CodeReadOnly
	CodeNotExecutable
	CodeMisaligned
	CodeSymbolNotFound
	CodeRegisterIndex
	CodeBreakpointLimit
	CodeTargetRunning
	CodeTargetHalted
	CodeStepBudget
	CodeSessionBusy
	CodeSessionClosed
	CodeBadChecksumFrame
	CodeMalformedPacket
	CodeTimeout
	CodeFeatureRejected
	CodeUnsupported
)

// Error is the structured error type used throughout the project. Code is
// stable and machine readable; Detail is human readable.
type Error struct {
	Code   Code
	Op     string
	Detail string
}

func (e *Error) Error() string {
	return fmt.Sprintf("target: %s: code=%d %s", e.Op, e.Code, e.Detail)
}

func newError(c Code, op, detail string) *Error {
	return &Error{Code: c, Op: op, Detail: detail}
}

// AsError extracts a *target.Error from any error.
func AsError(err error) (*Error, bool) {
	var te *Error
	if errors.As(err, &te) {
		return te, true
	}
	return nil, false
}

// CodeOf returns the stable code of err, or CodeOK for nil.
func CodeOf(err error) Code {
	if err == nil {
		return CodeOK
	}
	if te, ok := AsError(err); ok {
		return te.Code
	}
	return CodeImageCorrupt
}

// Perm describes segment access permissions.
type Perm uint8

const (
	PermRead  Perm = 1 << 0
	PermWrite Perm = 1 << 1
	PermExec  Perm = 1 << 2
)

func (p Perm) Readable() bool   { return p&PermRead != 0 }
func (p Perm) Writable() bool   { return p&PermWrite != 0 }
func (p Perm) Executable() bool { return p&PermExec != 0 }

// Segment is a contiguous, non-overlapping memory region loaded from an
// image. Addresses are byte addresses in a 32-bit address space.
type Segment struct {
	Name string `json:"name"`
	Addr uint32 `json:"addr"`
	Perm Perm   `json:"perm"`
	Data []byte `json:"data"`
}

// end returns the exclusive end address and false if the range overflows
// the 32-bit address space.
func (s *Segment) end() (uint32, bool) {
	e := uint64(s.Addr) + uint64(len(s.Data))
	if e > 0x100000000 {
		return 0, false
	}
	return uint32(e), true
}

// Contains reports whether addr falls inside the segment.
func (s *Segment) Contains(addr uint32) bool {
	end, ok := s.end()
	if !ok {
		return false
	}
	return addr >= s.Addr && addr < end
}

// Symbol is an optional named address. Stripped images contain none.
type Symbol struct {
	Name string `json:"name"`
	Addr uint32 `json:"addr"`
	Size uint32 `json:"size"`
}

// Image is a parsed debug target image. Segments never overlap and are
// sorted by address. Symbols may be empty (stripped image).
type Image struct {
	Entry    uint32    `json:"entry"`
	Stripped bool      `json:"stripped"`
	Segments []Segment `json:"segments"`
	Symbols  []Symbol  `json:"symbols"`
}

// LookupSymbol returns the named symbol. Missing symbols produce
// CodeSymbolNotFound.
func (img *Image) LookupSymbol(name string) (Symbol, error) {
	for i := range img.Symbols {
		if img.Symbols[i].Name == name {
			return img.Symbols[i], nil
		}
	}
	return Symbol{}, newError(CodeSymbolNotFound, "LookupSymbol", "symbol not found: "+name)
}

// segmentFor returns the segment containing addr, or nil if unmapped.
func (img *Image) segmentFor(addr uint32) *Segment {
	// binary search over non-overlapping, sorted segments
	idx := sort.Search(len(img.Segments), func(i int) bool {
		end, _ := img.Segments[i].end()
		return addr < end
	})
	if idx < len(img.Segments) && img.Segments[idx].Contains(addr) {
		return &img.Segments[idx]
	}
	return nil
}

const (
	imageMagic   = "RPROBE01"
	imageVersion = uint32(1)
	imageHdrLen  = len(imageMagic) + 4 + 4 // magic + version + payload length
)

type wirePayload struct {
	Entry    uint32    `json:"entry"`
	Stripped bool      `json:"stripped"`
	Segments []Segment `json:"segments"`
	Symbols  []Symbol  `json:"symbols"`
}

// validate normalises and validates the image layout. On success the
// segments are sorted by address and symbol order is unchanged.
func (img *Image) validate(op string) error {
	if img == nil {
		return newError(CodeImageCorrupt, op, "nil image")
	}
	if len(img.Segments) == 0 {
		return newError(CodeImageCorrupt, op, "image has no segments")
	}
	for i := range img.Segments {
		s := &img.Segments[i]
		if s.Perm == 0 {
			return newError(CodeImageCorrupt, op, fmt.Sprintf("segment %q has no permissions", s.Name))
		}
		if len(s.Data) == 0 {
			return newError(CodeImageCorrupt, op, fmt.Sprintf("segment %q is empty", s.Name))
		}
		if _, ok := s.end(); !ok {
			return newError(CodeImageCorrupt, op, fmt.Sprintf("segment %q overflows address space", s.Name))
		}
	}
	sort.SliceStable(img.Segments, func(i, j int) bool {
		return img.Segments[i].Addr < img.Segments[j].Addr
	})
	for i := 1; i < len(img.Segments); i++ {
		prevEnd, _ := img.Segments[i-1].end()
		cur := &img.Segments[i]
		if cur.Addr < prevEnd {
			return newError(CodeSegmentOverlap, op,
				fmt.Sprintf("segments %q and %q overlap", img.Segments[i-1].Name, cur.Name))
		}
	}
	seen := make(map[string]struct{}, len(img.Symbols))
	for i := range img.Symbols {
		sym := &img.Symbols[i]
		if sym.Name == "" {
			return newError(CodeImageCorrupt, op, "symbol with empty name")
		}
		if _, dup := seen[sym.Name]; dup {
			return newError(CodeImageCorrupt, op, "duplicate symbol: "+sym.Name)
		}
		seen[sym.Name] = struct{}{}
	}
	return nil
}

// clone returns a deep copy so callers cannot mutate target state through
// a parsed image.
func (img *Image) clone() *Image {
	cp := &Image{Entry: img.Entry, Stripped: img.Stripped}
	cp.Segments = make([]Segment, len(img.Segments))
	for i := range img.Segments {
		cp.Segments[i] = img.Segments[i]
		cp.Segments[i].Data = append([]byte(nil), img.Segments[i].Data...)
	}
	cp.Symbols = append([]Symbol(nil), img.Symbols...)
	return cp
}

// WriteImage serialises an image to the deterministic on-disk format and
// validates its layout first.
//
// Layout:
//
//	offset 0:  8 bytes magic "RPROBE01"
//	offset 8:  uint32 LE format version
//	offset 12: uint32 LE payload length
//	offset 16: JSON payload (segments embedded as base64 data)
//	tail:      uint32 LE CRC32-IEEE of the JSON payload
func WriteImage(path string, img *Image) error {
	const op = "WriteImage"
	if err := img.validate(op); err != nil {
		return err
	}
	payload, err := json.Marshal(&wirePayload{
		Entry:    img.Entry,
		Stripped: img.Stripped,
		Segments: img.Segments,
		Symbols:  img.Symbols,
	})
	if err != nil {
		return newError(CodeImageCorrupt, op, err.Error())
	}
	buf := make([]byte, 0, imageHdrLen+len(payload)+4)
	buf = append(buf, imageMagic...)
	buf = appendU32(buf, imageVersion)
	buf = appendU32(buf, uint32(len(payload)))
	buf = append(buf, payload...)
	buf = appendU32(buf, crc32.ChecksumIEEE(payload))
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		return newError(CodeImageCorrupt, op, err.Error())
	}
	return nil
}

// ReadImage parses an image file, verifying framing, checksum and layout.
// Distinct error codes identify truncation, bad magic, unsupported
// version, checksum failure and structural corruption.
func ReadImage(path string) (*Image, error) {
	const op = "ReadImage"
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, newError(CodeImageCorrupt, op, err.Error())
	}
	if len(raw) < imageHdrLen {
		return nil, newError(CodeImageTooShort, op,
			fmt.Sprintf("file is %d bytes, need at least %d", len(raw), imageHdrLen))
	}
	if string(raw[:len(imageMagic)]) != imageMagic {
		return nil, newError(CodeBadMagic, op, "bad image magic")
	}
	version := readU32(raw[8:])
	if version != imageVersion {
		return nil, newError(CodeUnsupportedVersion, op,
			fmt.Sprintf("unsupported image version %d", version))
	}
	plen := readU32(raw[12:])
	if uint64(imageHdrLen)+uint64(plen)+4 != uint64(len(raw)) {
		return nil, newError(CodeImageCorrupt, op,
			fmt.Sprintf("declared payload length %d does not match file size %d", plen, len(raw)))
	}
	payStart := imageHdrLen
	payEnd := payStart + int(plen)
	payload := raw[payStart:payEnd]
	wantSum := readU32(raw[payEnd:])
	if crc32.ChecksumIEEE(payload) != wantSum {
		return nil, newError(CodeBadChecksum, op, "payload checksum mismatch")
	}
	var wp wirePayload
	if err := json.Unmarshal(payload, &wp); err != nil {
		return nil, newError(CodeImageCorrupt, op, "invalid payload: "+err.Error())
	}
	img := &Image{
		Entry:    wp.Entry,
		Stripped: wp.Stripped,
		Segments: wp.Segments,
		Symbols:  wp.Symbols,
	}
	if err := img.validate(op); err != nil {
		return nil, err
	}
	return img, nil
}

func appendU32(b []byte, v uint32) []byte {
	return append(b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

func readU32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}
