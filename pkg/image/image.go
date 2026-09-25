// Package image defines the local, reproducible executable image format used
// as a stand-in for real target firmware. The format is self-contained: no ELF
// parser, no external toolchain. Stripped images (no symbols) remain fully
// loadable; missing symbols, truncation and corruption produce distinct errors.
//
// Layout (all integers little-endian):
//
//	0   8  magic "RDPIMG01"
//	8   2  version (u16), currently 1
//	10  4  entry (u32)
//	14  4  flags (u32; bit 0 => stripped)
//	18  8  build time (u64 unix nanoseconds)
//	26 32  build ID (raw bytes, displayed as hex)
//	58  4  region count (u32)
//	62 ..  regions
//	.. ..  symbols (zero when stripped)
//	tail 4  CRC-32/IEEE over every preceding byte
//
// Region entry: u16 nameLen, name, u32 addr, u32 size, u8 perm, <size> data.
// Symbol entry: u16 nameLen, name, u32 addr, u32 size.
package image

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"sort"
	"time"
)

const (
	magic       = "RDPIMG01"
	version1    = 1
	headerSize  = 62
	trailerSize = 4
	buildIDSize = 32

	flagStripped = 1 << 0
)

// Sentinel errors. Load wraps these with context; callers use errors.Is.
var (
	ErrTruncated      = errors.New("image: truncated file")
	ErrBadMagic       = errors.New("image: bad magic")
	ErrUnsupportedVer = errors.New("image: unsupported version")
	ErrCorrupt        = errors.New("image: checksum mismatch")
	ErrBadRegion      = errors.New("image: invalid memory region")
	ErrBadSymbol      = errors.New("image: invalid symbol table entry")
	ErrSymbolNotFound = errors.New("image: symbol not found")
)

// Perm describes memory region access permission.
type Perm uint8

// Permission flags.
const (
	PermRead Perm = 1 << iota
	PermWrite
	PermExecute
)

// Has reports whether p contains all bits in q.
func (p Perm) Has(q Perm) bool { return p&q == q }

func (p Perm) String() string {
	b := [3]byte{'-', '-', '-'}
	if p.Has(PermRead) {
		b[0] = 'r'
	}
	if p.Has(PermWrite) {
		b[1] = 'w'
	}
	if p.Has(PermExecute) {
		b[2] = 'x'
	}
	return string(b[:])
}

// Region is a contiguous memory segment loaded at Addr.
type Region struct {
	Name string
	Addr uint32
	Data []byte
	Perm Perm
}

// Size returns the region length.
func (r Region) Size() int { return len(r.Data) }

// Symbol maps a name to an address. A stripped image simply has none.
type Symbol struct {
	Name string
	Addr uint32
	Size uint32
}

// Image is a parsed executable image. Byte slices are owned by the Image;
// callers cannot mutate the original file buffer through it.
type Image struct {
	Version   uint16
	Entry     uint32
	Regions   []Region
	Symbols   []Symbol
	Stripped  bool
	BuildID   string
	BuildTime time.Time
}

// LookupSymbol resolves a name. Returns ErrSymbolNotFound when the image is
// stripped or simply does not define the symbol.
func (im *Image) LookupSymbol(name string) (Symbol, error) {
	for i := range im.Symbols {
		if im.Symbols[i].Name == name {
			return im.Symbols[i], nil
		}
	}
	return Symbol{}, fmt.Errorf("%w: %q", ErrSymbolNotFound, name)
}

// reader is a bounds-checked cursor over raw bytes.
type reader struct {
	buf []byte
	pos int
}

func (r *reader) u8() (byte, error) {
	if r.pos+1 > len(r.buf) {
		return 0, ErrTruncated
	}
	v := r.buf[r.pos]
	r.pos++
	return v, nil
}

func (r *reader) u16() (uint16, error) {
	if r.pos+2 > len(r.buf) {
		return 0, ErrTruncated
	}
	v := binary.LittleEndian.Uint16(r.buf[r.pos:])
	r.pos += 2
	return v, nil
}

func (r *reader) u32() (uint32, error) {
	if r.pos+4 > len(r.buf) {
		return 0, ErrTruncated
	}
	v := binary.LittleEndian.Uint32(r.buf[r.pos:])
	r.pos += 4
	return v, nil
}

func (r *reader) u64() (uint64, error) {
	if r.pos+8 > len(r.buf) {
		return 0, ErrTruncated
	}
	v := binary.LittleEndian.Uint64(r.buf[r.pos:])
	r.pos += 8
	return v, nil
}

func (r *reader) bytes(n int) ([]byte, error) {
	if n < 0 || r.pos+n > len(r.buf) {
		return nil, ErrTruncated
	}
	// Copy: decouple parsed image from the caller's buffer.
	out := make([]byte, n)
	copy(out, r.buf[r.pos:r.pos+n])
	r.pos += n
	return out, nil
}

// Load parses and validates an image from raw bytes. It is a pure function:
// identical input always yields an identical, independently owned Image.
func Load(raw []byte) (*Image, error) {
	if len(raw) < headerSize+trailerSize {
		return nil, fmt.Errorf("%w: need at least %d bytes, got %d",
			ErrTruncated, headerSize+trailerSize, len(raw))
	}
	if string(raw[:len(magic)]) != magic {
		return nil, fmt.Errorf("%w: %q", ErrBadMagic, string(raw[:len(magic)]))
	}
	wantCRC := binary.LittleEndian.Uint32(raw[len(raw)-trailerSize:])
	if got := crc32.ChecksumIEEE(raw[:len(raw)-trailerSize]); got != wantCRC {
		return nil, fmt.Errorf("%w: crc=%08x want=%08x", ErrCorrupt, got, wantCRC)
	}

	r := &reader{buf: raw[:len(raw)-trailerSize]}
	r.pos = len(magic)
	ver, err := r.u16()
	if err != nil {
		return nil, err
	}
	if ver != version1 {
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedVer, ver)
	}
	im := &Image{Version: ver}
	if im.Entry, err = r.u32(); err != nil {
		return nil, err
	}
	flags, err := r.u32()
	if err != nil {
		return nil, err
	}
	im.Stripped = flags&flagStripped != 0
	bt, err := r.u64()
	if err != nil {
		return nil, err
	}
	im.BuildTime = time.Unix(0, int64(bt)).UTC()
	id, err := r.bytes(buildIDSize)
	if err != nil {
		return nil, err
	}
	im.BuildID = hex.EncodeToString(id)

	regionCount, err := r.u32()
	if err != nil {
		return nil, err
	}
	// Cheap guard against a corrupt count forcing a huge allocation.
	minEntry := 2 + 4 + 4 + 1
	if uint64(regionCount)*uint64(minEntry) > uint64(len(r.buf)-r.pos) {
		return nil, fmt.Errorf("%w: region count %d exceeds file", ErrTruncated, regionCount)
	}
	im.Regions = make([]Region, 0, regionCount)
	for i := uint32(0); i < regionCount; i++ {
		reg, err := readRegion(r)
		if err != nil {
			return nil, fmt.Errorf("region %d: %w", i, err)
		}
		im.Regions = append(im.Regions, reg)
	}
	if err := validateRegions(im.Regions); err != nil {
		return nil, err
	}

	symbolCount, err := r.u32()
	if err != nil {
		return nil, err
	}
	minSym := 2 + 4 + 4
	if uint64(symbolCount)*uint64(minSym) > uint64(len(r.buf)-r.pos) {
		return nil, fmt.Errorf("%w: symbol count %d exceeds file", ErrTruncated, symbolCount)
	}
	im.Symbols = make([]Symbol, 0, symbolCount)
	for i := uint32(0); i < symbolCount; i++ {
		sym, err := readSymbol(r)
		if err != nil {
			return nil, fmt.Errorf("symbol %d: %w", i, err)
		}
		im.Symbols = append(im.Symbols, sym)
	}
	if err := validateSymbols(im.Symbols); err != nil {
		return nil, err
	}
	if r.pos != len(r.buf) {
		return nil, fmt.Errorf("%w: %d trailing bytes", ErrCorrupt, len(r.buf)-r.pos)
	}
	return im, nil
}

func readRegion(r *reader) (Region, error) {
	var reg Region
	nl, err := r.u16()
	if err != nil {
		return reg, err
	}
	name, err := r.bytes(int(nl))
	if err != nil {
		return reg, err
	}
	reg.Name = string(name)
	if reg.Addr, err = r.u32(); err != nil {
		return reg, err
	}
	size, err := r.u32()
	if err != nil {
		return reg, err
	}
	p, err := r.u8()
	if err != nil {
		return reg, err
	}
	reg.Perm = Perm(p)
	if reg.Data, err = r.bytes(int(size)); err != nil {
		return reg, err
	}
	return reg, nil
}

func readSymbol(r *reader) (Symbol, error) {
	var sym Symbol
	nl, err := r.u16()
	if err != nil {
		return sym, err
	}
	name, err := r.bytes(int(nl))
	if err != nil {
		return sym, err
	}
	sym.Name = string(name)
	if sym.Addr, err = r.u32(); err != nil {
		return sym, err
	}
	if sym.Size, err = r.u32(); err != nil {
		return sym, err
	}
	return sym, nil
}

// validateRegions enforces non-empty permissions, executable alignment and
// non-overlapping ranges; entry is checked by the target layer.
func validateRegions(regions []Region) error {
	type iv struct {
		lo, hi uint64
		name   string
	}
	ivs := make([]iv, 0, len(regions))
	for _, rg := range regions {
		if rg.Perm == 0 {
			return fmt.Errorf("%w: %q has no permissions", ErrBadRegion, rg.Name)
		}
		if len(rg.Data) == 0 {
			return fmt.Errorf("%w: %q is empty", ErrBadRegion, rg.Name)
		}
		if rg.Perm.Has(PermExecute) && (rg.Addr%4 != 0 || len(rg.Data)%4 != 0) {
			return fmt.Errorf("%w: executable %q must be 4-byte aligned", ErrBadRegion, rg.Name)
		}
		lo := uint64(rg.Addr)
		hi := lo + uint64(len(rg.Data))
		if hi > 1<<32 {
			return fmt.Errorf("%w: %q exceeds address space", ErrBadRegion, rg.Name)
		}
		ivs = append(ivs, iv{lo, hi, rg.Name})
	}
	sorted := make([]iv, len(ivs))
	copy(sorted, ivs)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].lo < sorted[j].lo })
	for i := 1; i < len(sorted); i++ {
		if sorted[i].lo < sorted[i-1].hi {
			return fmt.Errorf("%w: %q overlaps %q", ErrBadRegion, sorted[i].name, sorted[i-1].name)
		}
	}
	return nil
}

func validateSymbols(syms []Symbol) error {
	seen := make(map[string]struct{}, len(syms))
	for _, s := range syms {
		if s.Name == "" {
			return fmt.Errorf("%w: empty symbol name", ErrBadSymbol)
		}
		if _, dup := seen[s.Name]; dup {
			return fmt.Errorf("%w: duplicate symbol %q", ErrBadSymbol, s.Name)
		}
		seen[s.Name] = struct{}{}
	}
	return nil
}

// Builder constructs valid images, primarily for tests and the demo CLI.
type Builder struct {
	entry     uint32
	regions   []Region
	symbols   []Symbol
	stripped  bool
	buildID   string
	buildTime time.Time
}

// NewBuilder starts an empty image builder.
func NewBuilder() *Builder {
	return &Builder{buildTime: time.Unix(0, 0).UTC()}
}

// Entry sets the entry point.
func (b *Builder) Entry(addr uint32) *Builder { b.entry = addr; return b }

// Region appends a memory region (data is copied).
func (b *Builder) Region(r Region) *Builder {
	cp := make([]byte, len(r.Data))
	copy(cp, r.Data)
	r.Data = cp
	b.regions = append(b.regions, r)
	return b
}

// Symbol appends a symbol.
func (b *Builder) Symbol(s Symbol) *Builder { b.symbols = append(b.symbols, s); return b }

// Stripped marks the image as stripped (symbols are omitted on Build).
func (b *Builder) Stripped(v bool) *Builder { b.stripped = v; return b }

// BuildID sets an arbitrary identifier; it is zero-padded/truncated to 32 bytes.
func (b *Builder) BuildID(id string) *Builder { b.buildID = id; return b }

// BuildTime sets the recorded build timestamp.
func (b *Builder) BuildTime(t time.Time) *Builder { b.buildTime = t.UTC(); return b }

// Build serializes and validates the image, returning its raw bytes.
func (b *Builder) Build() ([]byte, error) {
	if err := validateRegions(b.regions); err != nil {
		return nil, err
	}
	syms := b.symbols
	if b.stripped {
		syms = nil
	}
	if err := validateSymbols(syms); err != nil {
		return nil, err
	}

	out := make([]byte, 0, headerSize)
	out = append(out, magic...)
	var tmp [8]byte
	binary.LittleEndian.PutUint16(tmp[:], version1)
	out = append(out, tmp[:2]...)
	binary.LittleEndian.PutUint32(tmp[:], b.entry)
	out = append(out, tmp[:4]...)
	var flags uint32
	if b.stripped {
		flags |= flagStripped
	}
	binary.LittleEndian.PutUint32(tmp[:], flags)
	out = append(out, tmp[:4]...)
	binary.LittleEndian.PutUint64(tmp[:], uint64(b.buildTime.UnixNano()))
	out = append(out, tmp[:8]...)
	id := make([]byte, buildIDSize)
	if b.buildID != "" {
		// Use raw bytes when the caller passed exactly 32 bytes, else hash the name.
		if len(b.buildID) == buildIDSize {
			copy(id, b.buildID)
		} else {
			copy(id, []byte(fmt.Sprintf("%032x", crc32.ChecksumIEEE([]byte(b.buildID)))))
		}
	}
	out = append(out, id...)

	binary.LittleEndian.PutUint32(tmp[:], uint32(len(b.regions)))
	out = append(out, tmp[:4]...)
	for _, rg := range b.regions {
		if len(rg.Name) > 0xffff {
			return nil, fmt.Errorf("%w: region name too long", ErrBadRegion)
		}
		binary.LittleEndian.PutUint16(tmp[:], uint16(len(rg.Name)))
		out = append(out, tmp[:2]...)
		out = append(out, rg.Name...)
		binary.LittleEndian.PutUint32(tmp[:], rg.Addr)
		out = append(out, tmp[:4]...)
		binary.LittleEndian.PutUint32(tmp[:], uint32(len(rg.Data)))
		out = append(out, tmp[:4]...)
		out = append(out, byte(rg.Perm))
		out = append(out, rg.Data...)
	}

	binary.LittleEndian.PutUint32(tmp[:], uint32(len(syms)))
	out = append(out, tmp[:4]...)
	for _, s := range syms {
		if len(s.Name) > 0xffff {
			return nil, fmt.Errorf("%w: symbol name too long", ErrBadSymbol)
		}
		binary.LittleEndian.PutUint16(tmp[:], uint16(len(s.Name)))
		out = append(out, tmp[:2]...)
		out = append(out, s.Name...)
		binary.LittleEndian.PutUint32(tmp[:], s.Addr)
		out = append(out, tmp[:4]...)
		binary.LittleEndian.PutUint32(tmp[:], s.Size)
		out = append(out, tmp[:4]...)
	}

	crc := crc32.ChecksumIEEE(out)
	binary.LittleEndian.PutUint32(tmp[:], crc)
	out = append(out, tmp[:4]...)
	return out, nil
}
