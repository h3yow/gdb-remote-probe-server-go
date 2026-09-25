package image

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"testing"
)

func demoBytes(t *testing.T, stripped bool) []byte {
	t.Helper()
	code := []byte{0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04}
	b := NewBuilder().
		BuildID("demo").
		Entry(0x1000).
		Region(Region{Name: "flash", Addr: 0x1000, Data: code, Perm: PermRead | PermExecute}).
		Region(Region{Name: "ram", Addr: 0x2000, Data: make([]byte, 16), Perm: PermRead | PermWrite}).
		Symbol(Symbol{Name: "main", Addr: 0x1000, Size: 8}).
		Symbol(Symbol{Name: "g_counter", Addr: 0x2000, Size: 4}).
		Stripped(stripped)
	raw, err := b.Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	return raw
}

func TestLoadRoundTrip(t *testing.T) {
	im, err := Load(demoBytes(t, false))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if im.Entry != 0x1000 || len(im.Regions) != 2 || len(im.Symbols) != 2 {
		t.Fatalf("unexpected image: %+v", im)
	}
	if s, err := im.LookupSymbol("main"); err != nil || s.Addr != 0x1000 {
		t.Fatalf("symbol lookup: %+v %v", s, err)
	}
	if _, err := im.LookupSymbol("missing"); !errors.Is(err, ErrSymbolNotFound) {
		t.Fatalf("want ErrSymbolNotFound, got %v", err)
	}
	// parsed data is independent of caller buffer
	raw := demoBytes(t, false)
	im2, _ := Load(raw)
	im2.Regions[0].Data[0] = 0xFF
	im3, _ := Load(raw)
	if im3.Regions[0].Data[0] != 0 {
		t.Fatal("Load did not copy region data")
	}
}

func TestLoadIsDeterministic(t *testing.T) {
	a := demoBytes(t, false)
	im1, err := Load(a)
	if err != nil {
		t.Fatal(err)
	}
	im2, err := Load(a)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(im1.Regions[0].Data, im2.Regions[0].Data) ||
		im1.BuildID != im2.BuildID || im1.BuildTime != im2.BuildTime {
		t.Fatal("same bytes gave different views")
	}
}

func TestStrippedImageLoads(t *testing.T) {
	im, err := Load(demoBytes(t, true))
	if err != nil {
		t.Fatalf("stripped load: %v", err)
	}
	if !im.Stripped || len(im.Symbols) != 0 {
		t.Fatalf("stripped flags wrong: %+v", im)
	}
	if _, err := im.LookupSymbol("main"); !errors.Is(err, ErrSymbolNotFound) {
		t.Fatalf("stripped lookup: %v", err)
	}
}

func TestLoadErrors(t *testing.T) {
	good := demoBytes(t, false)
	badVer := mutate(good, 8, 9)
	binary.LittleEndian.PutUint32(badVer[len(badVer)-4:], crc32.ChecksumIEEE(badVer[:len(badVer)-4]))
	cases := []struct {
		name string
		raw  []byte
		want error
	}{
		{"truncated-empty", []byte{}, ErrTruncated},
		{"truncated-header", good[:30], ErrTruncated},
		{"bad-magic", mutate(good, 0, 'X'), ErrBadMagic},
		{"bad-version", badVer, ErrUnsupportedVer},
		{"corrupt-crc", mutate(good, len(good)-1, 0xFF), ErrCorrupt},
		{"corrupt-body", mutate(good, 70, 0xFF), ErrCorrupt},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(tc.raw)
			if !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
		})
	}
}

func TestBadRegions(t *testing.T) {
	base := []byte{0, 0, 0, 0}
	cases := []struct {
		name string
		r    Region
	}{
		{"no-perms", Region{Name: "x", Addr: 0x1000, Data: base, Perm: 0}},
		{"empty", Region{Name: "x", Addr: 0x1000, Data: nil, Perm: PermRead}},
		{"unaligned-exec", Region{Name: "x", Addr: 0x1001, Data: base, Perm: PermExecute}},
		{"overflow", Region{Name: "x", Addr: 0xFFFFFFFF, Data: base, Perm: PermRead}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewBuilder().Entry(0x1000).Region(tc.r).Build()
			if !errors.Is(err, ErrBadRegion) {
				t.Fatalf("want ErrBadRegion, got %v", err)
			}
		})
	}
	t.Run("overlap", func(t *testing.T) {
		_, err := NewBuilder().
			Region(Region{Name: "a", Addr: 0x1000, Data: make([]byte, 8), Perm: PermRead}).
			Region(Region{Name: "b", Addr: 0x1004, Data: make([]byte, 8), Perm: PermRead}).
			Build()
		if !errors.Is(err, ErrBadRegion) {
			t.Fatalf("want overlap ErrBadRegion, got %v", err)
		}
	})
}

func TestDuplicateSymbol(t *testing.T) {
	_, err := NewBuilder().
		Region(Region{Name: "r", Addr: 0, Data: []byte{1, 2, 3, 4}, Perm: PermRead}).
		Symbol(Symbol{Name: "a", Addr: 0}).
		Symbol(Symbol{Name: "a", Addr: 4}).
		Build()
	if !errors.Is(err, ErrBadSymbol) {
		t.Fatalf("want ErrBadSymbol, got %v", err)
	}
}

func mutate(b []byte, idx int, v byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	out[idx] = v
	return out
}
