package protocol

import (
	"bytes"
	"sync"
)

// Impair defines deterministic faults applied by one Pipe endpoint to traffic
// it writes. Frame-level counters act on complete '$'...'#cc' sequences found
// inside each write; fragmentation applies to raw writes byte-wise.
type Impair struct {
	// DropFirstFrames drops the next n complete frames entirely.
	DropFirstFrames int
	// CorruptFirstFrames flips the last checksum nibble of the next n frames.
	CorruptFirstFrames int
	// DuplicateFirstFrames delivers the next n complete frames twice.
	DuplicateFirstFrames int
	// FragmentSize > 0 splits each write into chunks of that many bytes
	// (half packets). Zero disables.
	FragmentSize int
	// Stall makes writes succeed locally but never deliver bytes until the
	// flag is cleared (used to exercise retransmission timeouts).
	Stall bool
}

type pipeMsg struct{ data []byte }

type pipeCore struct {
	mu     sync.Mutex
	cond   *sync.Cond
	queues [2][]pipeMsg // queue[i] holds bytes destined for endpoint i
	closed [2]bool
}

// Pipe is one endpoint of an in-process lossy transport.
type Pipe struct {
	core *pipeCore
	idx  int // 0 or 1

	impMu  sync.Mutex
	impair Impair
}

// NewPipe returns a connected endpoint pair.
func NewPipe() (*Pipe, *Pipe) {
	c := &pipeCore{}
	c.cond = sync.NewCond(&c.mu)
	return &Pipe{core: c, idx: 0}, &Pipe{core: c, idx: 1}
}

// SetImpair replaces the impairment rules for this endpoint.
func (p *Pipe) SetImpair(im Impair) {
	p.impMu.Lock()
	p.impair = im
	p.impMu.Unlock()
}

// Write applies impairments and enqueues data for the peer. Never blocks.
func (p *Pipe) Write(b []byte) (int, error) {
	p.impMu.Lock()
	im := p.impair
	p.impMu.Unlock()

	chunks := make([][]byte, 0)
	for _, frag := range fragment(b, im.FragmentSize) {
		chunks = append(chunks, mutate(frag, &im)...)
	}
	// persist consumed counters
	p.impMu.Lock()
	p.impair = im
	stall := im.Stall
	p.impMu.Unlock()

	p.core.mu.Lock()
	defer p.core.mu.Unlock()
	if p.core.closed[p.idx] {
		return 0, ErrClosed
	}
	if stall {
		return len(b), nil
	}
	for _, data := range chunks {
		if len(data) == 0 {
			continue
		}
		p.core.queues[p.peer()] = append(p.core.queues[p.peer()],
			pipeMsg{data: append([]byte(nil), data...)})
	}
	p.core.cond.Broadcast()
	return len(b), nil
}

// mutate applies frame-level impairments to one raw chunk.
func mutate(chunk []byte, im *Impair) [][]byte {
	if !bytes.ContainsRune(chunk, '$') {
		return [][]byte{chunk}
	}
	var out [][]byte
	buf := append([]byte(nil), chunk...)
	for {
		start := bytes.IndexByte(buf, '$')
		if start < 0 {
			out = append(out, buf)
			break
		}
		if start > 0 {
			out = append(out, buf[:start])
			buf = buf[start:]
		}
		end := bytes.IndexByte(buf, '#')
		if end < 0 || end+2 >= len(buf) {
			out = append(out, buf) // incomplete frame: pass through untouched
			break
		}
		frameEnd := end + 3
		frame := buf[:frameEnd]
		rest := buf[frameEnd:]
		switch {
		case im.DropFirstFrames > 0:
			im.DropFirstFrames--
		case im.CorruptFirstFrames > 0:
			im.CorruptFirstFrames--
			corrupted := append([]byte(nil), frame...)
			corrupted[frameEnd-1] = flipNibble(corrupted[frameEnd-1])
			out = append(out, corrupted)
		case im.DuplicateFirstFrames > 0:
			im.DuplicateFirstFrames--
			out = append(out,
				append([]byte(nil), frame...),
				append([]byte(nil), frame...))
		default:
			out = append(out, frame)
		}
		buf = rest
	}
	return out
}

func flipNibble(b byte) byte {
	if b == '0' {
		return '1'
	}
	if b >= '0' && b < '9' {
		return b + 1
	}
	return '0'
}

func fragment(b []byte, size int) [][]byte {
	if size <= 0 || len(b) <= size {
		return [][]byte{b}
	}
	var out [][]byte
	for len(b) > 0 {
		n := size
		if n > len(b) {
			n = len(b)
		}
		out = append(out, b[:n])
		b = b[n:]
	}
	return out
}

// Read blocks until bytes arrive or either endpoint closes.
func (p *Pipe) Read(b []byte) (int, error) {
	p.core.mu.Lock()
	defer p.core.mu.Unlock()
	for {
		if q := p.core.queues[p.idx]; len(q) > 0 {
			n := copy(b, q[0].data)
			if n == len(q[0].data) {
				p.core.queues[p.idx] = q[1:]
			} else {
				p.core.queues[p.idx][0].data = q[0].data[n:]
			}
			return n, nil
		}
		if p.core.closed[p.peer()] || p.core.closed[p.idx] {
			return 0, ErrClosed
		}
		p.core.cond.Wait()
	}
}

// Close shuts this endpoint down; the peer's blocked reads return ErrClosed.
func (p *Pipe) Close() error {
	p.core.mu.Lock()
	p.core.closed[p.idx] = true
	p.core.cond.Broadcast()
	p.core.mu.Unlock()
	return nil
}

func (p *Pipe) peer() int { return 1 - p.idx }
