package protocol

import "errors"

// Conn is the byte transport used by Link. Implementations must support
// concurrent Read and Write.
type Conn interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	Close() error
}

// ErrInterrupted signals a Ctrl-C control byte observed during Recv.
var ErrInterrupted = errors.New("protocol: interrupted by control byte")
