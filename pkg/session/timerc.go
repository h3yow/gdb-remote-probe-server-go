package session

import (
	"time"

	"github.com/h3yow/gdb-remote-probe-server-go/pkg/clock"
)

// timerC is a small nullable wrapper around clock.Timer for the idle timeout.
type timerC struct {
	t clock.Timer
	c <-chan time.Time
}

func newTimerC(clk clock.Clock, d time.Duration) timerC {
	t := clk.NewTimer(d)
	return timerC{t: t, c: t.C()}
}

// stop is safe on the zero value and on an already fired timer.
func (tc timerC) stop() {
	if tc.t != nil {
		_ = tc.t.Stop()
	}
}
