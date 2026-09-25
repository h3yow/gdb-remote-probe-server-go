package session

import (
	"errors"

	"github.com/h3yow/gdb-remote-probe-server-go/pkg/protocol"
	"github.com/h3yow/gdb-remote-probe-server-go/pkg/target"
)

// Session is one owned connection. It is created by Server.ServeConn.
type Session struct {
	server *Server
	target *target.Target
	link   *protocol.Link
	log    Logger

	caps     capabilities
	attached bool

	// run is non-nil exactly while a Continue is executing. The main loop is
	// always the sole Recv consumer; run.deliver receives the final stop reply
	// when execution halts (breakpoint, fault, HALT or interrupt).
	run *runState
}

type runState struct {
	done chan runResult
}

type runResult struct {
	info target.HaltInfo
	err  error
}

// startRun launches an asynchronous Continue. The target itself executes
// cooperatively without blocking I/O, so this is safe to drive from the
// session loop.
func (sess *Session) startRun() {
	rs := &runState{done: make(chan runResult, 1)}
	sess.run = rs
	sess.log.Printf("state -> running pc=%#x", sess.target.PC())
	go func() {
		info, err := sess.target.Continue()
		rs.done <- runResult{info: info, err: err}
	}()
}

// finishRun drains the run completion and clears the running marker.
func (sess *Session) finishRun(r runResult) string {
	sess.run = nil
	if r.err != nil {
		return errorReply(mapTargetError(r.err))
	}
	sess.log.Printf("state -> halted(%s) pc=%#x", r.info.Reason, r.info.PC)
	return stopReply(sess.target)
}

// ctrlCPacket is an internal sentinel body for asynchronous interrupts.
var ctrlCPacket = []byte{protocol.ByteCtrlC}

func (sess *Session) recvPacket() ([]byte, error) {
	var (
		body []byte
		err  error
	)
	if d := sess.server.cfg.IdleTimeout; d > 0 {
		body, err = sess.link.RecvTimeout(d)
	} else {
		body, err = sess.link.Recv()
	}
	if errors.Is(err, protocol.ErrInterrupted) {
		sess.log.Printf("frame <- <ctrl-c>")
		return ctrlCPacket, nil
	}
	return body, err
}

// interruptTarget stops a running target and returns its result; no-op when
// the target is already halted.
func (sess *Session) interruptTarget() runResult {
	if sess.target.State() != target.StateRunning {
		info := sess.target.HaltInfo()
		return runResult{info: info}
	}
	info, err := sess.target.Interrupt()
	if err != nil {
		sess.log.Printf("interrupt failed: %v", err)
	} else {
		sess.log.Printf("state -> halted(pause) pc=%#x", info.PC)
	}
	return runResult{info: info, err: err}
}

// errDisconnected is an internal fatal sentinel meaning a clean peer disconnect.
var errDisconnected = errors.New("session: disconnected (internal)")
var errDetach = errors.New("session: detached by client (internal)")

// noReply is an internal dispatch result meaning "do not send a frame now"
// (used by async 'c'; the stop reply follows when execution halts).
const noReply = "\x00noReply\x00"

func (sess *Session) sendError(code byte, format string, args ...any) error {
	reply := errorReply(code)
	sess.log.Printf("reject: "+format+" -> %s", append(args, reply)...)
	return sess.link.Send([]byte(reply))
}

func (sess *Session) sendRaw(body string) error {
	sess.log.Printf("frame -> %q", body)
	return sess.link.Send([]byte(body))
}

// loop is the single request/response pump. It selects directly on the
// link's long-lived frame stream, an idle timer and (while running) run
// completion. There is exactly one frame consumer and no per-packet
// goroutines, so resuming/halting never races or drops a command.
func (sess *Session) loop() error {
	frames := sess.link.Frames()
	doneCh := sess.link.Done()
	var idle timerC
	armIdle := func() timerC {
		if d := sess.server.cfg.IdleTimeout; d > 0 {
			return newTimerC(sess.server.cfg.Clock, d)
		}
		return timerC{}
	}
	idle = armIdle()

	for {
		if sess.run != nil {
			select {
			case <-doneCh:
				sess.log.Printf("session: link closed while running")
				return nil
			case f := <-frames:
				reply, detach, fatal := sess.handleInbound(f)
				if errors.Is(fatal, errDisconnected) {
					return nil
				}
				if fatal != nil {
					return fatal
				}
				if err := sess.flush(reply, detach); err != nil {
					if errors.Is(err, errDetach) {
						return nil
					}
					return err
				}
				idle = armIdle()
			case r := <-sess.run.done:
				_ = sess.sendRaw(sess.finishRun(r))
				idle = armIdle()
			case <-idle.c:
				idle.stop()
				sess.log.Printf("session: idle timeout, closing deterministically")
				return ErrIdleTimeout
			}
			continue
		}

		select {
		case <-doneCh:
			sess.log.Printf("session: link closed")
			return nil
		case f := <-frames:
			reply, detach, fatal := sess.handleInbound(f)
			if errors.Is(fatal, errDisconnected) {
				return nil
			}
			if fatal != nil {
				return fatal
			}
			if err := sess.flush(reply, detach); err != nil {
				if errors.Is(err, errDetach) {
					return nil
				}
				return err
			}
			idle = armIdle()
		case <-idle.c:
			idle.stop()
			sess.log.Printf("session: idle timeout, closing deterministically")
			return ErrIdleTimeout
		}
	}
}

// flush sends the reply frame (an empty body is gdb's valid "unsupported"
// response) and maps detach to errDetach.
func (sess *Session) flush(reply string, detach bool) error {
	if reply == noReply {
		return nil
	}
	if err := sess.sendRaw(reply); err != nil {
		sess.log.Printf("session: send error: %v", err)
		return err
	}
	if detach {
		sess.log.Printf("session: detached by client")
		return errDetach
	}
	return nil
}

// handleInbound processes one frame whether halted or running. The third
// return is a non-nil fatal error that must terminate the session loop.
func (sess *Session) handleInbound(f protocol.Frame) (reply string, detach bool, fatal error) {
	// A control 0x03 is delivered as ErrInterrupted; translate it into the
	// in-band interrupt marker regardless of run state.
	if errors.Is(f.Err, protocol.ErrInterrupted) {
		f = protocol.Frame{Body: ctrlCPacket}
	}
	if f.Err != nil {
		switch {
		case errors.Is(f.Err, protocol.ErrClosed):
			sess.log.Printf("session: disconnected")
			return "", false, errDisconnected
		case errors.Is(f.Err, protocol.ErrTimeout):
			sess.log.Printf("session: idle timeout, closing deterministically")
			return "", false, ErrIdleTimeout
		default:
			sess.log.Printf("session: recv error: %v", f.Err)
			return "", false, f.Err
		}
	}
	body := f.Body
	if sess.run != nil {
		isCtrl := len(body) == 1 && body[0] == protocol.ByteCtrlC || string(body) == "vCtrlC"
		if isCtrl {
			rr := sess.interruptTarget()
			<-sess.run.done
			return sess.finishRun(rr), false, nil
		}
		// Ordinary command while running: if the run just finished, report it.
		select {
		case rr := <-sess.run.done:
			return sess.finishRun(rr), false, nil
		default:
		}
		sess.log.Printf("reject: command %q while running -> %s", string(body), errorReply(ErrRunning))
		return errorReply(ErrRunning), false, nil
	}
	reply, detach = sess.dispatch(body)
	return reply, detach, nil
}
