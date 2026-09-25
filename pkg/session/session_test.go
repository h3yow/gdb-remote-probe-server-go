package session

import (
	"context"
	"sync"
	"testing"

	"github.com/h3yow/gdb-remote-probe-server-go/pkg/target"
)

func sampleImage(t *testing.T) *target.Image {
	t.Helper()
	p := target.NewProgram().Movi(target.RegR0, 1).Label("loop").Jmp("loop")
	img, err := target.BuildImage(p, 0, 0x100, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	return img
}

func TestRepeatLoadSameView(t *testing.T) {
	m := NewManager()
	tg1, err := m.LoadImage("dev", sampleImage(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := tg1.WriteRegister(target.RegR1, 0x42); err != nil {
		t.Fatal(err)
	}
	tg2, err := m.LoadImage("dev", sampleImage(t))
	if err != nil {
		t.Fatal(err)
	}
	if tg1 != tg2 {
		t.Fatal("repeat load must return same target instance")
	}
	v, _ := tg2.ReadRegister(target.RegR1)
	if v != 0x42 {
		t.Fatalf("reconnected view lost state: %#x", v)
	}
}

func TestConcurrentAttachOnlyOneWins(t *testing.T) {
	m := NewManager()
	if _, err := m.LoadImage("dev", sampleImage(t)); err != nil {
		t.Fatal(err)
	}
	const n = 16
	var wg sync.WaitGroup
	var winners, busies int32
	var mu sync.Mutex
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			sess, err := m.Attach(context.Background(), "dev")
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				winners++
				_ = sess
			} else if target.CodeOf(err) == target.CodeSessionBusy {
				busies++
			}
		}()
	}
	wg.Wait()
	if winners != 1 || busies != n-1 {
		t.Fatalf("winners=%d busies=%d", winners, busies)
	}
	if !m.Active("dev") {
		t.Fatal("target should be active")
	}
}

func TestDetachReconnectPreservesState(t *testing.T) {
	m := NewManager()
	tg, _ := m.LoadImage("dev", sampleImage(t))

	s1, err := m.Attach(context.Background(), "dev")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tg.Step(); err != nil {
		t.Fatal(err)
	}
	pcAfterStep, _ := tg.ReadRegister(target.RegPC)
	if err := s1.Detach(); err != nil {
		t.Fatal(err)
	}
	if s1.Status() != StatusDetached {
		t.Fatalf("status = %s", s1.Status())
	}
	if m.Active("dev") {
		t.Fatal("target must be free after detach")
	}
	// idempotent detach
	if err := s1.Detach(); err != nil {
		t.Fatalf("repeat detach: %v", err)
	}
	// reconnect: same target, registers/PC preserved
	s2, err := m.Attach(context.Background(), "dev")
	if err != nil {
		t.Fatalf("reconnect: %v", err)
	}
	pc, _ := tg.ReadRegister(target.RegPC)
	if pc != pcAfterStep {
		t.Fatalf("pc changed across detach: %#x vs %#x", pc, pcAfterStep)
	}
	_ = s2
}

func TestKillResetsAndReconnect(t *testing.T) {
	m := NewManager()
	tg, _ := m.LoadImage("dev", sampleImage(t))
	s1, _ := m.Attach(context.Background(), "dev")
	if _, err := tg.Step(); err != nil {
		t.Fatal(err)
	}
	if err := s1.Kill(); err != nil {
		t.Fatal(err)
	}
	pc, _ := tg.ReadRegister(target.RegPC)
	if pc != 0 {
		t.Fatalf("kill must reset pc to entry, got %#x", pc)
	}
	if s1.Status() != StatusKilled {
		t.Fatalf("status = %s", s1.Status())
	}
	// idempotent
	if err := s1.Kill(); err != nil {
		t.Fatal(err)
	}
	s2, err := m.Attach(context.Background(), "dev")
	if err != nil {
		t.Fatalf("reconnect after kill: %v", err)
	}
	if s2.ID() == s1.ID() {
		t.Fatal("new session must have new id")
	}
}

func TestDetachWhileRunningConverges(t *testing.T) {
	m := NewManager()
	tg, _ := m.LoadImage("dev", sampleImage(t))
	s, _ := m.Attach(context.Background(), "dev")
	if err := tg.Resume(); err != nil {
		t.Fatal(err)
	}
	if err := s.Detach(); err != nil {
		t.Fatalf("detach running: %v", err)
	}
	if tg.IsRunning() {
		t.Fatal("target must be stopped after detach")
	}
	if m.Active("dev") {
		t.Fatal("slot must be free")
	}
	// state is terminal and reusable
	s2, err := m.Attach(context.Background(), "dev")
	if err != nil {
		t.Fatalf("reconnect: %v", err)
	}
	_ = s2
}
