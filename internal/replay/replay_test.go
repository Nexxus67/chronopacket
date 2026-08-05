package replay

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/chronopacket/chronopacket/internal/reader"
)

type fakeReader struct {
	packets []reader.Packet
	index   int
	err     error
}

func (r *fakeReader) Read() (reader.Packet, error) {
	if r.err != nil {
		return reader.Packet{}, r.err
	}
	if r.index == len(r.packets) {
		return reader.Packet{}, io.EOF
	}
	p := r.packets[r.index]
	r.index++
	return p, nil
}
func (r *fakeReader) Close() error { return nil }

type fakeSender struct {
	packets [][]byte
	err     error
}

func (s *fakeSender) Send(data []byte) error {
	if s.err != nil {
		return s.err
	}
	s.packets = append(s.packets, append([]byte(nil), data...))
	return nil
}
func (s *fakeSender) Close() error { return nil }

type fakeSleeper struct {
	waits []time.Duration
	err   error
}

func (s *fakeSleeper) Sleep(_ context.Context, d time.Duration) error {
	s.waits = append(s.waits, d)
	return s.err
}

func TestEnginePreservesScaledIntervals(t *testing.T) {
	base := time.Unix(100, 0)
	input := &fakeReader{packets: []reader.Packet{{Data: []byte("one"), Timestamp: base}, {Data: []byte("two"), Timestamp: base.Add(500 * time.Millisecond)}, {Data: []byte("three"), Timestamp: base.Add(250 * time.Millisecond)}}}
	output := &fakeSender{}
	sleeper := &fakeSleeper{}
	clock := func() time.Time { return base }
	engine, err := New(Options{Reader: input, Sender: output, Sleeper: sleeper, Speed: 2, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	stats, err := engine.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(output.packets) != 3 || stats.Bytes != 11 {
		t.Fatalf("unexpected output: packets=%d bytes=%d", len(output.packets), stats.Bytes)
	}
	if len(sleeper.waits) != 1 || sleeper.waits[0] != 250*time.Millisecond {
		t.Fatalf("unexpected waits: %v", sleeper.waits)
	}
}

func TestEnginePropagatesReadError(t *testing.T) {
	want := errors.New("broken capture")
	engine, err := New(Options{Reader: &fakeReader{err: want}, Sender: &fakeSender{}, Speed: 1})
	if err != nil {
		t.Fatal(err)
	}
	_, err = engine.Run(context.Background())
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
}

func TestNewRejectsInvalidOptions(t *testing.T) {
	if _, err := New(Options{Sender: &fakeSender{}, Speed: 1}); err == nil {
		t.Fatal("expected missing reader error")
	}
	if _, err := New(Options{Reader: &fakeReader{}, Sender: &fakeSender{}, Speed: 0}); err == nil {
		t.Fatal("expected invalid speed error")
	}
}
