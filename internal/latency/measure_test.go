package latency

import (
	"context"
	"testing"
	"time"
)

// probes builds a series with the given round trips in milliseconds, plus a
// given number of failures.
func probes(rtts []float64, failures int) []Probe {
	out := make([]Probe, 0, len(rtts)+failures)
	now := time.Now()
	for i, rtt := range rtts {
		out = append(out, Probe{
			At:        now.Add(time.Duration(i) * time.Second),
			RTT:       time.Duration(rtt * float64(time.Millisecond)),
			Sent:      true,
			Completed: true,
		})
	}
	for i := 0; i < failures; i++ {
		out = append(out, Probe{
			At:    now.Add(time.Duration(len(rtts)+i) * time.Second),
			Sent:  true,
			Error: "timeout",
		})
	}
	return out
}

func TestSummariseEmpty(t *testing.T) {
	stats := Summarise(nil)
	if stats.Count != 0 || stats.Lost != 0 || stats.Loss != 0 {
		t.Fatalf("an empty series must summarise to zeroes, got %+v", stats)
	}
	// A zero series must not divide by zero anywhere.
	if stats.Mean != 0 || stats.Min != 0 {
		t.Fatalf("empty stats should be zero, got mean=%v min=%v", stats.Mean, stats.Min)
	}
}

// TestSummariseAllLost checks that a series where nothing answered reports the
// loss rather than a clean result.
//
// This is the case that makes a latency tool worse than useless when it is
// wrong: reporting 0% loss on a path that dropped every packet.
func TestSummariseAllLost(t *testing.T) {
	stats := Summarise(probes(nil, 4))

	if stats.Count != 0 {
		t.Errorf("count: got %d, want 0", stats.Count)
	}
	if stats.Lost != 4 {
		t.Errorf("lost: got %d, want 4", stats.Lost)
	}
	if stats.Loss != 1 {
		t.Errorf("loss: got %v, want 1", stats.Loss)
	}
}

func TestSummariseBasic(t *testing.T) {
	stats := Summarise(probes([]float64{10, 20, 30, 40}, 0))

	if stats.Count != 4 {
		t.Errorf("count: got %d, want 4", stats.Count)
	}
	if stats.Min != 10*time.Millisecond {
		t.Errorf("min: got %v, want 10ms", stats.Min)
	}
	if stats.Max != 40*time.Millisecond {
		t.Errorf("max: got %v, want 40ms", stats.Max)
	}
	if stats.Mean != 25*time.Millisecond {
		t.Errorf("mean: got %v, want 25ms", stats.Mean)
	}
	if stats.Median != 20*time.Millisecond {
		t.Errorf("median: got %v, want 20ms", stats.Median)
	}
}

// TestSummariseCountsLossAgainstAllSent makes sure the loss fraction is computed
// against everything that was sent, not only against what came back.
func TestSummariseCountsLossAgainstAllSent(t *testing.T) {
	stats := Summarise(probes([]float64{10, 10}, 2))

	if stats.Loss != 0.5 {
		t.Errorf("loss: got %v, want 0.5 (two of four probes lost)", stats.Loss)
	}
	if stats.Count != 2 {
		t.Errorf("count counts completed probes: got %d, want 2", stats.Count)
	}
	if stats.Lost != 2 {
		t.Errorf("lost: got %d, want 2", stats.Lost)
	}
}

func TestSummariseJitter(t *testing.T) {
	// Differences: 10, 0, 10 -- absolute mean is 20/3.
	stats := Summarise(probes([]float64{10, 20, 20, 30}, 0))

	if stats.Jitter == 0 {
		t.Fatal("a varying series must have non-zero jitter")
	}
	if stats.Jitter < 6*time.Millisecond || stats.Jitter > 7*time.Millisecond {
		t.Errorf("jitter: got %v, want about 6.7ms", stats.Jitter)
	}
}

func TestSummariseJitterOfConstantSeriesIsZero(t *testing.T) {
	stats := Summarise(probes([]float64{25, 25, 25}, 0))
	if stats.Jitter != 0 {
		t.Errorf("a constant series has no jitter, got %v", stats.Jitter)
	}
}

func TestPercentilesAreNearestRank(t *testing.T) {
	// One sample per millisecond from 1 to 100.
	var rtts []float64
	for i := 1; i <= 100; i++ {
		rtts = append(rtts, float64(i))
	}
	stats := Summarise(probes(rtts, 0))

	want := map[string]time.Duration{
		"p50": 50 * time.Millisecond,
		"p90": 90 * time.Millisecond,
		"p95": 95 * time.Millisecond,
		"p99": 99 * time.Millisecond,
	}
	for key, expected := range want {
		got, ok := stats.Percentiles[key]
		if !ok {
			t.Errorf("%s is missing", key)
			continue
		}
		if got != expected {
			t.Errorf("%s: got %v, want %v", key, got, expected)
		}
	}
}

// TestPercentileDoesNotInterpolate records that a percentile is a measurement
// that happened, not a number invented between two.
func TestPercentileDoesNotInterpolate(t *testing.T) {
	sorted := []time.Duration{10 * time.Millisecond, 20 * time.Millisecond}

	// p99 of two samples is the slowest one: there is nothing between them that
	// was ever observed.
	if got := percentile(sorted, 99); got != 20*time.Millisecond {
		t.Errorf("p99 of two samples: got %v, want 20ms", got)
	}
	// Out-of-range values clamp rather than index out of bounds.
	if got := percentile(sorted, 0); got != 10*time.Millisecond {
		t.Errorf("p0: got %v, want 10ms", got)
	}
	if got := percentile(sorted, 100); got != 20*time.Millisecond {
		t.Errorf("p100: got %v, want 20ms", got)
	}
	if got := percentile(nil, 50); got != 0 {
		t.Errorf("an empty series has no percentile, got %v", got)
	}
}

func TestSamplesArePreserved(t *testing.T) {
	stats := Summarise(probes([]float64{10, 20, 30}, 0))
	// The raw series has to survive for a chart; a statistics block without it
	// cannot be plotted or re-analysed.
	if len(stats.Samples) != 3 {
		t.Fatalf("samples: got %d, want 3", len(stats.Samples))
	}
}

func TestFormat(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want string
	}{
		{0, "0"},
		{500 * time.Nanosecond, "500ns"},
		{1500 * time.Nanosecond, "2µs"},
		{1500 * time.Microsecond, "1.5ms"},
		{250 * time.Millisecond, "250.0ms"},
		{2 * time.Second, "2.00s"},
	}
	for _, item := range cases {
		if got := Format(item.in); got != item.want {
			t.Errorf("Format(%v): got %q, want %q", item.in, got, item.want)
		}
	}
}

// TestFormatSwitchesUnits is here because the first version printed
// "1500µs" where "1.5ms" was meant, which is the kind of thing that survives a
// code review and looks wrong on screen.
func TestFormatPicksReadableUnits(t *testing.T) {
	if got := Format(1500 * time.Microsecond); got != "1.5ms" {
		t.Errorf("sub-millisecond values should read as ms: got %q", got)
	}
	if got := Format(2 * time.Second); got != "2.00s" {
		t.Errorf("multi-second values should read as seconds: got %q", got)
	}
}

func TestLatencyClass(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want string
	}{
		{0, "unknown"},
		{5 * time.Millisecond, "good"},
		{50 * time.Millisecond, "fair"},
		{200 * time.Millisecond, "slow"},
		{time.Second, "very-slow"},
	}
	for _, item := range cases {
		if got := LatencyClass(item.in); got != item.want {
			t.Errorf("LatencyClass(%v): got %q, want %q", item.in, got, item.want)
		}
	}
}

// TestMeasureRespectsContextCancellation checks that an interrupted run stops
// promptly rather than after the remaining probes.
func TestMeasureRespectsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	// A target that will not answer, so only the timeout can end the run.
	probes, err := Measure(ctx, "192.0.2.1", Options{
		Count:    1000,
		Interval: time.Second,
		Timeout:  time.Second,
	})
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Measure should not error on cancellation: %v", err)
	}
	// One probe at most, then the context ends it.
	if len(probes) > 2 {
		t.Errorf("cancellation stopped too late: %d probes in %v", len(probes), elapsed)
	}
	if elapsed > 3*time.Second {
		t.Errorf("cancellation took %v, which is not prompt", elapsed)
	}
}

// TestMeasureStopsAtCount checks that a bounded run sends exactly what it was
// asked for.
func TestMeasureStopsAtCount(t *testing.T) {
	probes, err := Measure(context.Background(), "127.0.0.1", Options{
		Count:    3,
		Interval: 10 * time.Millisecond,
		Timeout:  time.Second,
		Port:     "1",
	})
	if err != nil {
		t.Fatalf("Measure: %v", err)
	}
	if len(probes) != 3 {
		t.Fatalf("expected 3 probes, got %d", len(probes))
	}
}
