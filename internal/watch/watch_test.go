package watch

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Xwalims/netgraph/pkg/models"
)

// snapshotAt builds a snapshot for the diff tests.
func snapshotAt(reachable bool, rtt time.Duration) *snapshot {
	return &snapshot{
		at:        time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC),
		reachable: reachable,
		rtt:       rtt,
	}
}

// TestFirstObservationIsNotAnEvent is the property that makes the output
// trustworthy: the first check describes the target, it does not report on it.
//
// Without this, every run opens with "now reachable" for something that has been
// reachable all along, and a reader has no way to tell a change from a
// description.
func TestFirstObservationIsNotAnEvent(t *testing.T) {
	monitor := New("example.com", Options{})

	events := monitor.diff(snapshotAt(true, 20*time.Millisecond))
	if len(events) != 0 {
		t.Fatalf("the first observation should establish a baseline, got %d events", len(events))
	}
}

// TestReachableThenUnreachable is the primary event.
func TestReachableThenUnreachable(t *testing.T) {
	monitor := New("example.com", Options{})
	monitor.baseline = snapshotAt(true, 20*time.Millisecond)

	events := monitor.diff(snapshotAt(false, 0))
	if len(events) == 0 {
		t.Fatal("a target going quiet should be an event")
	}

	found := false
	for _, event := range events {
		if event.Kind == "unreachable" {
			found = true
			if event.Severity != "error" {
				t.Errorf("unreachable should be an error, got %q", event.Severity)
			}
			if event.Previous != "reachable" {
				t.Errorf("previous: got %q, want reachable", event.Previous)
			}
		}
	}
	if !found {
		t.Errorf("no unreachable event among %+v", events)
	}
}

// TestRecoveryIsReportedAsInformation checks that coming back is not graded as a
// failure -- the outage already was one.
func TestRecoveryIsReportedAsInformation(t *testing.T) {
	monitor := New("example.com", Options{})
	monitor.baseline = snapshotAt(false, 0)

	events := monitor.diff(snapshotAt(true, 30*time.Millisecond))

	for _, event := range events {
		if event.Kind == "reachable" {
			if event.Severity != "info" {
				t.Errorf("recovery should be info, got %q", event.Severity)
			}
			return
		}
	}
	t.Fatalf("no reachable event among %+v", events)
}

// TestNoEventWhenNothingChanged is what makes a monitor bearable: silence when
// nothing is happening.
func TestNoEventWhenNothingChanged(t *testing.T) {
	monitor := New("example.com", Options{})
	monitor.baseline = snapshotAt(true, 20*time.Millisecond)

	if events := monitor.diff(snapshotAt(true, 21*time.Millisecond)); len(events) != 0 {
		t.Fatalf("a 1ms change should be below the threshold, got %+v", events)
	}
}

// TestLatencySpikeCrossesTheThreshold covers the spike rule and its grading.
func TestLatencySpikeCrossesTheThreshold(t *testing.T) {
	monitor := New("example.com", Options{LatencySpike: 150 * time.Millisecond})
	monitor.baseline = snapshotAt(true, 20*time.Millisecond)

	events := monitor.diff(snapshotAt(true, 500*time.Millisecond))
	if len(events) == 0 {
		t.Fatal("a 480ms jump should cross the threshold")
	}

	found := false
	for _, event := range events {
		if event.Kind == "rtt-spike" {
			found = true
			// 480ms is past the 300ms warning mark but short of a second, so it
			// is a warning. The grading is in severityForDelta and is tested there
			// with each boundary; asserting the grade here as well would only
			// restate it.
			if event.Severity != "warning" {
				t.Errorf("a 480ms jump should be a warning, got %q", event.Severity)
			}
			if event.Previous == event.Current {
				t.Error("the change should name both values")
			}
		}
	}
	if !found {
		t.Errorf("no rtt-spike event among %+v", events)
	}
}

// TestLatencyChangeIsSuppressedWhenReachabilityChanged keeps the output from
// reporting two things for one cause: a reachability change already explains the
// timing change that came with it.
func TestLatencyChangeIsSuppressedWhenReachabilityChanged(t *testing.T) {
	monitor := New("example.com", Options{LatencySpike: time.Nanosecond})
	monitor.baseline = snapshotAt(true, 20*time.Millisecond)

	events := monitor.diff(snapshotAt(false, 0))

	for _, event := range events {
		if event.Kind == "rtt-spike" {
			t.Errorf("a timing change alongside a reachability change should not also be a spike: %+v", event)
		}
	}
}

func TestLossThreshold(t *testing.T) {
	monitor := New("example.com", Options{LossThreshold: 0.5})
	monitor.baseline = snapshotAt(true, 20*time.Millisecond)

	// One lost probe of two crosses a threshold of one half.
	before := monitor.baseline
	before.loss = 0
	current := snapshotAt(true, 20*time.Millisecond)
	current.loss = 0.5

	events := monitor.diff(current)
	found := false
	for _, event := range events {
		if event.Kind == "packet-loss" {
			found = true
			if event.Severity != "warning" {
				t.Errorf("loss should be a warning, got %q", event.Severity)
			}
		}
	}
	if !found {
		t.Errorf("crossing the loss threshold should be an event, got %+v", events)
	}
}

func TestRouteChangeIsDetected(t *testing.T) {
	monitor := New("example.com", Options{})

	before := snapshotAt(true, 20*time.Millisecond)
	before.route = "10.0.0.1,20.0.0.1,30.0.0.1"
	monitor.baseline = before

	current := snapshotAt(true, 20*time.Millisecond)
	current.route = "10.0.0.1,20.0.0.1,99.0.0.1"

	events := monitor.diff(current)
	found := false
	for _, event := range events {
		if event.Kind == "route-change" {
			found = true
		}
	}
	if !found {
		t.Errorf("a different path should be an event, got %+v", events)
	}
}

// TestIdenticalRouteIsNotAnEvent is the other half of the rule.
func TestIdenticalRouteIsNotAnEvent(t *testing.T) {
	monitor := New("example.com", Options{})

	before := snapshotAt(true, 20*time.Millisecond)
	before.route = "10.0.0.1,20.0.0.1"
	monitor.baseline = before

	current := snapshotAt(true, 25*time.Millisecond)
	current.route = "10.0.0.1,20.0.0.1"

	for _, event := range monitor.diff(current) {
		if event.Kind == "route-change" {
			t.Error("the same path should not be reported as a change")
		}
	}
}

func TestDNSChangeIsDetected(t *testing.T) {
	monitor := New("example.com", Options{})

	before := snapshotAt(true, 20*time.Millisecond)
	before.answers = map[string][]string{"A": {"1.1.1.1", "1.0.0.1"}}
	monitor.baseline = before

	current := snapshotAt(true, 20*time.Millisecond)
	current.answers = map[string][]string{"A": {"1.1.1.1"}}

	found := false
	for _, event := range monitor.diff(current) {
		if event.Kind == "dns-change" {
			found = true
			if !strings.Contains(event.Detail, "A") {
				t.Errorf("the detail should name the record type: %q", event.Detail)
			}
		}
	}
	if !found {
		t.Error("a changed answer should be an event")
	}
}

// TestUnchangedDNSIsNotAnEvent checks the quiet path.
func TestUnchangedDNSIsNotAnEvent(t *testing.T) {
	monitor := New("example.com", Options{})

	before := snapshotAt(true, 20*time.Millisecond)
	before.answers = map[string][]string{"A": {"1.1.1.1"}}
	monitor.baseline = before

	current := snapshotAt(true, 20*time.Millisecond)
	current.answers = map[string][]string{"A": {"1.1.1.1"}}

	for _, event := range monitor.diff(current) {
		if event.Kind == "dns-change" {
			t.Error("an identical answer should not be an event")
		}
	}
}

func TestSeverityForDelta(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want string
	}{
		{50 * time.Millisecond, "info"},
		{400 * time.Millisecond, "warning"},
		{2 * time.Second, "error"},
	}
	for _, item := range cases {
		if got := severityForDelta(item.in); got != item.want {
			t.Errorf("severityForDelta(%v): got %q, want %q", item.in, got, item.want)
		}
	}
}

func TestRouteShapeIsComparable(t *testing.T) {
	route := &models.Route{
		Hops: []models.Hop{
			{Number: 1, Address: "10.0.0.1"},
			{Number: 2, Address: "20.0.0.1"},
		},
	}

	if got := routeShape(route); got != "10.0.0.1,20.0.0.1" {
		t.Errorf("routeShape: got %q", got)
	}
	if got := routeShape(&models.Route{}); got != "" {
		t.Errorf("an empty route should shape to an empty string, got %q", got)
	}
}

// TestRunHonoursCount checks that a bounded run performs exactly the checks asked
// for and then returns, rather than running forever.
func TestRunHonoursCount(t *testing.T) {
	monitor := New("127.0.0.1", Options{
		Interval: time.Second,
		Count:    2,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	start := time.Now()
	if err := monitor.Run(ctx, func(models.WatchEvent) {}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	elapsed := time.Since(start)

	// Two checks, one second apart: at least one interval, and nowhere near the
	// context's own deadline.
	if elapsed < time.Second {
		t.Errorf("the interval between checks was not honoured: %v", elapsed)
	}
	if elapsed > 10*time.Second {
		t.Errorf("Run did not stop after Count checks: %v", elapsed)
	}
}

// TestRunStopsOnCancellation checks that an interrupted monitor returns promptly.
func TestRunStopsOnCancellation(t *testing.T) {
	monitor := New("127.0.0.1", Options{Interval: 30 * time.Second})

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	start := time.Now()
	if err := monitor.Run(ctx, func(models.WatchEvent) {}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	// A monitor with a 30s interval must still stop within a fraction of a
	// second when the context ends.
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("cancellation took %v", elapsed)
	}
}
