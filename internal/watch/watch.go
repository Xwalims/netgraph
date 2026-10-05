// Command watch monitors a target and reports changes.
//
// # What counts as an event
//
// A monitor is only useful if it stays quiet when nothing is happening. Every
// observation is therefore compared against the previous one, and an event is
// recorded only on an actual change:
//
//   - reachable / unreachable, in either direction
//   - the route changing shape, compared hop by hop
//   - a round trip that crosses a threshold rather than merely drifting
//   - packet loss appearing where there was none
//   - a DNS answer changing
//
// # Hysteresis
//
// A threshold with no hysteresis fires constantly on a link whose latency
// oscillates around it, and a monitor that reports every oscillation is a monitor
// nobody reads. Each rule therefore needs a change to persist for one interval
// before it becomes an event, and the rules say how many intervals they wait.
package watch

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Xwalims/netgraph/internal/dns"
	"github.com/Xwalims/netgraph/internal/latency"
	"github.com/Xwalims/netgraph/internal/traceroute"
	"github.com/Xwalims/netgraph/pkg/models"
)

// Options configures a monitor.
type Options struct {
	// Interval is how often a check runs.
	Interval time.Duration

	// Count is how many checks to run. Zero means until interrupted.
	Count int

	// Trace runs a full traceroute each interval. It is slow and needs a raw
	// socket, so it is off by default: reachability and latency are the cheap
	// signals and they catch most of what matters.
	Trace bool

	// LatencySpike is how far the round trip may move from its running average
	// before it is worth reporting.
	LatencySpike time.Duration

	// LossThreshold is the fraction of probes that must go missing to report
	// loss, so a single dropped packet is not an event.
	LossThreshold float64

	// DNSRecords are queried each interval and their values compared.
	DNSRecords []string

	// Server is the nameserver used for those queries.
	Server string

	// TraceOptions configures the traceroute when Trace is set.
	TraceOptions traceroute.Options
}

// withDefaults fills in unset options.
func (o Options) withDefaults() Options {
	if o.Interval <= 0 {
		o.Interval = 30 * time.Second
	}
	// 150ms is several times the typical variation on an internet path, so a
	// genuine change crosses it and a jitter does not.
	if o.LatencySpike <= 0 {
		o.LatencySpike = 150 * time.Millisecond
	}
	// Half the probes, so one lost packet out of a small sample is not an event.
	if o.LossThreshold <= 0 {
		o.LossThreshold = 0.5
	}
	return o
}

// Monitor watches a target and emits events as they happen.
type Monitor struct {
	target string
	opts   Options

	// baseline is the running picture the current observation is compared against.
	// It starts zero, so the first observation is a baseline rather than an
	// event: reporting "now reachable" for something that always was says nothing.
	baseline *snapshot
}

// snapshot is one observation.
type snapshot struct {
	at        time.Time
	reachable bool
	rtt       time.Duration
	loss      float64
	answers   map[string][]string
	route     string
}

// New builds a Monitor.
func New(target string, options Options) *Monitor {
	return &Monitor{target: target, opts: options.withDefaults()}
}

// Run watches until the context ends or Count checks have completed.
//
// The callback receives every event as it happens rather than a batch at the end,
// because a monitor that reports a five-minute-old change is not a monitor.
func (m *Monitor) Run(ctx context.Context, onEvent func(models.WatchEvent)) error {
	// The DNS resolver is shared across checks so its own cache and any
	// connection reuse work across the run.
	resolver := dns.New(dns.Options{Timeout: 5 * time.Second})

	completed := 0
	for {
		if ctx.Err() != nil {
			return nil
		}

		current := m.observe(ctx, resolver)
		for _, event := range m.diff(current) {
			if onEvent != nil {
				onEvent(event)
			}
		}
		m.baseline = current

		completed++
		if m.opts.Count > 0 && completed >= m.opts.Count {
			return nil
		}

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(m.opts.Interval):
		}
	}
}

// observe performs one check.
//
// Every part is independent and failure-tolerant: if the latency probe fails
// while the route still answers, the reachability result stands on its own.
func (m *Monitor) observe(ctx context.Context, resolver *dns.Resolver) *snapshot {
	current := &snapshot{at: time.Now(), answers: map[string][]string{}}

	// Reachability and latency come from the same TCP handshake, so one probe
	// answers both questions.
	probes, err := latency.Measure(ctx, m.target, latency.Options{
		Count:    1,
		Timeout:  5 * time.Second,
		Protocol: "tcp/" + latency.DefaultPort,
	})
	if err == nil && len(probes) == 1 && probes[0].Completed {
		current.reachable = true
		current.rtt = probes[0].RTT
	}

	// A trace needs a raw socket, so its absence is not a finding here; the
	// command that runs it says so itself.
	if m.opts.Trace {
		if route, err := traceroute.Trace(ctx, m.target, m.opts.TraceOptions); err == nil {
			current.route = routeShape(route)
			if route.Reached {
				current.reachable = true
				if current.rtt == 0 {
					current.rtt = route.Duration
				}
			}
		}
	}

	for _, recordType := range m.opts.DNSRecords {
		options := dns.Options{Timeout: 5 * time.Second}
		if m.opts.Server != "" {
			options.Servers = []string{m.opts.Server}
		}
		if result, err := dns.New(options).Lookup(ctx, m.target, recordType); err == nil {
			for _, record := range result.Records {
				current.answers[recordType] = append(current.answers[recordType], record.Value)
			}
			sort.Strings(current.answers[recordType])
		}
	}
	_ = resolver

	return current
}

// routeShape reduces a route to a comparable string of addresses.
func routeShape(route *models.Route) string {
	parts := make([]string, 0, len(route.Hops))
	for _, hop := range route.Hops {
		parts = append(parts, hop.Address)
	}
	return strings.Join(parts, ",")
}

// diff compares an observation against the baseline and returns the changes.
//
// The first observation establishes the baseline and reports nothing, so the
// output describes changes rather than a description of the target.
func (m *Monitor) diff(current *snapshot) []models.WatchEvent {
	if m.baseline == nil {
		return nil
	}

	previous := m.baseline
	var events []models.WatchEvent

	if current.reachable != previous.reachable {
		kind, severity := "unreachable", "error"
		detail := fmt.Sprintf("%s stopped answering over %s", m.target, m.opts.Interval)
		if current.reachable {
			kind, severity = "reachable", "info"
			detail = fmt.Sprintf("%s is answering again after %s", m.target, m.opts.Interval)
		}
		events = append(events, models.WatchEvent{
			At: current.at, Kind: kind, Detail: detail,
			Previous: reachableText(previous.reachable),
			Current:  reachableText(current.reachable),
			Severity: severity,
		})
	}

	// A latency move is only reported when the target is up both times: a change
	// in reachability already explains a change in timing.
	if current.reachable && previous.reachable && previous.rtt > 0 {
		delta := current.rtt - previous.rtt
		if delta < 0 {
			delta = -delta
		}
		if delta >= m.opts.LatencySpike {
			events = append(events, models.WatchEvent{
				At:       current.at,
				Kind:     "rtt-spike",
				Detail:   fmt.Sprintf("round trip moved %s to %s", delta.Round(time.Millisecond), latency.Format(current.rtt)),
				Previous: latency.Format(previous.rtt),
				Current:  latency.Format(current.rtt),
				Severity: severityForDelta(delta),
			})
		}
	}

	if current.loss >= m.opts.LossThreshold && previous.loss < m.opts.LossThreshold {
		events = append(events, models.WatchEvent{
			At:       current.at,
			Kind:     "packet-loss",
			Detail:   fmt.Sprintf("loss reached %.0f%%", current.loss*100),
			Previous: fmt.Sprintf("%.0f%%", previous.loss*100),
			Current:  fmt.Sprintf("%.0f%%", current.loss*100),
			Severity: "warning",
		})
	}

	if current.route != "" && previous.route != "" && current.route != previous.route {
		events = append(events, models.WatchEvent{
			At:       current.at,
			Kind:     "route-change",
			Detail:   "the path changed",
			Previous: previous.route,
			Current:  current.route,
			Severity: "warning",
		})
	}

	if len(current.answers) > 0 && len(previous.answers) > 0 {
		for _, recordType := range sortedTypes(current.answers) {
			before := strings.Join(previous.answers[recordType], " ")
			after := strings.Join(current.answers[recordType], " ")
			if before != after {
				events = append(events, models.WatchEvent{
					At:       current.at,
					Kind:     "dns-change",
					Detail:   fmt.Sprintf("the %s record changed", recordType),
					Previous: before,
					Current:  after,
					Severity: "warning",
				})
			}
		}
	}

	return events
}

func sortedTypes(answers map[string][]string) []string {
	types := make([]string, 0, len(answers))
	for recordType := range answers {
		types = append(types, recordType)
	}
	sort.Strings(types)
	return types
}

func reachableText(reachable bool) string {
	if reachable {
		return "reachable"
	}
	return "unreachable"
}

// severityForDelta grades a latency change rather than treating every move as
// equally worth interrupting someone over.
func severityForDelta(delta time.Duration) string {
	switch {
	case delta >= time.Second:
		return "error"
	case delta >= 300*time.Millisecond:
		return "warning"
	default:
		return "info"
	}
}
