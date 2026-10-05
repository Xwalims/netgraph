// Package latency measures round-trip time and summarises it.
//
// # Why not just ping
//
// Three reasons, and each one produced a real bug before it was handled:
//
//   - ICMP needs a raw socket, so a latency measurement would need privileges
//     that a diagnostic tool should not demand. A TCP handshake measures the
//     same round trip over an ordinary socket, so it works unprivileged.
//   - Routers rate-limit ICMP aggressively and prioritise it differently from
//     real traffic. An ICMP RTT is a lower bound on the path, not a
//     measurement of it. Mixing the two in one report is misleading.
//   - A hop RTT and an end-to-end RTT are different quantities. A router can
//     deprioritise the ICMP it sends back, so its reply looks slower than the
//     destination's even though the destination is further away.
//
// So `Measure` returns end-to-end timings and `MeasureWithProtocol` names the
// protocol that produced them. Nothing here mixes the two silently.
package latency

import (
	"context"
	"fmt"
	"math"
	"net"
	"sort"
	"time"

	"github.com/Xwalims/netgraph/pkg/models"
)

// Probe is one measurement.
type Probe struct {
	// At is when the probe was sent.
	At time.Time

	// RTT is the round trip, or zero when the probe did not complete.
	RTT time.Duration

	// Sent is true when the probe left.
	Sent bool

	// Completed is true when an answer arrived in time.
	Completed bool

	// Error explains a failure, empty on success.
	Error string
}

// Options configures a measurement.
type Options struct {
	// Count is how many probes to send. Zero means continuous.
	Count int

	// Interval between probes. Defaults to one second.
	Interval time.Duration

	// Timeout bounds one probe. Defaults to two seconds.
	Timeout time.Duration

	// Port is the TCP port used for the handshake.
	Port string

	// Protocol names the measurement method, for the report.
	Protocol string

	// Now is injectable for tests.
	Now func() time.Time
}

// DefaultPort is the TCP port used when none is given. 443 is used rather than
// a high port because a firewall dropping it means the host is unreachable,
// which is a real answer rather than a measurement artefact.
const DefaultPort = "443"

// DefaultInterval is the pause between probes.
const DefaultInterval = time.Second

// DefaultTimeout bounds one probe.
const DefaultTimeout = 2 * time.Second

// Measure sends probes and returns the raw series.
//
// A failed probe is recorded with Completed false and counts towards loss; it
// is not dropped, because dropping it is exactly how a tool reports 0% loss on a
// path that is dropping everything.
func Measure(ctx context.Context, target string, options Options) ([]Probe, error) {
	address, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(target, portOf(options)))
	if err != nil {
		return nil, fmt.Errorf("cannot resolve %s: %w", target, err)
	}

	interval := options.Interval
	if interval <= 0 {
		interval = DefaultInterval
	}
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}

	var probes []Probe
	sent := 0

	for {
		// Check for cancellation before every probe, so Ctrl-C takes effect
		// within one interval rather than after the whole run.
		select {
		case <-ctx.Done():
			return probes, nil
		default:
		}

		probe := Probe{At: now(), Sent: true}
		start := time.Now()

		probeCtx, cancel := context.WithTimeout(ctx, timeout)
		conn, err := (&net.Dialer{}).DialContext(probeCtx, "tcp", address.String())
		elapsed := time.Since(start)
		cancel()

		if err != nil {
			probe.Error = err.Error()
		} else {
			probe.RTT = elapsed
			probe.Completed = true
			conn.Close()
		}
		probes = append(probes, probe)
		sent += 1

		if options.Count > 0 && sent >= options.Count {
			return probes, nil
		}

		select {
		case <-ctx.Done():
			return probes, nil
		case <-time.After(interval):
		}
	}
}

func portOf(options Options) string {
	if options.Port != "" {
		return options.Port
	}
	return DefaultPort
}

// Summarise turns a probe series into statistics.
//
// Only completed probes contribute to the timing statistics. The lost count
// includes every probe that was sent and did not come back, so loss and the
// timing figures are always describing the same set of attempts.
func Summarise(probes []Probe) models.LatencyStats {
	stats := models.LatencyStats{Count: len(probes)}
	if len(probes) == 0 {
		return stats
	}

	samples := make([]time.Duration, 0, len(probes))
	for _, probe := range probes {
		if !probe.Sent {
			continue
		}
		if !probe.Completed {
			stats.Lost += 1
			continue
		}
		samples = append(samples, probe.RTT)
	}
	stats.Count = len(samples)
	if len(probes) > 0 {
		stats.Loss = float64(stats.Lost) / float64(len(probes))
	}
	if len(samples) == 0 {
		return stats
	}

	sorted := make([]time.Duration, len(samples))
	copy(sorted, samples)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	var total time.Duration
	for _, sample := range samples {
		total += sample
	}
	mean := total / time.Duration(len(samples))

	stats.Min = sorted[0]
	stats.Max = sorted[len(sorted)-1]
	stats.Mean = mean
	stats.Median = percentile(sorted, 50)

	// Jitter is the mean absolute difference between consecutive samples, which
	// is the convention ping uses. It measures change rather than deviation,
	// which is why StdDev is reported separately.
	if len(samples) > 1 {
		var jitterTotal time.Duration
		for i := 1; i < len(samples); i++ {
			difference := samples[i] - samples[i-1]
			if difference < 0 {
				difference = -difference
			}
			jitterTotal += difference
		}
		stats.Jitter = jitterTotal / time.Duration(len(samples)-1)
	}

	var variance float64
	for _, sample := range samples {
		difference := float64(sample - mean)
		variance += difference * difference
	}
	variance /= float64(len(samples))
	stats.StdDev = time.Duration(math.Sqrt(variance))

	stats.Percentiles = map[string]time.Duration{
		"p50": percentile(sorted, 50),
		"p90": percentile(sorted, 90),
		"p95": percentile(sorted, 95),
		"p99": percentile(sorted, 99),
	}

	// The series is kept so a caller can plot it; a statistics block without
	// the samples cannot be turned into a chart or re-analysed.
	stats.Samples = samples

	return stats
}

// percentile returns the nearest-rank percentile of a sorted series.
//
// Nearest-rank rather than interpolating: with ten samples a p99 is simply the
// slowest one, and interpolating between two measurements would invent a value
// that was never observed.
func percentile(sorted []time.Duration, p int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	if p <= 0 {
		return sorted[0]
	}
	if p >= 100 {
		return sorted[len(sorted)-1]
	}
	rank := (p*len(sorted) + 99) / 100
	if rank < 1 {
		rank = 1
	}
	if rank > len(sorted) {
		rank = len(sorted)
	}
	return sorted[rank-1]
}

// Format renders an RTT for a terminal: microseconds below a millisecond,
// milliseconds below a second, seconds above.
//
// The sub-millisecond branch divides rather than calling rtt.Microseconds(),
// which truncates: 1.5µs came out as "1µs", so every sub-millisecond measurement
// was understated by up to a microsecond. Rounding removes the bias.
func Format(rtt time.Duration) string {
	switch {
	case rtt == 0:
		return "0"
	case rtt < time.Microsecond:
		return fmt.Sprintf("%dns", rtt.Nanoseconds())
	case rtt < time.Millisecond:
		return fmt.Sprintf("%.0fµs", float64(rtt)/float64(time.Microsecond))
	case rtt < time.Second:
		return fmt.Sprintf("%.1fms", float64(rtt)/float64(time.Millisecond))
	default:
		return fmt.Sprintf("%.2fs", rtt.Seconds())
	}
}

// LatencyClass buckets an RTT for colour coding.
//
// The thresholds are deliberately coarse. A precise grade on an end-to-end
// measurement over an internet path implies an accuracy the measurement does
// not have, and a latency figure that says 12.3ms is not better for saying
// than 20ms.
func LatencyClass(rtt time.Duration) string {
	switch {
	case rtt <= 0:
		return "unknown"
	case rtt < 20*time.Millisecond:
		return "good"
	case rtt < 100*time.Millisecond:
		return "fair"
	case rtt < 300*time.Millisecond:
		return "slow"
	default:
		return "very-slow"
	}
}
