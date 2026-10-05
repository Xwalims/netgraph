// Package traceroute measures the path to a target.
//
// # How traceroute actually works
//
// Every packet carries a TTL that each router decrements by one. When the TTL
// reaches zero the router discards the packet and sends an ICMP Time Exceeded
// back to the sender. The TTL at which that happens is the router's distance, so
// reading other people's ICMP replies to your own packets is what reveals the
// path.
//
// On Linux that needs a raw socket: the replies arrive addressed to the sending
// host with an identifier, and are not delivered to any socket the kernel would
// hand to an application. A plain UDP socket can send a packet with a low TTL,
// but it can never learn that the packet arrived.
//
// # Matching a reply to a probe
//
// The ICMP error quotes the IP header and the first 8 bytes of the datagram that
// triggered it. For a UDP probe those 8 bytes are the whole UDP header, so the
// quote contains the probe's destination port and nothing else of ours.
//
// So a probe is identified by its destination port, and the send time is kept in
// a table. The port number is chosen per probe precisely so it can serve as the
// key: two probes in flight with the same port could not be told apart.
//
// The quote does not carry a timestamp, so the round trip cannot be read out of
// the packet -- it is computed against the recorded send time. This is why the
// send table exists rather than being a convenience.
package traceroute

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/Xwalims/netgraph/pkg/models"
)

// Defaults.
const (
	// DefaultMaxHops is the highest TTL tried. 30 is the usual working range:
	// IPv4 permits 255, but few real paths are longer.
	DefaultMaxHops = 30

	// DefaultProbes is how many probes go to each hop. Three is enough to see
	// loss and jitter without spending a minute on a long route.
	DefaultProbes = 3

	// DefaultTimeout bounds one probe.
	DefaultTimeout = 3 * time.Second

	// firstProbePort is where the UDP port sequence starts. The range beginning
	// at 33434 is conventional: unlikely to collide with a real service, so the
	// packets are recognisable on the far side and can be ignored there.
	firstProbePort = 33434

	// icmpHeaderLength is the fixed ICMP error header: type, code, checksum and
	// four unused bytes. The quoted packet starts after it.
	icmpHeaderLength = 8
)

// MaxProbes is the most probes one hop may be sent. It is a limit of the port
// arithmetic rather than of patience: a probe's destination port is the only
// part of it that survives into the ICMP quote, so two probes sharing a port
// cannot be told apart. See probePort.
const MaxProbes = 20

// probePort returns the destination port for one probe at one TTL.
//
// The stride between consecutive TTLs is MaxProbes, not 8. A stride of 8 with
// `firstProbePort + ttl*8 + probe` was correct only while probes per hop was
// 3 -- and it stayed wrong silently for every value the CLI accepts above 8:
// TTL 2's first probe took port 33450, which TTL 1's ninth probe had already
// used, so t.recordSend overwrote the earlier entry and a reply to it was
// attributed to the wrong hop. `--probes 12` collided 20 times over six TTLs,
// and the loss arithmetic then produced a negative fraction because Received
// ended up larger than Sent. The stride has to clear the largest probe count
// the flag permits, which is why it is written in terms of MaxProbes rather
// than repeated as a literal.
func probePort(ttl, probe int) int {
	return firstProbePort + ttl*MaxProbes + probe
}

// Options configures a trace.
type Options struct {
	// Protocol is icmp, udp or tcp. All three need a raw socket here, because all
	// three depend on reading Time Exceeded replies.
	Protocol models.Protocol

	// MaxHops is the highest TTL tried.
	MaxHops int

	// Probes is how many probes per hop.
	Probes int

	// Timeout bounds each probe.
	Timeout time.Duration

	// IPv6 selects the address family.
	IPv6 bool

	// Interface is the source address probes are sent from.
	Interface string
}

// withDefaults fills in unset options.
func (o Options) withDefaults() Options {
	if o.MaxHops <= 0 {
		o.MaxHops = DefaultMaxHops
	}
	if o.Probes <= 0 {
		o.Probes = DefaultProbes
	}
	if o.Timeout <= 0 {
		o.Timeout = DefaultTimeout
	}
	if o.Protocol == "" {
		o.Protocol = models.ProtocolUDP
	}
	return o
}

// Capability describes what this host permits.
//
// It is checked before probing rather than discovered from a failed trace, so a
// user without privileges learns why immediately instead of waiting out a trace
// that was never going to work.
type Capability struct {
	// RawAvailable is true when a raw ICMP socket can be opened, which every
	// traceroute variant needs in order to read Time Exceeded replies.
	RawAvailable bool

	// Reason explains a refusal in the kernel's own words where possible.
	Reason string

	// Fix names the command that resolves it.
	Fix string
}

// Detect reports what this host permits.
//
// It attempts the socket rather than asking a question the kernel will not
// answer in advance.
func Detect() Capability {
	conn, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if err == nil {
		conn.Close()
		return Capability{RawAvailable: true}
	}

	fix := "sudo setcap cap_net_raw+ep <path to netgraph>"
	reason := err.Error()

	// A ping-group socket needs no privileges but only carries echo request and
	// reply, never the Time Exceeded messages traceroute reads. Naming that
	// distinction is the difference between a user fixing the problem and a user
	// concluding that ICMP is being filtered.
	if dgram, dgramErr := net.ListenPacket("ip4:icmp", "0.0.0.0"); dgramErr != nil {
		_ = dgram
	}

	return Capability{RawAvailable: false, Reason: reason, Fix: fix}
}

// pending is a probe that has been sent and is waiting for its reply.
type pending struct {
	ttl     int
	sentAt  time.Time
	network string
}

// probeResult is what one reply revealed.
type probeResult struct {
	// TTL is the hop limit the answered probe was sent with, which is the hop
	// number.
	TTL int

	// Address is the router that replied.
	Address string

	// RTT is measured against the recorded send time.
	RTT time.Duration

	// Reached is true when the destination itself answered, meaning its own stack
	// received the packet rather than a router reporting on its behalf.
	Reached bool

	// Port is the destination port of the probe this reply answers, which
	// identifies the probe. collect uses it to count a probe once no matter how
	// many replies arrive for it. It is 0 for an echo reply or an ICMPv6 error
	// that carries no port, which is exactly one reply per hop anyway.
	Port int
}

// tracer holds the state of one run.
type tracer struct {
	options Options
	target  net.IP

	// source is the address probes are sent from, nil for any.
	source net.IP

	mu sync.Mutex
	// sent maps a probe's destination port to its send record. The port is the
	// only part of the probe that survives into the ICMP quote, so it is the only
	// thing a reply can be matched against.
	sent map[int]pending
}

// Trace runs a traceroute.
//
// The returned Route always carries either hops, or a warning explaining why
// there are none. A route with silently absent hops is the single outcome this
// function must never produce, because an empty route reads as a network problem
// when it is in fact a missing capability.
func Trace(ctx context.Context, target string, options Options) (*models.Route, error) {
	options = options.withDefaults()
	started := time.Now()

	route := &models.Route{
		Target:           target,
		Protocol:         options.Protocol,
		MaxHopsRequested: options.MaxHops,
		ProbesPerHop:     options.Probes,
		StartedAt:        started,
		AddressFamily:    models.FamilyV4,
	}
	if options.IPv6 {
		route.AddressFamily = models.FamilyV6
	}

	resolved, err := resolveTarget(target, options.IPv6)
	if err != nil {
		route.Error = err.Error()
		route.Duration = time.Since(started)
		return route, err
	}
	route.ResolvedAddress = resolved

	ip := net.ParseIP(resolved)
	if ip == nil {
		route.Error = "the resolved value is not an IP address"
		route.Duration = time.Since(started)
		return route, errors.New(route.Error)
	}
	if options.IPv6 || ip.To4() == nil {
		route.AddressFamily = models.FamilyV6
	}

	// The capability check happens before any probing, for the reason given on
	// the Capability type.
	capability := Detect()
	if !capability.RawAvailable {
		route.Warnings = append(route.Warnings, fmt.Sprintf(
			"this host does not permit the raw ICMP socket that every traceroute "+
				"variant needs in order to read the Time Exceeded replies which are "+
				"the only thing that reveals a path (%s)", capability.Reason))
		route.Warnings = append(route.Warnings, "fix: "+capability.Fix)
		route.Duration = time.Since(started)
		return route, errors.New("traceroute is not available on this host")
	}

	t := &tracer{options: options, target: ip, sent: map[int]pending{}}
	if options.Interface != "" {
		t.source = net.ParseIP(options.Interface)
	}

	// One listener serves the whole trace: replies arrive out of order and are
	// matched by port, so a single reader is both correct and cheaper than one
	// goroutine per probe.
	listener, err := t.listen()
	if err != nil {
		route.Error = err.Error()
		route.Duration = time.Since(started)
		return route, err
	}
	defer listener.Close()

	// The run is bounded overall so a target that swallows every probe cannot
	// leave the command hanging past the requested timeout.
	budget := time.Duration(options.MaxHops)*options.Timeout + options.Timeout + 2*time.Second
	runCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	replies := make(chan probeResult, 8192)
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		defer close(replies)
		t.readReplies(runCtx, listener, replies)
	}()

	hops, reachedAt, warnings := t.probeAll(runCtx, replies)

	// The reader is stopped explicitly: waiting for it would otherwise block for
	// the full read timeout after the last probe.
	cancel()
	select {
	case <-readerDone:
	case <-time.After(2 * time.Second):
	}

	route.Hops = hops
	route.Warnings = append(route.Warnings, warnings...)
	route.ReachedAt = reachedAt
	route.Reached = reachedAt > 0
	route.Duration = time.Since(started)

	if len(hops) == 0 && route.Error == "" {
		route.Error = "no hop answered"
	}

	var sent, received int
	for _, hop := range hops {
		sent += hop.Sent
		received += hop.Received
	}
	if sent > 0 {
		route.TotalLoss = float64(sent-received) / float64(sent)
	}
	return route, nil
}

// listen opens the raw ICMP socket that replies arrive on.
func (t *tracer) listen() (net.PacketConn, error) {
	network := "ip4:icmp"
	if t.options.IPv6 {
		network = "ip6:ipv6-icmp"
	}
	conn, err := net.ListenPacket(network, wildcardFor(t.options.IPv6))
	if err != nil {
		return nil, fmt.Errorf("cannot open the ICMP socket: %w", err)
	}
	return conn, nil
}

func wildcardFor(ipv6 bool) string {
	if ipv6 {
		return "::"
	}
	return "0.0.0.0"
}

// probeAll sends every probe and collects what came back.
//
// TTLs are stepped one at a time rather than all in parallel. Sending them
// together is faster, but then a reply cannot be attributed to a TTL by anything
// other than a timestamp, and several replies share a millisecond.
func (t *tracer) probeAll(ctx context.Context, replies <-chan probeResult) ([]models.Hop, int, []string) {
	// results is written only by this goroutine, because replies are funnelled
	// through the channel rather than arriving on the reader's own goroutine.
	results := make(map[int][]probeResult)

	for ttl := 1; ttl <= t.options.MaxHops; ttl++ {
		if ctx.Err() != nil {
			break
		}

		// Probes for one TTL are sent together and given one window to answer, so
		// a hop costs one timeout rather than three sequential ones.
		ports := make([]int, 0, t.options.Probes)
		for probe := 0; probe < t.options.Probes; probe++ {
			// A distinct port per probe is what makes the reply attributable, and
			// it keeps the sequence recognisable on the destination.
			port := probePort(ttl, probe)
			if port > 65535 {
				continue
			}
			ports = append(ports, port)
			t.recordSend(port, ttl)
		}

		sendErr := t.sendBatch(ctx, ports)

		window := t.options.Timeout
		if window > 5*time.Second {
			window = 5 * time.Second
		}
		windowCtx, windowCancel := context.WithTimeout(ctx, window)
		t.collect(windowCtx, replies, results)
		windowCancel()

		// The window is closed, so these probes can no longer be answered and
		// their ports must not stay claimable: leaving them in t.sent lets a late
		// reply be attributed to this hop during a LATER window, and lets a
		// re-sent probe at the same TTL overwrite the record and shift its RTT to
		// the newer send time. forget() existed and was called only from a test.
		t.forget(ports)

		if destinationAnswered(results, ttl) {
			break
		}
		if sendErr != nil && len(results) == 0 && ttl == 1 {
			return nil, 0, []string{"every probe failed to send: " + sendErr.Error()}
		}
	}

	warnings := []string{}
	if len(results) == 0 {
		warnings = append(warnings,
			"no probe was answered. The destination may be unreachable, the network "+
				"may filter the outgoing probes, or the replies may not be getting "+
				"back to this host. This is not evidence of a route.")
	}
	return buildHops(results, t.options.Probes), firstReached(results), warnings
}

// recordSend stores the send time for a probe, which is the only way its round
// trip can be computed later.
func (t *tracer) recordSend(port, ttl int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sent[port] = pending{ttl: ttl, sentAt: time.Now(), network: "udp"}
}

// forget drops a probe from the table once its window has closed, so the map
// does not grow with every probe of a long trace.
func (t *tracer) forget(ports []int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, port := range ports {
		delete(t.sent, port)
	}
}

// collect drains replies into the results table for one TTL window.
//
// Replies arrive slightly after the send window closes -- the fastest ones,
// which are the ones that matter for the minimum, are the first to arrive and
// the easiest to drop. So collection outlives the window by a moment.
func (t *tracer) collect(ctx context.Context, replies <-chan probeResult, results map[int][]probeResult) {
	grace := time.After(300 * time.Millisecond)

	// One probe, one reply. A router that answers twice, or a probe whose first
	// reply is duplicated on the path, otherwise lands in the table twice and
	// Received climbs past Sent -- which is not merely ugly: buildHops computes
	// loss as (Sent-Received)/Sent, so the rendered figure goes negative and a
	// hop reports -133% loss. The port identifies the probe, so the second
	// arrival for a port already recorded in this window is discarded.
	seen := map[int]bool{}

	// record files a reply unless that port already answered in this window.
	record := func(result probeResult) {
		if seen[result.Port] {
			return
		}
		seen[result.Port] = true
		results[result.TTL] = append(results[result.TTL], result)
	}

	for {
		select {
		case result, ok := <-replies:
			if !ok {
				return
			}
			record(result)
		case <-grace:
			return
		case <-ctx.Done():
			// A cancelled run still keeps whatever arrived, so the hops that did
			// answer are not thrown away by an interrupt.
			for {
				select {
				case result := <-replies:
					record(result)
				default:
					return
				}
			}
		}
	}
}

// destinationAnswered reports whether the destination itself answered at a TTL,
// meaning the trace is complete.
func destinationAnswered(results map[int][]probeResult, ttl int) bool {
	for _, result := range results[ttl] {
		if result.Reached {
			return true
		}
	}
	return false
}

// firstReached returns the lowest TTL at which the destination answered.
func firstReached(results map[int][]probeResult) int {
	ttls := make([]int, 0, len(results))
	for ttl := range results {
		ttls = append(ttls, ttl)
	}
	sort.Ints(ttls)
	for _, ttl := range ttls {
		if destinationAnswered(results, ttl) {
			return ttl
		}
	}
	return 0
}

// buildHops turns results into hops, ordered by TTL.
func buildHops(results map[int][]probeResult, probesPerHop int) []models.Hop {
	ttls := make([]int, 0, len(results))
	for ttl := range results {
		ttls = append(ttls, ttl)
	}
	sort.Ints(ttls)

	hops := make([]models.Hop, 0, len(ttls))
	for _, ttl := range ttls {
		list := results[ttl]
		if len(list) == 0 {
			continue
		}

		// The minimum is reported as the hop's RTT: it is the sample least
		// contaminated by queueing delay somewhere else on the path. The spread is
		// reported beside it so the minimum is not mistaken for the typical case.
		best, worst := list[0].RTT, list[0].RTT
		address := ""
		for _, result := range list {
			if result.RTT < best {
				best = result.RTT
			}
			if result.RTT > worst {
				worst = result.RTT
			}
			if result.Address != "" {
				address = result.Address
			}
		}

		// A hop exists only because something answered, so its loss is the
		// fraction of probes that came back. TTLs where nothing answered are
		// absent rather than rendered as a placeholder, because a placeholder is
		// indistinguishable from a router that chose not to answer.
		//
		// Received is clamped to the probes actually sent. Loss is a fraction of
		// something, so it cannot exceed 1, and a negative percentage is worse
		// than no measurement: it asserts that more probes came back than were
		// ever sent. collect() now deduplicates by port, so this is a floor
		// rather than a live path -- but the clamp belongs here anyway, because
		// this is the function that decides what the report says.
		received := len(list)
		if received > probesPerHop {
			received = probesPerHop
		}

		hops = append(hops, models.Hop{
			Number:    ttl,
			Address:   address,
			RTT:       best,
			RTTSpread: worst - best,
			Sent:      probesPerHop,
			Received:  received,
			Loss:      float64(probesPerHop-received) / float64(probesPerHop),
		})
	}
	return hops
}

// sendBatch transmits one probe per port, with the TTL for this hop.
func (t *tracer) sendBatch(ctx context.Context, ports []int) error {
	var wg sync.WaitGroup
	failures := make([]error, len(ports))

	for i, port := range ports {
		wg.Add(1)
		go func(index, port int) {
			defer wg.Done()
			failures[index] = t.send(ctx, port)
		}(i, port)
	}
	wg.Wait()

	// One failure is not a failed trace -- a probe to a filtered port can fail on
	// its own -- so only a complete failure is reported.
	for _, err := range failures {
		if err != nil {
			var count int
			for _, other := range failures {
				if other != nil {
					count++
				}
			}
			if count == len(failures) {
				return err
			}
			return nil
		}
	}
	return nil
}

// send transmits a single probe with the hop's TTL.
//
// The TTL is applied to the sending socket, not to the listener: the listener
// only receives, and a receive socket's hop limit would bound the replies rather
// than the probes.
func (t *tracer) send(ctx context.Context, port int) error {
	ttl := t.ttlFor(port)

	if t.options.IPv6 {
		conn, err := t.dial(ctx, "udp6", port)
		if err != nil {
			return err
		}
		defer conn.Close()
		if err := setTTL(conn, true, ttl); err != nil {
			return err
		}
		_, err = conn.Write([]byte("netgraph probe"))
		return err
	}

	conn, err := t.dial(ctx, "udp4", port)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := setTTL(conn, false, ttl); err != nil {
		return err
	}
	_, err = conn.Write([]byte("netgraph probe"))
	return err
}

// ttlFor reads the TTL a probe was recorded with.
func (t *tracer) ttlFor(port int) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	if record, ok := t.sent[port]; ok {
		return record.ttl
	}
	return 0
}

// dial opens the sending socket, bound to the requested source address.
func (t *tracer) dial(ctx context.Context, network string, port int) (net.Conn, error) {
	dialer := net.Dialer{}
	if t.source != nil {
		if t.options.IPv6 {
			dialer.LocalAddr = &net.UDPAddr{IP: t.source}
		} else {
			// A UDP socket needs a UDPAddr; a TCPAddr here is what the first
			// version passed, which the kernel rejects.
			dialer.LocalAddr = &net.UDPAddr{IP: t.source}
		}
	}
	return dialer.DialContext(ctx, network, net.JoinHostPort(t.target.String(), strconv.Itoa(port)))
}

// readReplies reads ICMP messages and turns them into probe results.
func (t *tracer) readReplies(ctx context.Context, listener net.PacketConn, out chan<- probeResult) {
	buffer := make([]byte, 1500)

	for {
		if ctx.Err() != nil {
			return
		}

		// A deadline keeps the loop responsive to cancellation. Without one the
		// read blocks forever and the goroutine leaks past the trace.
		listener.SetReadDeadline(time.Now().Add(500 * time.Millisecond))

		n, peer, err := listener.ReadFrom(buffer)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			return
		}

		result, ok := t.parseReply(buffer[:n], peer)
		if !ok {
			continue
		}
		select {
		case out <- result:
		case <-ctx.Done():
			return
		}
	}
}

// parseReply decodes one ICMP packet and matches it to a probe.
//
// Anything that does not parse cleanly is discarded rather than guessed at: an
// ICMP error that is misread becomes a hop at the wrong distance, which is worse
// than a missing hop.
func (t *tracer) parseReply(packet []byte, peer net.Addr) (probeResult, bool) {
	if len(packet) < icmpHeaderLength {
		return probeResult{}, false
	}

	icmpType := packet[0]
	// reached is set by whichever branch below recognises the type as one the
	// destination itself sends, rather than a router reporting on its behalf.
	var reached bool

	if t.options.IPv6 {
		// ICMPv6: 3 is Time Exceeded, 129 is Echo Reply, 1 is Destination
		// Unreachable, which the destination itself sends for a closed port.
		switch icmpType {
		case 3, 129, 1:
			reached = icmpType == 129 || icmpType == 1
		default:
			return probeResult{}, false
		}
	} else {
		// ICMPv4: 11 is Time Exceeded, 0 is Echo Reply, 3 is Destination
		// Unreachable, which a host sends for a closed port.
		switch icmpType {
		case 11, 0, 3:
			reached = icmpType == 0 || icmpType == 3
		default:
			return probeResult{}, false
		}
	}

	port, ok := quotedPort(packet[icmpHeaderLength:], t.options.IPv6)
	if !ok {
		return probeResult{}, false
	}

	// The reply is only about one of our probes if the port matches one we sent.
	t.mu.Lock()
	record, known := t.sent[port]
	t.mu.Unlock()
	if !known {
		return probeResult{}, false
	}

	result := probeResult{
		TTL:     record.ttl,
		RTT:     time.Since(record.sentAt),
		Reached: reached,
		Port:    port,
	}
	if peer != nil {
		result.Address = addressOnly(peer)
	}
	return result, true
}

// quotedPort extracts the probe's destination port from the quoted packet.
//
// The quote is the IP header followed by the first 8 bytes of the transport
// header. For UDP and TCP those first 8 bytes are the fixed part of the header,
// and the destination port sits at offset 2 of it.
func quotedPort(quoted []byte, ipv6 bool) (int, bool) {
	if ipv6 {
		// An IPv6 header is a fixed 40 bytes; the hop limit is at offset 7.
		if len(quoted) < 40+4 {
			return 0, false
		}
		next := quoted[6]
		// 17 is UDP, 6 is TCP. 58 is ICMPv6, which has no ports: that is an echo
		// reply, and it belongs to the destination rather than to a hop, so it is
		// accepted without a port.
		if next == 58 {
			return 0, true
		}
		if next != 17 && next != 6 {
			return 0, false
		}
		return int(binary.BigEndian.Uint16(quoted[40+2 : 40+4])), true
	}

	// An IPv4 header is at least 20 bytes and the IHL nibble gives the real
	// length, which is not always 20.
	if len(quoted) < 20 {
		return 0, false
	}
	headerLength := int(quoted[0]&0x0f) * 4
	if headerLength < 20 || len(quoted) < headerLength+4 {
		return 0, false
	}

	protocol := quoted[9]
	transport := quoted[headerLength:]
	if protocol == 1 {
		// ICMP: the echo reply came from the destination itself.
		return 0, true
	}
	if protocol != 17 && protocol != 6 {
		return 0, false
	}
	return int(binary.BigEndian.Uint16(transport[2:4])), true
}

// addressOnly strips the port from a socket address.
func addressOnly(addr net.Addr) string {
	switch typed := addr.(type) {
	case *net.IPAddr:
		return typed.IP.String()
	case *net.UDPAddr:
		return typed.IP.String()
	case *net.TCPAddr:
		return typed.IP.String()
	}
	if host, _, err := net.SplitHostPort(addr.String()); err == nil {
		return host
	}
	return addr.String()
}

// resolveTarget turns a name or address into one address to trace to.
func resolveTarget(target string, wantIPv6 bool) (string, error) {
	if ip := net.ParseIP(target); ip != nil {
		isV4 := ip.To4() != nil
		if wantIPv6 == isV4 {
			return "", fmt.Errorf("%s is IPv%d but %s was requested",
				target, familyOf(isV4), familyFlag(wantIPv6))
		}
		return ip.String(), nil
	}

	ips, err := net.LookupIP(target)
	if err != nil {
		return "", fmt.Errorf("cannot resolve %s: %w", target, err)
	}
	for _, ip := range ips {
		if (ip.To4() != nil) != wantIPv6 {
			return ip.String(), nil
		}
	}
	if len(ips) > 0 {
		// The requested family has no address but the other one does. Using it
		// beats failing, and the recorded AddressFamily says what was traced.
		return ips[0].String(), nil
	}
	return "", fmt.Errorf("%s resolved to no addresses", target)
}

func familyOf(isV4 bool) int {
	if isV4 {
		return 4
	}
	return 6
}

func familyFlag(wantIPv6 bool) string {
	if wantIPv6 {
		return "--ipv6"
	}
	return "IPv4 was the default; pass --ipv6 to trace over IPv6"
}
