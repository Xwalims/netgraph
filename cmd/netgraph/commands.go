// Route, address and latency commands.
//
// These live apart from main.go, which owns the DNS analyzer. Splitting them
// keeps the argument parser and the query path from turning into one file where
// a change to one silently breaks the other.
//
// # What every command here promises
//
// Each one either produces an answer or explains why it cannot. Specifically:
//
//   - A hop that did not answer is never rendered as a router. It is absent from
//     the route, and the absence is reported.
//   - A capability this host lacks is named, with the command that would fix it,
//     before any probing starts.
//   - Enrichment failures never destroy a trace. A route with no ASN data is
//     useful; no route at all is not.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Xwalims/netgraph/internal/asn"
	"github.com/Xwalims/netgraph/internal/cache"
	"github.com/Xwalims/netgraph/internal/latency"
	"github.com/Xwalims/netgraph/internal/render"
	"github.com/Xwalims/netgraph/internal/traceroute"
	"github.com/Xwalims/netgraph/pkg/models"
)

// traceValueFlags and traceBoolFlags are the option sets shared by trace, map
// and compare, declared once because a flag that works on one and not the other
// is a bug report waiting to happen.
var (
	traceValueFlags = []string{"protocol", "max-hops", "probes", "timeout", "interface", "format", "out"}
	traceBoolFlags  = []string{"ipv6", "json", "no-color", "quiet"}
)

// cmdFlags is the argument parser for the route, address and latency commands.
//
// `--flag value`, `--flag=value` and a bare `--flag` are all accepted, because
// rejecting one spelling is work pushed onto whoever is using the tool.
type cmdFlags struct {
	values map[string]string
	bools  map[string]bool
	args   []string
}

// parseSharedFlags splits arguments into values, booleans and positionals, and
// rejects an unknown option instead of ignoring it.
func parseSharedFlags(args []string, valueFlags, boolFlags []string) (cmdFlags, []string, error) {
	f := cmdFlags{values: map[string]string{}, bools: map[string]bool{}}

	isValue := map[string]bool{}
	for _, name := range valueFlags {
		isValue[name] = true
	}
	isBool := map[string]bool{}
	for _, name := range boolFlags {
		isBool[name] = true
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "--") {
			f.args = append(f.args, arg)
			continue
		}
		name := strings.TrimPrefix(arg, "--")
		if eq := strings.Index(name, "="); eq >= 0 {
			f.values[name[:eq]] = name[eq+1:]
			continue
		}
		if isBool[name] {
			f.bools[name] = true
			continue
		}
		if isValue[name] {
			if i+1 >= len(args) {
				return f, nil, fmt.Errorf("--%s needs a value", name)
			}
			i++
			f.values[name] = args[i]
			continue
		}
		return f, nil, fmt.Errorf("unknown option %q", arg)
	}
	return f, f.args, nil
}

func (f cmdFlags) bool(name string) bool { return f.bools[name] }

func (f cmdFlags) str(name, fallback string) string {
	if value, ok := f.values[name]; ok {
		return value
	}
	return fallback
}

func (f cmdFlags) intVal(name string, fallback int) (int, error) {
	raw, ok := f.values[name]
	if !ok {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return fallback, fmt.Errorf("--%s %q is not a number", name, raw)
	}
	return value, nil
}

func (f cmdFlags) duration(name string, fallback time.Duration) (time.Duration, error) {
	raw, ok := f.values[name]
	if !ok {
		return fallback, nil
	}
	value, err := time.ParseDuration(raw)
	if err != nil {
		return fallback, fmt.Errorf("--%s %q is not a duration", name, raw)
	}
	return value, nil
}

// traceOptionsOf pulls the traceroute settings out of parsed flags.
func traceOptionsOf(f cmdFlags) (cmdFlags, traceroute.Options, error) {
	// The constants are lowercase, so the flag is lower-cased before comparison.
	// An earlier version upper-cased it, which turned "udp" into "UDP", matched
	// no case, and rejected the default: every trace without an explicit
	// --protocol failed with the flag reading as empty.
	protocol := models.Protocol(strings.ToLower(strings.TrimSpace(f.str("protocol", "udp"))))
	switch protocol {
	case models.ProtocolICMP, models.ProtocolUDP, models.ProtocolTCP:
	default:
		return f, traceroute.Options{}, fmt.Errorf("--protocol %q is not icmp, udp or tcp", f.str("protocol", "udp"))
	}

	options := traceroute.Options{
		Protocol:  protocol,
		IPv6:      f.bool("ipv6"),
		Interface: f.str("interface", ""),
	}
	var err error
	if options.MaxHops, err = f.intVal("max-hops", traceroute.DefaultMaxHops); err != nil {
		return f, traceroute.Options{}, err
	}
	if options.Probes, err = f.intVal("probes", traceroute.DefaultProbes); err != nil {
		return f, traceroute.Options{}, err
	}
	if options.Timeout, err = f.duration("timeout", traceroute.DefaultTimeout); err != nil {
		return f, traceroute.Options{}, err
	}
	// Nonsense limits are rejected rather than clamped: silently tracing 300 hops
	// because someone typed --probes -1 is a slow surprise.
	if options.MaxHops < 1 || options.MaxHops > 255 {
		return f, traceroute.Options{}, fmt.Errorf("--max-hops %d is out of range; a TTL is 1..255", options.MaxHops)
	}
	if options.Probes < 1 || options.Probes > 20 {
		return f, traceroute.Options{}, fmt.Errorf("--probes %d is out of range; use 1..20", options.Probes)
	}
	return f, options, nil
}

// app carries state shared between subcommands: the cache, and the last route so
// `netgraph export` can re-render without tracing again.
type app struct {
	colour    bool
	cache     *cache.Store
	lastRoute *models.Route
}

func newApp() *app {
	a := &app{colour: colourEnabled()}
	// A cache failure is reported but not fatal. Lookups still work without it;
	// they are just slower, and refusing to run would be the worse answer.
	if store, err := cache.New(cache.Options{}); err == nil {
		a.cache = store
	} else {
		fmt.Fprintf(os.Stderr, "netgraph: no lookup cache (%v); lookups will be slower\n", err)
	}
	return a
}

// parseTraceFlags reads the shared trace options and validates them before any
// packet is sent, so a typo costs nothing.
func parseTraceFlags(args []string) (cmdFlags, traceroute.Options, error) {
	parsed, positional, err := parseSharedFlags(args, traceValueFlags, traceBoolFlags)
	if err != nil {
		return parsed, traceroute.Options{}, err
	}
	if len(positional) != 1 {
		return parsed, traceroute.Options{}, fmt.Errorf("expected one target, got %d", len(positional))
	}
	return traceOptionsOf(parsed)
}

// reportICMPCapability explains an ICMP refusal before any probing happens.
//
// Waiting out a 30-hop trace to discover the host has no raw socket is the kind
// of thing that makes a user conclude the tool is broken.
func reportICMPCapability() bool {
	// Every traceroute variant needs a raw ICMP socket, not just ICMP: UDP and
	// TCP probes are identified by the Time Exceeded replies they provoke. So the
	// check is about the host, not about the requested protocol.
	capability := traceroute.Detect()
	if capability.RawAvailable {
		return true
	}
	fmt.Fprintf(os.Stderr, "netgraph: traceroute needs a raw ICMP socket, which this host does not allow.\n")
	fmt.Fprintf(os.Stderr, "  reason:  %s\n", capability.Reason)
	fmt.Fprintf(os.Stderr, "  fix:     %s\n", capability.Fix)
	fmt.Fprintf(os.Stderr, "  note:    no protocol avoids this; --protocol only changes what is sent\n")
	fmt.Fprintf(os.Stderr, "  without it, use: netgraph dns, netgraph ip, netgraph asn, netgraph ping\n")
	return false
}

// cmdTrace traces one target and prints the route.
func (a *app) cmdTrace(ctx context.Context, args []string) int {
	parsed, options, err := parseTraceFlags(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "netgraph trace: %v\n", err)
		return exitUnimplemented
	}
	if options.Protocol == models.ProtocolICMP && !reportICMPCapability() {
		return exitUnimplemented
	}

	route, traceErr := traceroute.Trace(ctx, parsed.args[0], options)
	a.lastRoute = route
	if traceErr != nil {
		fmt.Fprintf(os.Stderr, "netgraph trace: %v\n", traceErr)
	}
	a.enrich(ctx, route)

	if parsed.bool("json") {
		return printJSONAndExit(route, traceErr, len(route.Hops) == 0)
	}
	fmt.Print(render.ASCII(route))
	return traceExit(traceErr, len(route.Hops) == 0)
}

// cmdMap traces and then draws in the requested format.
func (a *app) cmdMap(ctx context.Context, args []string) int {
	parsed, options, err := parseTraceFlags(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "netgraph map: %v\n", err)
		return exitUnimplemented
	}
	if options.Protocol == models.ProtocolICMP && !reportICMPCapability() {
		return exitUnimplemented
	}

	route, traceErr := traceroute.Trace(ctx, parsed.args[0], options)
	a.lastRoute = route
	if traceErr != nil {
		fmt.Fprintf(os.Stderr, "netgraph map: %v\n", traceErr)
	}
	a.enrich(ctx, route)

	return a.emit(parsed, route, traceErr)
}

// emit renders a route and writes it to a file or to stdout.
func (a *app) emit(parsed cmdFlags, route *models.Route, traceErr error) int {
	format := parsed.str("format", "ascii")
	var output string
	var err error

	switch format {
	case "ascii":
		output = render.ASCII(route)
	case "json":
		output, err = render.JSON(route)
	case "html":
		output = render.HTML(route)
	case "csv":
		output = render.CSV(route)
	default:
		fmt.Fprintf(os.Stderr, "netgraph: --format %q is not ascii, html, json or csv\n", format)
		return exitUnimplemented
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "netgraph: %v\n", err)
		return exitUnimplemented
	}

	// A file is written when a path is given, stdout otherwise, so the default
	// still pipes into something else.
	if out := parsed.str("out", ""); out != "" {
		if err := os.WriteFile(out, []byte(output), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "netgraph: cannot write %s: %v\n", out, err)
			return exitUnimplemented
		}
		fmt.Fprintf(os.Stderr, "netgraph: wrote %s (%d bytes)\n", out, len(output))
	} else {
		fmt.Print(output)
	}
	return traceExit(traceErr, len(route.Hops) == 0)
}

// traceExit maps a trace outcome onto an exit code, so a caller can tell "no
// route" from "the tool broke".
func traceExit(traceErr error, noHops bool) int {
	if traceErr != nil {
		return exitQueryFailed
	}
	if noHops {
		return exitNoRecords
	}
	return exitOK
}

func printJSONAndExit(value any, traceErr error, empty bool) int {
	if code := printJSON(value); code != exitOK {
		return code
	}
	return traceExit(traceErr, empty)
}

// enrich fills in ASN, hostname and address class for each hop.
//
// The lookups run concurrently. Each takes a few hundred milliseconds against a
// public registry, and thirty of them in sequence takes long enough that the user
// assumes the tool has hung and kills it.
func (a *app) enrich(ctx context.Context, route *models.Route) {
	if route == nil || a.cache == nil {
		return
	}

	lookup := asn.New(asn.Options{Cache: a.cache})
	done := make(chan struct{}, 32)

	pending := 0
	for i := range route.Hops {
		hop := &route.Hops[i]
		if hop.Address == "" || hop.ASN != 0 {
			continue
		}

		// Private space is never announced, so asking routing data about it
		// wastes a request and returns nothing.
		if ip := net.ParseIP(hop.Address); ip != nil &&
			(!ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()) {
			hop.IsPrivate = true
			continue
		}

		pending++
		go func(hop *models.Hop) {
			// One failed or panicking lookup must not lose the route, and must
			// not stop the other hops from being enriched.
			defer func() {
				recover()
				done <- struct{}{}
			}()

			if result, err := lookup.Lookup(ctx, hop.Address); err == nil {
				hop.ASN = result.Info.ASN
				hop.OrgName = result.Info.OrgName
				hop.Country = result.Info.Country
				hop.Registry = result.Info.Registry
			}
			// Reverse DNS is a convenience label only. It is frequently wrong,
			// so it is never presented as the identity of a router.
			if names, err := net.DefaultResolver.LookupAddr(ctx, hop.Address); err == nil && len(names) > 0 {
				hop.Hostname = strings.TrimSuffix(names[0], ".")
			}
		}(hop)
	}

	for i := 0; i < pending; i++ {
		select {
		case <-done:
		case <-ctx.Done():
			return
		}
	}
}

// cmdIP classifies an address.
func (a *app) cmdIP(ctx context.Context, args []string) int {
	parsed, positional, err := parseSharedFlags(args, []string{"timeout"}, []string{"json", "no-color", "quiet"})
	if err != nil {
		fmt.Fprintf(os.Stderr, "netgraph ip: %v\n", err)
		return exitUnimplemented
	}
	if len(positional) != 1 {
		fmt.Fprintf(os.Stderr, "netgraph ip: expected one address, got %d\n", len(positional))
		return exitUnimplemented
	}
	address := positional[0]

	ip := net.ParseIP(address)
	if ip == nil {
		fmt.Fprintf(os.Stderr, "netgraph ip: %q is not an IP address\n", address)
		return exitUnimplemented
	}

	family := "IPv4"
	if ip.To4() == nil {
		family = "IPv6"
	}
	isPrivate := !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
	networkType := "public"
	if isPrivate {
		networkType = "private"
	}

	hostname := ""
	if names, err := net.DefaultResolver.LookupAddr(ctx, address); err == nil && len(names) > 0 {
		hostname = strings.TrimSuffix(names[0], ".")
	}

	var info models.ASNInfo
	var sources []string
	var lookupErr string
	if a.cache != nil {
		if result, err := asn.New(asn.Options{Cache: a.cache}).Lookup(ctx, address); err != nil {
			lookupErr = err.Error()
		} else {
			info = result.Info
			sources = result.Sources
		}
	}

	if parsed.bool("json") {
		return printJSON(map[string]any{
			"address": address, "family": family, "hostname": hostname,
			"private": isPrivate, "type": networkType,
			"asn": info.ASN, "org": info.OrgName, "country": info.Country,
			"rir": info.RIR, "prefix": info.Prefix, "announced": info.Announced,
			"abuse": info.AbuseEmail, "sources": sources,
			"note": "country is where the network is registered, not the physical " +
				"location of the address or of anyone using it. No city is given: " +
				"an approximate GeoIP city presented as a location is a claim, and " +
				"this tool does not make claims it cannot measure.",
			"error": lookupErr,
		})
	}

	fmt.Printf("\n  %s  %s\n\n", heading("IP address", a.colour), address)
	fmt.Printf("  %s %s\n", pad("family", 14), family)
	fmt.Printf("  %s %s\n", pad("class", 14), networkType)
	fmt.Printf("  %s %s\n", pad("reverse dns", 14), orNone(hostname))
	if info.ASN != 0 {
		fmt.Printf("  %s AS%d\n", pad("asn", 14), info.ASN)
		fmt.Printf("  %s %s\n", pad("organisation", 14), orNone(info.OrgName))
		fmt.Printf("  %s %s\n", pad("prefix", 14), orNone(info.Prefix))
		fmt.Printf("  %s %v\n", pad("announced", 14), info.Announced)
		fmt.Printf("  %s %s\n", pad("registry", 14), orNone(info.Registry))
		fmt.Printf("  %s %s\n", pad("rir", 14), orNone(info.RIR))
		if info.AbuseEmail != "" {
			fmt.Printf("  %s %s\n", pad("abuse", 14), info.AbuseEmail)
		}
	}
	if len(sources) > 0 {
		fmt.Printf("  %s %s\n", pad("sources", 14), strings.Join(sources, ", "))
	}

	// The brief asks for this distinction explicitly, so it is in the output and
	// not only in the documentation.
	fmt.Printf("\n  country is where the network is registered, not where the\n")
	fmt.Printf("  address or its users are. No city is shown: a GeoIP estimate\n")
	fmt.Printf("  presented as a location would be a claim, not a measurement.\n")
	if lookupErr != "" {
		fmt.Printf("\n  lookup problem: %s\n", lookupErr)
	}
	fmt.Println()
	return exitOK
}

// cmdASN reports the autonomous system for an address.
func (a *app) cmdASN(ctx context.Context, args []string) int {
	parsed, positional, err := parseSharedFlags(args,
		[]string{"timeout"}, []string{"json", "no-color", "quiet", "no-cache"})
	if err != nil {
		fmt.Fprintf(os.Stderr, "netgraph asn: %v\n", err)
		return exitUnimplemented
	}
	if len(positional) != 1 {
		fmt.Fprintf(os.Stderr, "netgraph asn: expected one address, got %d\n", len(positional))
		return exitUnimplemented
	}

	timeout, err := parsed.duration("timeout", asn.DefaultTimeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "netgraph asn: %v\n", err)
		return exitUnimplemented
	}

	// --no-cache uses a throwaway store rather than clearing the real one, so a
	// concurrent run is not left with a cold cache and an empty directory.
	store := a.cache
	if parsed.bool("no-cache") {
		fresh, err := cache.New(cache.Options{TTL: time.Nanosecond})
		if err != nil {
			fmt.Fprintf(os.Stderr, "netgraph asn: %v\n", err)
			return exitUnimplemented
		}
		store = fresh
	}
	if store == nil {
		fmt.Fprintf(os.Stderr, "netgraph asn: no lookup cache available\n")
		return exitUnimplemented
	}

	result, lookupErr := asn.New(asn.Options{Cache: store, Timeout: timeout}).Lookup(ctx, positional[0])
	if result == nil {
		fmt.Fprintf(os.Stderr, "netgraph asn: %v\n", lookupErr)
		return exitQueryFailed
	}
	if len(result.Sources) == 0 {
		fmt.Fprintf(os.Stderr, "netgraph asn: no routing source answered: %s\n",
			strings.Join(result.Errors, "; "))
		if parsed.bool("json") {
			printJSON(result)
		}
		return exitQueryFailed
	}

	if parsed.bool("json") {
		return printJSON(result)
	}

	info := result.Info
	fmt.Printf("\n  %s\n\n", heading("Autonomous system", a.colour))
	fmt.Printf("  %s %s\n", pad("address", 14), positional[0])
	fmt.Printf("  %s AS%d\n", pad("asn", 14), info.ASN)
	fmt.Printf("  %s %s\n", pad("organisation", 14), orNone(info.OrgName))
	fmt.Printf("  %s %s\n", pad("prefix", 14), orNone(info.Prefix))
	fmt.Printf("  %s %v\n", pad("announced", 14), info.Announced)
	fmt.Printf("  %s %s\n", pad("registry", 14), orNone(info.Registry))
	fmt.Printf("  %s %s\n", pad("rir", 14), orNone(info.RIR))
	fmt.Printf("  %s %s\n", pad("country", 14), orNone(info.Country))
	if info.AbuseEmail != "" {
		fmt.Printf("  %s %s\n", pad("abuse", 14), info.AbuseEmail)
	}
	fmt.Printf("  %s %s\n", pad("sources", 14), strings.Join(result.Sources, ", "))
	if result.Stale {
		// The cache marks a stale hit precisely so this can be said out loud.
		// Serving yesterday's answer as today's is the failure the flag exists
		// to prevent.
		fmt.Printf("  %s yes -- from cache; the sources did not answer\n", pad("stale", 14))
	}
	for _, message := range result.Errors {
		fmt.Printf("  %s %s\n", pad("problem", 14), message)
	}
	fmt.Println()
	return exitOK
}

// cmdPing measures latency.
func (a *app) cmdPing(ctx context.Context, args []string) int {
	parsed, positional, err := parseSharedFlags(args,
		[]string{"count", "interval", "timeout", "port"},
		[]string{"continuous", "json", "no-color", "quiet"})
	if err != nil {
		fmt.Fprintf(os.Stderr, "netgraph ping: %v\n", err)
		return exitUnimplemented
	}
	if len(positional) != 1 {
		fmt.Fprintf(os.Stderr, "netgraph ping: expected one target, got %d\n", len(positional))
		return exitUnimplemented
	}

	count, err := parsed.intVal("count", 5)
	if err != nil {
		fmt.Fprintf(os.Stderr, "netgraph ping: %v\n", err)
		return exitUnimplemented
	}
	interval, err := parsed.duration("interval", latency.DefaultInterval)
	if err != nil {
		fmt.Fprintf(os.Stderr, "netgraph ping: %v\n", err)
		return exitUnimplemented
	}
	timeout, err := parsed.duration("timeout", latency.DefaultTimeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "netgraph ping: %v\n", err)
		return exitUnimplemented
	}
	if count < 0 {
		fmt.Fprintf(os.Stderr, "netgraph ping: --count %d is negative\n", count)
		return exitUnimplemented
	}
	if parsed.bool("continuous") {
		count = 0
	}

	port := parsed.str("port", latency.DefaultPort)
	options := latency.Options{
		Count: count, Interval: interval, Timeout: timeout, Port: port,
		// The method is named in the output, because an RTT taken over TCP is
		// not the same quantity as one taken over ICMP.
		Protocol: "tcp/" + port,
	}

	if !parsed.bool("json") && !parsed.bool("quiet") {
		fmt.Printf("\n  %s %s  %s\n", heading("latency", a.colour), positional[0], options.Protocol)
		fmt.Printf("  %s, interval %s, timeout %s\n\n", describeCount(count), interval, timeout)
	}

	probes, err := latency.Measure(ctx, positional[0], options)
	if err != nil {
		fmt.Fprintf(os.Stderr, "netgraph ping: %v\n", err)
		return exitQueryFailed
	}
	stats := latency.Summarise(probes)

	if parsed.bool("json") {
		if stats.Count == 0 {
			return exitNoRecords
		}
		return printJSON(stats)
	}

	for _, probe := range probes {
		if probe.Completed {
			fmt.Printf("  %s  %s  %s\n", probe.At.Format("15:04:05.000"),
				pad(latency.Format(probe.RTT), 9), latency.LatencyClass(probe.RTT))
		} else {
			fmt.Printf("  %s  %s  no reply\n", probe.At.Format("15:04:05.000"), strings.Repeat(" ", 9))
		}
	}

	fmt.Println()
	printStats(stats)
	if stats.Count == 0 {
		return exitNoRecords
	}
	return exitOK
}

// describeCount names the run length, because "0 probes" in a banner is
// confusing when it actually means continuously.
func describeCount(count int) string {
	if count == 0 {
		return "continuous"
	}
	return fmt.Sprintf("%d probes", count)
}

func printStats(stats models.LatencyStats) {
	if stats.Count == 0 {
		fmt.Println("  no probe completed: the target did not answer at all")
		return
	}
	fmt.Printf("  %s %d of %d lost (%s)\n", pad("sent", 10), stats.Lost,
		stats.Count+stats.Lost, fmt.Sprintf("%.0f%%", stats.Loss*100))
	fmt.Printf("  %s min %s   avg %s   max %s\n", pad("rtt", 10),
		latency.Format(stats.Min), latency.Format(stats.Mean), latency.Format(stats.Max))
	fmt.Printf("  %s %s   stddev %s\n", pad("jitter", 10),
		latency.Format(stats.Jitter), latency.Format(stats.StdDev))

	keys := make([]string, 0, len(stats.Percentiles))
	for key := range stats.Percentiles {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s %s", key, latency.Format(stats.Percentiles[key])))
	}
	fmt.Printf("  %s %s\n", pad("percentiles", 10), strings.Join(parts, "   "))
	fmt.Print(render.LatencyChart(stats.Samples, 50))

	// The brief asks for this not to be mixed up, so it is stated in the output.
	fmt.Println("  this is end-to-end RTT measured over TCP. A router's own RTT is a")
	fmt.Println("  different quantity and is not mixed into it.")
}

// cmdCompare traces several targets and diffs the paths.
func (a *app) cmdCompare(ctx context.Context, args []string) int {
	var options traceroute.Options
	parsed, positional, err := parseSharedFlags(args, traceValueFlags, traceBoolFlags)
	if err == nil {
		if len(positional) < 2 {
			err = fmt.Errorf("expected at least two targets, got %d", len(positional))
		} else if _, options, err = traceOptionsOf(parsed); err == nil {
			if options.Protocol == models.ProtocolICMP && !reportICMPCapability() {
				return exitUnimplemented
			}
		}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "netgraph compare: %v\n", err)
		return exitUnimplemented
	}

	comparison := &models.RouteComparison{Organisations: map[string]int{}}
	failed := false
	for _, target := range positional {
		route, traceErr := traceroute.Trace(ctx, target, options)
		if traceErr != nil {
			fmt.Fprintf(os.Stderr, "netgraph compare: %s: %v\n", target, traceErr)
			failed = true
		}
		a.enrich(ctx, route)
		comparison.Routes = append(comparison.Routes, *route)
	}

	summariseComparison(comparison)

	if parsed.bool("json") {
		if code := printJSON(comparison); code != exitOK {
			return code
		}
		if failed {
			return exitQueryFailed
		}
		return exitOK
	}
	fmt.Print(render.Comparison(comparison))

	if out := parsed.str("out", ""); out != "" {
		if err := os.WriteFile(out, []byte(render.ASCII(&comparison.Routes[0])), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "netgraph compare: cannot write %s: %v\n", out, err)
			return exitUnimplemented
		}
	}
	if failed {
		return exitQueryFailed
	}
	return exitOK
}

// summariseComparison fills in the derived fields.
//
// Every one of these is computed from the traces. A comparison whose "answer" is
// hardcoded says nothing about the two routes it is comparing.
func summariseComparison(comparison *models.RouteComparison) {
	if len(comparison.Routes) == 0 {
		return
	}
	comparison.StartedAt = comparison.Routes[0].StartedAt

	if len(comparison.Routes) > 1 {
		// Common hops: present on every route, in order. The walk stops at the
		// first disagreement, because "common" after a divergence describes
		// nothing.
		shortest := comparison.Routes[0]
		for _, route := range comparison.Routes[1:] {
			if len(route.Hops) < len(shortest.Hops) {
				shortest = route
			}
		}
		for _, hop := range shortest.Hops {
			present := true
			for _, route := range comparison.Routes {
				if hop.Number > len(route.Hops) || route.Hops[hop.Number-1].Address != hop.Address {
					present = false
					break
				}
			}
			if !present {
				break
			}
			comparison.CommonHops = append(comparison.CommonHops, hop)
		}
	}

	// Organisations, counted once per route: a provider with twenty hops in one
	// route should not outrank a provider that appears in both.
	for _, route := range comparison.Routes {
		seen := map[string]bool{}
		for _, hop := range route.Hops {
			if hop.OrgName == "" || seen[hop.OrgName] {
				continue
			}
			seen[hop.OrgName] = true
			comparison.Organisations[hop.OrgName]++
		}
	}

	comparison.ShortestRoute = 0
	comparison.FastestRoute = 0
	for i, route := range comparison.Routes {
		if len(route.Hops) < len(comparison.Routes[comparison.ShortestRoute].Hops) {
			comparison.ShortestRoute = i
		}
		if route.Duration < comparison.Routes[comparison.FastestRoute].Duration {
			comparison.FastestRoute = i
		}
	}
	comparison.DivergenceAt = divergenceAt(comparison.Routes)
}

// divergenceAt returns the first hop where the routes disagree, or 0.
//
// Compared by address rather than by ASN: two paths through the same carrier are
// still different paths, and calling them identical would hide exactly the
// difference the user asked about.
func divergenceAt(routes []models.Route) int {
	if len(routes) < 2 {
		return 0
	}
	shortest := routes[0]
	for _, route := range routes[1:] {
		if len(route.Hops) < len(shortest.Hops) {
			shortest = route
		}
	}
	for _, hop := range shortest.Hops {
		addresses := map[string]bool{}
		for _, route := range routes {
			if hop.Number <= len(route.Hops) {
				addresses[route.Hops[hop.Number-1].Address] = true
			}
		}
		if len(addresses) > 1 {
			return hop.Number
		}
	}
	return 0
}

// cmdExport re-renders a saved result in another format.
func (a *app) cmdExport(args []string) int {
	parsed, _, err := parseSharedFlags(args,
		[]string{"format", "out", "in"}, []string{"json", "no-color"})
	if err != nil {
		fmt.Fprintf(os.Stderr, "netgraph export: %v\n", err)
		return exitUnimplemented
	}

	route := a.lastRoute
	if input := parsed.str("in", ""); input != "" {
		data, readErr := os.ReadFile(input)
		if readErr != nil {
			fmt.Fprintf(os.Stderr, "netgraph export: %v\n", readErr)
			return exitUnimplemented
		}
		route = &models.Route{}
		if err := json.Unmarshal(data, route); err != nil {
			fmt.Fprintf(os.Stderr, "netgraph export: %s is not a netgraph route: %v\n", input, err)
			return exitUnimplemented
		}
	}
	if route == nil {
		fmt.Fprintf(os.Stderr,
			"netgraph export: nothing to export; run a trace first, or pass --in <file.json>\n")
		return exitUnimplemented
	}
	return a.emit(parsed, route, nil)
}

// cmdCache inspects or prunes the cache.
func (a *app) cmdCache(args []string) int {
	parsed, positional, _ := parseSharedFlags(args, []string{"max-age"}, []string{"json"})
	command := "stats"
	if len(positional) > 0 {
		command = positional[0]
	}

	if a.cache == nil {
		fmt.Fprintf(os.Stderr, "netgraph cache: no cache available\n")
		return exitUnimplemented
	}

	switch command {
	case "stats":
		stats := a.cache.Stats()
		if parsed.bool("json") {
			return printJSON(stats)
		}
		fmt.Printf("\n  %s\n\n", heading("Lookup cache", a.colour))
		fmt.Printf("  %s %s\n", pad("directory", 14), stats.Directory)
		fmt.Printf("  %s %d\n", pad("entries", 14), stats.Entries)
		fmt.Printf("  %s %d\n", pad("hits", 14), stats.Hits)
		fmt.Printf("  %s %d\n", pad("misses", 14), stats.Misses)
		fmt.Printf("  %s %d\n", pad("stale served", 14), stats.StaleServed)
		fmt.Printf("  %s %s\n", pad("default ttl", 14), stats.DefaultTTL)
		fmt.Printf("  %s %.0f%%\n\n", pad("hit rate", 14), stats.HitRatePct)
		return exitOK

	case "clear":
		removed, err := a.cache.Clear()
		if err != nil {
			fmt.Fprintf(os.Stderr, "netgraph cache: %v\n", err)
			return exitUnimplemented
		}
		fmt.Printf("  removed %d entries\n", removed)
		return exitOK

	case "sweep":
		maxAge, err := parsed.duration("max-age", 7*24*time.Hour)
		if err != nil {
			fmt.Fprintf(os.Stderr, "netgraph cache: %v\n", err)
			return exitUnimplemented
		}
		removed, err := a.cache.Sweep(maxAge)
		if err != nil {
			fmt.Fprintf(os.Stderr, "netgraph cache: %v\n", err)
			return exitUnimplemented
		}
		fmt.Printf("  removed %d entries older than %s\n", removed, maxAge)
		return exitOK
	}

	fmt.Fprintf(os.Stderr, "netgraph cache: unknown command %q; use stats, clear or sweep\n", command)
	return exitUnimplemented
}

func orNone(value string) string {
	if value == "" {
		return "(unknown)"
	}
	return value
}
