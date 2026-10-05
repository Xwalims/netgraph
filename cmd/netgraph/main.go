// Command netgraph inspects a network path.
//
// # Scope of this build
//
// The traceroute engine, the TUI, the HTML exporter and the watch command are
// not implemented yet. Rather than ship commands that print nothing, every
// unimplemented command reports that plainly and exits non-zero, so a script
// depending on it fails loudly instead of silently succeeding.
//
// What does work today is the DNS analyzer, which is a complete implementation:
// it builds and parses DNS messages itself, supports every record type in the
// brief, compares servers, and reports RTT and TTL from real responses.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/Xwalims/netgraph/internal/dns"
)

// version is the module's version. It is stated once so the banner, --version
// and the build metadata cannot drift apart.
const version = "0.2.0"

const usage = `netgraph %s -- see how the internet reaches your destination

Usage:
  netgraph trace <target>        trace the route to a target
  netgraph map <target>          trace, then draw the route
  netgraph dns <domain>          resolve a name and show every record type
  netgraph ip <address>          classify an address
  netgraph asn <address>         look up an autonomous system
  netgraph ping <target>         measure latency
  netgraph compare <a> <b>...    trace several targets and diff the paths
  netgraph export                re-render a saved result in another format
  netgraph cache [cmd]           stats, clear or sweep the lookup cache
  netgraph watch <target>        monitor a route (not yet implemented)
  netgraph version               print the version
  netgraph help                  print this message

Options for trace, map and compare:
  --protocol icmp|udp|tcp      probe method (default udp)
  --max-hops <n>               highest TTL to try (default 30)
  --probes <n>                 probes per hop (default 3)
  --timeout <duration>         overall timeout (default 3s)
  --ipv6                       trace over IPv6
  --interface <address>        bind probes to a source address
  --format ascii|html|json|csv output format for map (default ascii)
  --out <path>                 write to a file instead of stdout

Options for ip, asn and ping:
  --count <n>                  probes to send (default 5)
  --interval <duration>        pause between probes (default 1s)
  --continuous                 keep sending until interrupted
  --port <n>                   TCP port to measure against (default 443)
  --no-cache                   refetch instead of using the cache

Options for dns:
  --server <addr>       query this nameserver instead of the system resolver
  --type <record>       query one record type (A, AAAA, MX, NS, TXT, SOA,
                        SRV, CAA, CNAME). May be repeated; duplicates are
                        collapsed.
  --all                query every record type that applies to a name
  --compare            query several servers and report the differences
  --reverse            treat the argument as an address and do a PTR lookup
  --timeout <duration>  per-query timeout (default 5s)
  --json               machine-readable output
  --no-color           disable colour (also honours NO_COLOR)
  --quiet              print values only, with no headings

Exit codes:
  0  success
  1  the query succeeded but returned no records
  2  the query failed, or the command is not implemented
`

func main() {
	os.Exit(run(os.Args[1:]))
}

// Exit codes, in one place.
//
// A failed query must be distinguishable from a successful query that found
// nothing: 1 means "the name has no such records", 2 means "I could not find
// out". Collapsing them told a script that a timed-out resolver had answered,
// which is the specific failure this tool exists to catch.
const (
	exitOK            = 0
	exitNoRecords     = 1
	exitUnimplemented = 2
	exitQueryFailed   = 2
)

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usageFmt())
		return exitUnimplemented
	}

	switch args[0] {
	case "help", "-h", "--help":
		fmt.Print(usageFmt())
		return exitOK
	case "version", "--version", "-v":
		fmt.Printf("netgraph %s\n", version)
		return exitOK
	}

	// Ctrl-C and SIGTERM must stop the command promptly rather than after the
	// last timeout, so the context is created once here and handed down.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// The DNS path keeps its own resolver and flag handling in this file; the
	// route, address and latency commands live in commands.go, next to the
	// shared argument parser.
	tool := newApp()

	switch args[0] {
	case "dns":
		return runDNS(ctx, args[1:])
	case "trace":
		return tool.cmdTrace(ctx, args[1:])
	case "map":
		return tool.cmdMap(ctx, args[1:])
	case "ip":
		return tool.cmdIP(ctx, args[1:])
	case "asn":
		return tool.cmdASN(ctx, args[1:])
	case "ping":
		return tool.cmdPing(ctx, args[1:])
	case "compare":
		return tool.cmdCompare(ctx, args[1:])
	case "export":
		return tool.cmdExport(args[1:])
	case "cache":
		return tool.cmdCache(args[1:])
	}

	fmt.Fprintf(os.Stderr, "netgraph: unknown command %q\n\n", args[0])
	fmt.Fprint(os.Stderr, usageFmt())
	return exitUnimplemented
}

func usageFmt() string {
	return strings.Replace(usage, "%s", version, 1)
}

// dnsFlags holds the parsed options for the dns command.
type dnsFlags struct {
	server  string
	types   []string
	all     bool
	compare bool
	reverse bool
	timeout time.Duration
	asJSON  bool
	colour  bool
	quiet   bool
}

func parseDNSFlags(args []string) (dnsFlags, []string, error) {
	flags := dnsFlags{timeout: 5 * time.Second, colour: colourEnabled()}
	var positional []string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		next := func() (string, error) {
			if i+1 >= len(args) {
				return "", fmt.Errorf("%s needs a value", arg)
			}
			i++
			return args[i], nil
		}

		switch arg {
		case "--server":
			value, err := next()
			if err != nil {
				return flags, nil, err
			}
			flags.server = value
		case "--type":
			value, err := next()
			if err != nil {
				return flags, nil, err
			}
			flags.types = append(flags.types, value)
		case "--timeout":
			value, err := next()
			if err != nil {
				return flags, nil, err
			}
			duration, err := time.ParseDuration(value)
			if err != nil {
				return flags, nil, fmt.Errorf("--timeout %q is not a duration: %w", value, err)
			}
			flags.timeout = duration
		case "--all":
			flags.all = true
		case "--compare":
			flags.compare = true
		case "--reverse":
			flags.reverse = true
		case "--json":
			flags.asJSON = true
		case "--quiet", "-q":
			flags.quiet = true
		case "--no-color", "--no-colour":
			flags.colour = false
		default:
			if strings.HasPrefix(arg, "-") {
				return flags, nil, fmt.Errorf("unknown option %q", arg)
			}
			positional = append(positional, arg)
		}
	}

	return flags, positional, nil
}

func runDNS(ctx context.Context, args []string) int {
	flags, positional, err := parseDNSFlags(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "netgraph: %v\n", err)
		return exitUnimplemented
	}

	if len(positional) == 0 {
		fmt.Fprintf(os.Stderr, "netgraph dns: no name given\n")
		return exitUnimplemented
	}
	if len(positional) > 1 {
		fmt.Fprintf(os.Stderr, "netgraph dns: expected one name, got %d\n", len(positional))
		return exitUnimplemented
	}
	name := positional[0]

	types, err := requestedTypes(flags)
	if err != nil {
		fmt.Fprintf(os.Stderr, "netgraph dns: %v\n", err)
		return exitUnimplemented
	}

	if flags.compare {
		return runDNSCompare(ctx, name, types, flags)
	}
	return runDNSSingle(ctx, name, types, flags)
}

// requestedTypes decides which record types to ask for, and rejects nonsense
// before any query is sent.
//
// --all walks the forward types only. PTR asks about an address rather than a
// name, so including it made every --all end with the error "google.com is not
// an IP address", which reads as a server failure rather than as a question
// that cannot apply.
func requestedTypes(flags dnsFlags) ([]string, error) {
	if flags.reverse {
		return []string{"PTR"}, nil
	}
	if flags.all {
		names := make([]string, 0, len(dns.ForwardTypes))
		for _, t := range dns.ForwardTypes {
			names = append(names, string(t))
		}
		return names, nil
	}
	if len(flags.types) == 0 {
		return []string{"A", "AAAA"}, nil
	}

	// Repeats are collapsed rather than rejected: "--type A --type A" is a
	// typo, and re-running the same query and printing the answer twice is
	// noise, not a different answer. What matters is that the user sees one
	// result for the type they named.
	seen := map[string]bool{}
	types := make([]string, 0, len(flags.types))
	for _, raw := range flags.types {
		parsed, err := dns.ParseRecordType(raw)
		if err != nil {
			return nil, err
		}
		key := string(parsed)
		if seen[key] {
			continue
		}
		seen[key] = true
		types = append(types, key)
	}
	return types, nil
}

func runDNSSingle(ctx context.Context, name string, types []string, flags dnsFlags) int {
	options := dns.Options{Timeout: flags.timeout}
	if flags.server != "" {
		options.Servers = []string{flags.server}
	}
	resolver := dns.New(options)

	if flags.asJSON {
		return runDNSJSON(ctx, resolver, name, types, flags)
	}

	// --quiet promises "values only, no headings". The DNS/name/server header
	// block used to print anyway, which broke the one mode a script would use
	// to pipe values into something else.
	if !flags.quiet {
		fmt.Printf("\n  %s\n", heading("DNS", flags.colour))
		fmt.Printf("  %s %s\n", pad("name", 10), name)
		fmt.Printf("  %s %s\n", pad("server", 10), serverLabel(flags.server, flags.reverse))
		fmt.Printf("  %s %s\n\n", pad("timeout", 10), flags.timeout)
	}

	total := 0
	failed := false
	for _, recordType := range types {
		result, err := resolver.Lookup(ctx, name, recordType)
		if err != nil {
			failed = true
			if flags.quiet {
				fmt.Fprintf(os.Stderr, "%s: %v\n", recordType, err)
			} else {
				fmt.Printf("  %s %s\n", pad(recordType, 6), dim("error: "+err.Error(), flags.colour))
			}
			continue
		}
		total += printRecords(result, flags)
	}

	if !flags.quiet {
		fmt.Printf("\n")
	}
	switch {
	case failed:
		// At least one question could not be answered. Saying "no records
		// found" here claimed the name has no records of that type, when the
		// truth is that the resolver never replied.
		if !flags.quiet {
			fmt.Printf("  the query failed against at least one nameserver\n")
		}
		return exitQueryFailed
	case total == 0:
		if !flags.quiet {
			fmt.Printf("  no records found\n")
		}
		return exitNoRecords
	}
	return exitOK
}

func printRecords(result *dns.Result, flags dnsFlags) int {
	if flags.quiet {
		for _, record := range result.Records {
			fmt.Println(record.Value)
		}
		// Warnings still go to stderr in quiet mode: quiet controls stdout's
		// shape, not whether the tool is allowed to say it knows less than it
		// was asked for.
		for _, warning := range result.Warnings {
			fmt.Fprintf(os.Stderr, "warning: %s\n", warning)
		}
		return len(result.Records)
	}

	meta := fmt.Sprintf("%d records  rtt=%s  rcode=%s",
		len(result.Records),
		result.RTT.Round(time.Microsecond*100),
		result.Response)

	if result.Truncated {
		meta += "  TRUNCATED"
	}
	fmt.Printf("  %s %s\n", pad(string(result.Type), 6), dim(meta, flags.colour))
	if result.RCode != 0 && len(result.Records) == 0 {
		fmt.Printf("        %s\n", dim("the name has no records of this type (rcode "+result.Response+")", flags.colour))
	}
	// A warning that never reaches the user makes a partial answer look
	// complete, which is the exact thing the resolver went out of its way to
	// record.
	for _, warning := range result.Warnings {
		fmt.Printf("        %s\n", dim("warning: "+warning, flags.colour))
	}
	for _, record := range result.Records {
		line := fmt.Sprintf("        %-32s", record.Value)
		if record.TTLKnown {
			line += fmt.Sprintf(" ttl=%d", record.TTL)
		}
		if record.Priority != 0 {
			line += fmt.Sprintf("  priority=%d", record.Priority)
		}
		if record.Port != 0 {
			line += fmt.Sprintf("  weight=%d port=%d", record.Weight, record.Port)
		}
		// The value column is padded for alignment, so a record with no TTL
		// and no priority ends in whitespace. Trailing blanks make a diff of
		// two runs look like something changed when nothing did.
		fmt.Println(strings.TrimRight(line, " "))
	}
	fmt.Println()
	return len(result.Records)
}

// runDNSCompare queries several servers and reports where they disagree, which
// is the whole point of --compare: a name that resolves differently depending on
// who is asked is either a misconfiguration or an attack in progress.
func runDNSCompare(ctx context.Context, name string, types []string, flags dnsFlags) int {
	servers := []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"}
	if flags.server != "" {
		servers = []string{flags.server}
	}

	type serverResult struct {
		Server  string   `json:"server"`
		Type    string   `json:"type"`
		Records []string `json:"records"`
		Error   string   `json:"error,omitempty"`
		RTT     string   `json:"rtt"`
	}

	var results []serverResult
	for _, server := range servers {
		for _, recordType := range types {
			resolver := dns.New(dns.Options{Servers: []string{server}, Timeout: flags.timeout})
			result, err := resolver.Lookup(ctx, name, recordType)
			entry := serverResult{Server: server, Type: recordType}
			if err != nil {
				entry.Error = err.Error()
			} else {
				for _, record := range result.Records {
					entry.Records = append(entry.Records, string(record.Type)+" "+record.Value)
				}
				sort.Strings(entry.Records)
				entry.RTT = result.RTT.Round(time.Microsecond * 100).String()
			}
			results = append(results, entry)
		}
	}

	if flags.asJSON {
		return printJSON(map[string]any{
			"name":    name,
			"servers": results,
		})
	}

	fmt.Printf("\n  %s   %s\n\n", heading("DNS comparison", flags.colour), name)
	for _, entry := range results {
		fmt.Printf("  %s\n", pad(entry.Server+"/"+entry.Type, 16))
		if entry.Error != "" {
			fmt.Printf("        %s\n", dim("error: "+entry.Error, flags.colour))
			continue
		}
		fmt.Printf("        %s  rtt=%s\n", dim(fmt.Sprintf("%d records", len(entry.Records)), flags.colour), entry.RTT)
		for _, record := range entry.Records {
			fmt.Printf("          %s\n", record)
		}
	}

	// Report agreement explicitly rather than leaving the reader to compare.
	byType := map[string]map[string][]string{}
	// A server that failed contributed nothing to the tally, so its silence
	// used to read as agreement. "two resolvers agree" when one of the three
	// never answered is a claim the data does not support.
	unverified := map[string]bool{}
	for _, entry := range results {
		if entry.Error != "" {
			unverified[entry.Type] = true
			continue
		}
		for _, record := range entry.Records {
			fields := strings.SplitN(record, " ", 2)
			recordType := fields[0]
			value := ""
			if len(fields) > 1 {
				value = fields[1]
			}
			if byType[recordType] == nil {
				byType[recordType] = map[string][]string{}
			}
			byType[recordType][value] = append(byType[recordType][value], entry.Server)
		}
	}

	fmt.Printf("\n  %s\n", dim("agreement:", flags.colour))
	typesSeen := make([]string, 0, len(byType))
	for recordType := range byType {
		typesSeen = append(typesSeen, recordType)
	}
	sort.Strings(typesSeen)

	divergent := false
	for _, recordType := range typesSeen {
		values := byType[recordType]
		if len(values) == 1 {
			value := ""
			for v := range values {
				value = v
			}
			if unverified[recordType] {
				fmt.Printf("    %s %s\n", pad(recordType, 8),
					dim("UNVERIFIED: only the servers that answered were counted", flags.colour))
				continue
			}
			if len(servers) < 2 {
				// One server cannot disagree with itself. Calling that
				// "consistent" would read as a finding.
				fmt.Printf("    %s %s\n", pad(recordType, 8),
					dim(fmt.Sprintf("single server: %s", value), flags.colour))
				continue
			}
			fmt.Printf("    %s %s\n", pad(recordType, 8), dim("consistent: "+value, flags.colour))
			continue
		}
		divergent = true
		fmt.Printf("    %s %s\n", pad(recordType, 8), "DIVERGENT")
		seen := make([]string, 0, len(values))
		for v := range values {
			seen = append(seen, v)
		}
		sort.Strings(seen)
		for _, value := range seen {
			fmt.Printf("        %s %s\n", pad(value, 32), strings.Join(values[value], ", "))
		}
	}
	fmt.Println()

	// A server that could not be reached leaves the question partly unanswered,
	// so it is a failure of the run even when the answers that did arrive agree.
	for _, recordType := range sortedKeys(unverified) {
		fmt.Fprintf(os.Stderr, "netgraph: %s could not be verified on at least one server\n", recordType)
		return exitQueryFailed
	}
	if divergent {
		return exitOK // A divergence is a finding, not a failure.
	}
	return exitOK
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// dnsJSONResult is the machine-readable shape, kept as a named type so the
// documented schema has one definition.
type dnsJSONResult struct {
	Name    string          `json:"name"`
	Server  string          `json:"server"`
	Results []dnsJSONRecord `json:"results"`
}

type dnsJSONRecord struct {
	Type      string   `json:"type"`
	RTT       string   `json:"rtt"`
	RCode     int      `json:"rcode"`
	Response  string   `json:"response"`
	Truncated bool     `json:"truncated"`
	Values    []string `json:"values"`
	TTL       []uint32 `json:"ttl,omitempty"`
	Error     string   `json:"error,omitempty"`
	Warnings  []string `json:"warnings,omitempty"`
}

func runDNSJSON(ctx context.Context, resolver *dns.Resolver, name string, types []string, flags dnsFlags) int {
	output := dnsJSONResult{Name: name, Server: serverLabel(flags.server, flags.reverse)}
	total := 0
	failed := false

	for _, recordType := range types {
		result, err := resolver.Lookup(ctx, name, recordType)
		entry := dnsJSONRecord{Type: recordType}
		if err != nil {
			entry.Error = err.Error()
			output.Results = append(output.Results, entry)
			failed = true
			continue
		}
		entry.RTT = result.RTT.Round(time.Microsecond * 100).String()
		entry.RCode = result.RCode
		entry.Response = result.Response
		entry.Truncated = result.Truncated
		entry.Warnings = result.Warnings
		for _, record := range result.Records {
			entry.Values = append(entry.Values, record.Value)
			if record.TTLKnown {
				entry.TTL = append(entry.TTL, record.TTL)
			}
		}
		total += len(entry.Values)
		output.Results = append(output.Results, entry)
	}

	printJSON(output)
	if failed {
		return exitQueryFailed
	}
	if total == 0 {
		return exitNoRecords
	}
	return exitOK
}

func printJSON(payload any) int {
	encoded, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "netgraph: cannot encode output: %v\n", err)
		return exitUnimplemented
	}
	fmt.Println(string(encoded))
	return exitOK
}

// serverLabel describes who was actually asked.
//
// A PTR lookup used to ignore --server and go to the operating system's
// resolver, and this function printed the requested server anyway, so the output
// named a nameserver that had never been queried. Both branches say "system
// resolver" because that is the only path that reaches one, but the reverse
// case is spelled out so a future fix has to change this and not just the
// resolver.
func serverLabel(server string, reverse bool) string {
	if server != "" {
		if reverse {
			return server + " (PTR is queried directly; no system resolver is used)"
		}
		return server
	}
	return "system resolver"
}

func colourEnabled() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if os.Getenv("FORCE_COLOR") != "" {
		return true
	}
	info, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func heading(text string, colour bool) string {
	if !colour {
		return text
	}
	return "\033[1m" + text + "\033[0m"
}

func dim(text string, colour bool) string {
	if !colour {
		return text
	}
	return "\033[2m" + text + "\033[0m"
}

func pad(text string, width int) string {
	if len(text) >= width {
		return text
	}
	return text + strings.Repeat(" ", width-len(text))
}
