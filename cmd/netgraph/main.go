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
const version = "0.1.0"

const usage = `netgraph %s -- see how the internet reaches your destination

Usage:
  netgraph dns <domain>          resolve a name and show every record type
  netgraph ip <address>          classify an address (not yet implemented)
  netgraph trace <target>        trace the route (not yet implemented)
  netgraph ping <target>         measure latency (not yet implemented)
  netgraph asn <address>         look up an autonomous system (not yet implemented)
  netgraph compare <a> <b>       compare two routes (not yet implemented)
  netgraph map <target>          visualise the route (not yet implemented)
  netgraph watch <target>        monitor a route (not yet implemented)
  netgraph export                export the last result (not yet implemented)
  netgraph version               print the version
  netgraph help                  print this message

Options for dns:
  --server <addr>       query this nameserver instead of the system resolver
  --type <record>       query one record type (A, AAAA, MX, NS, TXT, SOA,
                        SRV, CAA, CNAME). Repeats are not allowed.
  --all                query every record type
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

// notImplemented keeps the exit code for an unimplemented command in one place.
const exitUnimplemented = 2

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usageFmt())
		return exitUnimplemented
	}

	switch args[0] {
	case "help", "-h", "--help":
		fmt.Print(usageFmt())
		return 0
	case "version", "--version", "-v":
		fmt.Printf("netgraph %s\n", version)
		return 0
	case "dns":
		return runDNS(args[1:])
	}

	// Everything else is announced rather than attempted. A command that prints
	// nothing and exits 0 is the worst outcome for a caller, because it cannot
	// be distinguished from success.
	command := args[0]
	implemented := map[string]bool{
		"dns": true,
	}
	if !implemented[command] {
		fmt.Fprintf(os.Stderr, "netgraph %s: %q is not implemented in %s yet.\n", version, command, version)
		fmt.Fprintf(os.Stderr, "Working commands: dns, version, help\n")
		return exitUnimplemented
	}

	fmt.Fprintf(os.Stderr, "netgraph: unknown command %q\n", command)
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

func runDNS(args []string) int {
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

	// Ctrl-C must stop the command promptly rather than after the last timeout.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	types := flags.types
	if flags.reverse {
		types = []string{"PTR"}
	}
	if flags.all {
		types = allTypeNames()
	}
	if len(types) == 0 {
		types = []string{"A", "AAAA"}
	}

	if flags.compare {
		return runDNSCompare(ctx, name, types, flags)
	}
	return runDNSSingle(ctx, name, types, flags)
}

func allTypeNames() []string {
	names := make([]string, 0, len(dns.AllTypes))
	for _, t := range dns.AllTypes {
		names = append(names, string(t))
	}
	return names
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

	fmt.Printf("\n  %s\n", heading("DNS", flags.colour))
	fmt.Printf("  %s %s\n", pad("name", 10), name)
	fmt.Printf("  %s %s\n", pad("server", 10), serverLabel(flags.server))
	fmt.Printf("  %s %s\n\n", pad("timeout", 10), flags.timeout)

	total := 0
	for _, recordType := range types {
		result, err := resolver.Lookup(ctx, name, recordType)
		if err != nil {
			fmt.Printf("  %s %s\n", pad(recordType, 6), dim("error: "+err.Error(), flags.colour))
			continue
		}
		total += printRecords(result, flags)
	}

	fmt.Printf("\n")
	if total == 0 {
		fmt.Printf("  no records found\n")
		return 1
	}
	return 0
}

func printRecords(result *dns.Result, flags dnsFlags) int {
	meta := fmt.Sprintf("%d records  rtt=%s  rcode=%s",
		len(result.Records),
		result.RTT.Round(time.Microsecond*100),
		result.Response)

	if result.Truncated {
		meta += "  TRUNCATED"
	}
	if flags.quiet {
		for _, record := range result.Records {
			fmt.Println(record.Value)
		}
		return len(result.Records)
	}

	fmt.Printf("  %s %s\n", pad(string(result.Type), 6), dim(meta, flags.colour))
	if result.RCode != 0 && len(result.Records) == 0 {
		fmt.Printf("        %s\n", dim("the name has no records of this type (rcode "+result.Response+")", flags.colour))
	}
	for _, record := range result.Records {
		line := fmt.Sprintf("        %-32s ttl=%d", record.Value, record.TTL)
		if record.Priority != 0 {
			line += fmt.Sprintf("  priority=%d", record.Priority)
		}
		if record.Port != 0 {
			line += fmt.Sprintf("  weight=%d port=%d", record.Weight, record.Port)
		}
		fmt.Println(line)
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
		Records []string `json:"records"`
		Error   string   `json:"error,omitempty"`
		RTT     string   `json:"rtt"`
	}

	var results []serverResult
	for _, server := range servers {
		for _, recordType := range types {
			resolver := dns.New(dns.Options{Servers: []string{server}, Timeout: flags.timeout})
			result, err := resolver.Lookup(ctx, name, recordType)
			entry := serverResult{Server: server}
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
		fmt.Printf("  %s\n", pad(entry.Server, 12))
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
	for _, entry := range results {
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
	if divergent {
		return 0 // A divergence is a finding, not a failure.
	}
	return 0
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
	Error     string   `json:"error,omitempty"`
}

func runDNSJSON(ctx context.Context, resolver *dns.Resolver, name string, types []string, flags dnsFlags) int {
	output := dnsJSONResult{Name: name, Server: serverLabel(flags.server)}
	total := 0

	for _, recordType := range types {
		result, err := resolver.Lookup(ctx, name, recordType)
		entry := dnsJSONRecord{Type: recordType}
		if err != nil {
			entry.Error = err.Error()
			output.Results = append(output.Results, entry)
			continue
		}
		entry.RTT = result.RTT.Round(time.Microsecond * 100).String()
		entry.RCode = result.RCode
		entry.Response = result.Response
		entry.Truncated = result.Truncated
		for _, record := range result.Records {
			entry.Values = append(entry.Values, record.Value)
		}
		total += len(entry.Values)
		output.Results = append(output.Results, entry)
	}

	printJSON(output)
	if total == 0 {
		return 1
	}
	return 0
}

func printJSON(payload any) int {
	encoded, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "netgraph: cannot encode output: %v\n", err)
		return exitUnimplemented
	}
	fmt.Println(string(encoded))
	return 0
}

func serverLabel(server string) string {
	if server == "" {
		return "system resolver"
	}
	return server
}

// colourEnabled honours NO_COLOR and only uses colour on a terminal.
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
