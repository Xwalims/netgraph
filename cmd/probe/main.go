package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/Xwalims/netgraph/internal/dns"
)

const usage = `probe -- a live DNS query that keeps every field the standard resolver drops

usage:
  probe <name> <server> [type...]
  probe <name> <server> --all

  name    the name to resolve, e.g. www.github.com
  server  a resolver address, e.g. 1.1.1.1, 8.8.8.8:53 or [2606:4700::1111]
  type    record types to ask for: A AAAA CNAME MX NS TXT SOA SRV CAA PTR
          (case-insensitive). Defaults to A A and AAAA.

examples:
  probe www.github.com 1.1.1.1 CNAME A
  probe github.com 8.8.8.8 --all
`

func main() {
	if len(os.Args) < 3 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	// --help and -h are answered before anything else, and printing usage is
	// not a usage error.
	for _, arg := range os.Args[1:] {
		if arg == "--help" || arg == "-h" {
			fmt.Print(usage)
			return
		}
	}

	name := os.Args[1]
	server := os.Args[2]
	types := os.Args[3:]

	if len(types) == 1 && types[0] == "--all" {
		types = nil
		for _, t := range dns.AllTypes {
			types = append(types, string(t))
		}
	}
	if len(types) == 0 {
		types = []string{string(dns.TypeA), string(dns.TypeAAAA)}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fmt.Printf("=== живой запрос к %s ===\n", server)
	for _, recordType := range types {
		resolver := dns.New(dns.Options{Servers: []string{server}, Timeout: 5 * time.Second})
		result, err := resolver.Lookup(ctx, name, recordType)
		if err != nil {
			fmt.Printf("%-6s ОШИБКА: %v\n", recordType, err)
			continue
		}
		fmt.Printf("%-6s rtt=%-12v rcode=%s records=%d\n",
			recordType, result.RTT.Round(time.Millisecond), result.Response, len(result.Records))
		for _, warning := range result.Warnings {
			fmt.Printf("       ПРЕДУПРЕЖДЕНИЕ: %s\n", warning)
		}
		for _, record := range result.Records {
			fmt.Printf("       %s %s (ttl=%d%s)\n", record.Type, record.Value, record.TTL,
				prioritySuffix(record))
		}
	}
}

func prioritySuffix(record dns.Record) string {
	switch {
	case record.Priority != 0:
		return fmt.Sprintf(", priority=%d", record.Priority)
	case record.Port != 0:
		return fmt.Sprintf(", priority=%d weight=%d port=%d", record.Priority, record.Weight, record.Port)
	default:
		return ""
	}
}
