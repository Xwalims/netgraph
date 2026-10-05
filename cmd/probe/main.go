package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/Xwalims/netgraph/internal/dns"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	name := os.Args[1]
	server := os.Args[2]
	types := os.Args[3:]

	fmt.Printf("=== живой запрос к %s ===\n", server)
	for _, recordType := range types {
		resolver := dns.New(dns.Options{Servers: []string{server}, Timeout: 5 * time.Second})
		result, err := resolver.Lookup(ctx, name, recordType)
		_ = result
		if err != nil {
			fmt.Printf("%-6s ОШИБКА: %v\n", recordType, err)
			continue
		}
		fmt.Printf("%-6s rtt=%-12v rcode=%s records=%d\n",
			recordType, result.RTT.Round(time.Millisecond), result.Response, len(result.Records))
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
