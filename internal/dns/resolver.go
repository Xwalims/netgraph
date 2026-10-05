// Package dns implements DNS resolution and analysis.
//
// # Why the resolver is not net.LookupHost
//
// The standard resolver returns addresses and discards everything else: the
// TTL, which nameserver answered, how long it took, whether the answer was a
// CNAME chain, and which records exist that nobody asked for. All of that is the
// interesting part when someone is working out why a name resolves the way it
// does, which is what this tool is for.
//
// So queries are built and sent directly, and every field the user asked for is
// captured on the way past.
//
// # Timeouts and cancellation
//
// Every operation takes a context. A nameserver that accepts a TCP connection
// and then says nothing must not be able to hang the program, and a cancelled
// command must stop waiting immediately rather than after the next timeout.
package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// RecordType is a DNS record type, named as it appears on the wire.
type RecordType string

const (
	TypeA     RecordType = "A"
	TypeAAAA  RecordType = "AAAA"
	TypeCNAME RecordType = "CNAME"
	TypeMX    RecordType = "MX"
	TypeNS    RecordType = "NS"
	TypeTXT   RecordType = "TXT"
	TypeSOA   RecordType = "SOA"
	TypeSRV   RecordType = "SRV"
	TypeCAA   RecordType = "CAA"
	TypePTR   RecordType = "PTR"
)

// AllTypes is every record type this package can query, in the order `--all`
// walks them.
var AllTypes = []RecordType{
	TypeA, TypeAAAA, TypeCNAME, TypeMX, TypeNS,
	TypeTXT, TypeSOA, TypeSRV, TypeCAA, TypePTR,
}

// dnsType maps a RecordType to its numeric value for the wire query.
var dnsType = map[RecordType]uint16{
	TypeA: 1, TypeNS: 2, TypeCNAME: 5, TypeSOA: 6, TypePTR: 12,
	TypeMX: 15, TypeTXT: 16, TypeAAAA: 28, TypeSRV: 33, TypeCAA: 257,
}

// ParseRecordType accepts a user-supplied type name in any case.
func ParseRecordType(name string) (RecordType, error) {
	upper := RecordType(strings.ToUpper(strings.TrimSpace(name)))
	if _, ok := dnsType[upper]; ok {
		return upper, nil
	}
	return "", fmt.Errorf("unknown record type %q, expected one of %s", name, typeNames())
}

func typeNames() string {
	names := make([]string, 0, len(AllTypes))
	for _, t := range AllTypes {
		names = append(names, string(t))
	}
	return strings.Join(names, ", ")
}

// Options configures a Resolver.
type Options struct {
	// Servers to query, in order. Empty means the system resolver, which is
	// reported as such rather than as a specific address.
	Servers []string

	// Timeout per query. Defaults to 5s: long enough for a slow authoritative
	// server, short enough that a dead one does not stall a four-server
	// comparison.
	Timeout time.Duration

	// TCP forces DNS over TCP. A response larger than a UDP datagram is switched
	// over automatically regardless of this setting.
	TCP bool
}

// Resolver performs DNS queries.
type Resolver struct {
	options Options
}

// New builds a Resolver. Options are defaulted rather than rejected, so a zero
// value is usable.
func New(options Options) *Resolver {
	if options.Timeout <= 0 {
		options.Timeout = 5 * time.Second
	}
	return &Resolver{options: options}
}

// Result is the outcome of one query.
type Result struct {
	Name      string
	Type      RecordType
	Server    string
	Records   []Record
	RTT       time.Duration
	Truncated bool

	// RCode is the DNS response code, 0 for success. A non-zero value with no
	// error is possible: NXDOMAIN is a successful query with an empty answer,
	// and reporting it as a failure would be wrong.
	RCode int

	// Response is the human-readable meaning of RCode.
	Response string
}

// Record is one answer, normalised away from the wire format.
type Record struct {
	Name     string
	Type     RecordType
	TTL      uint32
	Value    string
	Priority uint16
	Weight   uint16
	Port     uint16
}

// rcodeName explains a DNS response code.
func rcodeName(code int) string {
	switch code {
	case 0:
		return "NOERROR"
	case 1:
		return "FORMERR"
	case 2:
		return "SERVFAIL"
	case 3:
		return "NXDOMAIN"
	case 4:
		return "NOTIMP"
	case 5:
		return "REFUSED"
	default:
		return fmt.Sprintf("RCODE%d", code)
	}
}

// Lookup resolves one name to one record type.
//
// The error is nil when the query succeeded even if the answer contains no
// records: an empty answer and a failed query are different facts and the caller
// must be able to tell them apart.
func (r *Resolver) Lookup(ctx context.Context, name, recordType string) (*Result, error) {
	parsed, err := ParseRecordType(recordType)
	if err != nil {
		return nil, err
	}
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if name == "" {
		return nil, errors.New("no name given")
	}

	queryCtx, cancel := context.WithTimeout(ctx, r.options.Timeout)
	defer cancel()

	// A PTR query is the reverse direction: the name on the wire is derived from
	// the address. Handling it here rather than in the caller keeps the record
	// type and the query shape from getting out of step.
	if parsed == TypePTR {
		return r.lookupPTR(queryCtx, name)
	}

	if len(r.options.Servers) == 0 {
		return r.lookupSystem(queryCtx, name, parsed)
	}

	// The first server that answers wins. Failing the whole lookup because one
	// server is down would be wrong for a diagnostic tool: the point is to find
	// out what each server says.
	query := buildQuery(name, dnsType[parsed], nextQueryID())
	var lastErr error
	for _, server := range r.options.Servers {
		result, err := r.queryServer(queryCtx, server, query, name, parsed)
		if err == nil {
			return result, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("every configured server failed, last error: %w", lastErr)
}

// lookupSystem uses the operating system resolver, for the case where the user
// has not asked for specific servers.
func (r *Resolver) lookupSystem(ctx context.Context, name string, parsed RecordType) (*Result, error) {
	start := time.Now()
	// The system resolver cannot be asked for a specific record type, so the
	// address set is fetched and filtered here. That is a real limitation of this
	// path, and it is why an explicit --server is the more useful mode.
	addrs, err := net.DefaultResolver.LookupHost(ctx, name)
	elapsed := time.Since(start)
	if err != nil {
		return nil, fmt.Errorf("system resolver: %w", err)
	}

	result := &Result{
		Name:     name,
		Type:     parsed,
		Server:   "system resolver",
		RTT:      elapsed,
		Response: rcodeName(0),
	}
	// A TTL is not exposed by the system resolver. Reporting the elapsed query
	// time as a TTL would be a fabrication, so TTL is left at zero and the
	// field is omitted when rendered.
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		switch {
		case ip.To4() != nil && parsed == TypeA:
			result.Records = append(result.Records, Record{
				Name: name, Type: TypeA, Value: addr,
			})
		case ip.To4() == nil && parsed == TypeAAAA:
			result.Records = append(result.Records, Record{
				Name: name, Type: TypeAAAA, Value: addr,
			})
		}
	}
	if len(result.Records) == 0 && parsed != TypeA && parsed != TypeAAAA {
		// The system resolver has no MX/TXT/etc. support, and saying so beats
		// returning an empty answer that reads like "this name has no MX".
		return result, fmt.Errorf(
			"the system resolver cannot answer %s queries; pass --server to use a specific resolver",
			parsed)
	}
	return result, nil
}

// lookupPTR reverses an address into a name.
func (r *Resolver) lookupPTR(ctx context.Context, address string) (*Result, error) {
	if net.ParseIP(address) == nil {
		return nil, fmt.Errorf("%q is not an IP address, so PTR does not apply", address)
	}
	start := time.Now()
	names, err := net.DefaultResolver.LookupAddr(ctx, address)
	if err != nil {
		return nil, fmt.Errorf("reverse lookup: %w", err)
	}
	result := &Result{
		Name:     address,
		Type:     TypePTR,
		Server:   "system resolver",
		RTT:      time.Since(start),
		Response: rcodeName(0),
	}
	for _, n := range names {
		result.Records = append(result.Records, Record{
			Name: n, Type: TypePTR, Value: strings.TrimSuffix(n, "."),
		})
	}
	return result, nil
}
