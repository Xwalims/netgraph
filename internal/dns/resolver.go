// Package dns implements DNS resolution and analysis.
//
// # Why the resolver is not net.LookupHost
//
// The standard resolver returns addresses and discards everything else: the
// TTL, which nameserver answered, how long it took, whether the answer was a
// CNAME chain, and which records exist that nobody asked for. All of that is
// the interesting part when someone is working out why a name resolves the way
// it does, which is what this tool is for.
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

// ForwardTypes is every record type that applies to a name rather than to an
// address. It exists because `--all` used to walk AllTypes, which included PTR:
// asking a forward question for an address produces the error "google.com is not
// an IP address" in the middle of an otherwise successful `--all`, which reads
// as the server failing rather than as the question being nonsense.
var ForwardTypes = []RecordType{
	TypeA, TypeAAAA, TypeCNAME, TypeMX, TypeNS,
	TypeTXT, TypeSOA, TypeSRV, TypeCAA,
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

	// Warnings records anything that made this result less complete than asked
	// for -- a truncated answer whose TCP retry failed, for instance. A tool
	// that quietly drops the warning is claiming an answer it does not have.
	Warnings []string
}

// Record is one answer, normalised away from the wire format.
//
// A TTL of zero means "the source did not tell us", not "expire immediately".
// The system resolver does not expose TTLs, so a record that came from it
// carries zero and the renderer says so rather than printing a confident 0.
type Record struct {
	Name     string
	Type     RecordType
	TTL      uint32
	Value    string
	Priority uint16
	Weight   uint16
	Port     uint16

	// TTLKnown is false when the answering path had no TTL to report, which is
	// the case for every record that came from the system resolver.
	TTLKnown bool
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

	if parsed == TypePTR {
		// A PTR query is the reverse direction: the name on the wire is derived
		// from the address, so an IP address is accepted here and turned into
		// the in-addr.arpa / ip6.arpa name itself. Doing that here rather than
		// in the caller keeps the record type and the query shape from getting
		// out of step.
		return r.lookupPTR(queryCtx, name)
	}

	if len(r.options.Servers) == 0 {
		return r.lookupSystem(queryCtx, name, parsed)
	}

	return r.lookupServers(queryCtx, name, parsed, r.options.Servers)
}

// lookupServers asks each configured server in turn and returns the first answer.
//
// The first server that answers wins. Failing the whole lookup because one
// server is down would be wrong for a diagnostic tool: the point is to find
// out what each server says.
func (r *Resolver) lookupServers(
	ctx context.Context, name string, parsed RecordType, servers []string,
) (*Result, error) {
	query, err := buildQuery(name, dnsType[parsed], nextQueryID())
	if err != nil {
		return nil, err
	}
	var lastErr error
	for i, server := range servers {
		result, err := r.queryServer(ctx, server, query, name, parsed, false, i == 0)
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
	// time as a TTL would be a fabrication, so TTL stays zero and TTLKnown
	// stays false, which is what makes the renderer omit the field instead of
	// printing a confident "ttl=0".
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
//
// The reverse name is derived here rather than handed in by the caller, so the
// caller's argument is always an address and never a half-built arpa name.
//
// When servers are configured the query goes to them directly. This used to
// call net.DefaultResolver.LookupAddr unconditionally, which meant --server was
// silently ignored for every reverse lookup: the tool printed the server in its
// own header and then asked the operating system instead. A user comparing
// resolvers was comparing nothing, and a reverse lookup could not be pointed at
// a server that does not share the local resolver's view of the zone.
func (r *Resolver) lookupPTR(ctx context.Context, address string) (*Result, error) {
	ip := net.ParseIP(address)
	if ip == nil {
		return nil, fmt.Errorf("%q is not an IP address, so PTR does not apply", address)
	}
	arpaName := reverseName(ip)

	if len(r.options.Servers) > 0 {
		result, err := r.lookupServers(ctx, arpaName, TypePTR, r.options.Servers)
		if err != nil {
			return nil, fmt.Errorf("reverse lookup of %s: %w", address, err)
		}
		// The name on the wire is the arpa form; the user asked about the
		// address, so Result.Name reports the address.
		result.Name = address
		return result, nil
	}

	start := time.Now()
	names, err := net.DefaultResolver.LookupAddr(ctx, address)
	elapsed := time.Since(start)
	if err != nil {
		return nil, fmt.Errorf("reverse lookup: %w", err)
	}
	result := &Result{
		Name:     address,
		Type:     TypePTR,
		Server:   "system resolver",
		RTT:      elapsed,
		Response: rcodeName(0),
	}
	for _, n := range names {
		result.Records = append(result.Records, Record{
			Name: n, Type: TypePTR, Value: strings.TrimSuffix(n, "."),
		})
	}
	return result, nil
}

// reverseName is the in-addr.arpa or ip6.arpa name for an address.
//
// The order is not a choice. An IPv4 address reverses as whole octets in
// reverse; an IPv6 address reverses as individual nibbles in reverse. Both are
// fixed by RFC 1035 and by what every resolver since has done, so getting
// either wrong makes the query ask about a different address than the user
// named, and that failure is silent: an empty answer for a name nobody hosts.
func reverseName(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", v4[3], v4[2], v4[1], v4[0])
	}
	v6 := ip.To16()
	if v6 == nil {
		return ""
	}
	const hex = "0123456789abcdef"
	out := make([]byte, 0, len(v6)*4+len(".ip6.arpa"))
	for i := len(v6) - 1; i >= 0; i-- {
		if len(out) > 0 {
			out = append(out, '.')
		}
		// Low nibble first: the last octet's least significant nibble leads.
		out = append(out, hex[v6[i]&0x0f], '.', hex[v6[i]>>4])
	}
	// The dot matters: "…0.2ip6.arpa" is not a name the ip6.arpa zone serves,
	// and the query for it fails silently as an empty answer.
	return string(out) + ".ip6.arpa"
}
