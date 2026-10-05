// Package models holds the data types that cross every internal boundary.
//
// The traceroute engine, the metadata lookups, the exporters and the TUI all
// speak in these types. They live in one package rather than next to their
// producers so that a change to a hop's shape cannot ripple into an import
// cycle, and so the JSON schema has exactly one place where it is defined.
package models

import (
	"time"
)

// Protocol identifies how a traceroute probe is sent.
type Protocol string

const (
	// ProtocolICMP uses ICMP Echo Requests. The most widely supported, and the
	// one that most often requires elevated privileges.
	ProtocolICMP Protocol = "icmp"
	// ProtocolUDP uses UDP datagrams to a high port. Needs a raw socket to read
	// the ICMP Time Exceeded that comes back.
	ProtocolUDP Protocol = "udp"
	// ProtocolTCP uses TCP SYN packets. Reaches hosts that filter ICMP, and is
	// the only variant that can distinguish a firewall drop from a lost packet.
	ProtocolTCP Protocol = "tcp"
)

// AddressFamily records which family an address belongs to.
type AddressFamily string

const (
	FamilyV4 AddressFamily = "ipv4"
	FamilyV6 AddressFamily = "ipv6"
)

// Hop is one measured point along a route.
//
// A Hop exists only for a probe that produced an answer. Unanswered probes are
// counted in Hop.Loss rather than being represented as synthetic hops, because
// a hop that did not respond is not a place on the path: inventing one is how a
// traceroute ends up showing a router that was never there.
type Hop struct {
	// Number is the TTL that produced this hop, 1-based.
	Number int `json:"number"`

	// Address is the responding router, empty when nothing answered.
	Address string `json:"address,omitempty"`

	// AddressFamily of Address.
	AddressFamily AddressFamily `json:"addressFamily,omitempty"`

	// Hostname is the reverse-DNS name. It is a convenience label, never
	// authoritative: reverse DNS is frequently wrong, and presenting it as the
	// identity of a router would be worse than showing nothing.
	Hostname string `json:"hostname,omitempty"`

	// RTT is the fastest of the probes that answered. The minimum is used
	// because it is the least contaminated by queueing delay elsewhere; the
	// spread is reported separately in RTTSpread.
	//
	// A negative value means the hop did not answer at all.
	RTT time.Duration `json:"rtt"`

	// RTTSpread is the difference between the slowest and fastest probe at this
	// hop, which is the local measure of jitter on that link.
	RTTSpread time.Duration `json:"rttSpread,omitempty"`

	// Sent is how many probes were aimed at this hop.
	Sent int `json:"sent"`

	// Received is how many of them answered.
	Received int `json:"received"`

	// Loss is Received out of Sent, as a fraction.
	Loss float64 `json:"loss"`

	// ASN and the organisation fields come from a routing registry. They are
	// empty when no lookup succeeded, and Source records where the answer came
	// from. Reporting a guessed ASN as fact would be worse than reporting none.
	ASN     uint32 `json:"asn,omitempty"`
	OrgName string `json:"org,omitempty"`
	Country string `json:"country,omitempty"`

	// Registry names the source of the ASN data: "rdap", "ripestat", or empty.
	Registry string `json:"registry,omitempty"`

	// Geo holds approximate coordinates when a GeoIP database is configured.
	// It is nil when it is not, and the UI never treats it as precise.
	Geo *GeoLocation `json:"geo,omitempty"`

	// IsPrivate marks RFC1918, loopback and link-local space. Those hops are
	// part of the local network and are not part of any AS path.
	IsPrivate bool `json:"isPrivate,omitempty"`
}

// GeoLocation is an approximate position derived from a GeoIP database.
type GeoLocation struct {
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude,omitempty"`
	City      string  `json:"city,omitempty"`
	Country   string  `json:"country,omitempty"`

	// Accuracy is the radius in kilometres within which the database claims the
	// location is. It exists so that no consumer can render a city-level guess
	// as a point on a map without also showing how wrong it might be.
	Accuracy int `json:"accuracyKm,omitempty"`

	// Source names the database. A GeoIP answer is only as good as the database
	// and its age, and both need to be visible.
	Source string `json:"source,omitempty"`
}

// Route is a completed traceroute.
type Route struct {
	// Target is what was asked for, as the user typed it.
	Target string `json:"target"`

	// ResolvedAddress is what that name resolved to at the time of the trace.
	ResolvedAddress string `json:"resolvedAddress,omitempty"`

	// AddressFamily of the route as a whole.
	AddressFamily AddressFamily `json:"addressFamily"`

	// Protocol used.
	Protocol Protocol `json:"protocol"`

	// Hops in TTL order. A hop is present only if something answered.
	Hops []Hop `json:"hops"`

	// MaxHopsRequested and ProbesPerHop record the parameters, so that a
	// truncated result is distinguishable from a short route.
	MaxHopsRequested int `json:"maxHopsRequested"`
	ProbesPerHop     int `json:"probesPerHop"`

	// Reached is true when a probe answered as the destination itself. A route
	// that stops before the target is a real and reportable outcome, not an
	// error, and it is the normal result when a firewall drops the probes.
	Reached bool `json:"reached"`

	// ReachedAt is the hop number of the destination, 0 when never reached.
	ReachedAt int `json:"reachedAt"`

	// TotalLoss is the fraction of all probes that went unanswered.
	TotalLoss float64 `json:"totalLoss"`

	// StartedAt is when the trace began, in UTC. A route changes over time and
	// a stored result without a timestamp cannot be interpreted later.
	StartedAt time.Time `json:"startedAt"`

	// Duration is the wall time the trace took.
	Duration time.Duration `json:"duration"`

	// Warnings records anything that made the result less complete than
	// requested: a missing privilege, an unresolved hop, a truncated read. A
	// tool that silently produces a partial answer is lying by omission.
	Warnings []string `json:"warnings,omitempty"`

	// Error is set only when the trace could not run at all.
	Error string `json:"error,omitempty"`
}

// ASNInfo is the routing-registry view of an address.
type ASNInfo struct {
	ASN uint32 `json:"asn,omitempty"`

	// OrgName is the organisation that holds the allocation.
	OrgName string `json:"org,omitempty"`

	// Country is the country code of the allocation, not of any router.
	Country string `json:"country,omitempty"`

	// Registry names the source: "rdap" or "ripestat".
	Registry string `json:"registry,omitempty"`

	// Prefix is the announced block the address falls in.
	Prefix string `json:"prefix,omitempty"`

	// RIR is the regional internet registry responsible.
	RIR string `json:"rir,omitempty"`

	// AbuseEmail is present when the registry publishes one.
	AbuseEmail string `json:"abuseEmail,omitempty"`

	// Announced is whether the prefix is actually routed. An allocation that is
	// not announced is real on paper and absent from every traceroute.
	Announced bool `json:"announced"`

	// Source and FetchedAt make the answer auditable: a stale or wrong registry
	// response should be visible rather than baked in.
	Source    string    `json:"source,omitempty"`
	FetchedAt time.Time `json:"fetchedAt"`

	// Error is set when the lookup failed. The rest of the record may still be
	// partially populated, and a caller must check.
	Error string `json:"error,omitempty"`
}

// DNSRecord is one answer from a DNS query.
type DNSRecord struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	TTL   uint32 `json:"ttl"`
	Value string `json:"value"`

	// Priority matters for MX and SRV and is meaningless otherwise, so it is
	// reported rather than encoded into Value.
	Priority uint16 `json:"priority,omitempty"`

	// Weight is the SRV weight.
	Weight uint16 `json:"weight,omitempty"`

	// Port is the SRV port.
	Port uint16 `json:"port,omitempty"`
}

// DNSResult is a full answer for one name and record type.
type DNSResult struct {
	Query    string        `json:"query"`
	Type     string        `json:"type"`
	Server   string        `json:"server,omitempty"`
	Records  []DNSRecord   `json:"records"`
	RTT      time.Duration `json:"rtt"`
	Response string        `json:"response,omitempty"`

	// Error is set when the query failed. An empty Records with a nil Error
	// would be indistinguishable from a real "no records", so the two are
	// always distinguished.
	Error string `json:"error,omitempty"`
}

// IPInfo is everything known about one address.
type IPInfo struct {
	Address       string        `json:"address"`
	AddressFamily AddressFamily `json:"addressFamily"`

	// ReverseDNS is a label, not an identity.
	ReverseDNS string `json:"reverseDns,omitempty"`

	ASN *ASNInfo     `json:"asn,omitempty"`
	Geo *GeoLocation `json:"geo,omitempty"`

	// IsPrivate covers RFC1918, loopback, link-local, CGNAT and unique-local.
	IsPrivate bool `json:"isPrivate"`

	// NetworkType is a coarse classification: "private", "loopback",
	// "link-local", "multicast", "reserved", "public", "documentation".
	NetworkType string `json:"networkType"`

	// Sources lists where each piece came from, so a partial answer is
	// distinguishable from a complete one.
	Sources []string `json:"sources,omitempty"`

	// Errors collects per-source failures. A lookup that failed is reported
	// rather than replaced with an invented value.
	Errors []string `json:"errors,omitempty"`
}

// LatencyStats is the statistical summary of a latency series.
type LatencyStats struct {
	Count int `json:"count"`

	// Lost is how many probes never answered.
	Lost int `json:"lost"`

	Loss float64 `json:"loss"`

	Min    time.Duration `json:"min"`
	Max    time.Duration `json:"max"`
	Mean   time.Duration `json:"mean"`
	Median time.Duration `json:"median"`

	// Jitter is the mean absolute difference between consecutive successful
	// samples, following the convention ping uses. A separate metric from
	// standard deviation, because it weights change rather than deviation.
	Jitter time.Duration `json:"jitter"`

	// StdDev measures spread around the mean.
	StdDev time.Duration `json:"stdDev"`

	// Percentiles are the requested quantiles of the successful samples.
	Percentiles map[string]time.Duration `json:"percentiles,omitempty"`

	// Samples is the raw successful series, in order, capped by the caller's
	// configuration. A stats block without the samples cannot be plotted.
	Samples []time.Duration `json:"samples,omitempty"`
}

// RouteComparison is the result of comparing several routes.
type RouteComparison struct {
	Routes []Route `json:"routes"`

	// CommonHops are hops present on every route, in order. Empty when the
	// routes share no hop beyond the local segment.
	CommonHops []Hop `json:"commonHops"`

	// Organisations lists the distinct organisations across all routes, with
	// how many routes pass through each.
	Organisations map[string]int `json:"organisations"`

	// ShortestRoute and FastestRoute name the winners by index into Routes.
	ShortestRoute int `json:"shortestRoute"`
	FastestRoute  int `json:"fastestRoute"`

	// DivergenceAt is the first hop number where the routes differ. It is where
	// a question like "why is one slower" actually gets answered.
	DivergenceAt int `json:"divergenceAt"`

	StartedAt time.Time `json:"startedAt"`
}

// WatchEvent is one change observed by the watch command.
type WatchEvent struct {
	At time.Time `json:"at"`

	// Kind: "reachable", "unreachable", "route-change", "rtt-spike",
	// "dns-change", "packet-loss".
	Kind string `json:"kind"`

	// Detail is a human-readable sentence.
	Detail string `json:"detail"`

	// Previous and Current make the change inspectable rather than just noted.
	Previous string `json:"previous,omitempty"`
	Current  string `json:"current,omitempty"`

	// Severity: "info", "warning", "error".
	Severity string `json:"severity"`

	// Route is the route as it stood at the moment of the event.
	Route *Route `json:"route,omitempty"`
}

// ASPath is one organisation along a route, for the visual map.
type ASPathEntry struct {
	ASN uint32 `json:"asn,omitempty"`
	Org string `json:"org"`
	Hop int    `json:"hop"`
	// Private marks a local-network hop that has no AS.
	Private bool `json:"private,omitempty"`
}
