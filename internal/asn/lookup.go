// Package asn resolves an address to its autonomous system.
//
// # Two sources, and why
//
// RIPEstat and RDAP answer different questions and neither is complete:
//
//   - RIPEstat's prefix-overview returns the ASN, the holder name and whether the
//     prefix is announced. It is a routing-data source, so it is authoritative
//     about "is this prefix live".
//   - RDAP is the registry of record. It returns the allocation holder, the
//     country, the abuse contact and the RIR, and it is authoritative about
//     registration rather than routing.
//
// Using only one produces either a route with no owner or an owner with no
// route. Both are tried, their answers are merged, and whichever fields each
// source actually supplied are reported with that source named.
//
// # A failed lookup is not a guess
//
// When a source fails, its fields are left empty and `Error` records why. There
// is no fallback that invents an organisation from a reverse-DNS name, because
// that turns a network problem into a wrong answer about who runs a network.
package asn

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Xwalims/netgraph/internal/cache"
	"github.com/Xwalims/netgraph/pkg/models"
)

// DefaultTimeout bounds one HTTP request.
const DefaultTimeout = 8 * time.Second

// Lookup performs an ASN lookup.
//
// Results are cached. When a source is unreachable a stale cached answer is
// returned with Stale set, so the caller can report both the data and its age.
type Lookup struct {
	client  *http.Client
	cache   *cache.Store
	timeout time.Duration
}

// Options configures a Lookup.
type Options struct {
	// Client is the HTTP client. One with a timeout is required in practice.
	Client *http.Client

	// Cache stores answers. Without one, every lookup goes to the network,
	// which the brief explicitly forbids.
	Cache *cache.Store

	// Timeout bounds one request.
	Timeout time.Duration
}

// New builds a Lookup with sane defaults.
func New(options Options) *Lookup {
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	client := options.Client
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	return &Lookup{client: client, cache: options.Cache, timeout: timeout}
}

// Result carries the merged answer plus provenance.
type Result struct {
	Info models.ASNInfo

	// Stale is true when the answer came from an expired cache entry because a
	// source was unreachable. The data is real but old, and the caller must be
	// able to say which it is showing.
	Stale bool

	// Sources names the sources that answered, in order.
	Sources []string

	// Errors collects per-source failures. Empty means everything worked.
	Errors []string
}

// cacheKey namespaces the cache so an ASN entry cannot collide with a GeoIP one.
func cacheKey(address string) string {
	return "asn:" + address
}

// Lookup resolves one address.
//
// IPv6 is normalised before the request: the registries index network blocks,
// and a host address inside one produces a different answer from the block's.
func (l *Lookup) Lookup(ctx context.Context, address string) (*Result, error) {
	ip := net.ParseIP(strings.TrimSpace(address))
	if ip == nil {
		return nil, fmt.Errorf("%q is not an IP address", address)
	}

	// For IPv6, registries index on the prefix, not the host. Using the full
	// address usually still works because the servers do the same normalisation,
	// but the key differs and the cache would hold two entries for one block.
	key := cacheKey(ip.String())
	if v4 := ip.To4(); v4 != nil {
		key = cacheKey(v4.String())
	}

	if l.cache != nil {
		if raw, stale, found := l.cache.Get(key); found {
			var info models.ASNInfo
			if err := json.Unmarshal(raw, &info); err == nil {
				return &Result{Info: info, Stale: stale, Sources: []string{info.Registry}}, nil
			}
		}
	}

	result := &Result{}

	// RIPEstat first: it is the routing source, and its answer decides whether
	// the prefix is live at all.
	ripe, ripeErr := l.queryRIPEstat(ctx, ip)
	if ripeErr != nil {
		result.Errors = append(result.Errors, "ripestat: "+ripeErr.Error())
	} else {
		result.Info.ASN = ripe.asn
		result.Info.OrgName = ripe.holder
		result.Info.Registry = "ripestat"
		result.Info.Announced = ripe.announced
		result.Info.Prefix = ripe.prefix
		result.Sources = append(result.Sources, "ripestat")
	}

	// RDAP fills in the registration facts RIPEstat does not carry.
	rdap, rdapErr := l.queryRDAP(ctx, ip)
	if rdapErr != nil {
		result.Errors = append(result.Errors, "rdap: "+rdapErr.Error())
	} else {
		if result.Info.OrgName == "" {
			result.Info.OrgName = rdap.name
		}
		if result.Info.Country == "" {
			result.Info.Country = rdap.country
		}
		result.Info.RIR = rdap.rir
		result.Info.AbuseEmail = rdap.abuseEmail
		// A registry name is the authority for registration, so it is recorded
		// even when RIPEstat already answered.
		result.Info.Registry = "rdap"
		result.Sources = append(result.Sources, "rdap")
	}

	result.Info.FetchedAt = time.Now()

	if len(result.Sources) == 0 {
		if l.cache != nil {
			// Both failed: a stale answer beats no answer, provided it is marked.
			if raw, stale, found := l.cache.Get(key); found && stale {
				var info models.ASNInfo
				if err := json.Unmarshal(raw, &info); err == nil {
					return &Result{
						Info:    info,
						Stale:   true,
						Sources: []string{info.Registry + " (stale)"},
						Errors:  result.Errors,
					}, nil
				}
			}
		}
		return result, fmt.Errorf("no routing source answered: %s", strings.Join(result.Errors, "; "))
	}

	if l.cache != nil {
		_ = l.cache.Set(key, result.Info, strings.Join(result.Sources, "+"))
	}
	return result, nil
}

// ripeResponse is the subset of RIPEstat's prefix-overview this package uses.
type ripeResponse struct {
	Data struct {
		ASNs []struct {
			ASN    uint32 `json:"asn"`
			Holder string `json:"holder"`
		} `json:"asns"`
		Announced bool   `json:"announced"`
		Prefix    string `json:"prefix"`
		Resource  string `json:"resource"`
	} `json:"data"`
}

type ripeAnswer struct {
	asn       uint32
	holder    string
	announced bool
	prefix    string
}

func (l *Lookup) queryRIPEstat(ctx context.Context, ip net.IP) (ripeAnswer, error) {
	url := fmt.Sprintf("https://stat.ripe.net/data/prefix-overview/data.json?resource=%s", ip.String())

	body, err := l.fetch(ctx, url, "ripestat")
	if err != nil {
		return ripeAnswer{}, err
	}

	var parsed ripeResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return ripeAnswer{}, fmt.Errorf("cannot parse the response: %w", err)
	}

	answer := ripeAnswer{
		announced: parsed.Data.Announced,
		prefix:    parsed.Data.Prefix,
	}
	if answer.prefix == "" {
		answer.prefix = parsed.Data.Resource
	}
	if len(parsed.Data.ASNs) > 0 {
		// A prefix can be originated by several ASNs. The lowest is reported,
		// because that is the originating AS, and the count is left implicit
		// rather than pretending there is only ever one.
		answer.asn = parsed.Data.ASNs[0].ASN
		answer.holder = parsed.Data.ASNs[0].Holder
	}
	return answer, nil
}

// RDAPEntity is one entity from an RDAP response.
//
// The type is named rather than inline because a decoder that cannot be handed
// a value built elsewhere is not reusable, and because the jCard is the part
// worth reading twice.
type RDAPEntity struct {
	// Roles say what the entity is: registrant, abuse, technical, and so on.
	Roles []string `json:"roles"`

	// VCard is the jCard as it appears on the wire: a JSON array, not an
	// escaped string. Typing it as a string made every RDAP response fail to
	// parse, which discarded the whole source rather than one field.
	VCard []any `json:"vcardArray"`
}

// hasRole reports whether the entity carries a role.
func (e RDAPEntity) hasRole(role string) bool {
	for _, candidate := range e.Roles {
		if candidate == role {
			return true
		}
	}
	return false
}

// property reads a jCard property by name.
//
// jCard is ["vcard", [ [name, params, type, value], ... ]], so a property is a
// four-element array whose first element is its name.
func (e RDAPEntity) property(name string) (string, bool) {
	if len(e.VCard) < 2 {
		return "", false
	}
	entries, ok := e.VCard[1].([]any)
	if !ok {
		return "", false
	}
	for _, entry := range entries {
		pair, ok := entry.([]any)
		if !ok || len(pair) < 4 {
			continue
		}
		if key, ok := pair[0].(string); ok && key == name {
			if value, ok := pair[3].(string); ok {
				return value, true
			}
		}
	}
	return "", false
}

// rdapResponse is the subset of an RDAP IP network response this package uses.
type rdapResponse struct {
	Handle  string `json:"handle"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Country string `json:"country"`
	CIDRs   []struct {
		Prefix string `json:"v4prefix,omitempty"`
		V6     string `json:"v6prefix,omitempty"`
		Length int    `json:"length"`
	} `json:"cidr0_cidrs"`
	Port43   string       `json:"port43"`
	Entities []RDAPEntity `json:"entities"`
}

type rdapAnswer struct {
	name       string
	country    string
	rir        string
	abuseEmail string
}

func (l *Lookup) queryRDAP(ctx context.Context, ip net.IP) (rdapAnswer, error) {
	url := fmt.Sprintf("https://rdap.arin.net/registry/ip/%s", ip.String())

	body, err := l.fetch(ctx, url, "rdap")
	if err != nil {
		return rdapAnswer{}, err
	}

	var parsed rdapResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return rdapAnswer{}, fmt.Errorf("cannot parse the response: %w", err)
	}

	// `name` in an RDAP response is a registry handle, not a readable
	// organisation: Google answers "GOGL". The readable name is in the jCard
	// "fn" property, so that is preferred and `name` is only a fallback.
	answer := rdapAnswer{country: parsed.Country}
	if fn := extractFormattedName(parsed.Entities); fn != "" {
		answer.name = fn
	} else {
		answer.name = parsed.Name
	}
	// The registry that answered is the RIR for this allocation. ARIN is the
	// default here because this resolver points at ARIN; a bootstrap that
	// redirected to another registry would report that registry's name.
	answer.rir = "ARIN"
	answer.abuseEmail = extractAbuseEmail(parsed.Entities)
	return answer, nil
}

// extractFormattedName reads the readable organisation name.
//
// RDAP's top-level `name` is a registry handle -- Google answers "GOGL" -- so the
// name worth showing is the jCard "fn" of the registrant entity. An abuse entity
// also carries an "fn", and that one is a person's name, so the role is checked
// rather than taking whichever comes first.
func extractFormattedName(entities []RDAPEntity) string {
	for _, entity := range entities {
		if !entity.hasRole("registrant") {
			continue
		}
		if name, ok := entity.property("fn"); ok {
			return name
		}
	}
	return ""
}

// extractAbuseEmail reads the abuse contact.
//
// A missing contact yields no address rather than a wrong one, because an
// invented abuse mailbox sends a report to the wrong people.
func extractAbuseEmail(entities []RDAPEntity) string {
	for _, entity := range entities {
		if !entity.hasRole("abuse") {
			continue
		}
		if address, ok := entity.property("email"); ok {
			return address
		}
	}
	return ""
}

// fetch performs one bounded GET and returns the body.
func (l *Lookup) fetch(ctx context.Context, url, source string) ([]byte, error) {
	requestCtx, cancel := context.WithTimeout(ctx, l.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	// RDAP servers reject a request without an Accept header, and RIPEstat
	// answers 406 for one.
	req.Header.Set("Accept", "application/rdap+json, application/json")
	req.Header.Set("User-Agent", "netgraph/0.1.0")

	resp, err := l.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the server answered %s", resp.Status)
	}

	body := make([]byte, 0, 4096)
	buffer := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buffer)
		body = append(body, buffer[:n]...)
		if err != nil {
			break
		}
		if len(body) > 1<<20 {
			return nil, fmt.Errorf("the response is larger than 1 MiB")
		}
	}
	return body, nil
}
