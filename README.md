# NETGRAPH

```
    ┌─┐┌─┐┌┬┐┌─┐┌┬┐┌─┐┌─┐┌─┐┐ ┬┐┌─┐┌┬┐
    │ ││ │││││ ││ ││┬┘│ │├─┤├┬┘│││ ││ ││
    └─┘└─┘└┴┐└─┐└┴┐└─┘└─┘└─┘└┴┘└─┘└─┘└─┘
```

> **See how the internet reaches your destination.**

A network diagnostic CLI combining traceroute, DNS analysis, ASN lookup, latency
monitoring and route visualisation. Linux, macOS and Windows.

---

## Status

`trace` and `map` need a raw socket, which not every host grants. Everything else
runs unprivileged.

| Command | State |
| --- | --- |
| `netgraph dns` | **working** — own DNS codec, all ten record types, real queries |
| `netgraph ip` | working — classification, ASN, reverse DNS |
| `netgraph asn` | working — RIPEstat and RDAP, merged, cached |
| `netgraph ping` | working — TCP RTT, jitter, loss, percentiles |
| `netgraph watch` | working — reachability, latency, route and DNS changes |
| `netgraph compare` | working — traces several targets and diffs them |
| `netgraph map` | working — ASCII, JSON, HTML and CSV output |
| `netgraph export` | working — re-renders a saved result |
| `netgraph cache` | working — stats, clear, sweep |
| `netgraph trace` | working, **requires `CAP_NET_RAW`** |
| `netgraph map` | working, **requires `CAP_NET_RAW`** |

Traceroute without that capability does not pretend:

```console
$ netgraph trace google.com
netgraph: traceroute needs a raw ICMP socket, which this host does not allow.
  reason:  listen ip4:icmp 0.0.0.0: socket: operation not permitted
  fix:     sudo setcap cap_net_raw+ep <path to netgraph>
  note:    no protocol avoids this; --protocol only changes what is sent
  without it, use: netgraph dns, netgraph ip, netgraph asn, netgraph ping

  no route was measured
$ echo $?
2
```

That message is the point. The alternative — an empty diagram and an exit code of
zero — is indistinguishable from a network problem, and gets diagnosed as one.

---

## Install

```console
$ git clone https://github.com/Xwalims/netgraph.git
$ cd netgraph
$ go build -o netgraph ./cmd/netgraph
```

Requires Go 1.23 or newer. **No third-party dependencies.**

```console
$ sudo setcap cap_net_raw+ep ./netgraph   # only if you want traceroute
```

---

## Usage

```console
$ netgraph trace example.com                  trace the route
$ netgraph trace example.com --protocol tcp --max-hops 30 --probes 5 --timeout 3s
$ netgraph trace example.com --ipv6 --interface 192.168.1.10

$ netgraph map example.com --format html --out route.html
$ netgraph map example.com --format csv  --out route.csv

$ netgraph dns example.com                    resolve with the system resolver
$ netgraph dns example.com --server 1.1.1.1   query a specific nameserver
$ netgraph dns example.com --type MX          one record type
$ netgraph dns example.com --all              every record type a name can have
$ netgraph dns example.com --compare          several servers, and where they disagree
$ netgraph dns 1.1.1.1 --reverse              PTR lookup
$ netgraph dns example.com --json             machine-readable

$ netgraph ip 1.1.1.1                         classify an address
$ netgraph asn 8.8.8.8                        look up the autonomous system
$ netgraph asn 8.8.8.8 --no-cache             refetch instead of using the cache

$ netgraph ping example.com --count 100 --interval 500ms
$ netgraph ping example.com --continuous

$ netgraph compare example.com example.org
$ netgraph export --in route.json --format html --out route.html
$ netgraph watch example.com --interval 30s --type A
$ netgraph cache stats
```

Global flags: `--json`, `--no-color` (honours `NO_COLOR`), `--quiet`.

Options:

```
  --server <addr>       query this nameserver instead of the system resolver
  --type <record>       A, AAAA, MX, NS, TXT, SOA, SRV, CAA, CNAME. Repeatable;
                        duplicates are collapsed into one query.
  --all                 every record type that applies to a name (no PTR)
  --compare             query several servers and report the differences
  --reverse             treat the argument as an address
  --timeout <duration>  per-query timeout (default 5s)
  --json                machine-readable output
  --no-color            disable colour (also honours NO_COLOR)
  --quiet               values only, no headings
```

Exit codes: `0` success, `1` the query worked but returned no records, `2` the query
failed or the command is not implemented.

A query that *failed* exits `2`, not `1`. The two are different facts — "this name
has no records of that type" versus "I could not find out" — and a script that
treats them the same reports a timed-out resolver as an authoritative answer.

---

## Real output

Captured from this machine, not written by hand:

```console
$ netgraph dns google.com --server 1.1.1.1 --type A --type MX

DNS
  name       google.com
  server     1.1.1.1
  timeout    5s

  A      6 records  rtt=21.7ms  rcode=NOERROR
        172.253.152.139                  ttl=284
        172.253.152.102                  ttl=284
        172.253.152.113                  ttl=284
        172.253.152.101                  ttl=284
        172.253.152.138                  ttl=284
        172.253.152.100                  ttl=284

  MX     1 records  rtt=20ms  rcode=NOERROR
        smtp.google.com                  ttl=189  priority=10
```

### Comparing servers finds real differences

Three public resolvers were asked for the same name at the same moment:

```console
$ netgraph dns github.com --type A --compare

  agreement:
    A        DIVERGENT
        140.82.121.3                     1.1.1.1
        140.82.121.4                     8.8.8.8
        4.225.11.194                     9.9.9.9
```

GitHub publishes several addresses and each resolver picked a different one. A
tool that reported only the first answer would have hidden the fact that the
answer is not stable, which is the thing worth knowing.

### Machine-readable

```console
$ netgraph dns github.com --server 1.1.1.1 --type A --json
{
  "name": "github.com",
  "server": "1.1.1.1",
  "results": [
    {
      "type": "A",
      "rtt": "23.2ms",
      "rcode": 0,
      "response": "NOERROR",
      "truncated": false,
      "values": [
        "140.82.121.3"
      ]
    }
  ]
}
```

---

## Why the resolver is written from scratch

`net.LookupHost` returns addresses and discards everything else: the TTL, which
nameserver answered, how long it took, whether the answer came through a CNAME
chain, and which records exist that nobody asked for. That is the entire reason
someone runs a tool like this.

So the DNS messages are built and parsed directly. Three bugs came out of that,
and all three were found by running against real servers rather than by reading
the code:

**A UDP socket does not buffer.** Reading the 12-byte header separately consumed
the whole 61-byte datagram and discarded the remaining 49 permanently, so every
query timed out on a network that answered in 40ms. The answer is now read in one
call. TCP genuinely is stream-oriented, so there the length prefix is read first.

**The name decoder returned the wrong resume position.** After a compression
pointer it returned an offset into the middle of the name, which made every
record in a response unparseable. The resume position is now tracked separately
from the walking offset and survives the jump.

**RDATA can itself be a compression pointer.** RFC 1035 §4.1.4 allows it, and the
decoder was resolving those pointers against the RDATA slice instead of against
the message. That silently dropped the CNAME chain from every ordinary lookup:
`www.github.com` returned `records=0` before the fix and `CNAME github.com
(ttl=3600)` after.

An earlier attempt also had a "strip the length prefix if it looks like one"
heuristic, which was removed: it could only ever fire on a message that had no
prefix, and it corrupts roughly one query in 65536, because the first two bytes
of a DNS query are the transaction ID.

### Four bugs that were found by running the binary

The unit tests were green for all of these. Only running the command against a
real nameserver exposed them, which is the whole argument for checking a
resolver against the network rather than against itself.

**`--reverse` ignored `--server` completely.** `lookupPTR` called
`net.DefaultResolver.LookupAddr` unconditionally, so the tool printed
`server 8.8.8.8` in its own header and then asked the operating system:

```console
$ # before the fix, against a server that does not exist at all
$ netgraph dns 1.1.1.1 --reverse --server 203.0.113.1
  DNS
  name       1.1.1.1
  server     203.0.113.1          <- printed, never queried

  PTR    1 records  rtt=3.4ms  rcode=NOERROR
        one.one.one.one
```

A user comparing resolvers was comparing nothing, and a reverse lookup could not
be pointed at a server that does not share the local resolver's view of the zone.
The query now goes to the configured server, and the reverse name is built here
rather than left to the OS — which also means `--reverse` finally works for an
address the local resolver has never heard of:

```console
$ netgraph dns 8.8.8.8 --reverse --server 1.1.1.1

  DNS
  name       8.8.8.8
  server     1.1.1.1 (PTR is queried directly; no system resolver is used)
  timeout    5s

  PTR    1 records  rtt=18ms  rcode=NOERROR
        dns.google                       ttl=73891
```

The nibble order in the generated `in-addr.arpa` / `ip6.arpa` name is verified
against CPython's `ipaddress.reverse_pointer`, an independent implementation of
the same rule.

**A failed query exited `1`, which means "no records".** The documented codes were
`0` success, `1` no records, `2` failure, and a query against a dead server
exited `1` with `no records found` printed underneath it. A script checking for
`1` was being told that a resolver which never answered had returned an empty
authoritative answer. The three cases are now distinct:

```console
$ netgraph dns github.com --server 1.1.1.1 --type A >/dev/null; echo $?
0
$ netgraph dns nx-4b7c2d.example --server 1.1.1.1 --type A >/dev/null; echo $?
1
$ netgraph dns github.com --server 203.0.113.1 --type A >/dev/null; echo $?
2
```

**`--quiet` printed the header block anyway.** The flag promises "values only, no
headings", and it did suppress the per-type heading while still emitting the
`DNS / name / server / timeout` preamble — which is precisely what a caller pipes
into `xargs` does not want.

**`--all` ended with an error about a name not being an address.** It walked
`AllTypes`, and `AllTypes` contains `PTR`, so every `--all` on a name finished
with `"google.com" is not an IP address, so PTR does not apply`. The failure was
reported by the tool as an error line, so it read as a server problem rather than
as a question that cannot apply to a name. `--all` now walks the forward types
only.

Two smaller fixes came out of the same run. A `ttl=0` was printed for records
that came from the system resolver, which has no TTLs at all — the field is now
marked known or unknown rather than conflated. And `Result.Warnings`, which the
resolver fills in when a truncated UDP answer could not be retried over TCP, was
never read by the CLI at all, so a partial answer looked complete; it is now
printed, and carried in `--json`.

---

### `netgraph ip 1.1.1.1`

```console
$ netgraph ip 1.1.1.1

  IP address  1.1.1.1

  family         IPv4
  class          public
  reverse dns    one.one.one.one
  asn            AS13335
  organisation   CLOUDFLARENET - Cloudflare, Inc.
  prefix         1.1.1.0/24
  announced      true
  registry       rdap
  rir            ARIN
  abuse          helpdesk@apnic.net
  sources        ripestat, rdap

  country is where the network is registered, not where the
  address or its users are. No city is shown: a GeoIP estimate
  presented as a location would be a claim, not a measurement.
```

No city. GeoIP city data is frequently off by hundreds of kilometres, and printing
it next to an exact IP address invites the reader to believe it.

### `netgraph ping 1.1.1.1`

```console
$ netgraph ping 1.1.1.1 --count 4 --interval 300ms

  latency 1.1.1.1  tcp/443
  4 probes, interval 300ms, timeout 2s

  10:48:23.584  18.3ms     good
  10:48:23.803  22.4ms     fair
  10:48:24.056  19.1ms     good
  10:48:24.311  20.2ms     good

  sent       0 of 4 lost (0%)
  rtt        min 18.3ms   avg 19.9ms   max 22.4ms
  jitter     2.4ms   stddev 1.5ms
  percentiles p50 20.2ms   p90 22.4ms   p95 22.4ms   p99 22.4ms
  ▇▅▆▅   18.3ms .. 22.4ms
  this is end-to-end RTT measured over TCP. A router's own RTT is a
  different quantity and is not mixed into it.
```

Measured over a TCP handshake rather than ICMP, because ICMP needs privileges and
routers deprioritise it: an ICMP RTT is a lower bound on the path, not a
measurement of it. The method is named in the header so the number is never
mistaken for the other quantity.

---

## The traceroute engine

Probes carry an increasing TTL; each router that decrements it to zero returns an
ICMP Time Exceeded. Reading those replies is what reveals the path, which is why a
raw socket is unavoidable — they arrive addressed to the sending host, not
delivered to any socket the kernel would hand to an application.

**Matching a reply to a probe.** The ICMP error quotes the IP header and the first
8 bytes of the datagram that provoked it. For a UDP probe those are the entire UDP
header, so the quote carries the probe's destination port and nothing else of
ours. Each probe therefore gets a distinct port — that is what makes the reply
attributable — and a table maps that port to the send time, from which the round
trip is computed.

**A port collision test.** Two probes in flight sharing a port could not be told
apart, and one hop's timing could be attributed to another. There is a test that
enumerates every port across the default range and fails on a repeat — and it
has to run at **every** probe count the `--probes` flag accepts, not just the
default. The stride between TTLs is the maximum probe count, so checking only the
default leaves the whole range above it untested: with a stride of 8, `--probes 9`
put TTL 2's first probe on port 33450, which TTL 1's ninth probe had already used,
and the send record was silently overwritten. That is a hop at the wrong distance,
which is the one error a traceroute exists to avoid.

**A probe is counted once, however many replies arrive.** `collect` keys its
de-duplication on the probe's port, so a router that answers twice does not make
`Received` exceed `Sent`. Without that, loss is computed as
`(Sent - Received) / Sent` and the report printed **-133%** — three probes sent,
seven replies received. Loss is a fraction, so `buildHops` also refuses to let
`Received` exceed `Sent` whatever reaches it. A probe's port is released as soon
as its measurement window closes, so a reply arriving late is discarded instead of
being attributed to a hop it never reached.

**Capability is checked before probing.** All three protocols need the socket,
not just ICMP: UDP and TCP are identified by the replies they provoke. So the
check is about the host, not about `--protocol`.

**An empty route draws nothing.** The first version drew `LOCAL -> DESTINATION`
with `0% loss`, asserting both that a path existed and that nothing was lost when
nothing had been measured.

---

## ASN intelligence

RIPEstat answers "is this prefix live"; RDAP answers "who is registered to it".
Neither is complete alone, so both are queried and merged, with the source of each
field recorded.

Lookups are cached on disk. A traceroute can produce thirty hops; asking a public
API thirty times in a row is how a tool gets rate-limited and then reports
nothing. Measured here: **1.4s to 22µs** for a cached lookup.

A stale entry is still returned when a source fails, with `stale` set so the
caller can say so. Serving yesterday's routing data as today's is the failure the
flag exists to prevent.

The RDAP decoder types `vcardArray` as a JSON **array**. Typing it as a string —
which is how it first appeared here — made every response fail to parse, so the
whole source was silently discarded and every answer came from one source that
looked like two.

---

## Architecture

```
cmd/netgraph/          the CLI: main.go holds DNS, commands.go the rest
cmd/asnprobe/          a driver for exercising ASN lookups live
pkg/models/            every type that crosses a module boundary
internal/dns/          query building, UDP and TCP transport, parsing
internal/traceroute/   the route engine and the reply matcher
internal/asn/          RIPEstat and RDAP, merged
internal/cache/        the on-disk lookup cache
internal/latency/      TCP round-trip measurement and statistics
internal/watch/        change detection over time
internal/render/       ASCII, table, CSV, JSON and HTML output
```

`internal/` is importable. Nothing in the network core imports the CLI.

---

## Permissions

The DNS analyzer, ASN lookup, latency measurement and every exporter need **no
privileges at all**. They speak ordinary UDP and TCP.

Traceroute needs a raw socket:

```console
$ sudo setcap cap_net_raw+ep ./netgraph
```

or run as root. On Linux, `net.ipv4.ping_group_range` can grant unprivileged ICMP
datagram sockets, but those carry only echo request and reply — never the Time
Exceeded messages traceroute reads. So that route does not work, and the message
says so rather than blaming the network.

UDP and TCP traceroute need the socket too, to read the replies they provoke,
which is why they cannot work where ICMP is filtered. That is reported in the
output rather than shown as a route with missing hops.

---

## Testing

```console
$ go test ./...
ok  	github.com/Xwalims/netgraph/internal/asn
ok  	github.com/Xwalims/netgraph/internal/cache
ok  	github.com/Xwalims/netgraph/internal/dns
ok  	github.com/Xwalims/netgraph/internal/latency
ok  	github.com/Xwalims/netgraph/internal/render
ok  	github.com/Xwalims/netgraph/internal/traceroute
ok  	github.com/Xwalims/netgraph/internal/watch
```

**120 tests.** They build synthetic packets rather than depending on a public
resolver being up, because a suite that fails because 1.1.1.1 is slow is a suite
that proves nothing about the decoder.

The DNS suite covers record-type parsing, response codes, name compression
including a deliberate pointer loop, TXT chunk concatenation, IPv6 address
handling, context cancellation, and reverse-lookup behaviour — including the
nibble order of the generated `in-addr.arpa` and `ip6.arpa` names, checked
against CPython's `ipaddress.reverse_pointer`.

Live behaviour is verified separately, against 1.1.1.1, 8.8.8.8, RIPEstat and
RDAP — which is how the DNS and ASN bugs above were found.

Three of these tests exist because they caught something:

- **The cache reported a hit rate of 200%.** Every `Get` ends in one of three
  outcomes — fresh hit, stale serve, or miss — and the denominator counted two
  while the numerator counted three.
- **Sub-millisecond timings were understated.** `Duration.Microseconds()` floors,
  so 1.5µs printed as `1µs`. Every such measurement was biased low.
- **Loss was read from a field rather than recomputed.** A hop built by any path
  other than the engine's reported 0% while dropping two probes of three.

---

## Limitations

**Traceroute needs `CAP_NET_RAW`.** No protocol avoids it.

**`netgraph ping` measures TCP, not ICMP.** It works without privileges and gives
a real end-to-end figure, but it is not the same number `ping` prints.

**No GeoIP city.** Approximate location is a guess, and the tool does not make
claims it cannot measure.

**ASN data is a snapshot.** Routing changes; the cache is marked stale rather
than silently refreshed.

**The cache is not shared between concurrent runs.** Two traces at once may each
fetch. It is a cache, not a lock.

---

## Licence

MIT. See [LICENSE](LICENSE).
