# NETGRAPH

```
    ┌─┐┌─┐┌┬┐┌─┐┌┬┐┌─┐┌─┐┌─┐┐ ┬┐┌─┐┌┬┐
    │ ││ │││││ ││ ││┬┘│ │├─┤├┬┘│││ ││ ││
    └─┘└─┘└┴┐└─┐└┴┐└─┘└─┘└─┘└┴┘└─┘└─┘└─┘
```

> **See how the internet reaches your destination.**

A network diagnostic CLI that combines traceroute, DNS analysis, ASN lookup and
latency measurement, with route visualisation. This is the v0.1.0 core: the DNS
analyzer is complete and runs against real servers; the traceroute engine is not
written yet.

---

## Status

Read this before the rest, because it decides what the tool can do today.

| Command | State |
| --- | --- |
| `netgraph dns` | **working** — full implementation, all record types, real queries |
| `netgraph version`, `help` | working |
| `netgraph ip` | not implemented |
| `netgraph trace` | not implemented |
| `netgraph ping` | not implemented |
| `netgraph asn` | not implemented |
| `netgraph compare` | not implemented |
| `netgraph map` | not implemented |
| `netgraph watch` | not implemented |
| `netgraph export` | not implemented |

Every unimplemented command says so and exits `2`. None of them prints nothing and
exits `0`, because a caller cannot tell that from success:

```console
$ netgraph trace google.com
netgraph 0.1.0: "trace" is not implemented in 0.1.0 yet.
Working commands: dns, version, help
$ echo $?
2
```

The data model for hops, routes, ASN records, latency statistics and watch events
already exists in `pkg/models`, so the remaining work is the code that fills it.

---

## Install

```console
$ git clone https://github.com/Xwalims/netgraph.git
$ cd netgraph
$ go build -o netgraph ./cmd/netgraph
```

Requires Go 1.23 or newer. No third-party dependencies at runtime.

---

## Usage

```console
$ netgraph dns example.com                    resolve with the system resolver
$ netgraph dns example.com --server 1.1.1.1   query a specific nameserver
$ netgraph dns example.com --type MX          one record type
$ netgraph dns example.com --all              every record type
$ netgraph dns example.com --compare          several servers, and where they disagree
$ netgraph dns 1.1.1.1 --reverse              PTR lookup
$ netgraph dns example.com --json             machine-readable
```

Options:

```
  --server <addr>       query this nameserver instead of the system resolver
  --type <record>       A, AAAA, MX, NS, TXT, SOA, SRV, CAA, CNAME, PTR
  --all                 query every record type
  --compare             query several servers and report the differences
  --reverse             treat the argument as an address
  --timeout <duration>  per-query timeout (default 5s)
  --json                machine-readable output
  --no-color            disable colour (also honours NO_COLOR)
  --quiet               values only, no headings
```

Exit codes: `0` success, `1` the query worked but returned no records, `2` the query
failed or the command is not implemented.

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

---

## Architecture

```
pkg/models/          every type that crosses a module boundary
internal/dns/        the resolver: query building, sending, parsing
cmd/netgraph/        the CLI
cmd/probe/           a small driver used to exercise the resolver
```

`internal/` is importable as a library; nothing in the network core imports the
CLI, so the traceroute engine will be usable without it.

---

## Permissions

The DNS analyzer needs **no privileges at all**. It speaks ordinary UDP and TCP.

The traceroute engine, once written, will need a raw socket for ICMP:

```console
$ sudo setcap cap_net_raw+ep ./netgraph
```

or run as root. On Linux, `net.ipv4.ping_group_range` can grant unprivileged ICMP
datagram sockets instead, where the distribution allows it.

UDP and TCP traceroute additionally need `CAP_NET_RAW` to read the ICMP Time
Exceeded replies, which is why they cannot work where ICMP is filtered by the
network at all. That limitation is reported in the output rather than shown as a
route with missing hops.

---

## Testing

```console
$ go test ./...
ok  	github.com/Xwalims/netgraph/internal/dns
```

60 test cases covering record-type parsing, response codes, name compression
including a deliberate pointer loop, TXT chunk concatenation, IPv6 address
handling and context cancellation.

They build synthetic packets rather than depending on a public resolver being up,
because a suite that fails because 1.1.1.1 is slow is a suite that tests nothing.

The live behaviour was verified separately, against 1.1.1.1 and 8.8.8.8.

---

## Licence

MIT. See [LICENSE](LICENSE).
