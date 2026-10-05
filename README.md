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
$ netgraph dns example.com --all              every record type a name can have
$ netgraph dns example.com --compare          several servers, and where they disagree
$ netgraph dns 1.1.1.1 --reverse              PTR lookup
$ netgraph dns example.com --json             machine-readable
```

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

36 test cases covering record-type parsing, response codes, name compression
including a deliberate pointer loop, TXT chunk concatenation, IPv6 address
handling, context cancellation, and reverse-lookup behaviour -- including the
nibble order of the generated `in-addr.arpa` and `ip6.arpa` names, checked
against CPython's `ipaddress.reverse_pointer`.

They build synthetic packets rather than depending on a public resolver being up,
because a suite that fails because 1.1.1.1 is slow is a suite that tests nothing.

The live behaviour was verified separately, against 1.1.1.1 and 8.8.8.8.

---

## Licence

MIT. See [LICENSE](LICENSE).
