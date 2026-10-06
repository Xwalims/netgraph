# Changelog

All notable changes to netgraph are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/).

## [0.2.0]

The route release. Every command in the brief now exists.

### Added

- `netgraph trace` with UDP, TCP and ICMP probes, IPv4 and IPv6, configurable
  hop count, probes per hop and timeout, and parallel probing. The reply matcher
  keys each ICMP error to its probe by the destination port quoted inside it, and
  a test enumerates the whole port range to prove no two probes can collide.
- `netgraph map`, which traces and then draws, as ASCII, JSON, HTML or CSV.
- `netgraph ip`, which classifies an address: family, public or private, reverse
  DNS, ASN, prefix, RIR and abuse contact.
- `netgraph asn`, merging RIPEstat's routing view with RDAP's registration view.
  A failed source leaves its fields empty and says so rather than guessing.
- `netgraph ping`, measuring end-to-end RTT over a TCP handshake so that no
  privileges are needed. Reports min, max, mean, median, jitter, standard
  deviation, loss and P50/P90/P95/P99, with a sparkline.
- `netgraph watch`, reporting reachability, latency, packet-loss, route and DNS
  changes. The first check establishes a baseline and reports nothing, so the
  output describes changes rather than describing the target.
- `netgraph compare`, which traces several targets and names the hop at which
  the paths diverge.
- `netgraph export`, re-rendering a saved result in any supported format.
- `netgraph cache stats`, `clear` and `sweep` over the on-disk lookup cache.
- An on-disk cache with atomic writes, an injectable clock, and a `stale` flag
  so an expired entry is served only when a source has failed, and only marked.

### Fixed

- The UDP traceroute could never work. It sent a probe and waited for a reply on
  a plain socket, but the reply that reveals a hop is the ICMP Time Exceeded,
  which is delivered to a raw socket. Every trace returned an empty route,
  indistinguishable from a filtered path.
- An empty route was drawn as `LOCAL -> DESTINATION` with `0% loss`, asserting
  both that a path existed and that nothing was lost.
- `--protocol` was upper-cased before comparison against lowercase constants, so
  the default value matched no case and every trace without an explicit flag was
  rejected.
- The capability check covered only ICMP, though UDP and TCP need the same
  socket to read the replies they provoke.
- The cache reported a hit rate above 100%: three outcomes ended a lookup and
  the denominator counted two.
- `Format` truncated sub-millisecond timings, biasing every such measurement low.
- Loss was read from `Hop.Loss` rather than recomputed from `Sent` and
  `Received`, so a hop built by another path reported 0% while dropping probes.
- The ASN decoder typed RDAP's `vcardArray` as a string. It is a JSON array, so
  every response failed to parse and that source was discarded wholesale.
- A DNS answer over TCP larger than 4096 bytes crashed the process. The read
  buffer was sized once for a UDP datagram and the TCP branch sliced it with the
  length the server announced, having rejected only lengths above 65535 -- so any
  answer between 4097 and 65535 bytes, which is exactly what TCP exists to
  carry, panicked with `slice bounds out of range`. Each transport now allocates
  for its own message, and both converge on one parse path.

### Known limitations

- Traceroute needs `CAP_NET_RAW`; no protocol avoids it. Unprivileged ICMP
  datagram sockets cannot receive Time Exceeded replies.
- `ping` measures TCP rather than ICMP. It needs no privileges and gives a real
  end-to-end figure, but it is not the number `ping` prints.
- No city-level GeoIP. An approximate city presented as a location is a claim
  this tool does not make.
- The cache is not shared between concurrent runs.

## [0.1.0]

### Added

- `netgraph dns` with all ten record types, real UDP and TCP queries, RTT and TTL
  from the responses, server comparison, reverse lookups and JSON output.
- The data model for hops, routes, ASN records, latency statistics, route
  comparison and watch events, in `pkg/models`.

### Fixed

- A failed query exited `1`, meaning "no records". A resolver that never replied
  was being reported as an authoritative empty answer.
- `--reverse` ignored `--server`, printing a server it had never queried.
- `--all` ended with an error about a name not being an address, because `PTR`
  was in the list of forward types.
- `--quiet` printed the header block anyway.
- Four bugs in the DNS codec itself: a UDP socket does not buffer, so reading the
  header separately discarded the rest of the datagram; the name decoder returned
  the wrong resume position after a compression pointer; RDATA compression
  pointers were resolved against the RDATA slice instead of the message, dropping
  every CNAME chain; and a length-prefix heuristic could corrupt roughly one
  query in 65536.
