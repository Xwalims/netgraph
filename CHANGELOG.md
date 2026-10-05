# Changelog

All notable changes to netgraph are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/).

## [0.1.0] — unreleased

The core release: the DNS analyzer and the data model every later command will
fill.

### Added

- `netgraph dns` with all ten record types, real UDP and TCP queries, per-server
  RTT and TTL, server comparison, reverse lookups, and JSON output.
- The data model for hops, routes, ASN records, latency statistics, route
  comparison and watch events, in `pkg/models`.
- Exit codes that compose in a pipeline: `0` success, `1` no records, `2` failure
  or an unimplemented command.

### Fixed

All of these reported success while doing the wrong thing. The unit tests were
green for every one of them; each was found by running the built binary against
real nameservers.

- `--reverse` ignored `--server` completely: the header printed the requested
  nameserver while the query went to the operating system, so a server that did
  not exist still answered successfully and `--compare` compared nothing.
  Reverse queries now go to the configured server, and the `in-addr.arpa` /
  `ip6.arpa` name is built here rather than delegated to the OS, which also makes
  `--reverse` work for an address the local resolver has never seen.
- A failed query exited `1`, the code for "no records". A dead resolver was
  reported as an authoritative empty answer, with `no records found` printed under
  the timeout error. Exit `2` is now distinct from exit `1` in every path,
  including `--json`.
- `--quiet` printed the `DNS / name / server / timeout` preamble despite
  promising values only.
- `--all` walked `AllTypes`, which contains `PTR`, so every `--all` on a name
  ended with the error `"google.com" is not an IP address`. Reported as an error
  line, that read as a server fault rather than as a question that cannot apply to
  a name. `--all` now walks the forward types only.
- A `ttl=0` was printed for records from the system resolver, which exposes no
  TTLs at all. TTL is now marked known or unknown rather than conflated.
- `Result.Warnings`, which the resolver fills in when a truncated UDP answer could
  not be retried over TCP, was never read by the CLI, so a partial answer looked
  complete. It is printed, and carried in `--json`.

### Known limitations

- Everything except `dns` is unimplemented and says so, rather than printing
  nothing and exiting `0`.
- The traceroute engine needs a raw socket, which this build environment does not
  provide. The data model is in place for it.