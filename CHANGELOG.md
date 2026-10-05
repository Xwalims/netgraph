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

### Known limitations

- Everything except `dns` is unimplemented and says so, rather than printing
  nothing and exiting `0`.
- The traceroute engine needs a raw socket, which this build environment does not
  provide. The data model is in place for it.
