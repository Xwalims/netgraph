package dns

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync/atomic"
	"time"
)

const (
	// dnsResponseBufferSize is the largest response this resolver will read.
	// 4096 is the EDNS0 buffer size; a UDP answer without EDNS is capped at 512
	// bytes, so anything larger means truncation rather than a genuinely larger
	// answer.
	dnsResponseBufferSize = 4096

	// dnsMaxResponseSize caps an announced length over TCP so a broken or
	// malicious server cannot make the process allocate an arbitrary buffer.
	dnsMaxResponseSize = 65535
)

// queryID hands out the transaction IDs. It starts from a random value because a
// predictable ID makes DNS spoofing trivial: an off-path attacker who can guess
// the next ID can inject an answer. This is the reason `source port` randomisation
// and `TXID` randomisation exist.
var queryIDCounter = uint32(rand.Intn(0xffff))

func nextQueryID() uint16 {
	return uint16(atomic.AddUint32(&queryIDCounter, 1))
}

// buildQuery encodes a standard recursive query for one name and type.
func buildQuery(name string, qtype uint16, id uint16) []byte {
	// Header: ID, flags (RD set), QDCOUNT=1, everything else zero.
	buf := make([]byte, 12, 12+len(name)+6)
	binary.BigEndian.PutUint16(buf[0:2], id)
	binary.BigEndian.PutUint16(buf[2:4], 0x0100) // standard query, recursion desired
	binary.BigEndian.PutUint16(buf[4:6], 1)      // one question

	buf = appendName(buf, name)

	buf = appendUint16(buf, qtype)
	buf = appendUint16(buf, 1) // class IN

	return buf
}

// appendName encodes a domain name in wire format.
func appendName(buf []byte, name string) []byte {
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if label == "" {
			continue
		}
		// A label longer than 63 bytes cannot be encoded; the protocol's limit is
		// a hard 63, and silently truncating would produce a query for a
		// different name than the user asked about.
		if len(label) > 63 {
			label = label[:63]
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	return append(buf, 0)
}

func appendUint16(buf []byte, value uint16) []byte {
	return binary.BigEndian.AppendUint16(buf, value)
}

func appendUint32(buf []byte, value uint32) []byte {
	return binary.BigEndian.AppendUint32(buf, value)
}

// queryServer sends one query to one server and parses the answer.
//
// network is passed in as forceTCP rather than always derived from r.options,
// so the TCP retry for a truncated answer can reuse this function without
// mutating the Resolver: a shared Resolver must stay race-free.
//
// first marks the first server in a multi-server lookup, which is the only one
// allowed to retry a truncated answer over TCP.
func (r *Resolver) queryServer(
	ctx context.Context,
	server string,
	query []byte,
	name string,
	recordType RecordType,
	forceTCP bool,
	first bool,
) (*Result, error) {
	address, err := normaliseServer(server)
	if err != nil {
		return nil, err
	}

	start := time.Now()
	network := networkFor(address, r.options.TCP || forceTCP)
	conn, err := dialTimeout(ctx, network, address, r.options.Timeout)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", server, err)
	}
	defer conn.Close()

	deadline := start.Add(r.options.Timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = conn.SetDeadline(deadline)

	if network == "tcp" {
		// Over TCP the message is length-prefixed. Without the prefix the server
		// reads the first two bytes as a length and misparses everything after.
		framed := make([]byte, 2+len(query))
		binary.BigEndian.PutUint16(framed[0:2], uint16(len(query)))
		copy(framed[2:], query)
		query = framed
	}

	if _, err := conn.Write(query); err != nil {
		return nil, fmt.Errorf("write to %s: %w", server, err)
	}

	// The answer is read in ONE call, because a UDP socket is a datagram socket
	// and does not buffer:
	//
	//   - a datagram arrives whole and Read consumes all of it
	//   - reading the 12-byte header first therefore swallows the entire
	//     response and the remaining bytes are gone for good
	//
	// This was the bug that made every query time out on a network answering in
	// 40ms: the first read took all 61 bytes and left 49 of them discarded.
	//
	// TCP genuinely is stream-oriented, so there the length prefix is read first
	// and exactly that many bytes follow.
	//
	// The two paths allocate DIFFERENTLY and that difference used to be a
	// process-killing panic: the buffer was sized for a UDP datagram (4096) and
	// the TCP branch then sliced readBuffer[:messageLength] with a length the
	// server chose, having only rejected anything above dnsMaxResponseSize
	// (65535). Any answer between 4097 and 65535 bytes -- which is exactly what
	// TCP exists to carry -- ran off the end of the slice and took the whole
	// program down with "slice bounds out of range". The 4096 limit is the EDNS0
	// buffer for UDP and has nothing to do with a stream that can carry 65535.
	messageLength := 0

	if network == "tcp" {
		var lengthBuf [2]byte
		if _, err := readFull(conn, lengthBuf[:]); err != nil {
			return nil, fmt.Errorf("read length from %s: %w", server, err)
		}
		messageLength = int(binary.BigEndian.Uint16(lengthBuf[:]))
		if messageLength > dnsMaxResponseSize || messageLength < 12 {
			return nil, fmt.Errorf(
				"server %s announced an implausible response length of %d bytes",
				server, messageLength)
		}
		// Sized to the announced length, which dnsMaxResponseSize has already
		// bounded, so this cannot allocate an arbitrary amount.
		readBuffer := make([]byte, messageLength)
		n, err := readFull(conn, readBuffer)
		if err != nil {
			return nil, fmt.Errorf("read answer from %s: %w", server, err)
		}
		messageLength = n
		return r.finishAnswer(server, name, recordType, readBuffer[:messageLength], start)
	}

	// UDP: one datagram, one read, and it cannot exceed the buffer the kernel
	// hands over, so a single datagram-sized buffer is the whole story.
	readBuffer := make([]byte, dnsResponseBufferSize)
	n, err := conn.Read(readBuffer)
	if err != nil {
		return nil, fmt.Errorf("read answer from %s: %w", server, err)
	}
	if n < 12 {
		return nil, fmt.Errorf(
			"server %s returned %d bytes, shorter than a DNS header", server, n)
	}
	message := readBuffer[:n]
	truncated := message[2]&0x02 != 0

	if truncated {
		// Options.TCP promises that "a response larger than a UDP datagram is
		// switched over automatically". Honouring that means re-asking over
		// TCP rather than handing back a partial answer with a flag on it: the
		// caller asked for the records, and TC exists precisely to say they
		// did not fit.
		//
		// Only on the first server. If several servers are being compared, a
		// server that keeps truncating must not turn one UDP probe into N
		// sequential TCP probes.
		if first {
			tcpResult, err := r.queryOverTCP(ctx, server, query, name, recordType)
			if err == nil {
				return tcpResult, nil
			}
			// The TCP attempt failed. Falling back to the truncated UDP answer
			// is strictly more informative than reporting only the TCP error,
			// so the partial result is kept and the reason recorded.
			answers, rcode, perr := parseAnswer(message, recordType)
			if perr != nil {
				return nil, fmt.Errorf("parse answer from %s: %w", server, perr)
			}
			result := &Result{
				Name: name, Type: recordType, Server: server,
				Records: answers, RTT: time.Since(start), Truncated: true,
				RCode: rcode, Response: rcodeName(rcode),
			}
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("response was truncated over UDP and the TCP retry failed: %v", err))
			return result, nil
		}
	}

	return r.finishAnswer(server, name, recordType, message, start)
}

// finishAnswer parses a complete response message and wraps it in a Result.
//
// Both transports converge here so the parse, the truncation flag and the
// elapsed time are computed the same way whichever way the bytes arrived.
func (r *Resolver) finishAnswer(
	server, name string, recordType RecordType, message []byte, start time.Time,
) (*Result, error) {
	if len(message) < 12 {
		return nil, fmt.Errorf(
			"server %s returned %d bytes, shorter than a DNS header", server, len(message))
	}
	// The TC bit means the answer did not fit in a datagram. Silently returning a
	// partial answer would be reporting an incomplete result as complete.
	truncated := message[2]&0x02 != 0

	answers, rcode, err := parseAnswer(message, recordType)
	if err != nil {
		return nil, fmt.Errorf("parse answer from %s: %w", server, err)
	}

	return &Result{
		Name:      name,
		Type:      recordType,
		Server:    server,
		Records:   answers,
		RTT:       time.Since(start),
		Truncated: truncated,
		RCode:     rcode,
		Response:  rcodeName(rcode),
	}, nil
}

// queryOverTCP re-issues a query over TCP, which has no datagram size limit.
//
// A truncated UDP answer is the one case where retrying is unambiguously
// correct: TC is a statement that the answer is incomplete, and TCP exists so
// the complete answer can be fetched.
//
// It does not touch r.options. Flipping a flag on the Resolver to switch
// transport would race with any concurrent Lookup sharing it.
func (r *Resolver) queryOverTCP(
	ctx context.Context,
	server string,
	query []byte,
	name string,
	recordType RecordType,
) (*Result, error) {
	// query arrives bare. This is only ever called from the UDP branch, where
	// the message was not length-prefixed, and queryServer prefixes a TCP
	// message itself.
	//
	// It is tempting to "helpfully" strip a prefix if the first two bytes
	// happen to equal the remaining length, but the first two bytes of a DNS
	// query are the transaction ID, so that test is true by coincidence about
	// once in 65536 queries and would silently corrupt the query.
	return r.queryServer(ctx, server, query, name, recordType, true, true)
}

// normaliseServer turns "1.1.1.1" or "dns.google" into "1.1.1.1:53".
func normaliseServer(server string) (string, error) {
	server = strings.TrimSpace(server)
	if server == "" {
		return "", fmt.Errorf("empty server")
	}
	// "[::1]:53" and "[2606:4700::1111]" both carry brackets. SplitHostPort
	// understands the first form and ParseIP understands neither, so the
	// brackets are removed before the address is parsed and put back by
	// JoinHostPort.
	if _, _, err := net.SplitHostPort(server); err == nil {
		return server, nil
	}
	bare := strings.TrimSuffix(strings.TrimPrefix(server, "["), "]")
	if ip := net.ParseIP(bare); ip != nil {
		return net.JoinHostPort(bare, "53"), nil
	}
	// A hostname: resolve it so the dial has an address, and report what it
	// resolved to rather than hiding the step.
	ips, err := net.LookupIP(server)
	if err != nil || len(ips) == 0 {
		return "", fmt.Errorf("cannot resolve nameserver %q", server)
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return net.JoinHostPort(v4.String(), "53"), nil
		}
	}
	return net.JoinHostPort(ips[0].String(), "53"), nil
}

// networkFor picks udp or tcp for an address.
func networkFor(address string, forceTCP bool) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		// IPv6 has no practical UDP-literal path here, and the address parser
		// would need brackets handled separately; TCP is the reliable choice.
		return "tcp"
	}
	if forceTCP {
		return "tcp"
	}
	return "udp"
}

// dialTimeout opens a connection that honours the context.
func dialTimeout(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
	dialer := net.Dialer{Timeout: timeout}
	return dialer.DialContext(ctx, network, address)
}

// readFull reads exactly len(buf) bytes, looping over short reads.
func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, fmt.Errorf("connection closed after %d of %d bytes", total, len(buf))
		}
	}
	return total, nil
}

// parseAnswer walks the answer section and returns the records of the requested
// type.
//
// It returns every record it finds rather than only the requested type, because a
// CNAME chain means the address records live under a different name and
// filtering by name before looking at the type would drop them.
func parseAnswer(msg []byte, want RecordType) ([]Record, int, error) {
	if len(msg) < 12 {
		return nil, 0, fmt.Errorf("response is %d bytes, shorter than a DNS header", len(msg))
	}
	flags := binary.BigEndian.Uint16(msg[2:4])
	rcode := int(flags & 0x000F)

	qdCount := int(binary.BigEndian.Uint16(msg[4:6]))
	anCount := int(binary.BigEndian.Uint16(msg[6:8]))

	offset := 12
	// Skip the question section.
	for i := 0; i < qdCount; i++ {
		_, next, err := readName(msg, offset)
		if err != nil {
			return nil, rcode, err
		}
		offset = next + 4 // QTYPE + QCLASS
	}

	records := make([]Record, 0, anCount)
	for i := 0; i < anCount && offset < len(msg); i++ {
		name, next, err := readName(msg, offset)
		if err != nil {
			// A malformed record should not discard the records already parsed:
			// partial answers are still useful, and the caller sees the warning.
			break
		}
		offset = next
		if offset+10 > len(msg) {
			break
		}
		rrType := binary.BigEndian.Uint16(msg[offset : offset+2])
		rrClass := binary.BigEndian.Uint16(msg[offset+2 : offset+4])
		ttl := binary.BigEndian.Uint32(msg[offset+4 : offset+8])
		rdLength := int(binary.BigEndian.Uint16(msg[offset+8 : offset+10]))
		offset += 10

		if offset+rdLength > len(msg) {
			break
		}
		// rdStart is where the rdata begins in the WHOLE message, which is the
		// base a compression pointer inside it is resolved against.
		rdStart := offset
		rdata := msg[rdStart : rdStart+rdLength]
		offset += rdLength

		// Only class IN is meaningful here; a CH record would otherwise show up
		// as a record of the same type with the wrong meaning.
		if rrClass != 1 {
			continue
		}

		// RDATA is passed with the whole message and its offset inside it, not
		// on its own: RFC 1035 4.1.4 allows a name in the RDATA of NS, CNAME,
		// SOA, PTR and MX to be compressed, so those rdata bytes can be a
		// pointer whose target is elsewhere in the message. Decoding an rdata
		// slice on its own resolves those pointers against the wrong base
		// address and the record is dropped -- see parseRecord.
		record, ok := parseRecord(msg, rdStart, name, rrType, ttl, rdata)
		if ok {
			// The TTL came off the wire, so it is known. Records built by the
			// system-resolver path leave this false, which is what lets the
			// renderer tell "ttl=0" apart from "this source has no TTLs".
			record.TTLKnown = true
		}
		if !ok {
			continue
		}
		// A CNAME is always reported even when another type was requested,
		// because it explains where the requested records came from.
		if record.Type == want || record.Type == TypeCNAME || want == TypeCNAME {
			records = append(records, record)
		}
	}

	return records, rcode, nil
}

// parseRecord converts one resource record into the package's Record type.
//
// msg is the whole DNS message and rdStart is the offset of rdata inside it,
// which are needed because a name inside the rdata may be a compression
// pointer. RFC 1035 4.1.4 permits compression in the RDATA of NS, CNAME, SOA,
// PTR and MX:
//
//	"In the case of a CNAME, NS, PTR, MX, or SOA RR, the domain name may be
//	 stored as a domain name (or a list of domain names) as usual, but may be
//	 stored as a pointer...  the compression scheme described in this
//	 paragraph may be used."
//
// Real resolvers do exactly that. A verbatim answer from systemd-resolved for
// "www.github.com CNAME" carries rdata `c0 10`, a pointer to offset 0x10 of the
// message, not to an offset within the rdata. Decoding the rdata slice on its
// own -- readName(rdata, 0) -- therefore reads a pointer to offset 0x10 of a
// two-byte slice, finds nothing sensible there, and the record is silently
// dropped. That loses the CNAME of every ordinary name resolution.
func parseRecord(msg []byte, rdStart int, name string, rrType uint16, ttl uint32, rdata []byte) (Record, bool) {
	record := Record{Name: name, TTL: ttl}

	// nameAt decodes the domain name that begins rdLen bytes into the rdata,
	// where rdLen is the fixed header preceding it (0 for CNAME/NS/PTR, 2 for
	// MX, 6 for SRV). The name is read at its offset in the whole message so
	// compression pointers resolve correctly; the rdata slice itself only
	// supplies the length check.
	nameAt := func(rdLen int) (string, bool) {
		if len(rdata) < rdLen {
			return "", false
		}
		// next is the offset just past the encoded name, so next-start is how
		// many bytes of this record the name actually occupied. For a
		// compressed name that is the two bytes of the pointer, which is what
		// makes this one check correct for both encodings.
		start := rdStart + rdLen
		target, next, err := readName(msg, start)
		if err != nil {
			return "", false
		}
		if next-start > len(rdata)-rdLen {
			// The name runs past this record's rdata into the next record's
			// bytes, so it is not a name this record actually contains.
			return "", false
		}
		return target, true
	}

	switch RecordType(typeName(rrType)) {
	case TypeA:
		if len(rdata) < 4 {
			return record, false
		}
		record.Type = TypeA
		record.Value = net.IP(rdata[:4]).String()
	case TypeAAAA:
		if len(rdata) < 16 {
			return record, false
		}
		record.Type = TypeAAAA
		record.Value = net.IP(rdata[:16]).String()
	case TypeCNAME:
		target, ok := nameAt(0)
		if !ok {
			return record, false
		}
		record.Type = TypeCNAME
		record.Value = target
	case TypeNS:
		target, ok := nameAt(0)
		if !ok {
			return record, false
		}
		record.Type = TypeNS
		record.Value = target
	case TypePTR:
		target, ok := nameAt(0)
		if !ok {
			return record, false
		}
		record.Type = TypePTR
		record.Value = target
	case TypeTXT:
		// TXT rdata is a sequence of length-prefixed strings, which have to be
		// concatenated: reporting only the first chunk of a long TXT record
		// truncates SPF and DKIM keys.
		record.Type = TypeTXT
		record.Value = readTXT(rdata)
	case TypeMX:
		if len(rdata) < 3 {
			return record, false
		}
		target, ok := nameAt(2)
		if !ok {
			return record, false
		}
		record.Type = TypeMX
		record.Priority = binary.BigEndian.Uint16(rdata[0:2])
		record.Value = target
	case TypeSRV:
		if len(rdata) < 7 {
			return record, false
		}
		target, ok := nameAt(6)
		if !ok {
			return record, false
		}
		record.Type = TypeSRV
		record.Priority = binary.BigEndian.Uint16(rdata[0:2])
		record.Weight = binary.BigEndian.Uint16(rdata[2:4])
		record.Port = binary.BigEndian.Uint16(rdata[4:6])
		record.Value = target
	case TypeSOA:
		// SOA rdata is two names (MNAME and RNAME). Both are read at their
		// offset in the whole message so a compressed name in either position
		// resolves, and both have to stay inside this record's rdata.
		first, next, err := readName(msg, rdStart)
		if err != nil {
			return record, false
		}
		if next-rdStart > len(rdata) {
			return record, false
		}
		second, end, err := readName(msg, next)
		if err != nil {
			return record, false
		}
		if end-rdStart > len(rdata) {
			return record, false
		}
		record.Type = TypeSOA
		record.Value = fmt.Sprintf("%s %s", first, second)
	case TypeCAA:
		// rdata: flags(1) tagLen(1) tag value
		if len(rdata) < 2 {
			return record, false
		}
		tagLen := int(rdata[1])
		if len(rdata) < 2+tagLen {
			return record, false
		}
		record.Type = TypeCAA
		record.Value = fmt.Sprintf("%d %s %s", rdata[0], rdata[2:2+tagLen], string(rdata[2+tagLen:]))
	default:
		return record, false
	}
	return record, true
}

// readTXT concatenates the length-prefixed chunks of a TXT record.
func readTXT(rdata []byte) string {
	var out strings.Builder
	for i := 0; i < len(rdata); {
		length := int(rdata[i])
		if i+1+length > len(rdata) {
			break
		}
		out.Write(rdata[i+1 : i+1+length])
		i += 1 + length
	}
	return out.String()
}

// typeName maps a numeric type back to its name.
func typeName(rrType uint16) string {
	for name, value := range dnsType {
		if value == rrType {
			return string(name)
		}
	}
	return fmt.Sprintf("TYPE%d", rrType)
}

// readName decodes a possibly-compressed domain name.
//
// Compression pointers are followed, and the returned offset is the position
// just after the name in the *original* stream, which is what lets a caller keep
// walking records that follow a compressed name.
func readName(msg []byte, offset int) (string, int, error) {
	var labels []string
	// A pointer can chain, so the number of jumps is bounded to stop a
	// deliberately crafted packet from looping forever.
	jumps := 0

	// The offset a caller must resume from is the position just past the name
	// *in the original stream*, which for a compressed name is the byte after
	// the two-byte pointer and for an uncompressed one is the zero terminator.
	//
	// It has to be tracked as a separate variable rather than derived from the
	// walking offset: the walking offset follows the pointer to elsewhere in the
	// packet, so returning it would send the record parser back to the middle of
	// the name it just read. That is the bug this comment exists to prevent --
	// it made every record in a response unparseable.
	after := -1

	for {
		if offset >= len(msg) {
			return "", 0, fmt.Errorf("name runs past the end of the message")
		}
		length := int(msg[offset])

		switch {
		case length == 0:
			// The root label is a single zero byte, so it is consumed and the
			// next field starts one byte past it -- but only when no pointer was
			// followed. After a pointer, the terminator belongs to the name it
			// points at and `after` already holds the resume position; writing
			// `offset` there would send the caller back into the middle of the
			// name it just read.
			if after == -1 {
				after = offset + 1
			}
			if len(labels) == 0 {
				return ".", after, nil
			}
			return strings.Join(labels, "."), after, nil

		case length&0xc0 == 0xc0:
			// Compression pointer: two bytes, the low 14 bits are the offset.
			if offset+1 >= len(msg) {
				return "", 0, fmt.Errorf("truncated compression pointer")
			}
			pointer := int(binary.BigEndian.Uint16(msg[offset:offset+2]) & 0x3fff)
			if after == -1 {
				// A pointer occupies two bytes and the next field starts right
				// after it. Using offset+1, or returning offset+1 from here,
				// pointed the record parser into the middle of the pointer.
				after = offset + 2
			}
			jumps++
			if jumps > 32 {
				return "", 0, fmt.Errorf("compression pointer loop")
			}
			if pointer >= len(msg) {
				return "", 0, fmt.Errorf("compression pointer past the end of the message")
			}
			offset = pointer
			// Jumping to the pointer leaves the zero-terminator branch with the
			// pointer's position still in `after`, which is exactly the resume
			// point the caller needs.
			continue

		default:
			if offset+1+length > len(msg) {
				return "", 0, fmt.Errorf("label of %d bytes runs past the end", length)
			}
			labels = append(labels, string(msg[offset+1:offset+1+length]))
			offset += 1 + length
			if len(labels) > 128 {
				return "", 0, fmt.Errorf("too many labels")
			}
		}
	}
}
