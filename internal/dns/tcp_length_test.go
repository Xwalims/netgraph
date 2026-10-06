package dns

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"
)

// A DNS answer over TCP can be up to 65535 bytes, which is the entire reason
// the TCP transport exists. The read buffer, however, was allocated once at the
// EDNS0/UDP size (4096) and the TCP branch then sliced it with the length the
// server announced, rejecting only anything above 65535 -- so every answer
// between 4097 and 65535 bytes panicked the process with "slice bounds out of
// range" instead of being parsed.
//
// These tests assert on behaviour, not on the buffer size: whatever the
// transport reads has to be able to carry a full answer.

// bigTCPServer answers a length-prefixed TCP DNS query with a syntactically
// valid message of at least target bytes.
type bigTCPServer struct {
	addr string
	size int
}

func startBigTCPServer(t *testing.T, target int) *bigTCPServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("tcp listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	s := &bigTCPServer{addr: ln.Addr().String(), size: target}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				var lenBuf [2]byte
				if _, err := readFull(c, lenBuf[:]); err != nil {
					return
				}
				query := make([]byte, int(lenBuf[0])<<8|int(lenBuf[1]))
				if _, err := readFull(c, query); err != nil {
					return
				}
				body := answerWithManyARecords(s.size)
				if _, err := c.Write(appendUint16(nil, uint16(len(body)))); err != nil {
					return
				}
				_, _ = c.Write(body)
			}(conn)
		}
	}()
	return s
}

// answerWithManyARecords builds one valid answer carrying enough A records to
// reach target bytes, with a QDCOUNT=1 question and an ANCOUNT that agrees with
// what follows. The counts have to be consistent or the parser is right to
// reject the message, which is why they are set explicitly rather than left at
// whatever the header helper happened to write.
func answerWithManyARecords(target int) []byte {
	const name = "big.example.com"
	qname := encodeName(name)

	if target > dnsMaxResponseSize {
		target = dnsMaxResponseSize
	}

	msg := headerWithAnswers(0)
	msg[4], msg[5] = 0, 1 // QDCOUNT 1
	msg = append(msg, qname...)
	msg = appendUint16(msg, 1) // QTYPE A
	msg = appendUint16(msg, 1) // QCLASS IN

	one := len(qname) + 10 + 4
	// Round UP so the finished message is at least `target` bytes. A fixture that
	// quietly undershoots is worse than no fixture: the subtest named 4097 was
	// really serving 4082 bytes, which fits the old 4096 buffer, so it passed
	// against the code it was written to catch.
	count := (target - len(msg) + one - 1) / one
	if count < 1 {
		count = 1
	}
	// The length prefix is 16 bits, so a message over dnsMaxResponseSize could
	// not be framed and would not be a legal DNS message anyway.
	if maxCount := (dnsMaxResponseSize - len(msg)) / one; count > maxCount {
		count = maxCount
	}
	if count < 1 {
		count = 1
	}
	msg[6], msg[7] = byte(count>>8), byte(count)
	for i := 0; i < count; i++ {
		msg = appendRecord(msg, name, 1, 1, 60, []byte{93, 184, 216, byte(i % 251)})
	}
	return msg
}

// The boundary that matters is one byte past the old 4096 buffer, plus the far
// end of what the length prefix can express. Every one of these panicked.
func TestTCPAnswerLargerThanTheUDPBufferIsParsed(t *testing.T) {
	for _, size := range []int{dnsResponseBufferSize + 1, 16384, dnsMaxResponseSize} {
		t.Run(strconv.Itoa(size)+"B", func(t *testing.T) {
			srv := startBigTCPServer(t, size)
			r := New(Options{Servers: []string{srv.addr}, Timeout: 20 * time.Second, TCP: true})

			result, err := r.Lookup(context.Background(), "big.example.com", "A")
			if err != nil {
				t.Fatalf("Lookup of a %d-byte TCP answer failed: %v", size, err)
			}
			if len(result.Records) == 0 {
				t.Fatalf("a %d-byte answer parsed to zero records", size)
			}
			if result.Truncated {
				t.Error("a complete TCP answer must not be reported as truncated")
			}
			if result.Response != "NOERROR" {
				t.Errorf("response = %q, want NOERROR", result.Response)
			}
			for _, rec := range result.Records {
				if rec.Type != TypeA || !rec.TTLKnown || rec.TTL != 60 {
					t.Fatalf("record decoded wrongly at scale: %+v", rec)
				}
			}
		})
	}
}

// oversizeTCPServer announces a length prefix and then sends exactly that many
// bytes, whatever they are.
type oversizeTCPServer struct {
	addr       string
	announce   int
	thenWrite  int
	garbageMsg bool
}

func startRawTCPServer(t *testing.T, announce, thenWrite int) *oversizeTCPServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("tcp listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	s := &oversizeTCPServer{addr: ln.Addr().String(), announce: announce, thenWrite: thenWrite}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				var lenBuf [2]byte
				if _, err := readFull(c, lenBuf[:]); err != nil {
					return
				}
				query := make([]byte, int(lenBuf[0])<<8|int(lenBuf[1]))
				_, _ = readFull(c, query)
				_, _ = c.Write(appendUint16(nil, uint16(s.announce)))
				body := answerWithManyARecords(s.thenWrite)
				_, _ = c.Write(body)
			}(conn)
		}
	}()
	return s
}

// A length prefix too small to be a DNS message is an error the server
// announced, not something to allocate and parse.
func TestAnnouncedLengthBelowAHeaderIsAnError(t *testing.T) {
	srv := startRawTCPServer(t, 11, 64)
	r := New(Options{Servers: []string{srv.addr}, Timeout: 5 * time.Second, TCP: true})

	if _, err := r.Lookup(context.Background(), "big.example.com", "A"); err == nil {
		t.Fatal("a length prefix of 11 bytes must be rejected, not parsed")
	}
}

// A server that announces more bytes than it sends must surface as a read
// error rather than as a half-parsed answer presented as complete.
func TestShortAnswerAfterALongAnnouncementIsAnError(t *testing.T) {
	srv := startRawTCPServer(t, 60000, 64)
	r := New(Options{Servers: []string{srv.addr}, Timeout: 5 * time.Second, TCP: true})

	result, err := r.Lookup(context.Background(), "big.example.com", "A")
	if err == nil {
		t.Fatalf("a truncated stream must not be reported as a result: %+v", result)
	}
}
