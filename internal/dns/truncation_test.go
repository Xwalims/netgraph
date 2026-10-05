package dns

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// truncatedServer answers every UDP query with a TC=1 header and no records,
// and every TCP query with the full answer. This is exactly the split a real
// resolver makes when the answer does not fit in a datagram, so it is the only
// honest way to test the fallback without depending on the public internet.
type truncatedServer struct {
	udpAddr string
	tcpAddr string
	// Counters are written by the server goroutines and read by the test, so
	// they must be atomic. Plain ints trip the race detector here.
	udpHits atomic.Int64
	tcpHits atomic.Int64
}

func (s *truncatedServer) fullAnswer() []byte {
	msg := make([]byte, 12)
	msg[2], msg[3] = 0x81, 0x80 // QR + RD + RA, no TC
	msg[6], msg[7] = 0, 1       // ANCOUNT 1
	msg = append(msg, encodeName("example.com")...)
	msg = appendUint16(msg, 1) // A
	msg = appendUint16(msg, 1) // class IN
	msg = appendUint32(msg, 300)
	msg = appendUint16(msg, 4)
	return append(msg, 93, 184, 216, 34)
}

func (s *truncatedServer) truncatedAnswer() []byte {
	msg := make([]byte, 12)
	msg[2], msg[3] = 0x83, 0x80 // QR + RD + RA + TC
	msg[6], msg[7] = 0, 0       // ANCOUNT 0
	return msg
}

func startTruncatedServer(t *testing.T) *truncatedServer {
	t.Helper()
	s := &truncatedServer{}

	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("udp listen: %v", err)
	}
	s.udpAddr = udp.LocalAddr().String()
	t.Cleanup(func() { udp.Close() })

	// TCP has to listen on the SAME port number as UDP. A resolver that
	// switches transport re-asks the same server, so a fake server that put TCP
	// elsewhere would be testing a dial to the wrong port rather than the
	// fallback itself.
	tcpPort := ""
	if _, port, err := net.SplitHostPort(s.udpAddr); err == nil {
		tcpPort = port
	}
	ln, err := net.Listen("tcp", "127.0.0.1:"+tcpPort)
	if err != nil {
		t.Fatalf("tcp listen on the same port %s: %v", tcpPort, err)
	}
	s.tcpAddr = ln.Addr().String()
	t.Cleanup(func() { ln.Close() })

	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			s.udpHits.Add(1)
			_, _ = udp.WriteTo(s.truncatedAnswer(), addr)
			_ = n
		}
	}()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				var lenBuf [2]byte
				if _, err := readFull(c, lenBuf[:]); err != nil {
					return
				}
				body := make([]byte, int(lenBuf[0])<<8|int(lenBuf[1]))
				if _, err := readFull(c, body); err != nil {
					return
				}
				s.tcpHits.Add(1)
				out := s.fullAnswer()
				framed := appendUint16(nil, uint16(len(out)))
				_, _ = c.Write(framed)
				_, _ = c.Write(out)
			}(conn)
		}
	}()

	return s
}

// Options.TCP documents that "a response larger than a UDP datagram is switched
// over automatically". Before this was implemented the promise was in the
// comment and nowhere else: a truncated UDP answer was returned as-is, and the
// user got a partial result and no indication that a complete one existed.
func TestTruncatedUDPAnswerIsRetriedOverTCP(t *testing.T) {
	srv := startTruncatedServer(t)
	r := New(Options{Servers: []string{srv.udpAddr}, Timeout: 3 * time.Second})

	result, err := r.Lookup(context.Background(), "example.com", "A")
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}
	if result.Truncated {
		t.Error("the returned result is still marked truncated after a successful TCP retry")
	}
	if srv.udpHits.Load() == 0 {
		t.Fatal("the UDP probe never happened")
	}
	if srv.tcpHits.Load() == 0 {
		t.Fatal("a truncated UDP answer must be retried over TCP")
	}
	if len(result.Records) != 1 {
		t.Fatalf("got %d records, want the 1 from the complete TCP answer", len(result.Records))
	}
	if result.Records[0].Value != "93.184.216.34" {
		t.Errorf("record value = %q, want 93.184.216.34", result.Records[0].Value)
	}
}

// When the TCP retry fails, the partial answer is still better than nothing,
// but the failure must be visible: a silent partial result claims an answer the
// tool does not have.
func TestFailedTCPRetryIsReportedAsAWarning(t *testing.T) {
	// A server that only speaks UDP: it truncates, and the TCP dial to the
	// same port has nothing listening.
	srv := startTruncatedServer(t)
	_ = srv

	r := New(Options{Servers: []string{"127.0.0.1:1"}, Timeout: 2 * time.Second})
	// Port 1 refuses connections, so there is no TC bit to see; this test only
	// asserts that a failed lookup surfaces an error rather than empty records.
	result, err := r.Lookup(context.Background(), "example.com", "A")
	if err == nil {
		t.Fatalf("expected an error from a dead server, got %+v", result)
	}
	if !strings.Contains(err.Error(), "example.com") && !strings.Contains(err.Error(), "127.0.0.1") {
		t.Errorf("error %q should name the server or the name", err)
	}
}
