package traceroute

import (
	"net"
	"syscall"
)

// The hop limit lives in a socket option, and the option number differs between
// the two families:
//
//   - IPv4: IP_TTL = 2
//   - IPv6: IPV6_UNICAST_HOPS = 31
//
// These are spelled numerically rather than imported from x/sys, because this
// module has no third-party dependencies and a whole package for two constants is
// not worth it. The numbers are stable ABI: they come from the kernel headers
// and have not changed since Linux 2.4 and the BSDs.
//
// This file is the line the whole engine turns on. A probe sent with the default
// TTL reaches the destination, and every reply is then attributed to the wrong
// hop -- which is why the first version of this traceroute, which never set one,
// could not produce a route at all.

// setTTL applies a hop limit to a sending socket.
func setTTL(conn net.Conn, ipv6 bool, ttl int) error {
	// Every connection the standard library hands back implements syscall.Conn,
	// so this succeeds for all of them; the error path exists because the type
	// assertion is checked rather than assumed.
	syscallConn, ok := conn.(syscall.Conn)
	if !ok {
		return syscall.EINVAL
	}
	raw, err := syscallConn.SyscallConn()
	if err != nil {
		return err
	}

	level, option := syscall.IPPROTO_IP, 2 // syscall.IP_TTL
	if ipv6 {
		level, option = syscall.IPPROTO_IPV6, 31 // syscall.IPV6_UNICAST_HOPS
	}

	// Control runs the callback with the socket's file descriptor while holding
	// it, which is required: the option is set per descriptor.
	var setErr error
	err = raw.Control(func(fd uintptr) {
		setErr = syscall.SetsockoptInt(int(fd), level, option, ttl)
	})
	if err != nil {
		return err
	}
	return setErr
}

// socketTTL reads back the hop limit, which the tests use to confirm the option
// was applied rather than assumed.
func socketTTL(conn net.Conn, ipv6 bool) (int, error) {
	syscallConn, ok := conn.(syscall.Conn)
	if !ok {
		return 0, syscall.EINVAL
	}
	raw, err := syscallConn.SyscallConn()
	if err != nil {
		return 0, err
	}

	level, option := syscall.IPPROTO_IP, 2
	if ipv6 {
		level, option = syscall.IPPROTO_IPV6, 31
	}

	// The read error is captured outside the closure: assigning to an outer
	// variable with := inside it shadows it, which silently discards the result
	// and leaves value at zero.
	var (
		value   int
		readErr error
	)
	err = raw.Control(func(fd uintptr) {
		value, readErr = syscall.GetsockoptInt(int(fd), level, option)
	})
	if err != nil {
		return 0, err
	}
	if readErr != nil {
		return 0, readErr
	}
	return value, nil
}
