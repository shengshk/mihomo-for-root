// AGH DNS bridge transports IPv6 TCP/UDP DNS to a fixed local IPv4 endpoint.
// It performs no DNS interpretation, caching, retries or upstream selection.
package main

import (
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"
)

const (
	ipv6Transparent = 75
	ipv6OrigDstAddr = 74
	maxActive       = 128
	requestTimeout  = 10 * time.Second
)

// Bound diagnostics on repeated upstream failures without logging query names.
var warningMu sync.Mutex
var lastWarning time.Time

func warn(text string) {
	warningMu.Lock()
	defer warningMu.Unlock()
	if time.Since(lastWarning) >= 30*time.Second {
		log.Print(text)
		lastWarning = time.Now()
	}
}

func socketControl(udp bool) func(string, string, syscall.RawConn) error {
	return func(_, _ string, raw syscall.RawConn) error {
		var setup error
		err := raw.Control(func(fd uintptr) {
			for _, opt := range [][3]int{{syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1}, {syscall.SOL_IPV6, syscall.IPV6_V6ONLY, 1}, {syscall.SOL_IPV6, ipv6Transparent, 1}} {
				if setup = syscall.SetsockoptInt(int(fd), opt[0], opt[1], opt[2]); setup != nil {
					return
				}
			}
			if udp {
				setup = syscall.SetsockoptInt(int(fd), syscall.SOL_IPV6, ipv6OrigDstAddr, 1)
			}
		})
		if err != nil {
			return err
		}
		return setup
	}
}

func destination(oob []byte) (*syscall.SockaddrInet6, error) {
	messages, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, err
	}
	for _, message := range messages {
		if message.Header.Level != syscall.SOL_IPV6 || message.Header.Type != ipv6OrigDstAddr || len(message.Data) < 28 {
			continue
		}
		if binary.NativeEndian.Uint16(message.Data[:2]) != syscall.AF_INET6 {
			continue
		}
		addr := &syscall.SockaddrInet6{Port: int(binary.BigEndian.Uint16(message.Data[2:4])), ZoneId: binary.NativeEndian.Uint32(message.Data[24:28])}
		copy(addr.Addr[:], message.Data[8:24])
		return addr, nil
	}
	return nil, errors.New("missing IPv6 original destination")
}

func replyUDP(payload []byte, source *syscall.SockaddrInet6, peer *net.UDPAddr) error {
	// A new transparent socket restores the DNS server's original source address.
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, syscall.IPPROTO_UDP)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	for _, opt := range [][3]int{{syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1}, {syscall.SOL_IPV6, syscall.IPV6_V6ONLY, 1}, {syscall.SOL_IPV6, ipv6Transparent, 1}} {
		if err = syscall.SetsockoptInt(fd, opt[0], opt[1], opt[2]); err != nil {
			return err
		}
	}
	if err = syscall.Bind(fd, source); err != nil {
		return err
	}
	target := &syscall.SockaddrInet6{Port: peer.Port}
	copy(target.Addr[:], peer.IP.To16())
	if peer.Zone != "" {
		if n, parseErr := strconv.Atoi(peer.Zone); parseErr == nil {
			target.ZoneId = uint32(n)
		} else if nic, lookupErr := net.InterfaceByName(peer.Zone); lookupErr == nil {
			target.ZoneId = uint32(nic.Index)
		} else {
			return lookupErr
		}
	}
	return syscall.Sendto(fd, payload, 0, target)
}

func serveUDP(conn *net.UDPConn, upstream string, slots chan struct{}, workers *sync.WaitGroup) error {
	data, control := make([]byte, 65535), make([]byte, 256)
	for {
		n, oobn, flags, peer, err := conn.ReadMsgUDP(data, control)
		if err != nil {
			return err
		}
		if flags&(syscall.MSG_TRUNC|syscall.MSG_CTRUNC) != 0 || n < 12 {
			continue
		}
		dest, err := destination(control[:oobn])
		if err != nil {
			warn("UDP original destination unavailable")
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			continue
		}
		query := append([]byte(nil), data[:n]...)
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer func() { <-slots }()
			upstreamConn, err := net.DialTimeout("udp4", upstream, requestTimeout)
			if err != nil {
				warn("UDP upstream connect failed")
				return
			}
			defer upstreamConn.Close()
			_ = upstreamConn.SetDeadline(time.Now().Add(requestTimeout))
			if _, err = upstreamConn.Write(query); err != nil {
				warn("UDP upstream write failed")
				return
			}
			answer := make([]byte, 65535)
			n, err := upstreamConn.Read(answer)
			if err != nil {
				warn("UDP upstream response failed")
				return
			}
			if replyUDP(answer[:n], dest, peer) != nil {
				warn("UDP reply failed")
			}
		}()
	}
}

func serveTCP(listener net.Listener, upstream string, slots chan struct{}, workers *sync.WaitGroup) error {
	for {
		client, err := listener.Accept()
		if err != nil {
			return err
		}
		select {
		case slots <- struct{}{}:
		default:
			client.Close()
			continue
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer func() { <-slots }()
			defer client.Close()
			server, err := net.DialTimeout("tcp4", upstream, requestTimeout)
			if err != nil {
				warn("TCP upstream connect failed")
				return
			}
			defer server.Close()
			deadline := time.Now().Add(requestTimeout)
			_ = client.SetDeadline(deadline)
			_ = server.SetDeadline(deadline)
			done := make(chan struct{})
			go func() {
				_, _ = io.Copy(server, client)
				if tcp, ok := server.(*net.TCPConn); ok {
					_ = tcp.CloseWrite()
				}
				close(done)
			}()
			_, _ = io.Copy(client, server)
			// Wake the other direction before returning; do not leak stalled relays.
			_ = client.Close()
			_ = server.Close()
			<-done
		}()
	}
}

func run() error {
	listen := flag.String("listen6", "[::1]:1055", "IPv6 transparent TCP/UDP listener")
	upstream := flag.String("upstream4", "127.0.0.1:1054", "fixed local AGH endpoint")
	ready := flag.String("ready-file", "", "private readiness file")
	flag.Parse()
	ip, _, err := net.SplitHostPort(*upstream)
	if err != nil || net.ParseIP(ip) == nil || !net.ParseIP(ip).IsLoopback() || net.ParseIP(ip).To4() == nil {
		return errors.New("upstream must be an IPv4 loopback endpoint")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	udpLC := net.ListenConfig{Control: socketControl(true)}
	packet, err := udpLC.ListenPacket(ctx, "udp6", *listen)
	if err != nil {
		return fmt.Errorf("UDP listener: %w", err)
	}
	defer packet.Close()
	tcpLC := net.ListenConfig{Control: socketControl(false)}
	listener, err := tcpLC.Listen(ctx, "tcp6", *listen)
	if err != nil {
		return fmt.Errorf("TCP listener: %w", err)
	}
	defer listener.Close()
	if *ready != "" {
		if err = os.WriteFile(*ready, []byte(strconv.Itoa(os.Getpid())+"\n"), 0600); err != nil {
			return err
		}
		defer os.Remove(*ready)
	}
	slots := make(chan struct{}, maxActive)
	var workers sync.WaitGroup
	results := make(chan error, 2)
	go func() { results <- serveUDP(packet.(*net.UDPConn), *upstream, slots, &workers) }()
	go func() { results <- serveTCP(listener, *upstream, slots, &workers) }()
	var result error
	select {
	case <-ctx.Done():
	case result = <-results:
	}
	_ = packet.Close()
	_ = listener.Close()
	// Both accept loops must stop before waiting for their workers.
	if result == nil {
		<-results
	}
	<-results
	workers.Wait()
	return result
}

func main() {
	log.SetFlags(log.Ldate | log.Ltime)
	if err := run(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}
