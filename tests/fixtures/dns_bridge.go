// Isolated DNS endpoint/probe for the Android namespace integration check.
package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"time"
)

func response(q []byte, ip string) []byte {
	if len(q) < 17 {
		return nil
	}
	end := 12
	for end < len(q) && q[end] != 0 {
		end += 1 + int(q[end])
	}
	end += 5
	if end > len(q) {
		return nil
	}
	kind := binary.BigEndian.Uint16(q[end-4 : end-2])
	payload := net.ParseIP(ip).To4()
	if kind == 28 {
		payload = net.ParseIP("2001:db8::7").To16()
	}
	if kind != 1 && kind != 28 {
		return nil
	}
	out := append([]byte(nil), q[:end]...)
	binary.BigEndian.PutUint16(out[2:4], 0x8180)
	binary.BigEndian.PutUint16(out[6:8], 1)
	out = append(out, 0xc0, 0x0c, 0, byte(kind), 0, 1, 0, 0, 0, 0, 0, byte(len(payload)))
	return append(out, payload...)
}
func serve(address, ip string) error {
	udp, err := net.ListenPacket("udp4", address)
	if err != nil {
		return err
	}
	defer udp.Close()
	tcp, err := net.Listen("tcp4", address)
	if err != nil {
		return err
	}
	defer tcp.Close()
	go func() {
		b := make([]byte, 65535)
		for {
			n, p, e := udp.ReadFrom(b)
			if e != nil {
				return
			}
			_, _ = udp.WriteTo(response(b[:n], ip), p)
		}
	}()
	for {
		c, e := tcp.Accept()
		if e != nil {
			return e
		}
		go func() {
			defer c.Close()
			for {
				h := make([]byte, 2)
				if _, e := io.ReadFull(c, h); e != nil {
					return
				}
				q := make([]byte, binary.BigEndian.Uint16(h))
				if _, e := io.ReadFull(c, q); e != nil {
					return
				}
				a := response(q, ip)
				binary.BigEndian.PutUint16(h, uint16(len(a)))
				_, _ = c.Write(append(h, a...))
			}
		}()
	}
}
func probe(address, proto string, qtype int, expected string, mark int) error {
	q := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, 'm', 'f', 'r', 7, 'i', 'n', 'v', 'a', 'l', 'i', 'd', 0, 0, byte(qtype), 0, 1}
	dialer := net.Dialer{Timeout: 3 * time.Second}
	if mark != 0 {
		dialer.Control = func(_, _ string, c syscall.RawConn) error {
			var e error
			err := c.Control(func(fd uintptr) { e = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, mark) })
			if err != nil {
				return err
			}
			return e
		}
	}
	c, e := dialer.DialContext(context.Background(), proto, address)
	if e != nil {
		return e
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(4 * time.Second))
	b := make([]byte, 65535)
	var n int
	if proto == "tcp6" || proto == "tcp4" {
		h := []byte{0, byte(len(q))}
		if _, e = c.Write(append(h, q...)); e != nil {
			return e
		}
		if _, e = io.ReadFull(c, h); e != nil {
			return e
		}
		n = int(binary.BigEndian.Uint16(h))
		_, e = io.ReadFull(c, b[:n])
	} else {
		_, e = c.Write(q)
		if e == nil {
			n, e = c.Read(b)
		}
	}
	if e != nil {
		return e
	}
	if expected == "any" {
		if n < 12 || binary.BigEndian.Uint16(b[:2]) != 0x1234 || (b[3]&15 != 0 && b[3]&15 != 3) {
			return fmt.Errorf("invalid or failed DNS response")
		}
		fmt.Printf("PASS %s qtype=%d rcode=%d answers=%d\n", proto, qtype, b[3]&15, binary.BigEndian.Uint16(b[6:8]))
		return nil
	}
	want := net.ParseIP(expected)
	if qtype == 1 {
		want = want.To4()
	} else {
		want = want.To16()
	}
	if n < len(want)+12 || binary.BigEndian.Uint16(b[:2]) != 0x1234 || b[3]&15 != 0 || !net.IP(b[n-len(want):n]).Equal(want) {
		return fmt.Errorf("unexpected DNS response")
	}
	fmt.Printf("PASS %s qtype=%d answer=%s\n", proto, qtype, expected)
	return nil
}
func main() {
	mode := flag.String("mode", "probe", "")
	addr := flag.String("address", "[2001:db8::53]:53", "")
	proto := flag.String("proto", "udp6", "")
	kind := flag.Int("qtype", 1, "")
	ip := flag.String("answer", "203.0.113.7", "")
	mark := flag.Int("mark", 0, "")
	flag.Parse()
	var e error
	if *mode == "serve" {
		e = serve(*addr, *ip)
	} else {
		e = probe(*addr, *proto, *kind, *ip, *mark)
	}
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
