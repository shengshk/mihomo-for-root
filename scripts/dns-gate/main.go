// dns-gate applies one AAAA policy before forwarding to the selected resolver.
// No caching, hostname lookup or answer-based upstream fallback is performed.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const timeout = 5 * time.Second

type Config struct {
	Mode           string    `json:"mode"`
	ChinaIPv6      bool      `json:"china_ipv6"`
	GeoSite        string    `json:"geosite,omitempty"`
	CNVersion      string    `json:"cn_version,omitempty"`
	CarrierVersion string    `json:"carrier_version,omitempty"`
	CNCount        int       `json:"cn_count,omitempty"`
	CarrierFile    string    `json:"carrier_file,omitempty"`
	Networks       []Network `json:"networks,omitempty"`
	DefaultNetwork int       `json:"default_network,omitempty"`
	china          *DomainSet
	carrier        map[string]bool
	Blacklist      []string `json:"blacklist"`
	Whitelist      []string `json:"whitelist"`
	Backend        string   `json:"backend"`
	Upstreams      []string `json:"upstreams"`
	Network        string   `json:"network"`
	Digest         string   `json:"digest,omitempty"`
	black, white   map[string]bool
}

func domains(lines []string) (map[string]bool, error) {
	if len(lines) > 2048 {
		return nil, errors.New("too many domain lines")
	}
	result := map[string]bool{}
	for _, line := range lines {
		d := strings.ToLower(strings.TrimSpace(line))
		if d == "" || strings.HasPrefix(d, "#") {
			continue
		}
		d = strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(d, "*."), "+."), ".")
		if len(d) > 253 || d == "" {
			return nil, errors.New("invalid domain length")
		}
		for _, label := range strings.Split(d, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return nil, errors.New("invalid domain label")
			}
			for _, r := range label {
				if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
					return nil, errors.New("invalid domain character")
				}
			}
		}
		result[d] = true
	}
	return result, nil
}

func load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) > 512*1024 {
		return nil, errors.New("configuration too large")
	}
	var c Config
	if err = json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	switch c.Mode {
	case "on", "off", "blacklist", "whitelist":
	default:
		return nil, errors.New("invalid mode")
	}
	switch c.Backend {
	case "agh", "mihomo", "system":
	default:
		return nil, errors.New("invalid backend")
	}
	if c.black, err = domains(c.Blacklist); err != nil {
		return nil, err
	}
	if c.white, err = domains(c.Whitelist); err != nil {
		return nil, err
	}
	if len(c.Upstreams) == 0 || len(c.Upstreams) > 16 {
		return nil, errors.New("invalid upstream count")
	}
	for i, address := range c.Upstreams {
		if ip, parseErr := netip.ParseAddr(address); parseErr == nil {
			address = net.JoinHostPort(ip.String(), "53")
		}
		host, p, err := net.SplitHostPort(address)
		port, e := strconv.Atoi(p)
		ip, parseErr := netip.ParseAddr(host)
		if err != nil || e != nil || port < 1 || port > 65535 || parseErr != nil {
			return nil, errors.New("upstream must be a numeric IP endpoint")
		}
		if c.Backend != "system" && !ip.IsLoopback() {
			return nil, errors.New("managed backend must be local")
		}
		c.Upstreams[i] = address
	}
	if c.ChinaIPv6 {
		c.china, err = loadChina(c.GeoSite)
		if err != nil {
			return nil, fmt.Errorf("China IPv6 preset: %w", err)
		}
		c.CNCount = c.china.count
	}
	if c.CarrierFile != "" {
		raw, e := os.ReadFile(c.CarrierFile)
		if e != nil {
			return nil, errors.New("carrier DNS rules unavailable")
		}
		c.carrier, err = domains(strings.Split(string(raw), "\n"))
		if err != nil {
			return nil, err
		}
	}
	if err = validateNetworks(c.Networks, c.DefaultNetwork); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	c.Digest = hex.EncodeToString(sum[:])
	return &c, nil
}

func matched(set map[string]bool, host string) bool {
	for {
		if set[host] {
			return true
		}
		i := strings.IndexByte(host, '.')
		if i < 0 {
			return false
		}
		host = host[i+1:]
	}
}
func (c *Config) blocked(host string, qt uint16) bool {
	if qt != 28 || (c.ChinaIPv6 && c.china.match(host)) {
		return false
	}
	switch c.Mode {
	case "off":
		return true
	case "blacklist":
		return matched(c.black, host)
	case "whitelist":
		return !matched(c.white, host)
	}
	return false
}

// Follow compressed names with explicit bounds. A response question is built
// uncompressed so pointers cannot reference bytes removed from the request.
func question(packet []byte) (host string, qt uint16, q []byte, err error) {
	if len(packet) < 12 || binary.BigEndian.Uint16(packet[4:6]) != 1 || packet[2]&0x80 != 0 {
		return "", 0, nil, errors.New("invalid request")
	}
	offset, end, jumps, total := 12, -1, 0, 0
	var labels []string
	for {
		if offset >= len(packet) {
			return "", 0, nil, io.ErrUnexpectedEOF
		}
		n := int(packet[offset])
		offset++
		if n&0xc0 == 0xc0 {
			if offset >= len(packet) || jumps >= 16 {
				return "", 0, nil, errors.New("invalid name pointer")
			}
			if end < 0 {
				end = offset + 1
			}
			offset = (n&0x3f)<<8 | int(packet[offset])
			jumps++
			continue
		}
		if n == 0 {
			if end < 0 {
				end = offset
			}
			break
		}
		if n > 63 || offset+n > len(packet) {
			return "", 0, nil, errors.New("invalid name")
		}
		total += n + 1
		if total > 254 {
			return "", 0, nil, errors.New("name too long")
		}
		label := packet[offset : offset+n]
		labels = append(labels, string(label))
		q = append(q, byte(n))
		q = append(q, label...)
		offset += n
	}
	if end+4 > len(packet) {
		return "", 0, nil, io.ErrUnexpectedEOF
	}
	q = append(q, 0)
	q = append(q, packet[end:end+4]...)
	return strings.ToLower(strings.Join(labels, ".")), binary.BigEndian.Uint16(packet[end : end+2]), q, nil
}
func empty(packet, q []byte, rcode byte) []byte {
	out := make([]byte, 12, len(q)+12)
	copy(out, packet)
	out[2] = (out[2] & 0x79) | 0x80
	out[3] = (out[3] & 0x10) | 0x80 | rcode
	for i := 4; i < 12; i++ {
		out[i] = 0
	}
	if len(q) > 0 {
		out[5] = 1
		out = append(out, q...)
	}
	return out
}

type Gate struct{ config atomic.Pointer[Config] }

func (g *Gate) answer(packet []byte, tcp bool) []byte {
	return g.answerFrom(packet, tcp, Origin{})
}
func (g *Gate) answerFrom(packet []byte, tcp bool, origin Origin) []byte {
	host, qt, q, err := question(packet)
	if err != nil {
		if len(packet) < 12 {
			return nil
		}
		return empty(packet, nil, 1)
	}
	c := g.config.Load()
	target, mark, blocked, ok := c.route(host, qt, origin)
	if blocked {
		return empty(packet, q, 0)
	}
	if !ok {
		return empty(packet, q, 2)
	}
	proto := "udp"
	if tcp {
		proto = "tcp"
	}
	dialer := net.Dialer{Timeout: timeout}
	if mark != 0 {
		dialer.Control = markControl(mark)
	}
	conn, err := dialer.Dial(proto, target)
	if err != nil {
		return empty(packet, q, 2)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if tcp {
		framed := make([]byte, len(packet)+2)
		binary.BigEndian.PutUint16(framed, uint16(len(packet)))
		copy(framed[2:], packet)
		if err = writeFull(conn, framed); err != nil {
			return empty(packet, q, 2)
		}
		var size [2]byte
		if _, err = io.ReadFull(conn, size[:]); err != nil {
			return empty(packet, q, 2)
		}
		reply := make([]byte, int(binary.BigEndian.Uint16(size[:])))
		if len(reply) < 12 {
			return empty(packet, q, 2)
		}
		if _, err = io.ReadFull(conn, reply); err != nil {
			return empty(packet, q, 2)
		}
		if !validReply(packet, reply) {
			return empty(packet, q, 2)
		}
		return reply
	}
	if _, err = conn.Write(packet); err != nil {
		return empty(packet, q, 2)
	}
	reply := make([]byte, 65535)
	n, err := conn.Read(reply)
	if err != nil || !validReply(packet, reply[:n]) {
		return empty(packet, q, 2)
	}
	return reply[:n]
}
func validReply(query, reply []byte) bool {
	return len(reply) >= 12 && reply[0] == query[0] && reply[1] == query[1] && reply[2]&0x80 != 0
}
func writeFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, e := w.Write(p)
		if e != nil {
			return e
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}
func (g *Gate) udp(conn *net.UDPConn, slots chan struct{}, workers *sync.WaitGroup) {
	data := make([]byte, 65535)
	for {
		n, peer, e := conn.ReadFromUDP(data)
		if e != nil {
			return
		}
		packet := append([]byte(nil), data[:n]...)
		select {
		case slots <- struct{}{}:
		default:
			continue
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer func() { <-slots }()
			if reply := g.answer(packet, false); reply != nil {
				_, _ = conn.WriteToUDP(reply, peer)
			}
		}()
	}
}
func (g *Gate) tcpFrom(listener net.Listener, slots chan struct{}, workers *sync.WaitGroup, transparent bool) {
	for {
		client, e := listener.Accept()
		if e != nil {
			return
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
			for {
				_ = client.SetDeadline(time.Now().Add(15 * time.Second))
				var size [2]byte
				if _, e := io.ReadFull(client, size[:]); e != nil {
					return
				}
				n := int(binary.BigEndian.Uint16(size[:]))
				if n < 12 {
					return
				}
				packet := make([]byte, n)
				if _, e := io.ReadFull(client, packet); e != nil {
					return
				}
				origin := Origin{}
				if transparent {
					origin.Destination = client.LocalAddr().String()
					origin.Source = hostIP(client.RemoteAddr().String())
				}
				reply := g.answerFrom(packet, true, origin)
				binary.BigEndian.PutUint16(size[:], uint16(len(reply)))
				if writeFull(client, size[:]) != nil || writeFull(client, reply) != nil {
					return
				}
			}
		}()
	}
}
func saveState(path string, c *Config) error {
	if path == "" {
		return nil
	}
	data, e := json.Marshal(c)
	if e != nil {
		return e
	}
	if e = os.WriteFile(path+".next", data, 0600); e != nil {
		return e
	}
	return os.Rename(path+".next", path)
}
func run() error {
	config := flag.String("config", "", "private JSON config")
	listen4 := flag.String("listen4", "127.0.0.1:15354", "local IPv4 listener")
	listen6 := flag.String("listen6", "", "optional local IPv6 listener")
	transparent4 := flag.String("transparent4", "", "transparent IPv4 listener")
	transparent6 := flag.String("transparent6", "", "transparent IPv6 listener")
	ready := flag.String("ready-file", "", "readiness PID file")
	state := flag.String("state-file", "", "applied configuration state")
	check := flag.Bool("check", false, "validate config and exit")
	flag.Parse()
	c, e := load(*config)
	if e != nil {
		return e
	}
	if *check {
		return nil
	}
	var gate Gate
	gate.config.Store(c)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	var udp []*net.UDPConn
	var tcp []net.Listener
	var interceptedUDP []*net.UDPConn
	var interceptedTCP []net.Listener
	defer func() {
		for _, p := range udp {
			p.Close()
		}
		for _, p := range tcp {
			p.Close()
		}
	}()
	for _, spec := range []struct{ network, address string }{{"4", *listen4}, {"6", *listen6}} {
		if spec.address == "" {
			continue
		}
		host, _, e := net.SplitHostPort(spec.address)
		if e != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
			return errors.New("listener must be loopback")
		}
		addr, e := net.ResolveUDPAddr("udp"+spec.network, spec.address)
		if e != nil {
			return e
		}
		p, e := net.ListenUDP("udp"+spec.network, addr)
		if e != nil {
			return e
		}
		udp = append(udp, p)
		l, e := net.Listen("tcp"+spec.network, spec.address)
		if e != nil {
			return e
		}
		tcp = append(tcp, l)
	}
	for _, spec := range []struct{ network, address string }{{"4", *transparent4}, {"6", *transparent6}} {
		if spec.address == "" {
			continue
		}
		host, _, err := net.SplitHostPort(spec.address)
		if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
			return errors.New("transparent listener must be loopback")
		}
		lc := net.ListenConfig{Control: transparentControl(spec.network, true)}
		packet, err := lc.ListenPacket(ctx, "udp"+spec.network, spec.address)
		if err != nil {
			return err
		}
		udp = append(udp, packet.(*net.UDPConn))
		interceptedUDP = append(interceptedUDP, packet.(*net.UDPConn))
		lc.Control = transparentControl(spec.network, false)
		listener, err := lc.Listen(ctx, "tcp"+spec.network, spec.address)
		if err != nil {
			return err
		}
		tcp = append(tcp, listener)
		interceptedTCP = append(interceptedTCP, listener)
	}
	if e = saveState(*state, c); e != nil {
		return e
	}
	if *ready != "" {
		if e = os.WriteFile(*ready, []byte(strconv.Itoa(os.Getpid())+"\n"), 0600); e != nil {
			return e
		}
		defer os.Remove(*ready)
	}
	slots := make(chan struct{}, 128)
	var workers, loops sync.WaitGroup
	for _, p := range udp {
		loops.Add(1)
		go func(p *net.UDPConn) {
			defer loops.Done()
			if containsUDP(interceptedUDP, p) {
				gate.transparentUDP(p, slots, &workers)
			} else {
				gate.udp(p, slots, &workers)
			}
		}(p)
	}
	for _, l := range tcp {
		loops.Add(1)
		go func(l net.Listener) {
			defer loops.Done()
			gate.tcpFrom(l, slots, &workers, containsTCP(interceptedTCP, l))
		}(l)
	}
	for {
		select {
		case <-ctx.Done():
			for _, p := range udp {
				p.Close()
			}
			for _, l := range tcp {
				l.Close()
			}
			loops.Wait()
			workers.Wait()
			return nil
		case <-hup:
			next, err := load(*config)
			if err != nil {
				log.Print("configuration reload rejected")
				continue
			}
			if err = saveState(*state, next); err != nil {
				log.Print("configuration state write failed")
				continue
			}
			gate.config.Store(next)
		}
	}
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// Carrier paths keep the DNS destination and Android network that belonged to
// the original socket. Private service networks are also exempted before capture.
type Network struct {
	ID        int      `json:"id"`
	Interface string   `json:"interface"`
	DNS       []string `json:"dns"`
	Addresses []string `json:"addresses"`
	Protected bool     `json:"protected"`
}
type Origin struct{ Destination, Source string }

func hostIP(address string) string { host, _, _ := net.SplitHostPort(address); return host }
func validateNetworks(networks []Network, defaultID int) error {
	if len(networks) > 64 || defaultID < 0 || defaultID > 65535 {
		return errors.New("invalid network inventory")
	}
	seen := map[int]bool{}
	for _, n := range networks {
		if n.ID <= 0 || n.ID > 65535 || seen[n.ID] || len(n.DNS) > 16 || len(n.Addresses) > 32 || len(n.Interface) > 32 {
			return errors.New("invalid network record")
		}
		seen[n.ID] = true
		if n.Interface != "" && !regexp.MustCompile(`^[A-Za-z0-9_.:-]+$`).MatchString(n.Interface) {
			return errors.New("invalid network interface")
		}
		for _, ip := range n.Addresses {
			if _, e := netip.ParseAddr(ip); e != nil {
				return errors.New("invalid network address")
			}
		}
		for _, server := range n.DNS {
			ip, e := netip.ParseAddr(server)
			if e != nil || ip.IsUnspecified() || ip.IsMulticast() {
				return errors.New("invalid network DNS")
			}
		}
	}
	return nil
}
func (c *Config) originalResolver(o Origin) (string, int, bool) {
	var selected *Network
	src, _ := netip.ParseAddr(o.Source)
	dst := hostIP(o.Destination)
	dstIP, _ := netip.ParseAddr(dst)
	// The source address preserves explicit network binding when multiple networks
	// share a resolver IP. Ambiguous matches fail closed rather than guess.
	if src.IsValid() && !src.IsLoopback() {
		for i := range c.Networks {
			for _, s := range c.Networks[i].Addresses {
				ip, _ := netip.ParseAddr(s)
				if ip.WithZone("") == src.WithZone("") {
					if selected != nil && selected.ID != c.Networks[i].ID {
						return "", 0, false
					}
					selected = &c.Networks[i]
				}
			}
		}
	}
	if selected == nil && dstIP.IsValid() && !dstIP.IsLoopback() {
		for i := range c.Networks {
			for _, s := range c.Networks[i].DNS {
				ip, _ := netip.ParseAddr(s)
				if ip.WithZone("") == dstIP.WithZone("") {
					if selected != nil && selected.ID != c.Networks[i].ID {
						return "", 0, false
					}
					selected = &c.Networks[i]
				}
			}
		}
	}
	if selected == nil {
		for i := range c.Networks {
			if c.Networks[i].ID == c.DefaultNetwork {
				selected = &c.Networks[i]
				break
			}
		}
	}
	if selected == nil {
		return "", 0, false
	}
	target := o.Destination
	if !dstIP.IsValid() || dstIP.IsLoopback() || dstIP.IsUnspecified() || dstIP.IsMulticast() {
		if len(selected.DNS) == 0 {
			return "", 0, false
		}
		target = net.JoinHostPort(selected.DNS[0], "53")
	} else {
		_, port, e := net.SplitHostPort(target)
		if e != nil || port != "53" {
			return "", 0, false
		}
		if dstIP.IsLinkLocalUnicast() && dstIP.Zone() == "" {
			target = net.JoinHostPort(dstIP.WithZone(selected.Interface).String(), "53")
		}
	}
	// netd Fwmark: netId + explicitlySelected + protectedFromVpn + SYSTEM
	// permission (root daemon), including restricted physical service networks.
	return target, selected.ID | 0xf0000, true
}
func markControl(mark int) func(string, string, syscall.RawConn) error {
	return func(_, _ string, raw syscall.RawConn) error {
		var e error
		err := raw.Control(func(fd uintptr) { e = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, mark) })
		if err != nil {
			return err
		}
		return e
	}
}

// GeoSite uses the public v2ray Domain schema. Only CN is retained in memory;
// suffix, full, keyword and RE2 expressions keep their original meaning.
type DomainSet struct {
	suffix, full map[string]bool
	keywords     []string
	expressions  []*regexp.Regexp
	count        int
}

func (d *DomainSet) match(host string) bool {
	if d == nil {
		return false
	}
	if matched(d.suffix, host) || d.full[host] {
		return true
	}
	for _, s := range d.keywords {
		if strings.Contains(host, s) {
			return true
		}
	}
	for _, r := range d.expressions {
		if r.MatchString(host) {
			return true
		}
	}
	return false
}

type protoField struct {
	number, wire int
	value        uint64
	data         []byte
}

func fields(data []byte, visit func(protoField) error) error {
	for len(data) > 0 {
		key, n := binary.Uvarint(data)
		if n <= 0 || key>>3 == 0 {
			return errors.New("invalid GeoSite field")
		}
		data = data[n:]
		f := protoField{number: int(key >> 3), wire: int(key & 7)}
		switch f.wire {
		case 0:
			v, n := binary.Uvarint(data)
			if n <= 0 {
				return io.ErrUnexpectedEOF
			}
			f.value = v
			data = data[n:]
		case 2:
			size, n := binary.Uvarint(data)
			if n <= 0 || size > uint64(len(data)-n) {
				return io.ErrUnexpectedEOF
			}
			data = data[n:]
			f.data = data[:int(size)]
			data = data[int(size):]
		case 1:
			if len(data) < 8 {
				return io.ErrUnexpectedEOF
			}
			data = data[8:]
		case 5:
			if len(data) < 4 {
				return io.ErrUnexpectedEOF
			}
			data = data[4:]
		default:
			return errors.New("unsupported GeoSite wire type")
		}
		if err := visit(f); err != nil {
			return err
		}
	}
	return nil
}
func loadChina(path string) (*DomainSet, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, errors.New("GeoSite database unavailable")
	}
	defer f.Close()
	data, e := io.ReadAll(io.LimitReader(f, 64*1024*1024+1))
	if e != nil || len(data) > 64*1024*1024 {
		return nil, errors.New("invalid GeoSite size")
	}
	out := &DomainSet{suffix: map[string]bool{}, full: map[string]bool{}}
	err := fields(data, func(entry protoField) error {
		if entry.number != 1 || entry.wire != 2 {
			return nil
		}
		code := ""
		if e := fields(entry.data, func(f protoField) error {
			if f.number == 1 && f.wire == 2 {
				code = strings.ToLower(string(f.data))
			}
			return nil
		}); e != nil {
			return e
		}
		if code != "cn" {
			return nil
		}
		return fields(entry.data, func(domain protoField) error {
			if domain.number != 2 || domain.wire != 2 {
				return nil
			}
			kind, value := uint64(0), ""
			if e := fields(domain.data, func(f protoField) error {
				if f.number == 1 && f.wire == 0 {
					kind = f.value
				}
				if f.number == 2 && f.wire == 2 {
					value = string(f.data)
				}
				return nil
			}); e != nil {
				return e
			}
			if value == "" || len(value) > 4096 || out.count >= 200000 {
				return errors.New("invalid CN domain rule")
			}
			switch kind {
			case 0:
				out.keywords = append(out.keywords, strings.ToLower(value))
			case 1:
				r, e := regexp.Compile(value)
				if e != nil {
					return errors.New("invalid CN expression")
				}
				out.expressions = append(out.expressions, r)
			case 2:
				out.suffix[strings.ToLower(value)] = true
			case 3:
				out.full[strings.ToLower(value)] = true
			default:
				return errors.New("unknown CN domain type")
			}
			out.count++
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	if out.count == 0 {
		return nil, errors.New("CN group missing from GeoSite")
	}
	return out, nil
}

// Transparent listeners preserve the resolver address for both UDP and TCP.
const ipOrigDst = 20
const ipv6OrigDst = 74

func transparentControl(family string, udp bool) func(string, string, syscall.RawConn) error {
	return func(_, _ string, raw syscall.RawConn) error {
		var setup error
		err := raw.Control(func(fd uintptr) {
			opts := [][3]int{{syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1}}
			if family == "4" {
				opts = append(opts, [3]int{syscall.SOL_IP, syscall.IP_TRANSPARENT, 1})
				if udp {
					opts = append(opts, [3]int{syscall.SOL_IP, ipOrigDst, 1})
				}
			} else {
				opts = append(opts, [3]int{syscall.SOL_IPV6, syscall.IPV6_V6ONLY, 1}, [3]int{syscall.SOL_IPV6, 75, 1})
				if udp {
					opts = append(opts, [3]int{syscall.SOL_IPV6, ipv6OrigDst, 1})
				}
			}
			for _, o := range opts {
				if setup = syscall.SetsockoptInt(int(fd), o[0], o[1], o[2]); setup != nil {
					return
				}
			}
		})
		if err != nil {
			return err
		}
		return setup
	}
}
func originalDestination(oob []byte) (syscall.Sockaddr, string, error) {
	messages, e := syscall.ParseSocketControlMessage(oob)
	if e != nil {
		return nil, "", e
	}
	for _, m := range messages {
		b := m.Data
		if m.Header.Level == syscall.SOL_IP && m.Header.Type == ipOrigDst && len(b) >= 16 && binary.NativeEndian.Uint16(b) == syscall.AF_INET {
			a := &syscall.SockaddrInet4{Port: int(binary.BigEndian.Uint16(b[2:4]))}
			copy(a.Addr[:], b[4:8])
			return a, net.JoinHostPort(net.IP(a.Addr[:]).String(), strconv.Itoa(a.Port)), nil
		}
		if m.Header.Level == syscall.SOL_IPV6 && m.Header.Type == ipv6OrigDst && len(b) >= 28 && binary.NativeEndian.Uint16(b) == syscall.AF_INET6 {
			a := &syscall.SockaddrInet6{Port: int(binary.BigEndian.Uint16(b[2:4])), ZoneId: binary.NativeEndian.Uint32(b[24:28])}
			copy(a.Addr[:], b[8:24])
			ip := net.IP(a.Addr[:]).String()
			if a.ZoneId != 0 {
				ip += "%" + strconv.Itoa(int(a.ZoneId))
			}
			return a, net.JoinHostPort(ip, strconv.Itoa(a.Port)), nil
		}
	}
	return nil, "", errors.New("original DNS destination unavailable")
}
func sendOriginal(payload []byte, source syscall.Sockaddr, peer *net.UDPAddr) error {
	family := syscall.AF_INET
	var target syscall.Sockaddr
	opts := [][3]int{{syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1}, {syscall.SOL_IP, syscall.IP_TRANSPARENT, 1}}
	if _, v6 := source.(*syscall.SockaddrInet6); v6 {
		family = syscall.AF_INET6
		opts = [][3]int{{syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1}, {syscall.SOL_IPV6, syscall.IPV6_V6ONLY, 1}, {syscall.SOL_IPV6, 75, 1}}
		a := &syscall.SockaddrInet6{Port: peer.Port}
		copy(a.Addr[:], peer.IP.To16())
		if peer.Zone != "" {
			n, e := strconv.Atoi(peer.Zone)
			if e == nil {
				a.ZoneId = uint32(n)
			} else {
				nic, e := net.InterfaceByName(peer.Zone)
				if e != nil {
					return e
				}
				a.ZoneId = uint32(nic.Index)
			}
		}
		target = a
	} else {
		a := &syscall.SockaddrInet4{Port: peer.Port}
		copy(a.Addr[:], peer.IP.To4())
		target = a
	}
	fd, e := syscall.Socket(family, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, syscall.IPPROTO_UDP)
	if e != nil {
		return e
	}
	defer syscall.Close(fd)
	for _, o := range opts {
		if e = syscall.SetsockoptInt(fd, o[0], o[1], o[2]); e != nil {
			return e
		}
	}
	if e = syscall.Bind(fd, source); e != nil {
		return e
	}
	return syscall.Sendto(fd, payload, 0, target)
}
func (g *Gate) transparentUDP(conn *net.UDPConn, slots chan struct{}, workers *sync.WaitGroup) {
	data, oob := make([]byte, 65535), make([]byte, 256)
	for {
		n, on, flags, peer, e := conn.ReadMsgUDP(data, oob)
		if e != nil {
			return
		}
		if flags&(syscall.MSG_TRUNC|syscall.MSG_CTRUNC) != 0 {
			continue
		}
		source, target, e := originalDestination(oob[:on])
		if e != nil {
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			continue
		}
		packet := append([]byte(nil), data[:n]...)
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer func() { <-slots }()
			reply := g.answerFrom(packet, false, Origin{Destination: target, Source: peer.IP.String()})
			if reply != nil {
				_ = sendOriginal(reply, source, peer)
			}
		}()
	}
}
func containsUDP(all []*net.UDPConn, p *net.UDPConn) bool {
	for _, v := range all {
		if v == p {
			return true
		}
	}
	return false
}
func containsTCP(all []net.Listener, p net.Listener) bool {
	for _, v := range all {
		if v == p {
			return true
		}
	}
	return false
}

// Mandatory carrier bypass precedes the optional CN preset and every user mode.
func (c *Config) route(host string, qt uint16, origin Origin) (target string, mark int, blocked, ok bool) {
	if matched(c.carrier, host) {
		target, mark, ok = c.originalResolver(origin)
		return
	}
	if c.blocked(host, qt) {
		return "", 0, true, true
	}
	return c.Upstreams[0], 0, false, true
}
