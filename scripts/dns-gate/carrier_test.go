package main

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

func protoBytes(field byte, b []byte) []byte {
	out := []byte{field<<3 | 2}
	out = binary.AppendUvarint(out, uint64(len(b)))
	return append(out, b...)
}
func TestCarrierPriorityAndNetworkFidelity(t *testing.T) {
	c := Config{Upstreams: []string{"127.0.0.1:1054"}, carrier: map[string]bool{"3gppnetwork.org": true},
		DefaultNetwork: 101, Networks: []Network{
			{ID: 101, Interface: "wlan0", DNS: []string{"10.0.0.1"}, Addresses: []string{"192.0.2.18"}},
			{ID: 102, Interface: "rmnet1", DNS: []string{"2001:db8::53"}, Addresses: []string{"2001:db8::2"}, Protected: true},
		}, black: map[string]bool{"3gppnetwork.org": true}, white: map[string]bool{}}
	for _, mode := range []string{"on", "off", "blacklist", "whitelist"} {
		for _, qt := range []uint16{1, 28, 35} {
			c.Mode = mode
			target, mark, blocked, ok := c.route("ims.mnc000.mcc460.3gppnetwork.org", qt, Origin{Destination: "[2001:db8::53]:53", Source: "2001:db8::2"})
			if !ok || blocked || target != "[2001:db8::53]:53" || mark != 102|0xf0000 {
				t.Fatalf("%s/%d: original carrier network lost: %s %x %v %v", mode, qt, target, mark, blocked, ok)
			}
		}
	}
	// A same-named parent lookalike remains subject to the user's filter.
	c.Mode = "off"
	_, _, blocked, ok := c.route("other3gppnetwork.org", 28, Origin{})
	if !blocked || !ok {
		t.Fatal("domain boundary bypassed")
	}
	// An unreachable original path is never retried on the managed backend.
	c.Networks = nil
	_, _, blocked, ok = c.route("3gppnetwork.org", 28, Origin{})
	if blocked || ok {
		t.Fatal("carrier query fell back into managed DNS")
	}
}
func TestOriginalResolverDoesNotGuessSharedDNS(t *testing.T) {
	c := Config{DefaultNetwork: 1, Networks: []Network{{ID: 1, Interface: "wlan0", DNS: []string{"10.0.0.1"}, Addresses: []string{"192.0.2.18"}}, {ID: 2, Interface: "rmnet0", DNS: []string{"10.0.0.1"}, Addresses: []string{"10.1.0.2"}}}}
	_, mark, ok := c.originalResolver(Origin{Destination: "10.0.0.1:53", Source: "10.1.0.2"})
	if !ok || mark != 2|0xf0000 {
		t.Fatal("explicit cellular source was lost")
	}
	if _, _, ok = c.originalResolver(Origin{Destination: "10.0.0.1:53"}); ok {
		t.Fatal("ambiguous resolver network guessed")
	}
	target, mark, ok := c.originalResolver(Origin{Destination: "127.0.0.1:53", Source: "127.0.0.1"})
	if !ok || target != "10.0.0.1:53" || mark != 1|0xf0000 {
		t.Fatal("loopback carrier query looped into local capture")
	}
	if _, _, ok = c.originalResolver(Origin{Destination: "10.0.0.1:1054"}); ok {
		t.Fatal("non-DNS destination accepted")
	}
}
func TestCNRulesAndPrecedence(t *testing.T) {
	var domains []byte
	for _, rule := range []struct {
		kind  byte
		value string
	}{{2, "example.cn"}, {3, "only.example"}, {0, "keyword"}, {1, `^api\d+\.example$`}} {
		d := append([]byte{8, rule.kind}, protoBytes(2, []byte(rule.value))...)
		domains = append(domains, protoBytes(2, d)...)
	}
	cn := append(protoBytes(1, []byte("CN")), domains...)
	path := filepath.Join(t.TempDir(), "GeoSite.dat")
	if e := os.WriteFile(path, protoBytes(1, cn), 0600); e != nil {
		t.Fatal(e)
	}
	set, e := loadChina(path)
	if e != nil {
		t.Fatal(e)
	}
	c := Config{Mode: "off", ChinaIPv6: true, china: set, Upstreams: []string{"127.0.0.1:1054"}, carrier: map[string]bool{}}
	for _, host := range []string{"example.cn", "sub.example.cn", "only.example", "has-keyword.example", "api42.example"} {
		target, mark, blocked, ok := c.route(host, 28, Origin{})
		if !ok || blocked || mark != 0 || target != c.Upstreams[0] {
			t.Fatal("CN domain did not keep managed upstream:", host)
		}
	}
	for _, host := range []string{"otherexample.cn", "sub.only.example", "api.example", "foreign.example"} {
		if !c.blocked(host, 28) {
			t.Fatal("CN rule widened:", host)
		}
	}
	c.ChinaIPv6 = false
	if !c.blocked("example.cn", 28) {
		t.Fatal("preset could not be disabled")
	}
	for _, raw := range [][]byte{{0}, {0x0a, 0xff}, {0x0b}, protoBytes(1, protoBytes(1, []byte("US")))} {
		if e := os.WriteFile(path, raw, 0600); e != nil {
			t.Fatal(e)
		}
		if _, e := loadChina(path); e == nil {
			t.Fatal("broken/missing CN accepted")
		}
	}
}
func TestTransparentOriginalDestinationParsing(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		size, level, kind, af := 16, syscall.SOL_IP, ipOrigDst, syscall.AF_INET
		if v6 {
			size, level, kind, af = 28, syscall.SOL_IPV6, ipv6OrigDst, syscall.AF_INET6
		}
		raw := make([]byte, syscall.CmsgSpace(size))
		h := (*syscall.Cmsghdr)(unsafe.Pointer(&raw[0]))
		h.Level = int32(level)
		h.Type = int32(kind)
		h.SetLen(syscall.CmsgLen(size))
		b := raw[syscall.CmsgLen(0):]
		binary.NativeEndian.PutUint16(b, uint16(af))
		binary.BigEndian.PutUint16(b[2:], 53)
		if v6 {
			b[8] = 0x20
			b[9] = 1
			b[10] = 0xd
			b[11] = 0xb8
			b[23] = 0x53
		} else {
			copy(b[4:], []byte{10, 0, 0, 1})
		}
		_, target, e := originalDestination(raw)
		if e != nil || !strings.HasSuffix(target, ":53") {
			t.Fatal(target, e)
		}
	}
	if _, _, e := originalDestination([]byte{1, 2}); e == nil {
		t.Fatal("truncated original-destination cmsg accepted")
	}
}
