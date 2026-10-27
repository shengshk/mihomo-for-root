package dnsforward

import (
	"context"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/aghnet"
	"github.com/AdguardTeam/AdGuardHome/internal/querylog"
	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/miekg/dns"
)

type mfrClientLookupLog struct {
	querylog.QueryLog
	server          *Server
	entered, resume chan struct{}
}

func (q *mfrClientLookupLog) ShouldLog(string, uint16, uint16, []string) bool {
	close(q.entered)
	<-q.resume
	q.server.IsBlockedClient(netip.MustParseAddr("127.0.0.1"), "")
	return false
}

// Exercise the real query-accounting callback while a reconfigure writer is
// queued. The callback must not recursively acquire serverLock's read lock.
func TestMFRAccountingClientLookupWithPendingWriter(t *testing.T) {
	access, err := newAccessCtx(nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{logger: testLogger, access: access, anonymizer: aghnet.NewIPMut(nil)}
	q := &mfrClientLookupLog{server: s, entered: make(chan struct{}), resume: make(chan struct{})}
	s.queryLog = q
	done, writerDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		s.processQueryLogsAndStats(context.Background(), testLogger, &dnsContext{
			startTime: time.Now(), proxyCtx: &proxy.DNSContext{
				Addr: netip.MustParseAddrPort("127.0.0.1:1234"),
				Req:  &dns.Msg{Question: []dns.Question{{Name: "example.invalid.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}},
			},
		})
	}()
	select {
	case <-q.entered:
	case <-time.After(time.Second):
		t.Fatal("accounting did not start")
	}
	go func() { s.serverLock.Lock(); s.serverLock.Unlock(); close(writerDone) }()
	deadline := time.Now().Add(time.Second)
	for s.serverLock.TryRLock() {
		s.serverLock.RUnlock()
		if time.Now().After(deadline) {
			t.Fatal("writer did not queue")
		}
		runtime.Gosched()
	}
	close(q.resume)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("client lookup deadlocked with accounting/reconfigure")
	}
	select {
	case <-writerDone:
	case <-time.After(time.Second):
		t.Fatal("writer remained blocked")
	}
}
