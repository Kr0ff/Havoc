# DNS Transport — Havoc C2

DNS-over-UDP/TCP transport for Demon agents. Tunnels the existing encrypted AuthWireBuffer (AES-256-CTR + HMAC-SHA256 + LZNT1) through DNS A and TXT queries, inheriting all HVC-001..008 hardening at zero cost.

---

## When to Use

Deploy DNS transport when HTTP/HTTPS egress is blocked but a corporate recursive resolver forwards external queries. A registered authoritative zone on the teamserver IP is required.

---

## Protocol

### Encoding

| Parameter | Value |
|---|---|
| Uplink record type | A (blends with normal traffic) |
| Downlink record type | TXT (maximum data per query) |
| Data encoding | Base32 (RFC 4648 `a-z2-7`, no padding, lowercase) |
| Bytes per label | 30 binary → 48 base32 chars |
| Response encoding | Base64 (standard) |

### Uplink (Agent → Server, A query)

```
<b32chunk>.<seq4><cid4><tot4>.<tok8>.<zone>
```

| Field | Width | Description |
|---|---|---|
| `b32chunk` | ≤ 48 chars | base32(30-byte chunk of AuthWireBuffer) |
| `seq4` | 4 hex chars | 16-bit rolling packet sequence (0x0001–0xFFFF) |
| `cid4` | 4 hex chars | chunk index within this packet (0-based, 0–65535) |
| `tot4` | 4 hex chars | total chunk count for this packet (1–65535) |
| `tok8` | 8 hex chars | per-session token (DWORD derived from AES key, not agent ID) |
| `zone` | variable | configured C2 zone domain |

Example: `nbswy3dpeb3w64tmmq.000100000001.deadbeef.c2.example.com`

A-record response:
- `0.0.0.1` — chunk ACK
- NXDOMAIN — invalid query (logged, no retry)

### Downlink (Agent → Server, TXT query)

After all uplink chunks ACK'd, agent polls for the response:

```
p.<seq4>.<off8>.<tok8>.<zone>
```

| Field | Width | Description |
|---|---|---|
| `p` | 1 char | literal prefix distinguishing downlink polls |
| `seq4` | 4 hex chars | same sequence as the uplink |
| `off8` | 8 hex chars | byte offset into queued response (DWORD, step = 189 bytes, supports up to 4 GB) |
| `tok8` | 8 hex chars | per-session token matching the uplink |
| `zone` | variable | C2 zone |

TXT response: base64-encoded encrypted bytes. Last chunk is prefixed with `0xFF` sentinel; agent strips it to detect end-of-response. Empty TXT = no data ready, agent retries after 500 ms.

### Security

All cryptographic transforms applied by `PackageTransmitAll()` before `DnsSend()` — the DNS layer never sees plaintext:

| Property | Mechanism |
|---|---|
| AES-256-CTR | Encrypted before transport |
| Per-packet random IV | Prepended by `PackageTransmitAll()` |
| HMAC-SHA256 | Tag appended before DNS layer |
| Header XOR mask (HVC-003) | Applied before transport |
| RSA-2048 key wrap (HVC-005) | Registration packet opaque to DNS |
| LZNT1 compression (HVC-007) | Applied before encryption |
| No RWX memory | No executable allocations in DNS code |

---

## Teamserver Configuration

Add a `Dns {}` block to your profile:

```
Listeners {
    Dns {
        Name         = "DNS C2"
        Hosts        = ["10.0.0.1"]
        HostBind     = "0.0.0.0"
        Port         = 53
        ZoneDomain   = "updates.company-cdn.net"
        QueryTimeout = 4000
        ChunkDelayMs = 50
    }
}
```

**DNS delegation:** The zone domain must be delegated via NS records to the teamserver IP. Example registrar config:

```
ns1.updates.company-cdn.net.  A   <teamserver-ip>
updates.company-cdn.net.      NS  ns1.updates.company-cdn.net.
```

### Port 53 on Linux

Binding port 53 requires root or a capability grant:

```bash
sudo setcap 'cap_net_bind_service=+ep' ./havoc
```

Or use a non-privileged port (e.g. 5353) for testing and redirect with iptables.

---

## Demon Build

Set `TRANSPORT=DNS` in the CMake or builder invocation. The teamserver builder automatically passes `-DTRANSPORT_DNS` and links `dnsapi.lib` when `LISTENER_DNS` is selected for payload generation.

Manual CMake build for testing:
```cmake
# In CMakeLists.txt, uncomment:
# add_compile_definitions( TRANSPORT_DNS )
# link_libraries( ... dnsapi )
```

The DNS transport is entirely gated by `#ifdef TRANSPORT_DNS` — all other transports (HTTP, SMB) are unaffected when DNS is not selected.

---

## Client UI

1. Open **Listeners** → **Add Listener**
2. Select **Dns** in the Payload dropdown
3. Fill in:
   - **Zone Domain** — authoritative zone (e.g. `updates.company-cdn.net`)
   - **Hosts** — comma-separated NS IPs shown in the listener table
   - **Host Bind** — bind address for the DNS server (default `0.0.0.0`)
   - **Port** — UDP/TCP port (default `53`)
   - **Query Timeout (ms)** — per-query timeout in milliseconds (default `4000`)
   - **Chunk Delay (ms)** — inter-chunk jitter delay (default `50`)
4. Click **Save** — the listener appears in the table with the zone domain in the Host column

---

## Implementation Files

### New Files

| File | Purpose |
|---|---|
| `teamserver/pkg/handlers/dns.go` | DNS handler: miekg/dns server, ServeDNS, uplink/downlink handlers |
| `teamserver/pkg/handlers/dns_protocol.go` | Base32 decode, FQDN parsers, TXT chunk constants |
| `payloads/Demon/include/core/TransportDns.h` | DNS_CONFIG struct, constants, function prototypes |
| `payloads/Demon/src/core/TransportDns.c` | DnsSend, DnsTransportInit, DnsQueryA, DnsQueryTxt, base32 encode/decode |

### Modified Files

| File | Change |
|---|---|
| `teamserver/go.mod` | Added `github.com/miekg/dns v1.1.62` |
| `teamserver/pkg/handlers/types.go` | Added `LISTENER_DNS=5`, `AGENT_DNS="Dns"`, `DNSConfig` struct |
| `teamserver/pkg/profile/config.go` | Added `ListenerDNS` struct, `Dns` field in `Listeners` |
| `teamserver/cmd/server/listener.go` | Added `LISTENER_DNS` case in `ListenerStart()` and `ListenerAdd()` |
| `teamserver/cmd/server/teamserver.go` | Added DNS listener startup loop from profile |
| `teamserver/pkg/events/listeners.go` | Added `LISTENER_DNS` case in `ListenerAdd()` event |
| `teamserver/pkg/common/builder/builder.go` | Added DNS config packing in `PatchConfig()`, `TRANSPORT_DNS` in `GetListenerDefines()` |
| `payloads/Demon/include/Demon.h` | Added `DnsCtx` to Transport struct, `DnsQuery_W`/`DnsRecordListFree` to Win32, `DnsApi` to Modules |
| `payloads/Demon/include/common/Defines.h` | Added `H_FUNC_DNSQUERY_W`, `H_FUNC_DNSRECORDLISTFREE` |
| `payloads/Demon/include/core/Runtime.h` | Added `RtDnsApi()` declaration |
| `payloads/Demon/src/Demon.c` | Added DNS config parsing block, `RtDnsApi` in `RtModules` array |
| `payloads/Demon/src/core/Runtime.c` | Added `RtDnsApi()` implementation |
| `payloads/Demon/src/core/Transport.c` | Added `TRANSPORT_DNS` branches in `TransportInit()` and `TransportSend()` |
| `payloads/Demon/CMakeLists.txt` | Added `TransportDns.c` to sources |
| `client/include/global.hpp` | Added `PayloadDNS` static QString, `Listener::DNS` struct |
| `client/src/global.cc` | Defined `PayloadDNS = "Dns"` |
| `client/include/UserInterface/Dialogs/Listener.hpp` | Added DNS widget pointer declarations |
| `client/src/UserInterface/Dialogs/Listener.cc` | Added DNS page construction, ComboPayload item, currentTextChanged handler, info extraction |
| `client/src/UserInterface/Widgets/ListenersTable.cc` | Added DNS display case (zone domain in Host column) |
| `client/src/Havoc/Packager.cc` | Added DNS `Listener::DNS` info parsing for Add and Edit events |

---

## OPSEC Notes

1. **Zone domain** — Use domains that blend with enterprise CDN/update traffic (e.g. `updates.company-cdn.net`). Register through a legitimate registrar.

2. **Query volume** — A 300-byte COMMAND_GET_JOB packet produces 10 A-queries per sleep cycle. At 60s sleep this is ~10 queries/minute — low, but still detectable by DNS analytics. Tune sleep accordingly.

3. **Direct resolver queries** — Demon queries the configured NS IP directly, bypassing the corporate recursive resolver. This creates a detectable pattern (DNS to an unusual external IP). Mitigation: delegate the zone publicly and let agents use the corporate resolver.

4. **Traffic asymmetry** — N A-queries (uplink) followed by M TXT-queries (downlink) is a fingerprinting signature. Dummy queries (random names that resolve to NXDOMAIN) can add noise — a future enhancement.

5. **DoH future path** — DNS-over-HTTPS would hide the DNS pattern entirely. The `DnsSend()` interface is transport-agnostic; a future DoH backend can be swapped in without changing upper layers.
