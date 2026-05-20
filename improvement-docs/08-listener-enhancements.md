# HVC-034 — Listener Enhancements

**Status:** Pending

---

## Problem

Operators running multiple listeners against the same engagement face several limitations in the current implementation:

- **Global jitter only.** `Demon.Sleep` and `Demon.Jitter` in the profile are shared across all agents regardless of which listener they check in through. Agents on a high-speed internal pivot listener and agents on a slow external HTTPS listener must use the same timing parameters, making tuning impossible without separate profiles.
- **Static fake response bodies.** `handlers/http.go` serves a hardcoded nginx-style 404 page for all unrecognised requests. The 200 OK response carries no configurable body. Both are trivial to fingerprint with passive scanner signatures and threat intel feeds.
- **No mutual TLS.** Listeners accept any TLS connection. An exposed listener (e.g., one reachable from the public internet after a firewall misconfiguration) accepts agent registration attempts from unauthorised hosts. There is no mechanism to restrict check-ins to known agents.
- **No per-listener 404 customisation.** Some targets host internal applications with branded error pages. Using the same nginx stub across all listeners makes traffic stand out when compared against baseline traffic from the same host.

---

## Scope

| Layer | Files |
|-------|-------|
| Teamserver | `teamserver/pkg/profile/config.go`, `teamserver/pkg/handlers/http.go`, `teamserver/pkg/common/builder/builder.go` |
| Demon | `payloads/Demon/include/Demon.h`, `payloads/Demon/src/Demon.c` |

---

## Design

### Sub-1: Per-Listener Jitter Override

**Current behaviour:** `Demon.Sleep` and `Demon.Jitter` are parsed once from the global `[Demon]` profile block and written into every built payload via `PatchConfig()`.

**New profile fields** under `[Listeners.Http]`:

```hcl
Listeners {
    Http {
        Name   = "primary"
        # ... existing fields ...
        Sleep  = 60    # optional; overrides global Demon.Sleep for agents on this listener
        Jitter = 25    # optional; overrides global Demon.Jitter (percentage, 0–100)
    }
}
```

When `Sleep` or `Jitter` is absent (or zero), the global `[Demon]` values apply unchanged — fully backward compatible.

**Implementation steps:**

1. `profile/config.go`: Add `Sleep int` and `Jitter int` to the `ListenerHTTP` struct. The YAOTL/HCL decoder already handles optional fields; zero value means "use global default".
2. `builder/builder.go`: After writing the existing HTTP config block in `PatchConfig()`, append two `int32` fields for per-listener sleep and jitter. The Demon config blob format must be updated correspondingly (increment config version constant).
3. `payloads/Demon/include/Demon.h`: Add `INT32 SleepDelay` and `INT32 Jitter` fields to the per-listener section of the config struct (or introduce a `LISTENER_OVERRIDES` sub-struct adjacent to the HTTP block).
4. `payloads/Demon/src/Demon.c` in `DemonConfig()`: After parsing the HTTP block, if `SleepDelay > 0` write it into `Config.Implant.SleepDelay`; if `Jitter > 0` write it into `Config.Implant.Jitter`. The existing global values are written first; the per-listener values overwrite them only when non-zero.

---

### Sub-2: Fake Response Body Customisation

**Current behaviour:** `http.go` returns a static 404 body string for unmatched paths and no configurable body for matched (agent) paths.

**New profile fields:**

```hcl
Listeners {
    Http {
        Response {
            Headers      = [ "Content-Type: text/html" ]
            Body         = ""                        # optional: inline string for 200 OK body
            BodyFile     = "/opt/c2/bodies/ok.html"  # optional: file path for 200 OK body
        }
        NotFoundBody = ""                            # optional: inline 404 body
        NotFoundFile = "/opt/c2/bodies/404.html"     # optional: file path for 404 body
    }
}
```

`BodyFile` takes precedence over `Body` when both are set. Same precedence for `NotFoundFile` over `NotFoundBody`.

**Implementation steps:**

1. `profile/config.go`: Add `Body string` and `BodyFile string` to `ListenerHTTPResponse`; add `NotFoundBody string` and `NotFoundFile string` to `ListenerHTTP`.
2. `handlers/http.go` at listener startup: if `BodyFile` is non-empty, read the file into a `[]byte` field on the handler struct. Do the same for `NotFoundFile`. Log a fatal error if a specified file cannot be read at startup — fail early rather than silently serving the wrong content.
3. On 200 OK response to an agent: if custom body bytes are present, write them; otherwise write nothing (preserving current behaviour).
4. On 404 response: check `NotFoundBody`/`NotFoundFile`; if configured, serve that content. If neither is configured, fall back to the existing hardcoded nginx page.

---

### Sub-3: mTLS Client Certificate Validation

**Goal:** Restrict agent check-ins to agents that present a valid TLS client certificate signed by a CA under operator control. An exposed listener that receives a connection from an unauthorised host will reject it at the TLS handshake before any HTTP data is exchanged.

**New profile fields:**

```hcl
Listeners {
    Http {
        ClientCertRequired = false                   # bool; enables mTLS enforcement
        ClientCAChain      = "/opt/c2/certs/ca.pem"  # path to PEM-encoded CA cert bundle
    }
}
```

**Teamserver implementation:**

In `http.go` where the `tls.Config` is constructed:

```go
if listener.ClientCertRequired {
    caCert, err := os.ReadFile(listener.ClientCAChain)
    // handle err — fatal if misconfigured
    pool := x509.NewCertPool()
    pool.AppendCertsFromPEM(caCert)
    tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
    tlsCfg.ClientCAs  = pool
}
```

Agents that do not present a certificate, or that present one signed by an unknown CA, will receive a TLS handshake failure and never reach the HTTP handler.

**Demon implementation:**

The builder embeds a client certificate and private key into the Demon config blob (PEM bytes, appended after the existing HTTP config block). In `TransportHttp.c`:

- At initialisation, call `WinHttpSetOption` with `WINHTTP_OPTION_CLIENT_CERT_CONTEXT` to attach the certificate to the session handle.
- `WinHttpSetOption` is resolved dynamically. Check `Win32.c`/`Runtime.c` for existing resolution; if absent, add the DJB2 hash constant `H_FUNC_WINHTTPSETOPTION` (hash of uppercase `"WINHTTPSETOPTION"`) to `Defines.h` and resolve it alongside the other `WINHTTP_*` functions.

**Cert management (out of scope):** Operators must provision client certs externally. A minimal setup with `openssl`:

```bash
# Generate CA
openssl req -newkey rsa:4096 -x509 -days 365 -keyout ca.key -out ca.pem -nodes -subj "/CN=HavocCA"
# Generate agent cert
openssl req -newkey rsa:2048 -keyout agent.key -out agent.csr -nodes -subj "/CN=agent"
openssl x509 -req -in agent.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out agent.crt -days 90
```

The builder accepts paths to `agent.crt` and `agent.key` when `ClientCertRequired = true` on the target listener.

---

### Sub-4: HTTP Response Code Variety

**Current behaviour:** All agent responses return `HTTP 200 OK`. High-rate 200 responses from a single endpoint is a common network anomaly signature used by SIEM correlation rules and beaconing detection tools.

**New profile field:**

```hcl
Listeners {
    Http {
        Response {
            StatusCode = 200    # default; operators may set 202, 206, etc.
        }
    }
}
```

Recommended alternate codes:
- `202 Accepted` — implies the server queued the request for asynchronous processing; common in REST APIs.
- `206 Partial Content` — plausible for range-based media or chunked upload responses.

**Implementation:** Add `StatusCode int` to `ListenerHTTPResponse` (default 200 if absent). In `http.go`, replace the hardcoded `ctx.Status(200)` call with `ctx.Status(listener.Response.StatusCode)`. This is a two-line change.

---

### Sub-5: ICMP Listener (Research Item — Spec Only)

**Status: Research — not yet specified for implementation.**

**Goal:** Tunnel C2 traffic inside ICMP echo request/reply payloads. Useful in environments where TCP and UDP egress is blocked but ICMP is permitted (e.g., certain guest Wi-Fi networks, some OT environments).

**Prerequisites (document clearly):**

> ICMP listeners require raw socket privileges: `CAP_NET_RAW` on Linux (or root), and elevated/administrator on Windows. Both the teamserver host and the target must be able to send and receive raw ICMP. Environments that perform ICMP inspection or block ICMP payloads above a certain size will break this transport.

**Protocol design:**

```
ICMP Echo Request (agent → teamserver):
  [ ICMP Type=8, Code=0 ]
  [ ID      = lower 16 bits of Agent ID ]
  [ Sequence = packet sequence number   ]
  [ Payload  = AES-encrypted C2 data   ]

ICMP Echo Reply (teamserver → agent):
  [ ICMP Type=0, Code=0 ]
  [ ID       = mirrored from request   ]
  [ Sequence = mirrored from request   ]
  [ Payload  = AES-encrypted tasking   ]
```

**Demon side (`TransportIcmp.c`, new file):**

- `WSAStartup` + `WSASocketW(AF_INET, SOCK_RAW, IPPROTO_ICMP, ...)` — requires elevated process.
- `WSASendTo` with a manually constructed ICMP header prepended to the C2 payload.
- Receive loop: `WSARecvFrom`, validate ICMP type=0 (reply) and matching ID/sequence.
- 65507 bytes maximum payload per echo packet; fragmentation needed for large task responses (sequence number used as fragment index).

**Teamserver side (`handlers/icmp.go`, new file):**

- Uses `golang.org/x/net/icmp` and `golang.org/x/net/ipv4` packages.
- Opens a `PacketConn` with `icmp.ListenPacket("ip4:icmp", listenAddr)`.
- Demultiplexes by agent ID extracted from the ICMP ID field.
- Sends replies via the same `PacketConn`.

**Known limitations:**

1. The host OS kernel may answer ICMP echo requests with its own reply before the userspace handler reads them — on Linux, this can be suppressed with `iptables -A OUTPUT -p icmp --icmp-type echo-reply -j DROP` (for raw socket listeners), but this is fragile.
2. Some NAT devices do not forward ICMP or rewrite the ID/sequence fields, breaking demultiplexing.
3. Payload size per packet is limited; large uploads/downloads require reliable fragmentation and reassembly logic.
4. ICMP tunnelling is a well-known exfiltration technique and is detected by many network monitoring tools (e.g., Suricata `icmp_payload_length` rules).

This sub-item should only be implemented on explicit operator request after evaluating the target environment.

---

## File Map

| File | Change |
|------|--------|
| `teamserver/pkg/profile/config.go` | Add `Sleep`, `Jitter` to `ListenerHTTP`; add `Body`, `BodyFile` to `ListenerHTTPResponse`; add `NotFoundBody`, `NotFoundFile`, `ClientCertRequired`, `ClientCAChain`, `StatusCode` to `ListenerHTTP` |
| `teamserver/pkg/handlers/http.go` | Load custom body files at startup; serve custom bodies on 200/404; add mTLS `ClientAuth` config; use configurable `StatusCode` |
| `teamserver/pkg/common/builder/builder.go` | Pass per-listener `Sleep`/`Jitter` overrides into Demon config blob after existing HTTP block |
| `payloads/Demon/include/Demon.h` | Add listener-specific sleep/jitter override fields to config struct |
| `payloads/Demon/src/Demon.c` | Parse per-listener sleep/jitter in `DemonConfig()`; apply overrides after global defaults |
| `payloads/Demon/src/core/Win32.c` or `Runtime.c` | Resolve `WinHttpSetOption` if not already present |
| `payloads/Demon/include/common/Defines.h` | Add `H_FUNC_WINHTTPSETOPTION` if absent |

---

## Tests

- **Per-listener jitter (Sub-1):** Build two payloads pointing at two listeners with `Sleep = 30 / Jitter = 10` and `Sleep = 120 / Jitter = 0` respectively. Verify each agent's observed check-in interval matches its listener's configured values, not the global defaults.
- **Custom body (Sub-2):** Start a listener with `BodyFile = "/tmp/test_body.html"`. Send an HTTP GET to the agent URI. Verify the response body matches the file content exactly.
- **Custom 404 (Sub-2):** Start a listener with `NotFoundFile = "/tmp/test_404.html"`. Request a random path. Verify 404 response body matches the file.
- **mTLS rejection (Sub-3):** Start a listener with `ClientCertRequired = true`. Attempt a raw TLS connection without a client certificate. Verify connection is rejected at handshake (no HTTP response received).
- **mTLS acceptance (Sub-3):** Agent built with embedded cert signed by the configured CA checks in successfully.
- **Status code (Sub-4):** Set `StatusCode = 202`. Verify agent check-in response carries `HTTP/1.1 202 Accepted`.

---

## Notes

- **Sub-1 (per-listener jitter)** is the highest-value quick win — approximately 30 lines of profile struct + builder changes with no Demon ABI risk if the config version constant is incremented correctly.
- **Sub-3 (mTLS)** is operationally valuable for exposed listeners but requires the operator to provision and rotate certificates. Document the openssl workflow in `profiles/README.md` when implementing.
- **Sub-5 (ICMP)** is speculative. The protocol design above is sufficient to begin implementation when requested; do not implement it speculatively.
- Sub-4 is a two-line change and should be bundled with Sub-2 in the same PR to avoid noise.
