#!/usr/bin/env python3
"""
create_profile.py — Generate a Havoc C2 YAOTL profile from command-line arguments.

All possible configurable fields from the teamserver and Demon codebase are
available as CLI flags. Required fields default to sensible placeholder values
when not supplied; optional fields are included only when explicitly set.

Usage:
    python3 scripts/create_profile.py [OPTIONS] [-o profile.yaotl]

Output is written to stdout by default, or to the file specified with -o.

Examples:
    # Minimal profile with defaults printed to stdout
    python3 scripts/create_profile.py \\
        --ts-host 0.0.0.0 --ts-port 40056 \\
        --operator admin:password1234 \\
        --http-name "HTTP Agent" --http-host 10.10.10.1 --http-port 443 \\
        --smb-name "SMB Pivot" --smb-pipe msagent_01

    # Full-featured profile saved to file
    python3 scripts/create_profile.py \\
        --ts-host 0.0.0.0 --ts-port 40056 \\
        --operator red:hunter2 --operator blue:hunter3 \\
        --http-name "HTTPS Agent" --http-host 192.168.1.10 --http-port 443 \\
        --http-secure --http-ua "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \\
        --http-uri "/js/jquery.min.js" --http-uri "/api/update" \\
        --http-header "X-Custom: header" \\
        --http-resp-header "Content-Type: application/json" \\
        --smb-name "Pivot" --smb-pipe demon_pipe \\
        --demon-sleep 5 --demon-jitter 20 \\
        --demon-spawn64 "C:\\\\Windows\\\\System32\\\\Werfault.exe" \\
        --demon-sleep-technique Ekko \\
        --demon-indirect-syscall --demon-stack-duplication \\
        -o profiles/myprofile.yaotl

Field reference (from teamserver/pkg/profile/config.go):
  Teamserver:      Host, Port, Build.Compiler64/86/Nasm
  Operators:       user "<name>" { Password }  (multiple allowed)
  Listeners.Http:  Name, Hosts, HostBind, HostRotation, PortBind, PortConn,
                   Secure, UserAgent, Headers, Uris, KillDate, WorkingHours,
                   Method, Response.Headers, Cert.Cert/Key, Proxy.*
  Listeners.Smb:   Name, PipeName, KillDate, WorkingHours
  Listeners.Ext:   Name, Endpoint
  Listeners.Dns:   Name, Hosts, HostBind, Port, ZoneDomain, QueryTimeout, ChunkDelayMs
  Demon:           Sleep, Jitter, IndirectSyscall, StackDuplication,
                   SleepTechnique, ProxyLoading, AmsiEtwPatching,
                   TrustXForwardedFor, DotNetNamePipe, RandGadget, UnhookNtdll, HideModules, PeStomp, SleepCipher,
                   Verbose, CoffeeVeh, CoffeeThreaded,
                   SleepObfStartAddr.{Library,Function,Offset},
                   InjectSpoofAddr.{Library,Function,Offset},
                   Injection.Spawn64/Spawn32,
                   Binary.Header.{MagicMz-x64/x86, CompileTime, ImageSize-x64/x86}
                   Binary.ReplaceStrings-x64/x86
  Service:         Endpoint, Password
  WebHook.Discord: Url, AvatarUrl, User
"""

import argparse
import sys
import os
import textwrap
from typing import Optional

# ---------------------------------------------------------------------------
# YAOTL emitter
# ---------------------------------------------------------------------------

class Emitter:
    """Builds a YAOTL document incrementally."""

    def __init__(self):
        self._lines: list[str] = []

    def blank(self):
        self._lines.append("")

    def comment(self, text: str):
        for line in text.splitlines():
            self._lines.append(f"# {line}" if line else "#")

    def line(self, text: str = "", indent: int = 0):
        self._lines.append("    " * indent + text)

    def block_open(self, name: str, label: Optional[str] = None, indent: int = 0):
        prefix = "    " * indent
        if label is not None:
            self._lines.append(f'{prefix}{name} "{label}" {{')
        else:
            self._lines.append(f"{prefix}{name} {{")

    def block_close(self, indent: int = 0):
        self._lines.append("    " * indent + "}")

    def attr(self, key: str, value, indent: int = 1):
        prefix = "    " * indent
        if isinstance(value, bool):
            self._lines.append(f"{prefix}{key} = {str(value).lower()}")
        elif isinstance(value, int):
            self._lines.append(f"{prefix}{key} = {value}")
        elif isinstance(value, str):
            # Escape backslashes
            escaped = value.replace("\\", "\\\\")
            self._lines.append(f'{prefix}{key} = "{escaped}"')
        else:
            raise TypeError(f"unsupported attr type: {type(value)}")

    def attr_list(self, key: str, values: list, indent: int = 1):
        if not values:
            return
        prefix = "    " * indent
        inner = "    " * (indent + 1)
        self._lines.append(f"{prefix}{key} = [")
        for v in values:
            escaped = v.replace("\\", "\\\\")
            self._lines.append(f'{inner}"{escaped}",')
        self._lines.append(f"{prefix}]")

    def attr_map(self, key: str, pairs: dict, indent: int = 1):
        if not pairs:
            return
        prefix = "    " * indent
        inner = "    " * (indent + 1)
        self._lines.append(f"{prefix}{key} = {{")
        for k, v in pairs.items():
            ek = k.replace("\\", "\\\\")
            ev = v.replace("\\", "\\\\")
            self._lines.append(f'{inner}"{ek}": "{ev}",')
        self._lines.append(f"{prefix}}}")

    def render(self) -> str:
        return "\n".join(self._lines) + "\n"


# ---------------------------------------------------------------------------
# Profile builder
# ---------------------------------------------------------------------------

def build_profile(args: argparse.Namespace) -> str:
    e = Emitter()

    e.comment("Havoc C2 profile — generated by scripts/create_profile.py")
    e.comment("Reference: teamserver/pkg/profile/config.go")
    e.blank()

    # ── Teamserver ────────────────────────────────────────────────────────
    e.block_open("Teamserver")
    e.attr("Host", args.ts_host)
    e.attr("Port", args.ts_port)

    if args.compiler64 or args.compiler86 or args.nasm:
        e.blank()
        e.block_open("Build", indent=1)
        if args.compiler64:
            e.attr("Compiler64", args.compiler64, indent=2)
        if args.compiler86:
            e.attr("Compiler86", args.compiler86, indent=2)
        if args.nasm:
            e.attr("Nasm", args.nasm, indent=2)
        e.block_close(indent=1)

    e.block_close()
    e.blank()

    # ── Operators ─────────────────────────────────────────────────────────
    e.block_open("Operators")
    for op in args.operator:
        if ":" in op:
            username, password = op.split(":", 1)
        else:
            username, password = op, "changeme"
        e.blank()
        e.block_open("user", label=username, indent=1)
        e.attr("Password", password, indent=2)
        e.block_close(indent=1)
    e.blank()
    e.block_close()
    e.blank()

    # ── Service (optional) ────────────────────────────────────────────────
    if args.svc_endpoint:
        e.comment("Optional: external C2 service API")
        e.block_open("Service")
        e.attr("Endpoint", args.svc_endpoint)
        e.attr("Password", args.svc_password or "service-password")
        e.block_close()
        e.blank()

    # ── Listeners ─────────────────────────────────────────────────────────
    e.block_open("Listeners")

    # HTTP listeners
    for i in range(len(args.http_name)):
        def _get(lst, idx, default=None):
            return lst[idx] if idx < len(lst) else (lst[0] if lst else default)

        name         = _get(args.http_name, i, "HTTP Agent")
        hosts        = args.http_host if args.http_host else ["127.0.0.1"]
        host_bind    = _get(args.http_bind, i, "0.0.0.0")
        port_bind    = _get(args.http_port, i, 80)
        port_conn    = _get(args.http_port_conn, i, None)
        secure       = args.http_secure
        ua           = _get(args.http_ua, i, None)
        uris         = args.http_uri if args.http_uri else []
        req_hdrs     = args.http_header if args.http_header else []
        resp_hdrs    = args.http_resp_header if args.http_resp_header else []
        kill_date    = _get(args.http_kill_date, i, None)
        working_hrs  = _get(args.http_working_hours, i, None)
        host_rot     = _get(args.http_rotation, i, "round-robin")
        method       = _get(args.http_method, i, None)
        cert_file    = _get(args.http_cert, i, None)
        cert_key     = _get(args.http_cert_key, i, None)
        proxy_host   = _get(args.http_proxy_host, i, None)
        proxy_port   = _get(args.http_proxy_port, i, None)
        proxy_user   = _get(args.http_proxy_user, i, None)
        proxy_pass   = _get(args.http_proxy_pass, i, None)

        e.blank()
        e.block_open("Http", indent=1)
        e.attr("Name", name, indent=2)
        e.attr_list("Hosts", hosts, indent=2)
        e.attr("HostBind", host_bind, indent=2)
        e.attr("PortBind", int(port_bind), indent=2)
        if port_conn is not None:
            e.attr("PortConn", int(port_conn), indent=2)
        e.attr("HostRotation", host_rot, indent=2)
        e.attr("Secure", secure, indent=2)
        if method:
            e.attr("Method", method, indent=2)
        if ua:
            e.attr("UserAgent", ua, indent=2)
        if uris:
            e.attr_list("Uris", uris, indent=2)
        if req_hdrs:
            e.attr_list("Headers", req_hdrs, indent=2)
        if kill_date:
            e.attr("KillDate", kill_date, indent=2)
        if working_hrs:
            e.attr("WorkingHours", working_hrs, indent=2)

        if resp_hdrs:
            e.blank()
            e.block_open("Response", indent=2)
            e.attr_list("Headers", resp_hdrs, indent=3)
            e.block_close(indent=2)

        if cert_file and cert_key:
            e.blank()
            e.block_open("Cert", indent=2)
            e.attr("Cert", cert_file, indent=3)
            e.attr("Key", cert_key, indent=3)
            e.block_close(indent=2)

        if proxy_host and proxy_port:
            e.blank()
            e.block_open("Proxy", indent=2)
            e.attr("Host", proxy_host, indent=3)
            e.attr("Port", int(proxy_port), indent=3)
            if proxy_user:
                e.attr("Username", proxy_user, indent=3)
            if proxy_pass:
                e.attr("Password", proxy_pass, indent=3)
            e.block_close(indent=2)

        e.blank()
        e.block_close(indent=1)

    # SMB listeners
    for i in range(len(args.smb_name)):
        def _get(lst, idx, default=None):
            return lst[idx] if idx < len(lst) else (lst[0] if lst else default)

        name        = args.smb_name[i]
        pipe        = _get(args.smb_pipe, i, "agent_pipe")
        kill_date   = _get(args.smb_kill_date, i, None)
        working_hrs = _get(args.smb_working_hours, i, None)

        e.blank()
        e.block_open("Smb", indent=1)
        e.attr("Name", name, indent=2)
        e.attr("PipeName", pipe, indent=2)
        if kill_date:
            e.attr("KillDate", kill_date, indent=2)
        if working_hrs:
            e.attr("WorkingHours", working_hrs, indent=2)
        e.blank()
        e.block_close(indent=1)

    # External listeners
    for i in range(len(args.ext_name)):
        def _get(lst, idx, default=None):
            return lst[idx] if idx < len(lst) else (lst[0] if lst else default)

        name     = args.ext_name[i]
        endpoint = _get(args.ext_endpoint, i, "/")

        e.blank()
        e.block_open("External", indent=1)
        e.attr("Name", name, indent=2)
        e.attr("Endpoint", endpoint, indent=2)
        e.blank()
        e.block_close(indent=1)

    # DNS listeners
    for i in range(len(args.dns_name)):
        def _get(lst, idx, default=None):
            return lst[idx] if idx < len(lst) else (lst[0] if lst else default)

        name        = args.dns_name[i]
        zone        = _get(args.dns_zone, i, "c2.example.com")
        hosts       = args.dns_host if args.dns_host else []
        host_bind   = _get(args.dns_bind, i, "0.0.0.0")
        port        = _get(args.dns_port, i, 53)
        timeout     = _get(args.dns_timeout, i, None)
        chunk_delay = _get(args.dns_chunk_delay, i, None)

        e.blank()
        e.block_open("Dns", indent=1)
        e.attr("Name", name, indent=2)
        if hosts:
            e.attr_list("Hosts", hosts, indent=2)
        e.attr("HostBind", host_bind, indent=2)
        e.attr("Port", int(port), indent=2)
        e.attr("ZoneDomain", zone, indent=2)
        if timeout is not None:
            e.attr("QueryTimeout", int(timeout), indent=2)
        if chunk_delay is not None:
            e.attr("ChunkDelayMs", int(chunk_delay), indent=2)
        e.blank()
        e.block_close(indent=1)

    e.blank()
    e.block_close()
    e.blank()

    # ── Demon ─────────────────────────────────────────────────────────────
    e.block_open("Demon")

    if args.demon_sleep is not None:
        e.attr("Sleep", args.demon_sleep)
    if args.demon_jitter is not None:
        e.attr("Jitter", args.demon_jitter)

    if args.demon_indirect_syscall:
        e.attr("IndirectSyscall", True)
    if args.demon_stack_duplication:
        e.attr("StackDuplication", True)
    if args.demon_rand_gadget:
        e.attr("RandGadget", True)
    if args.demon_unhook_ntdll:
        e.attr("UnhookNtdll", True)
    if args.demon_hide_modules:
        e.attr("HideModules", True)
    if args.demon_pe_stomp:
        e.attr("PeStomp", True)
    if args.demon_sleep_cipher:
        e.attr("SleepCipher", args.demon_sleep_cipher)
    if args.demon_verbose:
        e.attr("Verbose", True)
    if args.demon_coffee_veh:
        e.attr("CoffeeVeh", True)
    if args.demon_coffee_threaded:
        e.attr("CoffeeThreaded", True)

    if args.demon_sleep_obf_addr_lib and args.demon_sleep_obf_addr_func:
        e.blank()
        e.block_open("SleepObfStartAddr", indent=1)
        e.attr("Library",  args.demon_sleep_obf_addr_lib, indent=2)
        e.attr("Function", args.demon_sleep_obf_addr_func, indent=2)
        if args.demon_sleep_obf_addr_offset:
            e.attr("Offset", args.demon_sleep_obf_addr_offset, indent=2)
        e.block_close(indent=1)

    if args.demon_inject_spoof_lib and args.demon_inject_spoof_func:
        e.blank()
        e.block_open("InjectSpoofAddr", indent=1)
        e.attr("Library",  args.demon_inject_spoof_lib, indent=2)
        e.attr("Function", args.demon_inject_spoof_func, indent=2)
        if args.demon_inject_spoof_offset:
            e.attr("Offset", args.demon_inject_spoof_offset, indent=2)
        e.block_close(indent=1)

    if args.demon_sleep_technique:
        e.attr("SleepTechnique", args.demon_sleep_technique)
    if args.demon_proxy_loading:
        e.attr("ProxyLoading", args.demon_proxy_loading)
    if args.demon_amsi_etw:
        e.attr("AmsiEtwPatching", args.demon_amsi_etw)
    if args.demon_dotnet_pipe:
        e.attr("DotNetNamePipe", args.demon_dotnet_pipe)
    if args.demon_trust_xff:
        e.attr("TrustXForwardedFor", True)

    if args.demon_spawn64 or args.demon_spawn32:
        e.blank()
        e.block_open("Injection", indent=1)
        if args.demon_spawn64:
            e.attr("Spawn64", args.demon_spawn64, indent=2)
        if args.demon_spawn32:
            e.attr("Spawn32", args.demon_spawn32, indent=2)
        e.block_close(indent=1)

    binary_needed = (
        args.demon_magic_mz_x64 or args.demon_magic_mz_x86 or
        args.demon_compile_time or
        args.demon_image_size_x64 is not None or
        args.demon_image_size_x86 is not None or
        args.demon_replace_str_x64 or args.demon_replace_str_x86
    )
    if binary_needed:
        e.blank()
        e.block_open("Binary", indent=1)

        header_needed = (
            args.demon_magic_mz_x64 or args.demon_magic_mz_x86 or
            args.demon_compile_time or
            args.demon_image_size_x64 is not None or
            args.demon_image_size_x86 is not None
        )
        if header_needed:
            e.block_open("Header", indent=2)
            if args.demon_magic_mz_x64:
                e.attr("MagicMz-x64", args.demon_magic_mz_x64, indent=3)
            if args.demon_magic_mz_x86:
                e.attr("MagicMz-x86", args.demon_magic_mz_x86, indent=3)
            if args.demon_compile_time:
                e.attr("CompileTime", args.demon_compile_time, indent=3)
            if args.demon_image_size_x64 is not None:
                e.attr("ImageSize-x64", args.demon_image_size_x64, indent=3)
            if args.demon_image_size_x86 is not None:
                e.attr("ImageSize-x86", args.demon_image_size_x86, indent=3)
            e.block_close(indent=2)

        if args.demon_replace_str_x64:
            pairs = dict(p.split("=", 1) for p in args.demon_replace_str_x64 if "=" in p)
            e.attr_map("ReplaceStrings-x64", pairs, indent=2)
        if args.demon_replace_str_x86:
            pairs = dict(p.split("=", 1) for p in args.demon_replace_str_x86 if "=" in p)
            e.attr_map("ReplaceStrings-x86", pairs, indent=2)

        e.block_close(indent=1)

    e.blank()
    e.block_close()
    e.blank()

    # ── WebHook (optional) ────────────────────────────────────────────────
    if args.discord_url:
        e.comment("Optional: Discord webhook notifications")
        e.block_open("WebHook")
        e.blank()
        e.block_open("Discord", indent=1)
        e.attr("Url", args.discord_url, indent=2)
        if args.discord_avatar:
            e.attr("AvatarUrl", args.discord_avatar, indent=2)
        if args.discord_user:
            e.attr("User", args.discord_user, indent=2)
        e.blank()
        e.block_close(indent=1)
        e.blank()
        e.block_close()
        e.blank()

    return e.render()


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def make_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="create_profile.py",
        description="Generate a Havoc C2 YAOTL profile.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
        Notes:
          --operator can be repeated for multiple operators: --operator alice:pw --operator bob:pw
          --http-name / --smb-name can be repeated for multiple listeners of the same type.
          --http-host can be repeated to set multiple callback hosts for one HTTP listener.
          --http-uri / --http-header / --http-resp-header can be repeated.
          --demon-replace-str-x64 uses KEY=VALUE syntax and can be repeated.

        Valid values:
          --http-rotation:         round-robin | random
          --demon-sleep-technique: Ekko | Zilean | FOLIAGE | WaitForSingleObjectEx
          --demon-proxy-loading:   RTLREGISTERWAIT | RTLCREATETIMER | RTLQUEUEWORKITEM
          --demon-amsi-etw:        HWBP | MEMORY
        """),
    )

    # Output
    p.add_argument("-o", "--output", metavar="FILE",
                   help="Output file path (default: stdout)")

    # Teamserver
    g = p.add_argument_group("Teamserver")
    g.add_argument("--ts-host", default="0.0.0.0", metavar="HOST",
                   help="Teamserver bind address (default: 0.0.0.0)")
    g.add_argument("--ts-port", type=int, default=40056, metavar="PORT",
                   help="Teamserver port (default: 40056)")
    g.add_argument("--compiler64", metavar="PATH",
                   help="Path to x86_64-w64-mingw32-gcc")
    g.add_argument("--compiler86", metavar="PATH",
                   help="Path to i686-w64-mingw32-gcc")
    g.add_argument("--nasm", metavar="PATH",
                   help="Path to nasm assembler")

    # Operators
    g = p.add_argument_group("Operators")
    g.add_argument("--operator", action="append", default=[], metavar="USER:PASS",
                   help="Operator credential (repeatable). Format: username:password")

    # HTTP listener
    g = p.add_argument_group("HTTP Listener (repeatable via multiple --http-name values)")
    g.add_argument("--http-name", action="append", default=[], metavar="NAME",
                   help="Listener name (repeatable for multiple HTTP listeners)")
    g.add_argument("--http-host", action="append", default=[], metavar="HOST",
                   help="Callback host/IP (repeatable for multiple hosts)")
    g.add_argument("--http-bind", action="append", default=[], metavar="IP",
                   help="Bind address (default: 0.0.0.0)")
    g.add_argument("--http-port", action="append", type=int, default=[], metavar="PORT",
                   help="PortBind — port the teamserver listens on (default: 80)")
    g.add_argument("--http-port-conn", action="append", type=int, default=[], metavar="PORT",
                   help="PortConn — port agents connect to (default: same as PortBind)")
    g.add_argument("--http-rotation", action="append", default=[], metavar="MODE",
                   help="Host rotation mode: round-robin (default) | random")
    g.add_argument("--http-secure", action="store_true",
                   help="Enable HTTPS (Secure = true)")
    g.add_argument("--http-method", action="append", default=[], metavar="METHOD",
                   help="HTTP method (default: POST)")
    g.add_argument("--http-ua", action="append", default=[], metavar="UA",
                   help="User-Agent string")
    g.add_argument("--http-uri", action="append", default=[], metavar="URI",
                   help="Allowed URI path (repeatable). E.g. /api/update")
    g.add_argument("--http-header", action="append", default=[], metavar="HEADER",
                   help="Required request header (repeatable). Format: 'Name: value'")
    g.add_argument("--http-resp-header", action="append", default=[], metavar="HEADER",
                   help="Response header (repeatable). Format: 'Name: value'")
    g.add_argument("--http-kill-date", action="append", default=[], metavar="DATETIME",
                   help="Kill date: 'YYYY-MM-DD HH:MM:SS'")
    g.add_argument("--http-working-hours", action="append", default=[], metavar="HOURS",
                   help="Working hours: 'H:MM-H:MM' (e.g. 8:00-17:00)")
    g.add_argument("--http-cert", action="append", default=[], metavar="PATH",
                   help="TLS certificate file path (requires --http-cert-key)")
    g.add_argument("--http-cert-key", action="append", default=[], metavar="PATH",
                   help="TLS private key file path")
    g.add_argument("--http-proxy-host", action="append", default=[], metavar="HOST",
                   help="Proxy host")
    g.add_argument("--http-proxy-port", action="append", default=[], metavar="PORT",
                   help="Proxy port")
    g.add_argument("--http-proxy-user", action="append", default=[], metavar="USER",
                   help="Proxy username")
    g.add_argument("--http-proxy-pass", action="append", default=[], metavar="PASS",
                   help="Proxy password")

    # SMB listener
    g = p.add_argument_group("SMB Listener (repeatable via multiple --smb-name values)")
    g.add_argument("--smb-name", action="append", default=[], metavar="NAME",
                   help="SMB listener name (repeatable)")
    g.add_argument("--smb-pipe", action="append", default=[], metavar="PIPE",
                   help="Named pipe name (e.g. msagent_01)")
    g.add_argument("--smb-kill-date", action="append", default=[], metavar="DATETIME",
                   help="Kill date: 'YYYY-MM-DD HH:MM:SS'")
    g.add_argument("--smb-working-hours", action="append", default=[], metavar="HOURS",
                   help="Working hours: 'H:MM-H:MM'")

    # External listener
    g = p.add_argument_group("External Listener")
    g.add_argument("--ext-name", action="append", default=[], metavar="NAME",
                   help="External listener name (repeatable)")
    g.add_argument("--ext-endpoint", action="append", default=[], metavar="EP",
                   help="External listener endpoint")

    # DNS listener
    g = p.add_argument_group("DNS Listener (repeatable via multiple --dns-name values)")
    g.add_argument("--dns-name", action="append", default=[], metavar="NAME",
                   help="DNS listener name (repeatable)")
    g.add_argument("--dns-zone", action="append", default=[], metavar="ZONE",
                   help="Authoritative DNS zone domain (e.g. updates.company-cdn.net)")
    g.add_argument("--dns-host", action="append", default=[], metavar="IP",
                   help="NS IP address(es) shown in listener table (repeatable)")
    g.add_argument("--dns-bind", action="append", default=[], metavar="IP",
                   help="Bind address for DNS server (default: 0.0.0.0)")
    g.add_argument("--dns-port", action="append", type=int, default=[], metavar="PORT",
                   help="UDP/TCP port (default: 53; use 5353 for unprivileged testing)")
    g.add_argument("--dns-timeout", action="append", type=int, default=[], metavar="MS",
                   help="Per-query timeout in milliseconds (default: 4000)")
    g.add_argument("--dns-chunk-delay", action="append", type=int, default=[], metavar="MS",
                   help="Inter-chunk jitter delay in milliseconds (default: 50)")

    # Demon
    g = p.add_argument_group("Demon defaults")
    g.add_argument("--demon-sleep", type=int, metavar="SECS",
                   help="Sleep delay in seconds (default: 2)")
    g.add_argument("--demon-jitter", type=int, metavar="PCT",
                   help="Sleep jitter percentage 0-100 (default: 15)")
    g.add_argument("--demon-indirect-syscall", action="store_true",
                   help="Enable indirect syscalls (IndirectSyscall = true)")
    g.add_argument("--demon-stack-duplication", action="store_true",
                   help="Enable stack duplication (StackDuplication = true)")
    g.add_argument(
        "--demon-rand-gadget",
        action="store_true",
        default=False,
        help="Re-select a random gadget address each Ekko/Zilean sleep cycle",
    )
    g.add_argument(
        "--demon-unhook-ntdll",
        action="store_true",
        default=False,
        help="Overwrite loaded ntdll .text with a clean copy from \\KnownDlls at startup (removes EDR inline hooks)",
    )
    g.add_argument(
        "--demon-hide-modules",
        action="store_true",
        default=False,
        help="Hide dynamically loaded modules from PEB LDR lists (HideModules = true)",
    )
    g.add_argument(
        "--demon-pe-stomp",
        action="store_true",
        default=False,
        help="Stomp PE header region during default sleep (PeStomp = true; leave off for injected payloads)",
    )
    g.add_argument(
        "--demon-sleep-cipher",
        choices=["RC4", "ChaCha20"],
        default=None,
        help="Sleep obfuscation cipher: RC4 (default) or ChaCha20 (HVC-045)",
    )
    g.add_argument(
        "--demon-verbose",
        action="store_true",
        default=False,
        help="Enable verbose debug logging in Demon (Verbose = true)",
    )
    g.add_argument(
        "--demon-coffee-veh",
        action="store_true",
        default=False,
        help="Enable VEH for BOF/object file loading (CoffeeVeh = true)",
    )
    g.add_argument(
        "--demon-coffee-threaded",
        action="store_true",
        default=False,
        help="Enable threaded BOF/object file execution (CoffeeThreaded = true)",
    )
    g.add_argument(
        "--demon-sleep-obf-addr-lib",
        metavar="LIB",
        help="DLL for custom sleep-obf thread start address (e.g. ntdll.dll)",
    )
    g.add_argument(
        "--demon-sleep-obf-addr-func",
        metavar="FUNC",
        help="Function name for custom sleep-obf thread start address",
    )
    g.add_argument(
        "--demon-sleep-obf-addr-offset",
        type=int,
        default=0,
        metavar="BYTES",
        help="Byte offset from function for sleep-obf start address (default: 0)",
    )
    g.add_argument(
        "--demon-inject-spoof-lib",
        metavar="LIB",
        help="DLL for injection spoof address (e.g. kernel32.dll)",
    )
    g.add_argument(
        "--demon-inject-spoof-func",
        metavar="FUNC",
        help="Function name for injection spoof address",
    )
    g.add_argument(
        "--demon-inject-spoof-offset",
        type=int,
        default=0,
        metavar="BYTES",
        help="Byte offset from function for injection spoof address (default: 0)",
    )
    g.add_argument("--demon-sleep-technique", metavar="TECHNIQUE",
                   choices=["Ekko", "Zilean", "FOLIAGE", "WaitForSingleObjectEx"],
                   help="Sleep obfuscation technique")
    g.add_argument("--demon-proxy-loading", metavar="METHOD",
                   choices=["RTLREGISTERWAIT", "RTLCREATETIMER", "RTLQUEUEWORKITEM"],
                   help="DLL proxy-loading method")
    g.add_argument("--demon-amsi-etw", metavar="MODE",
                   choices=["HWBP", "MEMORY"],
                   help="AMSI/ETW patching mode")
    g.add_argument("--demon-dotnet-pipe", metavar="PIPE",
                   help="Named pipe for .NET runtime comms (DotNetNamePipe)")
    g.add_argument("--demon-trust-xff", action="store_true",
                   help="Trust X-Forwarded-For header (TrustXForwardedFor = true)")
    g.add_argument("--demon-spawn64", metavar="PATH",
                   help="x64 spawn process path (Injection.Spawn64)")
    g.add_argument("--demon-spawn32", metavar="PATH",
                   help="x86 spawn process path (Injection.Spawn32)")
    g.add_argument("--demon-magic-mz-x64", metavar="2BYTES",
                   help="PE MZ magic override for x64 binary (max 2 bytes)")
    g.add_argument("--demon-magic-mz-x86", metavar="2BYTES",
                   help="PE MZ magic override for x86 binary (max 2 bytes)")
    g.add_argument("--demon-compile-time", metavar="DATETIME",
                   help="Fake compile timestamp for PE header")
    g.add_argument("--demon-image-size-x64", type=int, metavar="BYTES",
                   help="PE SizeOfImage override for x64 binary")
    g.add_argument("--demon-image-size-x86", type=int, metavar="BYTES",
                   help="PE SizeOfImage override for x86 binary")
    g.add_argument("--demon-replace-str-x64", action="append", default=[], metavar="OLD=NEW",
                   help="String replacement in x64 binary (repeatable). E.g. 'demon.x64.dll='")
    g.add_argument("--demon-replace-str-x86", action="append", default=[], metavar="OLD=NEW",
                   help="String replacement in x86 binary (repeatable)")

    # Service
    g = p.add_argument_group("Service (optional external C2 API)")
    g.add_argument("--svc-endpoint", metavar="EP",
                   help="Service endpoint path")
    g.add_argument("--svc-password", metavar="PASS",
                   help="Service password")

    # WebHook
    g = p.add_argument_group("WebHook (optional Discord notifications)")
    g.add_argument("--discord-url", metavar="URL",
                   help="Discord webhook URL")
    g.add_argument("--discord-avatar", metavar="URL",
                   help="Discord bot avatar URL (optional)")
    g.add_argument("--discord-user", metavar="NAME",
                   help="Discord bot username (optional)")

    return p


# ---------------------------------------------------------------------------
# Validation of user input
# ---------------------------------------------------------------------------

def validate_args(args, p) -> list[str]:
    errs = []

    if not args.operator:
        errs.append("at least one --operator USER:PASS is required")

    if not args.http_name and not args.smb_name and not args.ext_name and not args.dns_name:
        errs.append("at least one listener is required (--http-name, --smb-name, --ext-name, or --dns-name)")

    if not (1 <= args.ts_port <= 65535):
        errs.append(f"--ts-port must be 1-65535, got {args.ts_port}")

    for port in args.http_port + args.http_port_conn:
        if not (1 <= port <= 65535):
            errs.append(f"--http-port / --http-port-conn must be 1-65535, got {port}")

    for port in args.dns_port:
        if not (1 <= port <= 65535):
            errs.append(f"--dns-port must be 1-65535, got {port}")

    for op in args.operator:
        if ":" not in op:
            errs.append(f"--operator must be 'user:password', got {op!r}")

    for rot in args.http_rotation:
        if rot not in ("round-robin", "random"):
            errs.append(f"--http-rotation must be 'round-robin' or 'random', got {rot!r}")

    if args.demon_jitter is not None and not (0 <= args.demon_jitter <= 100):
        errs.append(f"--demon-jitter must be 0-100, got {args.demon_jitter}")

    for v in args.demon_magic_mz_x64 or []:
        if len(v) > 2:
            errs.append(f"--demon-magic-mz-x64 must be at most 2 bytes, got {v!r}")
    for v in args.demon_magic_mz_x86 or []:
        if len(v) > 2:
            errs.append(f"--demon-magic-mz-x86 must be at most 2 bytes, got {v!r}")

    return errs


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    p = make_arg_parser()
    args = p.parse_args()

    # Apply defaults for common optional fields that have defaults in the codebase
    if args.demon_sleep is None and not any([
        args.demon_jitter, args.demon_indirect_syscall, args.demon_stack_duplication,
        args.demon_sleep_technique, args.demon_proxy_loading, args.demon_amsi_etw,
        args.demon_spawn64, args.demon_spawn32,
    ]):
        # Only set defaults if at least one Demon field was given, otherwise include
        # both so the user sees they're configurable.
        pass

    if not args.operator:
        args.operator = ["operator:changeme"]
        sys.stderr.write("Warning: no --operator given; using placeholder 'operator:changeme'\n")

    if not args.http_name and not args.smb_name and not args.ext_name and not args.dns_name:
        # Provide a minimal HTTP listener as a placeholder
        args.http_name = ["HTTP Agent"]
        args.http_host = ["127.0.0.1"]
        sys.stderr.write("Warning: no listener given; generating placeholder HTTP listener\n")

    errs = validate_args(args, p)
    if errs:
        for e in errs:
            sys.stderr.write(f"Error: {e}\n")
        sys.exit(1)

    profile = build_profile(args)

    if args.output:
        outdir = os.path.dirname(args.output)
        if outdir and not os.path.exists(outdir):
            os.makedirs(outdir, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(profile)
        print(f"Profile written to: {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(profile)


if __name__ == "__main__":
    main()
