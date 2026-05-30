#!/usr/bin/env python3
"""
check_profile.py — Havoc C2 YAOTL profile validator and mock-traffic viewer.

Usage:
    python3 check_profile.py <profile.yaotl> [--traffic] [--strict]

Options:
    --traffic   Show mock HTTP/SMB traffic for each listener (default: enabled)
    --strict    Treat warnings as errors
    -h/--help   Show this help

Examples:
    python3 scripts/check_profile.py profiles/havoc.yaotl
    python3 scripts/check_profile.py profiles/http_smb.yaotl --strict
"""

import sys
import os
import re
import textwrap
from dataclasses import dataclass, field
from typing import Any, Optional
from datetime import datetime

# ---------------------------------------------------------------------------
# Tokeniser
# ---------------------------------------------------------------------------

TOKEN_IDENT    = "IDENT"
TOKEN_STRING   = "STRING"
TOKEN_NUMBER   = "NUMBER"
TOKEN_BOOL     = "BOOL"
TOKEN_EQ       = "EQ"
TOKEN_LBRACE   = "LBRACE"
TOKEN_RBRACE   = "RBRACE"
TOKEN_LBRACKET = "LBRACKET"
TOKEN_RBRACKET = "RBRACKET"
TOKEN_COMMA    = "COMMA"
TOKEN_COLON    = "COLON"
TOKEN_EOF      = "EOF"
TOKEN_NEWLINE  = "NEWLINE"


@dataclass
class Token:
    kind: str
    value: Any
    line: int
    col: int

    def __repr__(self):
        return f"Token({self.kind}, {self.value!r}, line={self.line})"


class LexError(Exception):
    def __init__(self, msg, line, col):
        super().__init__(msg)
        self.line = line
        self.col = col


class Lexer:
    def __init__(self, text: str):
        self.text = text
        self.pos = 0
        self.line = 1
        self.col = 1
        self._tokens: list[Token] = []
        self._tokenise()

    def _peek(self, offset=0) -> str:
        p = self.pos + offset
        return self.text[p] if p < len(self.text) else ""

    def _advance(self) -> str:
        ch = self.text[self.pos]
        self.pos += 1
        if ch == "\n":
            self.line += 1
            self.col = 1
        else:
            self.col += 1
        return ch

    def _skip_whitespace_and_comments(self):
        while self.pos < len(self.text):
            ch = self._peek()
            if ch in " \t\r\n":
                self._advance()
            elif ch == "#":
                # line comment
                while self.pos < len(self.text) and self._peek() != "\n":
                    self._advance()
            else:
                break

    def _read_string(self) -> str:
        self._advance()  # consume opening "
        buf = []
        while self.pos < len(self.text):
            ch = self._advance()
            if ch == "\\":
                esc = self._advance()
                if esc == "n":
                    buf.append("\n")
                elif esc == "t":
                    buf.append("\t")
                elif esc == "\\":
                    buf.append("\\")
                elif esc == '"':
                    buf.append('"')
                else:
                    buf.append(esc)
            elif ch == '"':
                return "".join(buf)
            else:
                buf.append(ch)
        raise LexError("Unterminated string", self.line, self.col)

    def _read_number(self) -> Any:
        buf = []
        while self.pos < len(self.text) and (self._peek().isdigit() or self._peek() in ".-"):
            buf.append(self._advance())
        s = "".join(buf)
        if "." in s:
            return float(s)
        return int(s)

    def _read_ident(self) -> str:
        buf = []
        while self.pos < len(self.text):
            ch = self._peek()
            if ch.isalnum() or ch in "_-":
                buf.append(self._advance())
            else:
                break
        return "".join(buf)

    def _tokenise(self):
        while True:
            self._skip_whitespace_and_comments()
            if self.pos >= len(self.text):
                self._tokens.append(Token(TOKEN_EOF, None, self.line, self.col))
                break

            ln, cl = self.line, self.col
            ch = self._peek()

            if ch == '"':
                s = self._read_string()
                self._tokens.append(Token(TOKEN_STRING, s, ln, cl))
            elif ch.isdigit() or (ch == "-" and self._peek(1).isdigit()):
                n = self._read_number()
                self._tokens.append(Token(TOKEN_NUMBER, n, ln, cl))
            elif ch == "=":
                self._advance()
                self._tokens.append(Token(TOKEN_EQ, "=", ln, cl))
            elif ch == "{":
                self._advance()
                self._tokens.append(Token(TOKEN_LBRACE, "{", ln, cl))
            elif ch == "}":
                self._advance()
                self._tokens.append(Token(TOKEN_RBRACE, "}", ln, cl))
            elif ch == "[":
                self._advance()
                self._tokens.append(Token(TOKEN_LBRACKET, "[", ln, cl))
            elif ch == "]":
                self._advance()
                self._tokens.append(Token(TOKEN_RBRACKET, "]", ln, cl))
            elif ch == ",":
                self._advance()
                self._tokens.append(Token(TOKEN_COMMA, ",", ln, cl))
            elif ch == ":":
                self._advance()
                self._tokens.append(Token(TOKEN_COLON, ":", ln, cl))
            elif ch.isalpha() or ch == "_":
                ident = self._read_ident()
                if ident.lower() in ("true", "false"):
                    self._tokens.append(Token(TOKEN_BOOL, ident.lower() == "true", ln, cl))
                else:
                    self._tokens.append(Token(TOKEN_IDENT, ident, ln, cl))
            else:
                raise LexError(f"Unexpected character: {ch!r}", ln, cl)

    def tokens(self):
        return self._tokens


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------
# Grammar:
#   file         := top_block*
#   top_block    := IDENT label? '{' body '}'
#   label        := STRING
#   body         := item*
#   item         := attr | sub_block
#   sub_block    := IDENT label? '{' body '}'   (no '=' before '{')
#   attr         := IDENT '=' value
#   value        := STRING | NUMBER | BOOL | array | map_literal
#   array        := '[' (value (',' value)*)? ','? ']'
#   map_literal  := '{' (STRING (':' | '=') value (',' STRING (':' | '=') value)*)? ','? '}'

class ParseError(Exception):
    def __init__(self, msg, line, col=0):
        super().__init__(msg)
        self.line = line
        self.col = col


class Parser:
    def __init__(self, tokens: list[Token]):
        self.tokens = tokens
        self.pos = 0

    def _peek(self, offset=0) -> Token:
        p = self.pos + offset
        if p < len(self.tokens):
            return self.tokens[p]
        return Token(TOKEN_EOF, None, 0, 0)

    def _consume(self, expected_kind=None) -> Token:
        tok = self.tokens[self.pos]
        if expected_kind and tok.kind != expected_kind:
            raise ParseError(
                f"expected {expected_kind}, got {tok.kind} ({tok.value!r})",
                tok.line, tok.col,
            )
        self.pos += 1
        return tok

    def parse_file(self) -> dict:
        """Returns {block_name: [block_dict, ...]} for top-level blocks."""
        result = {}
        while self._peek().kind != TOKEN_EOF:
            if self._peek().kind != TOKEN_IDENT:
                tok = self._peek()
                raise ParseError(f"expected block name, got {tok.kind}", tok.line, tok.col)
            name_tok = self._consume(TOKEN_IDENT)
            label = None
            if self._peek().kind == TOKEN_STRING:
                label = self._consume(TOKEN_STRING).value
            self._consume(TOKEN_LBRACE)
            body = self._parse_body()
            self._consume(TOKEN_RBRACE)
            if label is not None:
                body["__label__"] = label
            result.setdefault(name_tok.value, []).append(body)
        return result

    def _parse_body(self) -> dict:
        body = {}
        while self._peek().kind not in (TOKEN_RBRACE, TOKEN_EOF):
            if self._peek().kind != TOKEN_IDENT:
                tok = self._peek()
                raise ParseError(f"expected attribute or block name, got {tok.kind!r} ({tok.value!r})", tok.line, tok.col)

            name_tok = self._peek()

            # Look-ahead to distinguish attr from sub-block
            next1 = self._peek(1)
            if next1.kind == TOKEN_EQ:
                # attribute
                self._consume(TOKEN_IDENT)
                self._consume(TOKEN_EQ)
                value = self._parse_value()
                key = name_tok.value
                if key in body:
                    # If already present, convert to list
                    existing = body[key]
                    if not isinstance(existing, list):
                        body[key] = [existing]
                    body[key].append(value)
                else:
                    body[key] = value
            elif next1.kind == TOKEN_LBRACE or next1.kind == TOKEN_STRING:
                # sub-block (possibly labeled)
                self._consume(TOKEN_IDENT)
                label = None
                if self._peek().kind == TOKEN_STRING:
                    label = self._consume(TOKEN_STRING).value
                self._consume(TOKEN_LBRACE)
                sub_body = self._parse_body()
                self._consume(TOKEN_RBRACE)
                if label is not None:
                    sub_body["__label__"] = label
                key = name_tok.value
                body.setdefault(key, [])
                if not isinstance(body[key], list):
                    body[key] = [body[key]]
                body[key].append(sub_body)
            else:
                tok = self._peek()
                raise ParseError(
                    f"unexpected token after identifier '{name_tok.value}': {next1.kind!r}",
                    tok.line, tok.col,
                )
        return body

    def _parse_value(self) -> Any:
        tok = self._peek()
        if tok.kind == TOKEN_STRING:
            return self._consume(TOKEN_STRING).value
        elif tok.kind == TOKEN_NUMBER:
            return self._consume(TOKEN_NUMBER).value
        elif tok.kind == TOKEN_BOOL:
            return self._consume(TOKEN_BOOL).value
        elif tok.kind == TOKEN_LBRACKET:
            return self._parse_array()
        elif tok.kind == TOKEN_LBRACE:
            return self._parse_map()
        else:
            raise ParseError(f"expected value, got {tok.kind!r} ({tok.value!r})", tok.line, tok.col)

    def _parse_array(self) -> list:
        self._consume(TOKEN_LBRACKET)
        items = []
        while self._peek().kind not in (TOKEN_RBRACKET, TOKEN_EOF):
            items.append(self._parse_value())
            if self._peek().kind == TOKEN_COMMA:
                self._consume(TOKEN_COMMA)
        self._consume(TOKEN_RBRACKET)
        return items

    def _parse_map(self) -> dict:
        self._consume(TOKEN_LBRACE)
        result = {}
        while self._peek().kind not in (TOKEN_RBRACE, TOKEN_EOF):
            key_tok = self._consume(TOKEN_STRING)
            if self._peek().kind in (TOKEN_COLON, TOKEN_EQ):
                self._consume()
            else:
                raise ParseError("expected ':' or '=' after map key", key_tok.line)
            val = self._parse_value()
            result[key_tok.value] = val
            if self._peek().kind == TOKEN_COMMA:
                self._consume(TOKEN_COMMA)
        self._consume(TOKEN_RBRACE)
        return result


# ---------------------------------------------------------------------------
# Schema definition (derived from teamserver/pkg/profile/config.go)
# ---------------------------------------------------------------------------

@dataclass
class FieldSpec:
    name: str
    type_: str          # "string", "int", "bool", "[]string", "map", "block"
    required: bool = True
    choices: Optional[list] = None
    validator: Optional[Any] = None  # callable(value) -> Optional[str]  (error msg)


def _validate_port(v):
    if not isinstance(v, int) or not (1 <= v <= 65535):
        return f"must be an integer in range 1–65535, got {v!r}"


def _validate_killdate(v):
    if not isinstance(v, str):
        return "must be a string"
    try:
        datetime.strptime(v, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return f"must match format 'YYYY-MM-DD HH:MM:SS', got {v!r}"


def _validate_workinghours(v):
    if not isinstance(v, str):
        return "must be a string"
    m = re.match(r"^(\d{1,2}):(\d{2})-(\d{1,2}):(\d{2})$", v)
    if not m:
        return f"must match format 'H:MM-H:MM', got {v!r}"


def _validate_hostrotation(v):
    if v not in ("round-robin", "random"):
        return f"must be 'round-robin' or 'random', got {v!r}"


def _validate_sleep_technique(v):
    # Accepted values must match the switch cases in teamserver/pkg/common/builder/builder.go
    valid = ("Ekko", "Zilean", "Foliage", "WaitForSingleObjectEx")
    if v not in valid:
        return f"unknown SleepTechnique {v!r}; known values: {', '.join(valid)}"


def _validate_proxy_loading(v):
    # Accepted values must match the switch cases in teamserver/pkg/common/builder/builder.go
    valid = ("None (LdrLoadDll)", "RtlRegisterWait", "RtlCreateTimer", "RtlQueueWorkItem")
    if v not in valid:
        return f"unknown ProxyLoading {v!r}; known values: {', '.join(valid)}"


def _validate_jmp_gadget(v):
    # Accepted values must match the switch cases in teamserver/pkg/common/builder/builder.go
    valid = ("None", "jmp rax", "jmp rbx")
    if v not in valid:
        return f"unknown SleepJmpGadget {v!r}; known values: {', '.join(valid)}"


def _validate_amsi_etw(v):
    if v not in ("HWBP", "MEMORY"):
        return f"unknown AmsiEtwPatching {v!r}; must be 'HWBP' or 'MEMORY'"


def _validate_sleep_cipher(v):
    # Accepted values must match the switch cases in teamserver/pkg/common/builder/builder.go
    valid = ("RC4", "ChaCha20")
    if v not in valid:
        return f"unknown SleepCipher {v!r}; known values: {', '.join(valid)}"


# Schema: maps block path → list of FieldSpec
SCHEMA = {
    "Teamserver": [
        FieldSpec("Host", "string", required=True),
        FieldSpec("Port", "int", required=True, validator=_validate_port),
        FieldSpec("HeaderMaskSeed", "string", required=False),  # per-packet XOR mask seed (HVC-003)
    ],
    "Teamserver.Build": [
        FieldSpec("Compiler64", "string", required=False),
        FieldSpec("Compiler86", "string", required=False),
        FieldSpec("Nasm", "string", required=False),
    ],
    "Operators": [],  # validated separately (user blocks)
    "Operators.user": [
        FieldSpec("Password", "string", required=True),
    ],
    "Listeners.Http": [
        FieldSpec("Name", "string", required=True),
        FieldSpec("Hosts", "[]string", required=True),
        FieldSpec("HostBind", "string", required=True),
        FieldSpec("HostRotation", "string", required=True, validator=_validate_hostrotation),
        FieldSpec("PortBind", "int", required=True, validator=_validate_port),
        FieldSpec("PortConn", "int", required=False, validator=_validate_port),
        FieldSpec("Method", "string", required=False),
        FieldSpec("UserAgent", "string", required=False),
        FieldSpec("Headers", "[]string", required=False),
        FieldSpec("Uris", "[]string", required=False),
        FieldSpec("Secure", "bool", required=False),
        FieldSpec("KillDate", "string", required=False, validator=_validate_killdate),
        FieldSpec("WorkingHours", "string", required=False, validator=_validate_workinghours),
    ],
    "Listeners.Http.Response": [
        FieldSpec("Headers", "[]string", required=False),
    ],
    "Listeners.Http.Cert": [
        FieldSpec("Cert", "string", required=True),
        FieldSpec("Key", "string", required=True),
    ],
    "Listeners.Http.Proxy": [
        FieldSpec("Host", "string", required=True),
        FieldSpec("Port", "int", required=True, validator=_validate_port),
        FieldSpec("Username", "string", required=False),
        FieldSpec("Password", "string", required=False),
    ],
    "Listeners.Smb": [
        FieldSpec("Name", "string", required=True),
        FieldSpec("PipeName", "string", required=True),
        FieldSpec("KillDate", "string", required=False, validator=_validate_killdate),
        FieldSpec("WorkingHours", "string", required=False, validator=_validate_workinghours),
    ],
    "Listeners.External": [
        FieldSpec("Name", "string", required=True),
        FieldSpec("Endpoint", "string", required=True),
    ],
    "Listeners.Dns": [
        FieldSpec("Name", "string", required=True),
        FieldSpec("Hosts", "[]string", required=False),
        FieldSpec("HostBind", "string", required=True),
        FieldSpec("Port", "int", required=True, validator=_validate_port),
        FieldSpec("ZoneDomain", "string", required=True),
        FieldSpec("QueryTimeout", "int", required=False),
        FieldSpec("ChunkDelayMs", "int", required=False),
    ],
    "Demon": [
        FieldSpec("Sleep", "int", required=False),
        FieldSpec("Jitter", "int", required=False),
        FieldSpec("IndirectSyscall", "bool", required=False),
        FieldSpec("StackDuplication", "bool", required=False),
        FieldSpec("SleepTechnique", "string", required=False, validator=_validate_sleep_technique),
        FieldSpec("SleepJmpGadget", "string", required=False, validator=_validate_jmp_gadget),
        FieldSpec("RandGadget", "bool", required=False),           # HVC-030 Sub-3: random gadget per cycle
        FieldSpec("UnhookNtdll", "bool", required=False),          # HVC-031 Sub-4: overwrite ntdll .text with clean KnownDlls copy
        FieldSpec("HideModules", "bool", required=False),           # HVC-031 Sub-2: unlink loaded modules from PEB LDR lists
        FieldSpec("PeStomp", "bool", required=False),               # ISS-037: stomp PE header during default sleep; off by default
        FieldSpec("SleepCipher", "string", required=False, validator=_validate_sleep_cipher),  # HVC-045: "RC4" or "ChaCha20"
        FieldSpec("Verbose", "bool", required=False),               # enable verbose debug logging
        FieldSpec("CoffeeVeh", "bool", required=False),             # enable VEH for BOF loading
        FieldSpec("CoffeeThreaded", "bool", required=False),        # enable threaded BOF execution
        FieldSpec("ExecDelay", "int", required=False),               # HVC-046: base delay ms between injection stages; 0 = disabled
        FieldSpec("ExecDelayJitter", "int", required=False),         # HVC-046: jitter % applied to ExecDelay (0-100)
        FieldSpec("ProxyLoading", "string", required=False, validator=_validate_proxy_loading),
        FieldSpec("AmsiEtwPatching", "string", required=False, validator=_validate_amsi_etw),
        FieldSpec("DotNetNamePipe", "string", required=False),
        FieldSpec("TrustXForwardedFor", "bool", required=False),
    ],
    "Demon.Injection": [
        FieldSpec("Spawn64", "string", required=False),
        FieldSpec("Spawn32", "string", required=False),
        FieldSpec("Alloc", "string", required=False),              # memory allocation technique
        FieldSpec("Execute", "string", required=False),            # memory execution technique
    ],
    "Demon.SleepObfStartAddr": [
        FieldSpec("Library", "string", required=True),
        FieldSpec("Function", "string", required=True),
        FieldSpec("Offset", "int", required=False),
    ],
    "Demon.InjectSpoofAddr": [
        FieldSpec("Library", "string", required=True),
        FieldSpec("Function", "string", required=True),
        FieldSpec("Offset", "int", required=False),
    ],
    "Demon.StackSpoofStartAddr": [
        FieldSpec("Library", "string", required=True),
        FieldSpec("Function", "string", required=True),
        FieldSpec("Offset", "int", required=False),
    ],
    "Demon.StackSpoofFrame0": [
        FieldSpec("Library", "string", required=True),
        FieldSpec("Function", "string", required=True),
        FieldSpec("Offset", "int", required=False),
    ],
    "Demon.StackSpoofFrame1": [
        FieldSpec("Library", "string", required=True),
        FieldSpec("Function", "string", required=True),
        FieldSpec("Offset", "int", required=False),
    ],
    "Demon.StackSpoofFrame2": [
        FieldSpec("Library", "string", required=True),
        FieldSpec("Function", "string", required=True),
        FieldSpec("Offset", "int", required=False),
    ],
    "Demon.StackSpoofFrame3": [
        FieldSpec("Library", "string", required=True),
        FieldSpec("Function", "string", required=True),
        FieldSpec("Offset", "int", required=False),
    ],
    "Demon.Binary": [],
    "Demon.Binary.Header": [
        FieldSpec("MagicMz-x64", "string", required=False),
        FieldSpec("MagicMz-x86", "string", required=False),
        FieldSpec("CompileTime", "string", required=False),
        FieldSpec("ImageSize-x64", "int", required=False),
        FieldSpec("ImageSize-x86", "int", required=False),
    ],
    "Service": [
        FieldSpec("Endpoint", "string", required=True),
        FieldSpec("Password", "string", required=True),
    ],
    "WebHook.Discord": [
        FieldSpec("Url", "string", required=True),
        FieldSpec("AvatarUrl", "string", required=False),
        FieldSpec("User", "string", required=False),
    ],
}

KNOWN_TOP_LEVEL_BLOCKS = {"Teamserver", "Operators", "Listeners", "Demon", "Service", "WebHook"}
REQUIRED_TOP_LEVEL = {"Teamserver", "Operators"}


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------

@dataclass
class Issue:
    level: str   # "error" or "warning"
    path: str    # e.g. "Listeners.Http[0].PortBind"
    message: str
    line: int = 0

    def __str__(self):
        loc = f" (line {self.line})" if self.line else ""
        level_str = f"\033[31mERROR\033[0m" if self.level == "error" else f"\033[33mWARN \033[0m"
        return f"  {level_str}  {self.path}{loc}: {self.message}"


class Validator:
    def __init__(self, tree: dict):
        self.tree = tree
        self.issues: list[Issue] = []

    def _err(self, path, msg, line=0):
        self.issues.append(Issue("error", path, msg, line))

    def _warn(self, path, msg, line=0):
        self.issues.append(Issue("warning", path, msg, line))

    def _block(self, name) -> Optional[dict]:
        """Return first block body or None."""
        blocks = self.tree.get(name, [])
        return blocks[0] if blocks else None

    def _validate_fields(self, body: dict, schema_key: str, path_prefix: str):
        specs = SCHEMA.get(schema_key, [])
        known_keys = {s.name for s in specs}

        for spec in specs:
            if spec.required and spec.name not in body:
                self._err(f"{path_prefix}.{spec.name}", f"required field '{spec.name}' is missing")
            elif spec.name in body:
                val = body[spec.name]
                # Type check
                if spec.type_ == "int" and not isinstance(val, int):
                    self._err(f"{path_prefix}.{spec.name}", f"expected int, got {type(val).__name__} ({val!r})")
                elif spec.type_ == "bool" and not isinstance(val, bool):
                    self._err(f"{path_prefix}.{spec.name}", f"expected bool, got {type(val).__name__} ({val!r})")
                elif spec.type_ == "string" and not isinstance(val, str):
                    self._err(f"{path_prefix}.{spec.name}", f"expected string, got {type(val).__name__} ({val!r})")
                elif spec.type_ == "[]string":
                    if not isinstance(val, list):
                        self._err(f"{path_prefix}.{spec.name}", f"expected list of strings, got {type(val).__name__}")
                    else:
                        for i, item in enumerate(val):
                            if not isinstance(item, str):
                                self._err(f"{path_prefix}.{spec.name}[{i}]", f"expected string, got {type(item).__name__}")
                # Value constraint
                if spec.validator and spec.name in body:
                    msg = spec.validator(val)
                    if msg:
                        self._err(f"{path_prefix}.{spec.name}", msg)

        # Warn about unrecognised fields
        skip_keys = {"__label__", "Build", "Response", "Cert", "Proxy", "Injection", "Binary", "Header", "Discord", "SleepObfStartAddr", "InjectSpoofAddr", "StackSpoofStartAddr", "StackSpoofFrame0", "StackSpoofFrame1", "StackSpoofFrame2", "StackSpoofFrame3"}
        for key in body:
            if key not in known_keys and key not in skip_keys:
                self._warn(f"{path_prefix}.{key}", f"unrecognised field '{key}'")

    def validate(self):
        # Check for required top-level blocks
        for name in REQUIRED_TOP_LEVEL:
            if name not in self.tree:
                self._err(name, f"required top-level block '{name}' is missing")

        # Warn about unknown top-level blocks
        for name in self.tree:
            if name not in KNOWN_TOP_LEVEL_BLOCKS:
                self._warn(name, f"unknown top-level block '{name}'")

        self._validate_teamserver()
        self._validate_operators()
        self._validate_listeners()
        self._validate_demon()
        self._validate_service()
        self._validate_webhook()

        return self.issues

    def _validate_teamserver(self):
        ts = self._block("Teamserver")
        if ts is None:
            return
        self._validate_fields(ts, "Teamserver", "Teamserver")

        # Build sub-block
        for build_list in [ts.get("Build", [])]:
            if isinstance(build_list, list):
                for i, b in enumerate(build_list):
                    self._validate_fields(b, "Teamserver.Build", f"Teamserver.Build")

    def _validate_operators(self):
        ops = self._block("Operators")
        if ops is None:
            return
        users = ops.get("user", [])
        if not users:
            self._err("Operators", "at least one 'user' block is required")
        else:
            for i, u in enumerate(users):
                label = u.get("__label__", f"[{i}]")
                self._validate_fields(u, "Operators.user", f"Operators.user \"{label}\"")

    def _validate_listeners(self):
        listeners = self._block("Listeners")
        if listeners is None:
            return

        http_list = listeners.get("Http", [])
        if not isinstance(http_list, list):
            http_list = [http_list]
        for i, h in enumerate(http_list):
            pfx = f"Listeners.Http[{i}] \"{h.get('Name', '?')}\""
            self._validate_fields(h, "Listeners.Http", pfx)
            # Response sub-block
            for r in h.get("Response", []):
                self._validate_fields(r, "Listeners.Http.Response", f"{pfx}.Response")
            # Cert sub-block
            for c in h.get("Cert", []):
                self._validate_fields(c, "Listeners.Http.Cert", f"{pfx}.Cert")
            # Proxy sub-block
            for p in h.get("Proxy", []):
                self._validate_fields(p, "Listeners.Http.Proxy", f"{pfx}.Proxy")

            # Warn if Secure=true but no Cert block
            if h.get("Secure") is True and not h.get("Cert"):
                self._warn(pfx, "Secure = true but no Cert block; teamserver will auto-generate certificate")
            # Warn if no Uris defined
            if not h.get("Uris"):
                self._warn(pfx, "no Uris defined; Demon will use the root path '/'")

        smb_list = listeners.get("Smb", [])
        if not isinstance(smb_list, list):
            smb_list = [smb_list]
        for i, s in enumerate(smb_list):
            pfx = f"Listeners.Smb[{i}] \"{s.get('Name', '?')}\""
            self._validate_fields(s, "Listeners.Smb", pfx)
            # Warn about generic pipe names
            pipe = s.get("PipeName", "")
            if pipe.lower() in ("msagent_01", "mspipe", "pipe", "agent"):
                self._warn(pfx, f"PipeName '{pipe}' is a well-known default; consider a custom value")

        ext_list = listeners.get("External", [])
        if not isinstance(ext_list, list):
            ext_list = [ext_list]
        for i, e in enumerate(ext_list):
            pfx = f"Listeners.External[{i}] \"{e.get('Name', '?')}\""
            self._validate_fields(e, "Listeners.External", pfx)

        dns_list = listeners.get("Dns", [])
        if not isinstance(dns_list, list):
            dns_list = [dns_list]
        for i, d in enumerate(dns_list):
            pfx = f"Listeners.Dns[{i}] \"{d.get('Name', '?')}\""
            self._validate_fields(d, "Listeners.Dns", pfx)
            zone = d.get("ZoneDomain", "")
            if zone and "." not in zone:
                self._warn(pfx, f"ZoneDomain '{zone}' has no dot; must be a valid DNS zone (e.g. 'c2.example.com')")
            port = d.get("Port", 0)
            if isinstance(port, int) and port == 53:
                self._warn(pfx, "Port = 53 requires root or cap_net_bind_service on Linux; consider 5353 for testing")

    def _validate_demon(self):
        demon = self._block("Demon")
        if demon is None:
            return
        self._validate_fields(demon, "Demon", "Demon")

        sleep = demon.get("Sleep", 0)
        jitter = demon.get("Jitter", 0)
        if isinstance(sleep, int) and sleep <= 0:
            self._warn("Demon.Sleep", f"Sleep = {sleep}; very low sleep makes beacons noisy")
        if isinstance(jitter, int) and (jitter < 0 or jitter > 100):
            self._err("Demon.Jitter", f"Jitter must be 0-100, got {jitter}")

        for inj in demon.get("Injection", []):
            self._validate_fields(inj, "Demon.Injection", "Demon.Injection")
            for arch, key in (("x64", "Spawn64"), ("x86", "Spawn32")):
                v = inj.get(key, "")
                if v and not v.startswith("C:\\"):
                    self._warn(f"Demon.Injection.{key}", f"path '{v}' does not look like a Windows absolute path")

        for addr_blk in demon.get("SleepObfStartAddr", []):
            self._validate_fields(addr_blk, "Demon.SleepObfStartAddr", "Demon.SleepObfStartAddr")

        for addr_blk in demon.get("InjectSpoofAddr", []):
            self._validate_fields(addr_blk, "Demon.InjectSpoofAddr", "Demon.InjectSpoofAddr")
        for addr_blk in demon.get("StackSpoofStartAddr", []):
            self._validate_fields(addr_blk, "Demon.StackSpoofStartAddr", "Demon.StackSpoofStartAddr")
        for addr_blk in demon.get("StackSpoofFrame0", []):
            self._validate_fields(addr_blk, "Demon.StackSpoofFrame0", "Demon.StackSpoofFrame0")
        for addr_blk in demon.get("StackSpoofFrame1", []):
            self._validate_fields(addr_blk, "Demon.StackSpoofFrame1", "Demon.StackSpoofFrame1")
        for addr_blk in demon.get("StackSpoofFrame2", []):
            self._validate_fields(addr_blk, "Demon.StackSpoofFrame2", "Demon.StackSpoofFrame2")
        for addr_blk in demon.get("StackSpoofFrame3", []):
            self._validate_fields(addr_blk, "Demon.StackSpoofFrame3", "Demon.StackSpoofFrame3")

        for bin_blk in demon.get("Binary", []):
            for hdr in bin_blk.get("Header", []):
                self._validate_fields(hdr, "Demon.Binary.Header", "Demon.Binary.Header")
                for fld in ("MagicMz-x64", "MagicMz-x86"):
                    v = hdr.get(fld)
                    if v and len(v) > 2:
                        self._err(f"Demon.Binary.Header.{fld}", f"MagicMz must be at most 2 bytes, got {len(v)}: {v!r}")

    def _validate_service(self):
        svc = self._block("Service")
        if svc is None:
            return
        self._validate_fields(svc, "Service", "Service")

    def _validate_webhook(self):
        wh = self._block("WebHook")
        if wh is None:
            return
        for disc in wh.get("Discord", []):
            self._validate_fields(disc, "WebHook.Discord", "WebHook.Discord")


# ---------------------------------------------------------------------------
# Mock traffic renderer
# ---------------------------------------------------------------------------

class TrafficRenderer:
    def __init__(self, tree: dict):
        self.tree = tree

    def render(self):
        output = []
        listeners = (self.tree.get("Listeners") or [{}])[0]
        demon = (self.tree.get("Demon") or [{}])[0]
        sleep = demon.get("Sleep", 2)
        jitter = demon.get("Jitter", 15)

        http_list = listeners.get("Http", [])
        if not isinstance(http_list, list):
            http_list = [http_list]
        smb_list = listeners.get("Smb", [])
        if not isinstance(smb_list, list):
            smb_list = [smb_list]
        ext_list = listeners.get("External", [])
        if not isinstance(ext_list, list):
            ext_list = [ext_list]
        dns_list = listeners.get("Dns", [])
        if not isinstance(dns_list, list):
            dns_list = [dns_list]

        for h in http_list:
            output.append(self._render_http(h, sleep, jitter))
        for s in smb_list:
            output.append(self._render_smb(s, sleep, jitter))
        for e in ext_list:
            output.append(self._render_external(e))
        for d in dns_list:
            output.append(self._render_dns(d, sleep, jitter))

        return "\n".join(output)

    def _render_http(self, h: dict, sleep: int, jitter: int) -> str:
        name = h.get("Name", "unnamed")
        hosts = h.get("Hosts", ["<host>"])
        port = h.get("PortConn") or h.get("PortBind", 443)
        secure = h.get("Secure", False)
        scheme = "https" if secure else "http"
        uris = h.get("Uris") or ["/"]
        method = h.get("Method") or "POST"
        ua = h.get("UserAgent", "Mozilla/5.0 (compatible; Havoc)")
        req_headers = h.get("Headers") or []
        resp_headers = []
        for resp_blk in h.get("Response", []):
            resp_headers.extend(resp_blk.get("Headers") or [])
        kill_date = h.get("KillDate", "")
        working_hours = h.get("WorkingHours", "")

        host = hosts[0] if hosts else "<host>"
        uri = uris[0] if uris else "/"

        lines = [
            f"┌─── HTTP Listener: {name} ───",
            f"│  Endpoint:       {scheme}://{host}:{port}",
            f"│  HostBind:       {h.get('HostBind','0.0.0.0')}:{h.get('PortBind', port)}",
            f"│  HostRotation:   {h.get('HostRotation','round-robin')}",
            f"│  Sleep/Jitter:   {sleep}s / {jitter}%",
        ]
        if kill_date:
            lines.append(f"│  KillDate:       {kill_date}")
        if working_hours:
            lines.append(f"│  WorkingHours:   {working_hours}")
        lines.append("│")
        lines.append(f"│  ── Mock Demon → Teamserver (check-in) ──")
        lines.append(f"│  {method} {uri} HTTP/1.1")
        lines.append(f"│  Host: {host}:{port}")
        lines.append(f"│  User-Agent: {ua}")
        for hdr in req_headers:
            lines.append(f"│  {hdr}")
        lines.append(f"│  Content-Length: <varies>  (base64-encoded encrypted blob)")
        lines.append(f"│")
        lines.append(f"│  Wire payload structure (inside base64 body):")
        lines.append(f"│    [4]  SIZE (BE, bit-31=LZNT1 flag)")
        lines.append(f"│    [4]  MAGIC 0xDEADBEEF (XOR'd with SIZE^0xA3F1C2B4)")
        lines.append(f"│    [4]  AgentID (XOR'd)")
        lines.append(f"│    [4]  CommandID (XOR'd, GET_JOB=1)")
        lines.append(f"│    [4]  RequestID (XOR'd)")
        lines.append(f"│    [16] per-request IV")
        lines.append(f"│    [N]  AES-256-CTR encrypted payload")
        lines.append(f"│    [32] HMAC-SHA256 tag (known agents only)")
        lines.append(f"│")
        lines.append(f"│  ── Mock Teamserver → Demon (response) ──")
        lines.append(f"│  HTTP/1.1 200 OK")
        for hdr in resp_headers:
            lines.append(f"│  {hdr}")
        if not resp_headers:
            lines.append(f"│  Content-Type: application/octet-stream")
        lines.append(f"│  Content-Length: <varies>")
        lines.append(f"│")
        lines.append(f"│  Response body structure:")
        lines.append(f"│    [4]  CommandID (LE, e.g. NOJOB=10 / task command)")
        lines.append(f"│    [4]  RequestID (LE)")
        lines.append(f"│    [4]  DataSize (LE)")
        lines.append(f"│    [N]  AES-256-CTR encrypted task data")
        if len(uris) > 1:
            lines.append(f"│")
            lines.append(f"│  All configured URIs ({len(uris)}):")
            for u in uris:
                lines.append(f"│    {scheme}://{host}:{port}{u}")
        if len(hosts) > 1:
            lines.append(f"│")
            lines.append(f"│  All callback hosts:")
            for hst in hosts:
                lines.append(f"│    {scheme}://{hst}:{port}")
        lines.append(f"└───")
        return "\n".join(lines)

    def _render_smb(self, s: dict, sleep: int, jitter: int) -> str:
        name = s.get("Name", "unnamed")
        pipe = s.get("PipeName", "agent_pipe")
        kill_date = s.get("KillDate", "")
        working_hours = s.get("WorkingHours", "")

        lines = [
            f"┌─── SMB Listener: {name} ───",
            f"│  Named pipe:     \\\\.\\pipe\\{pipe}",
            f"│  Sleep/Jitter:   {sleep}s / {jitter}%  (inherited from Demon defaults)",
        ]
        if kill_date:
            lines.append(f"│  KillDate:       {kill_date}")
        if working_hours:
            lines.append(f"│  WorkingHours:   {working_hours}")
        lines += [
            f"│",
            f"│  ── Mock Child → Parent pipe write (SmbSend) ──",
            f"│  WriteFile(\\\\.\\pipe\\{pipe}, ...)",
            f"│    [4]  DemonID XOR 0xA3F1C2B4       (HVC-008 frame mask)",
            f"│    [4]  PackageSize XOR 0x00A3F1C2   (HVC-008 frame mask)",
            f"│    [4]  SIZE (BE, bit-31=LZNT1 flag)",
            f"│    [4]  MAGIC 0xDEADBEEF (XOR'd with SIZE^0xA3F1C2B4)",
            f"│    [4]  AgentID (XOR'd)",
            f"│    [4]  CommandID (XOR'd)",
            f"│    [4]  RequestID (XOR'd)",
            f"│    [16] per-request IV",
            f"│    [N]  AES-256-CTR encrypted payload",
            f"│    [32] HMAC-SHA256 tag",
            f"│",
            f"│  ── Parent bundles for teamserver (HTTP POST body) ──",
            f"│  COMMAND_PIVOT (0x9D8) job in parent's HTTP check-in:",
            f"│    Data[0] = DEMON_PIVOT_SMB_COMMAND (12)",
            f"│    Data[1] = child AgentID (uint32)",
            f"│    Data[2] = Packer{{ AgentID(4) + child_packet_bytes }}",
            f"│",
            f"│  ── Teamserver → Parent → Child (task delivery) ──",
            f"│  Teamserver puts COMMAND_PIVOT job on parent's JobQueue.",
            f"│  Parent writes to child's pipe via SmbSend on next connect.",
            f"│  Child reads via SmbRecv (PeekNamedPipe non-blocking).",
            f"└───",
        ]
        return "\n".join(lines)

    def _render_dns(self, d: dict, sleep: int, jitter: int) -> str:
        name = d.get("Name", "unnamed")
        zone = d.get("ZoneDomain", "<zone>")
        hosts = d.get("Hosts", ["<ns-ip>"])
        port = d.get("Port", 53)
        host_bind = d.get("HostBind", "0.0.0.0")
        timeout = d.get("QueryTimeout", 4000)
        chunk_delay = d.get("ChunkDelayMs", 50)
        ns_ip = hosts[0] if hosts else "<ns-ip>"

        lines = [
            f"┌─── DNS Listener: {name} ───",
            f"│  Zone:           {zone}",
            f"│  HostBind:       {host_bind}:{port}  (UDP + TCP)",
            f"│  NS IP(s):       {', '.join(hosts) if isinstance(hosts, list) else hosts}",
            f"│  QueryTimeout:   {timeout} ms",
            f"│  ChunkDelayMs:   {chunk_delay} ms",
            f"│  Sleep/Jitter:   {sleep}s / {jitter}%",
            f"│",
            f"│  ── Mock Demon → Teamserver (uplink, A queries) ──",
            f"│  Each 30-byte chunk of the AuthWireBuffer is base32-encoded",
            f"│  and sent as an A-record query label:",
            f"│",
            f"│  DnsQuery_W(L\"nbswy3dpeb3w.00010001.deadbeef.{zone}\", DNS_TYPE_A)",
            f"│    → 0.0.0.1  (chunk ACK)",
            f"│  DnsQuery_W(L\"64tmmqqjv3dp.00010101.deadbeef.{zone}\", DNS_TYPE_A)",
            f"│    → 0.0.0.1  (chunk ACK)",
            f"│  ... (one A query per 30 bytes; a 300-byte packet = 10 queries)",
            f"│",
            f"│  FQDN format: <b32chunk>.<seq4><cid2><tot2>.<aid8>.<zone>",
            f"│    seq4  = 16-bit rolling packet sequence (hex)",
            f"│    cid2  = chunk index within this packet (hex)",
            f"│    tot2  = total chunks for this packet (hex)",
            f"│    aid8  = 32-bit agent ID (hex; 00000000 = registration)",
            f"│",
            f"│  Wire payload inside base32 (inherited from PackageTransmitAll):",
            f"│    [4]  SIZE (BE, bit-31=LZNT1 flag)",
            f"│    [4]  MAGIC 0xDEADBEEF (XOR'd with SIZE^0xA3F1C2B4)",
            f"│    [4]  AgentID (XOR'd)",
            f"│    [4]  CommandID (XOR'd)",
            f"│    [4]  RequestID (XOR'd)",
            f"│    [16] per-request IV",
            f"│    [N]  AES-256-CTR encrypted payload",
            f"│    [32] HMAC-SHA256 tag",
            f"│",
            f"│  ── Mock Demon → Teamserver (downlink poll, TXT queries) ──",
            f"│  After all uplink chunks ACK'd, Demon polls for the response:",
            f"│",
            f"│  DnsQuery_W(L\"p.0001.0000.deadbeef.{zone}\", DNS_TYPE_TXT)",
            f"│    → TXT \"<base64-encoded encrypted response bytes>\"",
            f"│  Last TXT chunk is prefixed with 0xFF sentinel (stripped by agent).",
            f"│  Empty TXT response = no data ready; agent retries after 500 ms.",
            f"│",
            f"│  FQDN format: p.<seq4>.<off4>.<aid8>.<zone>",
            f"│    off4 = byte offset into queued response (hex, step = 189 bytes)",
            f"│",
            f"│  DNS delegation required:",
            f"│    ns1.{zone}.  A   {ns_ip}",
            f"│    {zone}.      NS  ns1.{zone}.",
            f"└───",
        ]
        return "\n".join(lines)

    def _render_external(self, e: dict) -> str:
        name = e.get("Name", "unnamed")
        ep = e.get("Endpoint", "<endpoint>")
        lines = [
            f"┌─── External Listener: {name} ───",
            f"│  Endpoint:  {ep}",
            f"│  (External C2 service - traffic format defined by 3rd-party agent)",
            f"└───",
        ]
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _colour_off():
    """Return True if stdout is not a TTY (disable ANSI codes)."""
    return not sys.stdout.isatty()


def _strip_ansi(s):
    return re.sub(r"\033\[[0-9;]*m", "", s)


def main():
    args = sys.argv[1:]
    if not args or "-h" in args or "--help" in args:
        print(__doc__)
        sys.exit(0)

    profile_path = None
    show_traffic = True
    strict = False

    for a in args:
        if a == "--traffic":
            show_traffic = True
        elif a == "--no-traffic":
            show_traffic = False
        elif a == "--strict":
            strict = True
        elif not a.startswith("-"):
            profile_path = a
        else:
            print(f"Unknown option: {a}", file=sys.stderr)
            sys.exit(1)

    if profile_path is None:
        print("Error: no profile path given.", file=sys.stderr)
        sys.exit(1)

    if not os.path.exists(profile_path):
        print(f"Error: file not found: {profile_path}", file=sys.stderr)
        sys.exit(1)

    use_colour = not _colour_off()

    print(f"\n{'='*60}")
    print(f"  Havoc profile checker: {profile_path}")
    print(f"{'='*60}\n")

    # --- Parse ---
    try:
        with open(profile_path, "r", encoding="utf-8") as f:
            text = f.read()
        tokens = Lexer(text).tokens()
        tree = Parser(tokens).parse_file()
    except LexError as e:
        print(f"  \033[31mSYNTAX ERROR\033[0m  line {e.line}: {e}")
        sys.exit(1)
    except ParseError as e:
        print(f"  \033[31mPARSE ERROR\033[0m   line {e.line}: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"  \033[31mERROR\033[0m  {e}")
        sys.exit(1)

    print("  ✓ Syntax OK\n")

    # --- Validate ---
    issues = Validator(tree).validate()
    errors = [i for i in issues if i.level == "error"]
    warnings = [i for i in issues if i.level == "warning"]

    if issues:
        print(f"  Validation results: {len(errors)} error(s), {len(warnings)} warning(s)\n")
        for issue in issues:
            line = str(issue)
            if not use_colour:
                line = _strip_ansi(line)
            print(line)
        print()
    else:
        print("  ✓ Validation OK - no issues found\n")

    # --- Summary ---
    listeners = (tree.get("Listeners") or [{}])[0]
    n_http = len(listeners.get("Http") or [])
    n_smb = len(listeners.get("Smb") or [])
    n_ext = len(listeners.get("External") or [])
    n_dns = len(listeners.get("Dns") or [])
    demon = (tree.get("Demon") or [{}])[0]

    ts = (tree.get("Teamserver") or [{}])[0]
    print(f"  Profile summary:")
    print(f"    Teamserver:         {ts.get('Host','?')}:{ts.get('Port','?')}")
    ops = (tree.get("Operators") or [{}])[0]
    users = ops.get("user") or []
    usernames = [u.get("__label__", "?") for u in users]
    print(f"    Operators:          {', '.join(usernames) or '(none)'}")
    print(f"    HTTP listeners:     {n_http}")
    print(f"    SMB listeners:      {n_smb}")
    print(f"    External listeners: {n_ext}")
    print(f"    DNS listeners:      {n_dns}")
    print(f"    Demon sleep/jitter: {demon.get('Sleep',2)}s / {demon.get('Jitter',15)}%")
    print()

    # --- Mock traffic ---
    if show_traffic and (n_http + n_smb + n_ext + n_dns) > 0:
        print(f"  Mock traffic preview:")
        print()
        renderer = TrafficRenderer(tree)
        for line in renderer.render().splitlines():
            print(f"  {line}")
        print()

    # --- Exit code ---
    exit_code = 0
    if errors:
        exit_code = 1
    elif strict and warnings:
        exit_code = 1

    if exit_code == 0:
        print(f"  \033[32m✓ Profile is valid\033[0m" if use_colour else "  ✓ Profile is valid")
    else:
        print(f"  \033[31m✗ Profile has errors\033[0m" if use_colour else "  ✗ Profile has errors")
    print()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
