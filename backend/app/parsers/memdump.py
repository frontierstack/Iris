"""Binary / memory-dump parser: printable-strings extraction (ASCII + UTF-16LE, like `strings -a -el`)."""
from __future__ import annotations

import re
from typing import Iterable, Iterator, Optional

from ..normalize import IPV4_RE, IPV6_RE, parse_ts
from .base import BaseParser, ParsedEvent
from .tabular import TS_IN_TEXT

EXTENSIONS = (".dmp", ".raw", ".mem", ".bin", ".img", ".vmem", ".core", ".hiberfil", ".pagefile", ".dump", ".vmss", ".vmsn",
              ".lime", ".elf", ".exe", ".dll", ".sys", ".so", ".o", ".dat")
MIN_LEN = 6
MAX_STRINGS = 200_000
MAX_STRING_LEN = 4096

_ASCII_RUN = re.compile(rb"[\x20-\x7e\t]{%d,}" % MIN_LEN)
_UTF16_RUN = re.compile(rb"(?:[\x20-\x7e\t]\x00){%d,}" % MIN_LEN)

URL_RE = re.compile(r"\b((?:https?|ftp|ftps|smb|ldap|wss?)://[\w.-]+(?::\d+)?(?:/[\w./%?=&+#~:@!$'()*,;-]*)?)", re.I)
EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
WINPATH_RE = re.compile(r"(?<![\w])((?:[A-Za-z]:|\\\\[\w.-]+)\\(?:[^\\/:*?\"<>|\r\n\x00 ]+\\)*[^\\/:*?\"<>|\r\n\x00 ]*)")
UNIXPATH_RE = re.compile(r"(?<![\w/.-])(/(?:bin|sbin|usr|etc|var|opt|home|root|tmp|dev|proc|sys|lib|lib64|mnt|srv|data|boot|run|Applications|Library|System|Users)/[\w./+@-]*)")
REGKEY_RE = re.compile(r"\b((?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)|HKLM|HKCU|HKCR|HKU|HKCC)\\[\w\\ .{}()-]+)", re.I)
REGKEY_NT_RE = re.compile(r"(\\REGISTRY\\(?:MACHINE|USER)\\[\w\\ .{}()-]+)", re.I)
PE_SECTION_RE = re.compile(r"^(\.text|\.data|\.rdata|\.idata|\.edata|\.pdata|\.rsrc|\.reloc|\.bss|\.tls|\.CRT|\.debug|UPX[0-9]|\.upx|\.aspack|\.vmp[0-9]|\.themida|\.petite)\b")
ONION_RE = re.compile(r"\b([a-z2-7]{16}|[a-z2-7]{56})\.onion\b", re.I)
B64_BLOB_RE = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{200,}={0,2})(?![A-Za-z0-9+/=])")
DOMAIN_RE = re.compile(r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|xyz|top|info|biz|onion|gov|edu|co|uk|de|fr|jp|br|in|nl|se|no|pl|it|es|us|me|cc|tv|su|pw|tk|ml|ga|cf|gq|link|click|site|online|shop|app|dev|cloud|live|work|zip|mov))\b", re.I)

SUSPICIOUS = [
    (re.compile(r"powershell(?:\.exe)?[^\n]{0,80}?\s-(?:enc|encodedcommand|e)\b", re.I), "powershell -enc"),
    (re.compile(r"powershell(?:\.exe)?[^\n]{0,80}?\s-(?:nop|noprofile|w hidden|windowstyle hidden|exec bypass|ep bypass)", re.I), "powershell evasion flags"),
    (re.compile(r"\bmimikatz\b|sekurlsa::|lsadump::|kerberos::|privilege::debug", re.I), "mimikatz"),
    (re.compile(r"\bcmd(?:\.exe)?\s+/[ck]\b", re.I), "cmd.exe /c"),
    (re.compile(r"\b(?:Invoke-Expression|IEX|Invoke-Mimikatz|Invoke-WebRequest|DownloadString|DownloadFile|FromBase64String|Invoke-Shellcode|Add-MpPreference|Set-MpPreference)\b", re.I), "powershell download/exec"),
    (re.compile(r"\b(?:certutil(?:\.exe)?\s+-(?:urlcache|decode|encode)|bitsadmin\s+/transfer|mshta(?:\.exe)?\s+(?:http|vbscript|javascript)|regsvr32(?:\.exe)?\s+/s\s+/n\s+/u\s+/i:|rundll32(?:\.exe)?\s+javascript:|wmic\s+.*process\s+call\s+create)", re.I), "LOLBin"),
    (re.compile(r"\b(?:vssadmin\s+delete\s+shadows|wbadmin\s+delete|bcdedit\s+/set\s+.*recoveryenabled\s+no|wevtutil\s+cl\b|cipher\s+/w:)", re.I), "destructive admin command"),
    (re.compile(r"\b(?:procdump|lsass\.dmp|comsvcs\.dll,\s*MiniDump|sekurlsa|ntds\.dit|SAM\\|SYSTEM\\hive)", re.I), "credential dumping"),
    (re.compile(r"\b(?:meterpreter|metasploit|cobalt ?strike|beacon\.dll|sliver|brute ?ratel|empire agent|covenant grunt|psexec|paexec|winexe|smbexec|wmiexec|impacket)\b", re.I), "offensive tooling"),
    (re.compile(r"\b(?:nc(?:at)?\s+-e|/dev/tcp/|bash\s+-i\s*>&|socat\s+.*exec:|reverse_tcp|bind_tcp)", re.I), "reverse shell"),
    (re.compile(r"\b(?:schtasks\s+/create|reg\s+add\s+.*\\Run\b|CurrentVersion\\Run\b|sc\s+create|New-Service|StartupFolder|Winlogon\\Shell)", re.I), "persistence"),
    (re.compile(r"\b(?:xmrig|minerd|stratum\+tcp://|cryptonight|monero)\b", re.I), "cryptominer"),
    (re.compile(r"\b(?:ransom|decrypt(?:or|_files|ion key)|your files (?:have been|are) encrypted|\.locked\b|\.crypt\b|readme_to_decrypt|how_to_recover)", re.I), "ransomware note"),
    (re.compile(r"\b(?:AmsiScanBuffer|amsi\.dll|EtwEventWrite|NtUnmapViewOfSection|VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|QueueUserAPC|SetWindowsHookEx|NtQueueApcThread|RtlCreateUserThread)\b"), "injection API"),
    (re.compile(r"\b(?:passw(?:or)?d|pwd|passwd)\s*[=:]\s*\S{4,}", re.I), "credential in string"),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "AWS access key"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "private key"),
    (re.compile(r"\b(?:eval\(base64_decode|gzinflate\(base64_decode|str_rot13\(|assert\(\$_|system\(\$_(?:GET|POST|REQUEST)|shell_exec\(\$_)", re.I), "webshell"),
]

_REPEAT_RE = re.compile(r"^(.)\1+$")
_TWO_REPEAT_RE = re.compile(r"^(..)\1{2,}$")


def is_binary(head: bytes) -> bool:
    """True if the first bytes don't look like text (NULs, >30% non-printable, or invalid UTF-8)."""
    if not head:
        return False
    if b"\x00" in head:
        return True
    try:
        head.decode("utf-8")
    except UnicodeDecodeError:
        try:
            head[:-4].decode("utf-8")  # cut a possibly-split multibyte char at the end
        except UnicodeDecodeError:
            return True
    printable = sum(1 for b in head if 0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D) or b >= 0x80)
    return (len(head) - printable) / len(head) > 0.30


def _is_junk(s: str) -> bool:
    st = s.strip()
    if len(st) < MIN_LEN:
        return True
    if _REPEAT_RE.match(st) or _TWO_REPEAT_RE.match(st):
        return True
    distinct = len(set(st))
    if distinct <= 2 and len(st) >= 8:
        return True
    if distinct <= 3 and len(st) >= 24:
        return True
    letters = sum(1 for c in st if c.isalnum())
    if letters / len(st) < 0.3 and len(st) >= 12:  # mostly punctuation runs like "@@@@||||"
        return True
    return False


def extract_strings(data: bytes) -> Iterator[tuple[int, str, str]]:
    """Yield (offset, encoding, text) for ASCII and UTF-16LE runs, merged in offset order."""
    ascii_iter = ((m.start(), "ascii", m.group().decode("ascii")) for m in _ASCII_RUN.finditer(data))
    utf16_iter = ((m.start(), "utf-16le", m.group().decode("utf-16-le", errors="replace")) for m in _UTF16_RUN.finditer(data))
    a = next(ascii_iter, None)
    u = next(utf16_iter, None)
    while a is not None or u is not None:
        if u is None or (a is not None and a[0] <= u[0]):
            yield a  # type: ignore[misc]
            a = next(ascii_iter, None)
        else:
            yield u  # type: ignore[misc]
            u = next(utf16_iter, None)


class MemdumpParser(BaseParser):
    name = "Binary strings"
    family = "binary.strings"
    binary = True
    extensions = EXTENSIONS

    def sniff(self, sample: list[str], filename: str = "", head: bytes = b"") -> float:
        lower = filename.lower()
        if lower.endswith(EXTENSIONS):
            return 0.95 if is_binary(head) else 0.6
        if is_binary(head):
            return 0.9
        return 0.0

    def parse(self, lines: Iterable[str]) -> Iterator[ParsedEvent]:
        data = "\n".join(lines).encode("utf-8", errors="replace")
        return self.parse_bytes(data)

    def parse_bytes(self, data: bytes) -> Iterator[ParsedEvent]:
        n = 0
        skipped_junk = 0
        for offset, enc, text in extract_strings(data):
            if _is_junk(text):
                skipped_junk += 1
                continue
            if len(text) > MAX_STRING_LEN:
                text = text[:MAX_STRING_LEN]
            n += 1
            if n > MAX_STRINGS:
                yield ParsedEvent(raw="", msg=f"string extraction capped at {MAX_STRINGS:,} strings for this file "
                                              f"(offset 0x{offset:x} of {len(data):,} bytes)",
                                  fields={"offset": f"0x{offset:x}", "note": "capped", "encoding": enc})
                return
            yield self._event(offset, enc, text)

    def _event(self, offset: int, enc: str, text: str) -> ParsedEvent:
        s = text.strip()
        fields: dict[str, str] = {"offset": f"0x{offset:x}", "encoding": enc, "length": str(len(text))}
        ts = None
        ts_text = ""
        for p in TS_IN_TEXT[:-1]:  # skip bare-epoch pattern: too many false positives in binaries
            m = p.search(s)
            if m:
                cand = m.group(1)
                ts = parse_ts(cand)
                if ts is not None:
                    ts_text = cand
                    fields["timestamp"] = cand
                    break
        ips = [ip for ip in IPV4_RE.findall(s) if ip not in ("0.0.0.0",) and not _looks_like_version(s, ip)]
        if ips:
            fields["ip"] = ",".join(dict.fromkeys(ips))
        ip6 = [ip for ip in IPV6_RE.findall(s) if ip.count(":") >= 2 and not ip.startswith("::")]
        if ip6:
            fields["ipv6"] = ",".join(dict.fromkeys(ip6[:5]))
        urls = URL_RE.findall(s)
        if urls:
            fields["url"] = ",".join(dict.fromkeys(u.rstrip(".,;)") for u in urls[:5]))
        emails = EMAIL_RE.findall(s)
        if emails:
            fields["email"] = ",".join(dict.fromkeys(emails[:5]))
        wp = [p.rstrip(".,;)") for p in WINPATH_RE.findall(s) if len(p) > 4]
        if wp:
            fields["path"] = ",".join(dict.fromkeys(wp[:5]))
        up = [p.rstrip(".,;)") for p in UNIXPATH_RE.findall(s) if len(p) > 4]
        if up:
            fields["path"] = ",".join(dict.fromkeys((fields.get("path", "").split(",") if "path" in fields else []) + up[:5]))
        rk = REGKEY_RE.findall(s) + REGKEY_NT_RE.findall(s)
        if rk:
            fields["registry_key"] = ",".join(dict.fromkeys(k.rstrip(" .,;") for k in rk[:5]))
        pe = PE_SECTION_RE.match(s)
        if pe:
            fields["pe_section"] = pe.group(1)
        onion = ONION_RE.findall(s)
        if onion:
            fields["onion"] = ",".join(dict.fromkeys(f"{o}.onion" for o in onion[:5]))
        elif not urls and not emails:
            doms = [d for d in DOMAIN_RE.findall(s) if not IPV4_RE.fullmatch(d)]
            if doms:
                fields["domain"] = ",".join(dict.fromkeys(d.lower() for d in doms[:5]))
        sev: Optional[str] = None
        tags: list[str] = []
        for rx, tag in SUSPICIOUS:
            if rx.search(s):
                tags.append(tag)
        if onion:
            tags.append(".onion")
        if B64_BLOB_RE.search(s):
            tags.append("base64 blob")
        if tags:
            fields["suspicious"] = ", ".join(dict.fromkeys(tags))
            sev = "medium"
        return ParsedEvent(raw=text, msg=s[:300], ts=ts, ts_text=ts_text, sev=sev, fields=fields)


def _looks_like_version(s: str, ip: str) -> bool:
    """'6.1.7601.1' style version strings match IPV4_RE loosely; reject when preceded by 'v'/'version'."""
    i = s.find(ip)
    before = s[max(0, i - 12):i].lower()
    return before.rstrip().endswith(("version", "ver", "v", "v.", "build"))
