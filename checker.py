"""Email deliverability checker: the verification logic (no web code in here).

Every address goes through these layers, in order, and stops at the first one that
settles the question:

    1. Syntax      email-validator (RFC rules)                  -> bounce
    2. Typo        edit distance against popular mail domains   -> bounce
    3. Disposable  ~10k throw-away domains                      -> bounce
    4. DNS MX      does the domain publish a mail server?       -> bounce / unknown
    5. Provider    Gmail/Yahoo/Outlook/... never confirm        -> unknown (SMTP skipped)
    6. SMTP        MAIL FROM + RCPT TO, then QUIT. Never DATA.  -> delivered / bounce / unknown

The tool never sends a message. Layer 6 stops right after the RCPT TO reply.
"""
from __future__ import annotations

import logging
import os
import re
import secrets
import smtplib
import socket
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

import dns.exception
import dns.name
import dns.resolver
from email_validator import EmailNotValidError, validate_email

log = logging.getLogger("checker")

DELIVERED = "likely to be delivered"
BOUNCE = "likely to bounce"
UNKNOWN = "unknown"

DATA_DIR = Path(__file__).resolve().parent / "data"


# --------------------------------------------------------------------------- settings
def _env(name: str, default, cast=str):
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return cast(raw.strip())
    except ValueError:
        log.warning("Ignoring invalid value for %s: %r", name, raw)
        return default


@dataclass
class Settings:
    max_emails: int = 10               # addresses accepted per request
    smtp_mode: str = "auto"            # auto = probe port 25 once, on = always try, off = never
    smtp_port: int = 25
    smtp_timeout: float = 8.0          # seconds per SMTP socket operation
    smtp_delay: float = 1.0            # seconds to wait between two SMTP checks
    max_mx_tries: int = 2              # how many MX hosts to try per address
    dns_timeout: float = 5.0
    request_budget: float = 75.0       # total seconds one request may spend on SMTP
    mail_from: str = "verify@example.com"   # envelope sender used in MAIL FROM (set to your own)
    helo_hostname: str = ""            # name announced in EHLO (default: this host's FQDN)
    probe_hosts: tuple = ("gmail-smtp-in.l.google.com", "aspmx.l.google.com")
    probe_timeout: float = 5.0
    probe_ttl: float = 600.0           # how long the "is port 25 open?" answer is cached

    @classmethod
    def from_env(cls) -> "Settings":
        d = cls()
        mode = str(_env("SMTP_MODE", d.smtp_mode)).lower()
        if mode not in ("auto", "on", "off"):
            log.warning("SMTP_MODE must be auto, on or off; using auto")
            mode = "auto"
        return cls(
            max_emails=_env("MAX_EMAILS", d.max_emails, int),
            smtp_mode=mode,
            smtp_port=_env("SMTP_PORT", d.smtp_port, int),
            smtp_timeout=_env("SMTP_TIMEOUT", d.smtp_timeout, float),
            smtp_delay=_env("SMTP_DELAY", d.smtp_delay, float),
            max_mx_tries=_env("MAX_MX_TRIES", d.max_mx_tries, int),
            dns_timeout=_env("DNS_TIMEOUT", d.dns_timeout, float),
            request_budget=_env("REQUEST_BUDGET", d.request_budget, float),
            mail_from=_env("VERIFY_MAIL_FROM", d.mail_from),
            helo_hostname=_env("HELO_HOSTNAME", d.helo_hostname),
        )


# --------------------------------------------------------------------------- reference data
def _load_domains(path: Path) -> frozenset:
    try:
        with path.open(encoding="utf-8") as fh:
            return frozenset(
                line.strip().lower() for line in fh if line.strip() and not line.startswith("#")
            )
    except OSError:
        log.warning("Could not read %s; disposable detection will use the built-in list only", path)
        return frozenset()


# Well-known throw-away services that the community list does not always include.
_EXTRA_DISPOSABLE = {
    "tempmail.com", "temp-mail.io", "tempmail.net", "tempmail.org", "tempmailo.com",
    "10minutemail.net", "10minutemail.org", "20minutemail.com", "throwawaymail.com",
    "trashmail.com", "fakeinbox.com", "getnada.com", "maildrop.cc", "dispostable.com",
}
DISPOSABLE_DOMAINS = _load_domains(DATA_DIR / "disposable_domains.txt") | _EXTRA_DISPOSABLE

# The most commonly used consumer mail domains. A domain that is one edit away from
# one of these (but is not itself one of them) is almost certainly a typo.
TOP_DOMAINS = (
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com", "aol.com",
    "live.com", "msn.com", "protonmail.com", "proton.me", "mail.com", "gmx.com",
    "yandex.com", "zoho.com", "comcast.net", "verizon.net", "att.net", "me.com",
    "qq.com", "googlemail.com", "yahoo.co.uk", "hotmail.co.uk", "rediffmail.com", "ymail.com",
)
# Real domains that happen to sit one edit away from a top domain: never call them typos.
_NOT_TYPOS = {"q.com", "email.com", "gmx.net", "gmx.de", "gmx.at", "gmx.ch", "mail.ru", "aim.com"}

# Providers that answer "250 OK" to RCPT TO for any address (anti-enumeration), so an SMTP
# probe says nothing about whether the mailbox exists. We skip SMTP for these entirely.
_REG = r"(com|co\.[a-z]{2}|com\.[a-z]{2}|[a-z]{2})"
ANTI_ENUMERATION_PROVIDERS = (
    (re.compile(r"^(gmail|googlemail)\.com$"), "Gmail"),
    (re.compile(rf"^(yahoo|ymail|rocketmail)\.{_REG}$"), "Yahoo"),
    (re.compile(rf"^(outlook|hotmail|live|msn)\.{_REG}$"), "Outlook/Hotmail"),
    (re.compile(r"^aol\.com$"), "AOL"),
)
OTHER_FREE_PROVIDERS = {
    "icloud.com", "me.com", "mac.com", "proton.me", "protonmail.com", "gmx.com", "gmx.net",
    "mail.com", "zoho.com", "yandex.com", "rediffmail.com", "qq.com",
}

# If a domain's MX records point at one of these gateways, the real mailbox directory sits
# behind them and the gateway answers for everyone: same problem, same "unknown" answer.
MX_GATEWAYS = (
    ("google.com", "Google"), ("googlemail.com", "Google"),
    ("protection.outlook.com", "Microsoft 365"), ("outlook.com", "Microsoft"),
    ("hotmail.com", "Microsoft"), ("yahoodns.net", "Yahoo"),
    ("mimecast.com", "Mimecast"), ("pphosted.com", "Proofpoint"),
    ("ppe-hosted.com", "Proofpoint"), ("messagelabs.com", "Symantec"),
    ("barracudanetworks.com", "Barracuda"), ("iphmx.com", "Cisco"),
)

# Role accounts (compared with . _ - removed and any +tag dropped).
ROLE_ACCOUNTS = frozenset(
    """admin administrator info information support help helpdesk sales contact contactus hello hi
    team office mail email enquiry enquiries inquiry inquiries service services billing accounts
    accounting finance payments hr humanresources careers career jobs recruiting recruitment
    marketing press media pr news newsletter noreply donotreply notifications notification
    postmaster webmaster hostmaster abuse security privacy legal compliance root feedback orders
    order booking bookings reservations customerservice customersupport techsupport itsupport
    admissions registrar""".split()
)


# --------------------------------------------------------------------------- helpers
def osa_distance(a: str, b: str) -> int:
    """Levenshtein distance that also counts swapping two adjacent letters as one edit."""
    if a == b:
        return 0
    la, lb = len(a), len(b)
    d = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        d[i][0] = i
    for j in range(lb + 1):
        d[0][j] = j
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[la][lb]


def suggest_domain(domain: str) -> str | None:
    """Return the popular domain this one is probably a typo of, or None."""
    if domain in TOP_DOMAINS or domain in _NOT_TYPOS:
        return None
    for known in TOP_DOMAINS:
        if abs(len(known) - len(domain)) <= 1 and osa_distance(domain, known) == 1:
            return known
    return None


def is_disposable(domain: str) -> str | None:
    """Return the matching disposable domain (the domain itself or a parent of it)."""
    labels = domain.split(".")
    for i in range(len(labels) - 1):
        candidate = ".".join(labels[i:])
        if candidate in DISPOSABLE_DOMAINS:
            return candidate
    return None


def free_provider_name(domain: str) -> str | None:
    """Name of an anti-enumeration provider (SMTP is skipped for these), else None."""
    for pattern, name in ANTI_ENUMERATION_PROVIDERS:
        if pattern.match(domain):
            return name
    return None


def is_role_account(local_part: str) -> bool:
    base = local_part.lower().split("+", 1)[0]
    return re.sub(r"[._-]", "", base) in ROLE_ACCOUNTS


def gateway_name(mx_host: str) -> str | None:
    host = mx_host.rstrip(".").lower()
    for suffix, name in MX_GATEWAYS:
        if host == suffix or host.endswith("." + suffix):
            return name
    return None


_SPLIT = re.compile(r"[\s,;]+")


def parse_input(data) -> tuple[list[str], int]:
    """Turn pasted text (or a list of strings) into unique addresses.

    Returns (addresses, number_of_duplicates_dropped). Raises ValueError on bad input.
    """
    if isinstance(data, str):
        chunks = [data]
    elif isinstance(data, (list, tuple)) and all(isinstance(x, str) for x in data):
        chunks = list(data)
    else:
        raise ValueError("emails must be a string or a list of strings")
    seen, out, dupes = set(), [], 0
    for chunk in chunks:
        for token in _SPLIT.split(chunk):
            token = token.strip().strip("<>\"'")
            if token.lower().startswith("mailto:"):
                token = token[7:]
            if not token:
                continue
            key = token.lower()
            if key in seen:
                dupes += 1
                continue
            seen.add(key)
            out.append(token)
    return out, dupes


# --------------------------------------------------------------------------- SMTP reply classification
_ENHANCED = re.compile(r"\b5\.(\d{1,3})\.(\d{1,3})\b")
_RECIPIENT_CODES = {"1.1", "1.2", "1.3", "1.6", "1.10"}   # 5.1.1 = bad mailbox, etc.
_RECIPIENT_GONE = re.compile(
    r"no such user|user unknown|unknown user|does not exist|doesn'?t exist|"
    r"invalid (recipient|mailbox|address)|mailbox (unavailable|not found)|"
    r"recipient (not found|unknown)|no mailbox|account (is )?(disabled|not found)|unrouteable",
    re.I,
)
_POLICY = re.compile(
    r"spam|block ?list|blacklist|blocked|\brbl\b|spamhaus|reputation|policy|denied|"
    r"relay|authenticat|sender|banned|greylist|rate limit|too many",
    re.I,
)


def classify_rcpt(code: int, text: str) -> str:
    """Map a RCPT TO reply to: accepted | rejected | temp | policy | other."""
    if 200 <= code < 300:
        return "accepted"
    if 400 <= code < 500:
        return "temp"
    if 500 <= code < 600:
        m = _ENHANCED.search(text)
        if m:
            if m.group(1) == "7":                              # 5.7.x = security / policy
                return "policy"
            if f"{m.group(1)}.{m.group(2)}" in _RECIPIENT_CODES:
                return "rejected"
        if _RECIPIENT_GONE.search(text):
            return "rejected"
        if _POLICY.search(text):                               # a block on US, not on the mailbox
            return "policy"
        if code in (550, 551, 553):
            return "rejected"
    return "other"


@dataclass
class SmtpOutcome:
    verdict: str            # accepted | catch_all | rejected | temp | policy | other | unreachable | busy
    code: int | None = None
    detail: str = ""
    mx: str = ""


def _text(msg) -> str:
    if isinstance(msg, bytes):
        msg = msg.decode("utf-8", "replace")
    return " ".join(str(msg).split())[:160]


# --------------------------------------------------------------------------- DNS
@dataclass
class MxResult:
    kind: str                                   # ok | nxdomain | none | null | error
    hosts: list = field(default_factory=list)   # [(preference, hostname)] best first
    detail: str = ""


def _make_resolver(timeout: float) -> dns.resolver.Resolver:
    try:
        resolver = dns.resolver.Resolver()
    except dns.resolver.NoResolverConfiguration:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
    resolver.timeout = timeout
    resolver.lifetime = timeout
    return resolver


# --------------------------------------------------------------------------- SMTP availability
class SmtpAvailability:
    """Finds out (once, then cached) whether this host may open outbound connections on port 25.

    Many cloud hosts block it. Without this check every address would burn a full timeout
    before falling back, so we test against well-known public MX hosts first.
    """

    def __init__(self, settings: Settings):
        self.s = settings
        self._lock = threading.Lock()
        self._state: dict | None = None
        self._at = 0.0

    def _probe(self) -> dict:
        errors = []
        for host in self.s.probe_hosts:
            try:
                with socket.create_connection((host, self.s.smtp_port), timeout=self.s.probe_timeout) as sock:
                    sock.settimeout(self.s.probe_timeout)
                    greeting = sock.recv(256)
                    try:
                        sock.sendall(b"QUIT\r\n")
                    except OSError:
                        pass
                if greeting.startswith(b"220"):
                    return {"available": True, "state": "open",
                            "reason": f"Outbound port {self.s.smtp_port} is reachable from this host."}
                errors.append(f"{host}: connected but no SMTP greeting")
            except OSError as exc:
                errors.append(f"{host}: {type(exc).__name__}")
        return {
            "available": False, "state": "blocked",
            "reason": (f"Outbound connections to port {self.s.smtp_port} are blocked or unreachable "
                       "from this host (common on free cloud hosting)."),
            "errors": errors,
        }

    def get(self, block: bool = True) -> dict:
        if self.s.smtp_mode == "off":
            return {"available": False, "state": "disabled",
                    "reason": "SMTP probing is switched off (SMTP_MODE=off)."}
        if self.s.smtp_mode == "on":
            return {"available": True, "state": "forced", "reason": "SMTP probing is forced on (SMTP_MODE=on)."}
        fresh = self._state is not None and (time.monotonic() - self._at) < self.s.probe_ttl
        if fresh:
            return self._state
        if not block:
            return self._state or {"available": None, "state": "checking",
                                   "reason": "Checking whether outbound SMTP is possible from this host..."}
        with self._lock:
            if self._state is None or (time.monotonic() - self._at) >= self.s.probe_ttl:
                self._state = self._probe()
                self._at = time.monotonic()
            return self._state

    def refresh_in_background(self) -> None:
        if self.s.smtp_mode == "auto":
            threading.Thread(target=self.get, kwargs={"block": True}, daemon=True).start()


class SmtpGate:
    """Allows one SMTP check at a time, with a pause between checks (be polite, avoid blacklists)."""

    def __init__(self, delay: float):
        self.delay = delay
        self._lock = threading.Lock()
        self._ready_at = 0.0

    def acquire(self, timeout: float) -> bool:
        if not self._lock.acquire(timeout=max(0.0, timeout)):
            return False
        wait = self._ready_at - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        return True

    def release(self) -> None:
        self._ready_at = time.monotonic() + self.delay
        self._lock.release()


# --------------------------------------------------------------------------- the checker
class Checker:
    def __init__(self, settings: Settings | None = None):
        self.s = settings or Settings.from_env()
        self.availability = SmtpAvailability(self.s)
        self.gate = SmtpGate(self.s.smtp_delay)
        self.helo = self.s.helo_hostname or socket.getfqdn() or "localhost"
        self._dns_ok: bool | None = None
        self._dns_ok_at = 0.0

    # ---- layer 4: DNS
    def _resolve(self, name: str, rtype: str):
        return _make_resolver(self.s.dns_timeout).resolve(name, rtype)

    def _dns_works(self) -> bool:
        """Is the resolver trustworthy? A known-good domain must resolve.

        Some networks (captive portals, broken or filtering resolvers) answer NXDOMAIN for
        everything. Without this check every address would be reported as "bounce".
        """
        now = time.monotonic()
        if self._dns_ok is not None and now - self._dns_ok_at < (300 if self._dns_ok else 15):
            return self._dns_ok
        try:
            self._resolve("example.com", "A")
            ok = True
        except dns.resolver.NoAnswer:
            ok = True                                          # it did answer
        except Exception:                                      # noqa: BLE001  (NXDOMAIN, timeout, ...)
            ok = False
        self._dns_ok, self._dns_ok_at = ok, now
        return ok

    def lookup_mx(self, domain: str) -> MxResult:
        try:
            answers = self._resolve(domain, "MX")
        except dns.resolver.NXDOMAIN:
            if not self._dns_works():
                return MxResult("error", detail="DNS resolver is not answering correctly")
            return MxResult("nxdomain", detail="NXDOMAIN")
        except dns.resolver.NoAnswer:
            # No MX record. Report it as "none" (RFC 5321 would fall back to the A record, but a
            # domain that publishes no MX almost never runs a mailbox server).
            return MxResult("none", detail="no MX record")
        except (dns.exception.Timeout, dns.resolver.NoNameservers, dns.resolver.NoResolverConfiguration,
                dns.exception.DNSException, OSError) as exc:
            return MxResult("error", detail=f"{type(exc).__name__}")
        hosts = sorted((r.preference, r.exchange.to_text().rstrip(".").lower()) for r in answers)
        if len(hosts) == 1 and hosts[0][1] == "":                # RFC 7505 "null MX"
            return MxResult("null", detail="null MX")
        hosts = [(p, h) for p, h in hosts if h]
        return MxResult("ok", hosts=hosts) if hosts else MxResult("none", detail="no MX record")

    # ---- layer 6: SMTP
    def _probe_host(self, host: str, address: str) -> SmtpOutcome:
        domain = address.rsplit("@", 1)[1]
        smtp = smtplib.SMTP(local_hostname=self.helo, timeout=self.s.smtp_timeout)
        try:
            code, msg = smtp.connect(host, self.s.smtp_port)
            if code != 220:
                return SmtpOutcome("unreachable", code, f"greeting {code}", host)
            smtp.ehlo_or_helo_if_needed()
            code, msg = smtp.mail(self.s.mail_from)
            if code != 250:
                kind = "temp" if 400 <= code < 500 else "policy"
                return SmtpOutcome(kind, code, _text(msg), host)
            code, msg = smtp.rcpt(address)
            kind = classify_rcpt(code, _text(msg))
            if kind != "accepted":
                return SmtpOutcome(kind, code, _text(msg), host)
            # The address was accepted. Ask for a made-up one at the same domain: if that is
            # accepted too, the server accepts everything (catch-all) and tells us nothing.
            fake = f"vc-{secrets.token_hex(8)}@{domain}"
            code2, msg2 = smtp.rcpt(fake)
            if 200 <= code2 < 300:
                return SmtpOutcome("catch_all", code, "accepts every address", host)
            if 500 <= code2 < 600:
                return SmtpOutcome("accepted", code, "made-up address was rejected", host)
            return SmtpOutcome("accepted", code, "catch-all test inconclusive", host)
        finally:
            try:
                smtp.quit()                                      # polite QUIT; DATA is never sent
            except Exception:                                    # noqa: BLE001
                pass
            try:
                smtp.close()
            except Exception:                                    # noqa: BLE001
                pass

    def smtp_check(self, address: str, mx_hosts: list, deadline: float) -> SmtpOutcome:
        if not self.gate.acquire(deadline - time.monotonic()):
            return SmtpOutcome("busy", detail="server busy or time budget used up")
        try:
            last = SmtpOutcome("unreachable", detail="could not connect")
            for _pref, host in mx_hosts[: max(1, self.s.max_mx_tries)]:
                if time.monotonic() >= deadline:
                    return SmtpOutcome("busy", detail="time budget used up", mx=host)
                try:
                    outcome = self._probe_host(host, address)
                except (smtplib.SMTPException, OSError) as exc:
                    last = SmtpOutcome("unreachable", detail=f"{type(exc).__name__}: {exc}"[:120], mx=host)
                    continue
                if outcome.verdict == "unreachable":
                    last = outcome
                    continue
                return outcome
            return last
        finally:
            self.gate.release()

    # ---- orchestration
    def check_many(self, emails: list[str]) -> list[dict]:
        deadline = time.monotonic() + self.s.request_budget
        ctx = {"mx": {}, "smtp": None, "deadline": deadline}
        return [self.check_one(e, ctx) for e in emails]

    def check_one(self, raw: str, ctx: dict) -> dict:
        checks: dict[str, str] = {}
        flags: list[str] = []

        def done(status: str, reason: str, **extra) -> dict:
            return {"email": raw, "status": status, "reason": reason, "flags": flags,
                    "checks": checks, **extra}

        # 1. syntax ------------------------------------------------------------------
        try:
            parsed = validate_email(raw, check_deliverability=False)
        except EmailNotValidError as exc:
            checks["syntax"] = "fail"
            return done(BOUNCE, f"Invalid syntax: {str(exc).rstrip('.')}")
        checks["syntax"] = "pass"
        local, domain, ascii_domain = parsed.local_part, parsed.domain.lower(), parsed.ascii_domain.lower()
        address = f"{local}@{ascii_domain}"

        role = is_role_account(local)
        if role:
            flags.append("role-based")
        provider = free_provider_name(domain)
        if provider or domain in OTHER_FREE_PROVIDERS:
            flags.append("free provider")

        # 2. typo --------------------------------------------------------------------
        suggestion = suggest_domain(domain)
        if suggestion:
            checks["typo"] = "fail"
            flags.append("typo")
            return done(BOUNCE, f"Possible typo: did you mean {suggestion}?",
                        suggestion=f"{local}@{suggestion}")
        checks["typo"] = "pass"

        # 3. disposable --------------------------------------------------------------
        hit = is_disposable(ascii_domain)
        if hit:
            checks["disposable"] = "fail"
            flags.append("disposable")
            return done(BOUNCE, f"Disposable email domain ({hit}): high risk")
        checks["disposable"] = "pass"

        # 4. DNS MX ------------------------------------------------------------------
        mx = ctx["mx"].get(ascii_domain)
        if mx is None:
            mx = ctx["mx"][ascii_domain] = self.lookup_mx(ascii_domain)
        if mx.kind == "nxdomain":
            checks["mx"] = "fail"
            return done(BOUNCE, "Domain does not exist (DNS NXDOMAIN)")
        if mx.kind == "none":
            checks["mx"] = "fail"
            return done(BOUNCE, "Domain has no mail server (no MX record)")
        if mx.kind == "null":
            checks["mx"] = "fail"
            return done(BOUNCE, "Domain explicitly does not accept email (null MX record)")
        if mx.kind == "error":
            checks["mx"] = "unknown"
            return done(UNKNOWN, "DNS lookup failed or timed out, so the domain could not be checked. Try again.")
        checks["mx"] = "pass"
        top_mx = mx.hosts[0][1]

        # 5. providers that never confirm mailboxes ----------------------------------
        if provider:
            checks["smtp"] = "skipped"
            return done(UNKNOWN, f"{provider} does not confirm mailboxes (anti-enumeration: it accepts "
                                 "any address at the SMTP stage). Syntax and MX are valid, but the "
                                 "mailbox cannot be verified.", mx=top_mx)
        gateway = gateway_name(top_mx)
        if gateway:
            checks["smtp"] = "skipped"
            return done(UNKNOWN, f"Mail for this domain is handled by {gateway} infrastructure, which does "
                                 "not reliably confirm individual mailboxes to outside probes. Syntax and "
                                 "MX are valid, but the mailbox cannot be verified.", mx=top_mx)

        role_note = ("Role-based address: valid but low engagement, and many companies block or "
                     "filter these")

        # 6. SMTP --------------------------------------------------------------------
        if not local.isascii():
            checks["smtp"] = "skipped"
            return done(UNKNOWN, "Internationalised mailbox name: the SMTP probe was skipped. "
                                 "Syntax and MX are valid." + (f" {role_note}." if role else ""), mx=top_mx)
        if ctx["smtp"] is None:
            ctx["smtp"] = self.availability.get(block=True)
        if not ctx["smtp"]["available"]:
            checks["smtp"] = "skipped"
            if role:
                return done(UNKNOWN, f"{role_note}. Deliverability cannot be verified from this host "
                                     "(outbound SMTP is blocked), but syntax and MX are valid.", mx=top_mx)
            return done(UNKNOWN, "Deliverability cannot be verified from this host (outbound SMTP port 25 "
                                 "is blocked), but syntax and MX are valid.", mx=top_mx)

        outcome = self.smtp_check(address, mx.hosts, ctx["deadline"])
        server = f"Server said: {outcome.code} {outcome.detail}" if outcome.code else outcome.detail
        mx_used = outcome.mx or top_mx

        if outcome.verdict == "rejected":
            checks["smtp"] = "fail"
            return done(BOUNCE, f"Mail server rejected this mailbox. {server}", mx=mx_used)
        if outcome.verdict in ("accepted", "catch_all"):
            checks["smtp"] = "pass"
            if outcome.verdict == "catch_all":
                flags.append("catch-all")
            if role:
                return done(UNKNOWN, f"{role_note}. The mail server accepted it"
                                     f"{' (but accepts every address)' if outcome.verdict == 'catch_all' else ''}.",
                            mx=mx_used)
            if outcome.verdict == "catch_all":
                return done(DELIVERED, "The mail server accepts every address at this domain (catch-all): "
                                       "the message would be accepted, but this mailbox cannot be confirmed.",
                            mx=mx_used)
            return done(DELIVERED, "Mail server accepted this recipient and rejected a made-up one, "
                                   "so the mailbox very likely exists.", mx=mx_used)

        checks["smtp"] = "unknown"
        if outcome.verdict == "temp":
            why = f"The mail server gave a temporary answer (greylisting or rate limit). {server}"
        elif outcome.verdict == "policy":
            why = f"The mail server refused the probe for policy reasons, not because of the mailbox. {server}"
        elif outcome.verdict == "busy":
            why = "The check was skipped because the server is busy or this request ran out of time."
        elif outcome.verdict == "other":
            why = f"The mail server gave an answer that does not say whether the mailbox exists. {server}"
        else:
            why = f"Could not connect to the domain's mail server ({outcome.detail or 'no response'})."
        if role:
            why = f"{role_note}. {why}"
        return done(UNKNOWN, why, mx=mx_used)
