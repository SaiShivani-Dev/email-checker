"""Tests. Run with:  python -m unittest discover -s tests -v

No internet is needed: DNS is stubbed and SMTP is exercised against a tiny fake server on localhost.
"""
import socketserver
import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import checker as C                                   # noqa: E402
from checker import BOUNCE, DELIVERED, UNKNOWN, Checker, MxResult, Settings   # noqa: E402


# ----------------------------------------------------------------------------- helpers
def make_checker(mx=None, smtp_mode="off", **kw):
    """Checker whose DNS answers come from the `mx` dict: domain -> MxResult."""
    s = Settings(smtp_mode=smtp_mode, smtp_delay=0, smtp_timeout=3, **kw)
    c = Checker(s)
    table = dict(mx or {})
    c.lookup_mx = lambda domain: table.get(domain, MxResult("nxdomain", detail="NXDOMAIN"))
    return c


def ok_mx(host="mx.example.test"):
    return MxResult("ok", hosts=[(10, host)])


def one(checker, email):
    return checker.check_many([email])[0]


class FakeSmtpServer:
    """A minimal SMTP server. `rules` maps a lowercase local part to a (code, text) reply for RCPT TO."""

    def __init__(self, rules=None, default=(250, "2.1.5 OK"), greeting="220 fake ESMTP", mail_reply="250 OK"):
        self.rules, self.default, self.greeting, self.mail_reply = rules or {}, default, greeting, mail_reply
        self.commands = []
        outer = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                self.wfile.write((outer.greeting + "\r\n").encode())
                while True:
                    line = self.rfile.readline()
                    if not line:
                        return
                    cmd = line.decode().strip()
                    outer.commands.append(cmd)
                    up = cmd.upper()
                    if up.startswith(("EHLO", "HELO")):
                        self.wfile.write(b"250 fake\r\n")
                    elif up.startswith("MAIL"):
                        self.wfile.write((outer.mail_reply + "\r\n").encode())
                    elif up.startswith("RCPT"):
                        local = cmd.split("<", 1)[1].split("@", 1)[0].lower()
                        key = "vc-random" if local.startswith("vc-") else local
                        code, text = outer.rules.get(key, outer.default)
                        self.wfile.write(f"{code} {text}\r\n".encode())
                    elif up.startswith("QUIT"):
                        self.wfile.write(b"221 bye\r\n")
                        return
                    else:
                        self.wfile.write(b"502 not implemented\r\n")

        class Server(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        self.server = Server(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def smtp_checker(fake, **kw):
    c = make_checker({"corp-mail.org": MxResult("ok", hosts=[(10, "127.0.0.1")])}, smtp_mode="on",
                     smtp_port=fake.port, **kw)
    return c


# ----------------------------------------------------------------------------- unit tests
class ParseInput(unittest.TestCase):
    def test_splits_on_newlines_commas_spaces_and_dedupes(self):
        out, dupes = C.parse_input("a@x.com, b@x.com;\nA@X.COM  c@x.com\n\n")
        self.assertEqual(out, ["a@x.com", "b@x.com", "c@x.com"])
        self.assertEqual(dupes, 1)

    def test_strips_brackets_and_mailto(self):
        self.assertEqual(C.parse_input("<a@x.com> mailto:b@x.com")[0], ["a@x.com", "b@x.com"])

    def test_rejects_non_strings(self):
        with self.assertRaises(ValueError):
            C.parse_input(123)
        with self.assertRaises(ValueError):
            C.parse_input(["a@x.com", 5])


class Helpers(unittest.TestCase):
    def test_distance(self):
        self.assertEqual(C.osa_distance("gmai.com", "gmail.com"), 1)
        self.assertEqual(C.osa_distance("gmial.com", "gmail.com"), 1)     # transposition
        self.assertEqual(C.osa_distance("abc", "abc"), 0)
        self.assertGreater(C.osa_distance("example.com", "gmail.com"), 2)

    def test_typo_suggestions(self):
        self.assertEqual(C.suggest_domain("gmai.com"), "gmail.com")
        self.assertEqual(C.suggest_domain("gmail.con"), "gmail.com")
        self.assertEqual(C.suggest_domain("hotmial.com"), "hotmail.com")
        self.assertEqual(C.suggest_domain("yaho.com"), "yahoo.com")

    def test_real_domains_are_not_typos(self):
        for d in ("gmail.com", "mail.com", "email.com", "q.com", "yahoo.co.in", "mycollege.edu", "example.org"):
            self.assertIsNone(C.suggest_domain(d), d)

    def test_disposable(self):
        self.assertEqual(C.is_disposable("tempmail.com"), "tempmail.com")
        self.assertEqual(C.is_disposable("10minutemail.com"), "10minutemail.com")
        self.assertEqual(C.is_disposable("mailinator.com"), "mailinator.com")
        self.assertEqual(C.is_disposable("x.mailinator.com"), "mailinator.com")       # sub-domain
        self.assertIsNone(C.is_disposable("gmail.com"))
        self.assertGreater(len(C.DISPOSABLE_DOMAINS), 5000)

    def test_roles(self):
        for lp in ("admin", "Support", "info", "sales", "no-reply", "noreply", "info+tag", "no_reply"):
            self.assertTrue(C.is_role_account(lp), lp)
        for lp in ("john", "sales.john", "priya.sharma"):
            self.assertFalse(C.is_role_account(lp), lp)

    def test_free_providers(self):
        for d in ("gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.in", "outlook.com", "hotmail.com",
                  "live.com", "hotmail.co.uk", "aol.com"):
            self.assertIsNotNone(C.free_provider_name(d), d)
        for d in ("yahoo.evil.com", "gmail.com.evil.io", "mycollege.edu"):
            self.assertIsNone(C.free_provider_name(d), d)

    def test_classify_rcpt(self):
        self.assertEqual(C.classify_rcpt(250, "OK"), "accepted")
        self.assertEqual(C.classify_rcpt(550, "5.1.1 User unknown"), "rejected")
        self.assertEqual(C.classify_rcpt(550, "No such user here"), "rejected")
        self.assertEqual(C.classify_rcpt(553, "Mailbox name not allowed"), "rejected")
        self.assertEqual(C.classify_rcpt(551, "User not local"), "rejected")
        self.assertEqual(C.classify_rcpt(550, "5.7.1 Service unavailable; client host blocked"), "policy")
        self.assertEqual(C.classify_rcpt(550, "blocked using zen.spamhaus.org"), "policy")
        self.assertEqual(C.classify_rcpt(550, "Sender address rejected: Access denied"), "policy")
        self.assertEqual(C.classify_rcpt(450, "greylisted"), "temp")
        self.assertEqual(C.classify_rcpt(421, "try later"), "temp")
        self.assertEqual(C.classify_rcpt(552, "mailbox full"), "other")


class Layers(unittest.TestCase):
    def test_invalid_syntax_bounces(self):
        r = one(make_checker(), "invalid@@gmail.com")
        self.assertEqual(r["status"], BOUNCE)
        self.assertIn("Invalid syntax", r["reason"])
        self.assertEqual(r["checks"], {"syntax": "fail"})

    def test_garbage_bounces(self):
        for bad in ("plainaddress", "@no-local.com", "a@b", "a b@c.com", "a@-bad-.com", "x" * 300 + "@gmail.com"):
            self.assertEqual(one(make_checker(), bad)["status"], BOUNCE, bad)

    def test_typo_bounces_with_suggestion(self):
        r = one(make_checker(), "test@gmai.com")
        self.assertEqual(r["status"], BOUNCE)
        self.assertEqual(r["reason"], "Possible typo: did you mean gmail.com?")
        self.assertEqual(r["suggestion"], "test@gmail.com")

    def test_disposable_bounces(self):
        for dom in ("tempmail.com", "10minutemail.com"):
            r = one(make_checker(), f"x@{dom}")
            self.assertEqual(r["status"], BOUNCE)
            self.assertIn("Disposable", r["reason"])
            self.assertIn("disposable", r["flags"])

    def test_no_mx_bounces(self):
        c = make_checker({"nomx-mail.org": MxResult("none")})
        self.assertIn("no MX", one(c, "a@nomx-mail.org")["reason"])
        self.assertEqual(one(c, "a@nomx-mail.org")["status"], BOUNCE)

    def test_nxdomain_bounces(self):
        r = one(make_checker(), "a@does-not-exist-mail.org")
        self.assertEqual(r["status"], BOUNCE)
        self.assertIn("does not exist", r["reason"])

    def test_null_mx_bounces(self):
        r = one(make_checker({"null-mail.org": MxResult("null")}), "a@null-mail.org")
        self.assertEqual(r["status"], BOUNCE)
        self.assertIn("null MX", r["reason"])

    def test_dns_error_is_unknown_not_bounce(self):
        r = one(make_checker({"flaky-mail.org": MxResult("error", detail="Timeout")}), "a@flaky-mail.org")
        self.assertEqual(r["status"], UNKNOWN)

    def test_free_provider_is_unknown_and_smtp_never_attempted(self):
        c = make_checker({d: ok_mx("gmail-smtp-in.l.google.com") for d in ("gmail.com", "yahoo.com", "outlook.com", "hotmail.com")},
                         smtp_mode="on")
        c.smtp_check = lambda *a, **k: self.fail("SMTP must be skipped for free providers")
        for email in ("test@gmail.com", "no_such_user_12345@yahoo.com", "a@outlook.com", "b@hotmail.com"):
            r = one(c, email)
            self.assertEqual(r["status"], UNKNOWN, email)
            self.assertEqual(r["checks"]["smtp"], "skipped")
            self.assertIn("free provider", r["flags"])
            self.assertIn("anti-enumeration", r["reason"])

    def test_gateway_mx_is_unknown(self):
        c = make_checker({"mycollege.edu": ok_mx("aspmx.l.google.com")}, smtp_mode="on")
        c.smtp_check = lambda *a, **k: self.fail("SMTP must be skipped behind gateways")
        r = one(c, "student@mycollege.edu")
        self.assertEqual(r["status"], UNKNOWN)
        self.assertIn("Google", r["reason"])

    def test_role_based_is_unknown(self):
        c = make_checker({"mycollege.edu": ok_mx("mail.mycollege.edu")}, smtp_mode="off")
        c.availability.get = lambda block=True: {"available": False}
        r = one(c, "admin@mycollege.edu")
        self.assertEqual(r["status"], UNKNOWN)
        self.assertIn("Role-based", r["reason"])
        self.assertIn("role-based", r["flags"])

    def test_smtp_blocked_fallback_message(self):
        c = make_checker({"corp-mail.org": ok_mx("mx.corp-mail.org")}, smtp_mode="off")
        r = one(c, "jane@corp-mail.org")
        self.assertEqual(r["status"], UNKNOWN)
        self.assertIn("Deliverability cannot be verified from this host", r["reason"])
        self.assertIn("syntax and MX are valid", r["reason"])
        self.assertEqual(r["checks"]["mx"], "pass")

    def test_mx_cached_per_request(self):
        calls = []
        c = make_checker(smtp_mode="off")
        c.lookup_mx = lambda d: calls.append(d) or ok_mx()
        c.check_many(["a@corp-mail.org", "b@corp-mail.org", "c@corp-mail.org"])
        self.assertEqual(calls, ["corp-mail.org"])

    def test_internationalised_local_part_skips_smtp(self):
        c = make_checker({"corp-mail.org": ok_mx("127.0.0.1")}, smtp_mode="on")
        c.smtp_check = lambda *a, **k: self.fail("must not probe non-ASCII mailboxes")
        r = one(c, "josé@corp-mail.org")
        self.assertEqual(r["status"], UNKNOWN)


class RealDnsLogic(unittest.TestCase):
    """lookup_mx itself, with the resolver stubbed."""

    def checker_with(self, answers):
        import dns.resolver
        c = Checker(Settings(smtp_mode="off"))

        class Rec:                                              # stands in for an MX answer
            def __init__(self, pref, host):
                self.preference = pref
                self.exchange = type("N", (), {"to_text": lambda s: host})()

        def fake(name, rtype):
            res = answers.get((name, rtype))
            if isinstance(res, Exception):
                raise res
            if res is None:
                raise dns.resolver.NXDOMAIN()
            return [Rec(p, h) for p, h in res]

        c._resolve = fake
        return c

    def test_nxdomain_is_trusted_when_resolver_is_healthy(self):
        import dns.resolver
        c = self.checker_with({("example.com", "A"): [(0, "93.184.216.34.")]})
        self.assertEqual(c.lookup_mx("nope-nope.org").kind, "nxdomain")

    def test_nxdomain_is_not_trusted_when_resolver_is_broken(self):
        c = self.checker_with({})                               # NXDOMAIN for everything, even example.com
        r = c.lookup_mx("gmail.com")
        self.assertEqual(r.kind, "error")
        self.assertEqual(one_with(c, "a@gmail.com")["status"], UNKNOWN)

    def test_mx_records_sorted_and_null_mx(self):
        c = self.checker_with({("a-mail.org", "MX"): [(20, "mx2.a-mail.org."), (10, "mx1.a-mail.org.")],
                               ("b-mail.org", "MX"): [(0, ".")]})
        self.assertEqual(c.lookup_mx("a-mail.org").hosts, [(10, "mx1.a-mail.org"), (20, "mx2.a-mail.org")])
        self.assertEqual(c.lookup_mx("b-mail.org").kind, "null")

    def test_no_answer_and_timeout(self):
        import dns.exception
        import dns.resolver
        c = self.checker_with({("a-mail.org", "MX"): dns.resolver.NoAnswer(),
                               ("b-mail.org", "MX"): dns.exception.Timeout()})
        self.assertEqual(c.lookup_mx("a-mail.org").kind, "none")
        self.assertEqual(c.lookup_mx("b-mail.org").kind, "error")


def one_with(checker, email):
    return checker.check_many([email])[0]


class SmtpAgainstFakeServer(unittest.TestCase):
    def run_case(self, server, email="jane@corp-mail.org", **kw):
        try:
            c = smtp_checker(server, **kw)
            return one(c, email)
        finally:
            server.close()

    def test_accepted_and_random_rejected_is_delivered(self):
        fake = FakeSmtpServer(rules={"vc-random": (550, "5.1.1 No such user")})
        r = self.run_case(fake)
        self.assertEqual(r["status"], DELIVERED)
        self.assertIn("very likely exists", r["reason"])
        self.assertNotIn("catch-all", r["flags"])
        cmds = [c.split()[0].upper() for c in fake.commands]
        self.assertNotIn("DATA", cmds)                          # never sends a message
        self.assertEqual(cmds[-1], "QUIT")                      # and disconnects politely

    def test_catch_all_is_delivered_with_flag(self):
        fake = FakeSmtpServer()                                  # accepts everything
        r = self.run_case(fake)
        self.assertEqual(r["status"], DELIVERED)
        self.assertIn("catch-all", r["flags"])
        self.assertIn("cannot be confirmed", r["reason"])

    def test_550_no_such_user_bounces(self):
        fake = FakeSmtpServer(rules={"ghost": (550, "5.1.1 <ghost@corp-mail.org>: User unknown")})
        r = self.run_case(fake, "ghost@corp-mail.org")
        self.assertEqual(r["status"], BOUNCE)
        self.assertIn("550", r["reason"])
        self.assertNotIn("DATA", [c.split()[0].upper() for c in fake.commands])

    def test_553_bounces(self):
        fake = FakeSmtpServer(rules={"jane": (553, "Mailbox name not allowed")})
        self.assertEqual(self.run_case(fake)["status"], BOUNCE)

    def test_450_greylist_is_unknown(self):
        fake = FakeSmtpServer(rules={"jane": (450, "4.2.0 Greylisted, try later")})
        r = self.run_case(fake)
        self.assertEqual(r["status"], UNKNOWN)
        self.assertIn("temporary", r["reason"])

    def test_421_greeting_is_unknown(self):
        fake = FakeSmtpServer(greeting="421 Too busy")
        self.assertEqual(self.run_case(fake)["status"], UNKNOWN)

    def test_policy_block_is_unknown_not_bounce(self):
        fake = FakeSmtpServer(rules={"jane": (550, "5.7.1 Client host blocked by spamhaus")})
        r = self.run_case(fake)
        self.assertEqual(r["status"], UNKNOWN)
        self.assertIn("policy", r["reason"])

    def test_sender_refused_is_unknown(self):
        fake = FakeSmtpServer(mail_reply="550 5.7.1 Sender not allowed")
        self.assertEqual(self.run_case(fake)["status"], UNKNOWN)

    def test_role_based_accepted_stays_unknown(self):
        fake = FakeSmtpServer(rules={"vc-random": (550, "no such user")})
        r = self.run_case(fake, "admin@corp-mail.org")
        self.assertEqual(r["status"], UNKNOWN)
        self.assertIn("Role-based", r["reason"])

    def test_role_based_explicit_rejection_still_bounces(self):
        fake = FakeSmtpServer(rules={"admin": (550, "5.1.1 User unknown")})
        self.assertEqual(self.run_case(fake, "admin@corp-mail.org")["status"], BOUNCE)

    def test_connection_refused_is_unknown(self):
        fake = FakeSmtpServer()
        port_closed = fake.port
        fake.close()
        c = make_checker({"corp-mail.org": MxResult("ok", hosts=[(10, "127.0.0.1")])}, smtp_mode="on", smtp_port=port_closed)
        r = one(c, "jane@corp-mail.org")
        self.assertEqual(r["status"], UNKNOWN)
        self.assertIn("Could not connect", r["reason"])

    def test_falls_back_to_second_mx(self):
        dead = FakeSmtpServer()
        dead_port = dead.port
        dead.close()
        good = FakeSmtpServer(rules={"vc-random": (550, "no such user")})
        try:
            c = make_checker({"corp-mail.org": MxResult("ok", hosts=[(10, "127.0.0.1"), (20, "localhost")])},
                             smtp_mode="on", smtp_port=good.port)
            # first host gets the live port too, so simulate failure by making the first attempt raise
            real = c._probe_host
            seen = []

            def flaky(host, address):
                seen.append(host)
                if len(seen) == 1:
                    raise OSError("boom")
                return real(host, address)

            c._probe_host = flaky
            self.assertEqual(one(c, "jane@corp-mail.org")["status"], DELIVERED)
            self.assertEqual(len(seen), 2)
        finally:
            good.close()

    def test_delay_between_smtp_checks(self):
        import time
        fake = FakeSmtpServer(rules={"vc-random": (550, "no such user")})
        try:
            c = smtp_checker(fake)
            c.gate.delay = 0.4
            t0 = time.monotonic()
            c.check_many(["a@corp-mail.org", "b@corp-mail.org", "c@corp-mail.org"])
            self.assertGreaterEqual(time.monotonic() - t0, 0.8)     # two gaps of >= 0.4 s
        finally:
            fake.close()

    def test_request_budget_stops_smtp(self):
        fake = FakeSmtpServer()
        try:
            c = smtp_checker(fake, request_budget=0)
            r = one(c, "jane@corp-mail.org")
            self.assertEqual(r["status"], UNKNOWN)
        finally:
            fake.close()


class Availability(unittest.TestCase):
    def test_modes(self):
        self.assertFalse(C.SmtpAvailability(Settings(smtp_mode="off")).get()["available"])
        self.assertTrue(C.SmtpAvailability(Settings(smtp_mode="on")).get()["available"])

    def test_blocked_port_is_detected_quickly(self):
        # Nothing listens on this port, so the probe fails like a firewall-blocked port 25 would.
        s = Settings(smtp_mode="auto", smtp_port=1, probe_hosts=("127.0.0.1",), probe_timeout=1)
        state = C.SmtpAvailability(s).get()
        self.assertFalse(state["available"])
        self.assertEqual(state["state"], "blocked")

    def test_open_port_is_detected(self):
        fake = FakeSmtpServer()
        try:
            s = Settings(smtp_mode="auto", smtp_port=fake.port, probe_hosts=("127.0.0.1",), probe_timeout=2)
            self.assertTrue(C.SmtpAvailability(s).get()["available"])
        finally:
            fake.close()

    def test_non_blocking_get_reports_checking(self):
        a = C.SmtpAvailability(Settings(smtp_mode="auto"))
        self.assertEqual(a.get(block=False)["state"], "checking")


class Api(unittest.TestCase):
    def setUp(self):
        import app as app_module
        s = Settings(smtp_mode="off", smtp_delay=0)
        self.app = app_module.create_app(s, rate_limit=1000)
        chk = self.app.extensions["checker"]
        chk.lookup_mx = lambda d: {"corp-mail.org": ok_mx("mx.corp-mail.org"), "gmail.com": ok_mx("gmail-smtp-in.l.google.com")}.get(
            d, MxResult("nxdomain"))
        self.client = self.app.test_client()

    def post(self, payload):
        return self.client.post("/api/check", json=payload)

    def test_index_and_health(self):
        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"Email Deliverability Checker", r.data)
        self.assertIn("nonce-", r.headers["Content-Security-Policy"])
        self.assertEqual(self.client.get("/healthz").get_json(), {"ok": True})

    def test_happy_path(self):
        r = self.post({"emails": "test@gmail.com\ninvalid@@gmail.com\njane@corp-mail.org\njane@corp-mail.org"})
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertEqual([x["status"] for x in body["results"]], [UNKNOWN, BOUNCE, UNKNOWN])
        self.assertEqual(body["meta"]["duplicates_removed"], 1)
        self.assertEqual(body["meta"]["count"], 3)

    def test_list_payload(self):
        self.assertEqual(self.post({"emails": ["jane@corp-mail.org"]}).status_code, 200)

    def test_limit_of_ten(self):
        ten = "\n".join(f"u{i}@corp-mail.org" for i in range(10))
        eleven = ten + "\nu10@corp-mail.org"
        self.assertEqual(self.post({"emails": ten}).status_code, 200)
        r = self.post({"emails": eleven})
        self.assertEqual(r.status_code, 400)
        self.assertIn("limit is 10", r.get_json()["error"])

    def test_bad_requests(self):
        self.assertEqual(self.post({"emails": ""}).status_code, 400)
        self.assertEqual(self.post({"emails": "   \n  "}).status_code, 400)
        self.assertEqual(self.post({"nope": 1}).status_code, 400)
        self.assertEqual(self.post({"emails": 5}).status_code, 400)
        self.assertEqual(self.client.post("/api/check", data="not json", content_type="text/plain").status_code, 400)
        self.assertEqual(self.client.get("/api/check").status_code, 405)
        self.assertEqual(self.client.get("/nothing").status_code, 404)

    def test_payload_too_large(self):
        self.assertEqual(self.client.post("/api/check", json={"emails": "a" * 40000}).status_code, 413)

    def test_html_in_input_is_returned_as_plain_data(self):
        r = self.post({"emails": '<script>alert(1)</script>@gmail.com'})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["results"][0]["status"], BOUNCE)

    def test_status_endpoint(self):
        body = self.client.get("/api/status").get_json()
        self.assertEqual(body["max_emails"], 10)
        self.assertFalse(body["smtp"]["available"])

    def test_rate_limit(self):
        import app as app_module
        app = app_module.create_app(Settings(smtp_mode="off"), rate_limit=2)
        app.extensions["checker"].lookup_mx = lambda d: ok_mx()
        client = app.test_client()
        codes = [client.post("/api/check", json={"emails": "a@corp-mail.org"}).status_code for _ in range(3)]
        self.assertEqual(codes, [200, 200, 429])
        self.assertIn("Retry-After", client.post("/api/check", json={"emails": "a@corp-mail.org"}).headers)


if __name__ == "__main__":
    unittest.main(verbosity=2)
