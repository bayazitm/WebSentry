import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from engine import ScanCancelled, ScanError, assess, build_report, check_hsts, normalize_url, scan
from reports import render_html, save_report


def checks(pairs, url="https://example.test/", status=200):
    findings, _ = assess(url, status, pairs, [{"url": url, "status": status}])
    return {item["id"]: item for item in findings}


class RulesTests(unittest.TestCase):
    def test_hsts_disabled_is_not_pass(self):
        self.assertEqual(check_hsts(["max-age=0"], "https://example.test/")["status"], "Warning")

    def test_hsts_numeric_parsing_and_duplicates(self):
        for value in ("max-age=wat", "max-age=-1", "max-age=1; max-age=99999999", "max-age=1; includeSubDomains=maybe", "max-age=1.5"):
            with self.subTest(value=value):
                self.assertEqual(check_hsts([value], "https://example.test/")["status"], "Review")
        self.assertEqual(check_hsts(['max-age="31536000"; includeSubDomains'], "https://example.test/")["status"], "Pass")

    def test_hsts_is_not_evaluated_over_http_or_ip(self):
        for url in ("http://example.test/", "https://127.0.0.1/", "https://[::1]/"):
            self.assertEqual(check_hsts(["max-age=31536000"], url)["status"], "Not applicable")

    def test_report_only_does_not_establish_enforced_csp(self):
        result = checks([("Content-Type", "text/html"), ("Content-Security-Policy-Report-Only", "default-src 'none'")])
        self.assertEqual(result["csp"]["status"], "Warning")
        self.assertEqual(result["framing"]["status"], "Warning")

    def test_frame_ancestors_counts_without_xfo(self):
        result = checks([("Content-Type", "text/html"), ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")])
        self.assertEqual(result["framing"]["status"], "Pass")

    def test_default_src_is_not_frame_ancestors_fallback(self):
        result = checks([("Content-Type", "text/html"), ("Content-Security-Policy", "default-src 'none'")])
        self.assertEqual(result["framing"]["status"], "Warning")

    def test_multiple_csp_policies_are_not_flattened_into_one(self):
        result = checks([("Content-Type", "text/html"), ("Content-Security-Policy", "default-src *"), ("Content-Security-Policy", "default-src 'none'; frame-ancestors 'self'")])
        self.assertEqual(result["framing"]["status"], "Pass")
        self.assertIn("Multiple policies", result["csp"]["explanation"])

    def test_nonce_avoids_false_unsafe_inline_flag(self):
        result = checks([("Content-Type", "text/html"), ("Content-Security-Policy", "script-src 'nonce-abcdef' 'unsafe-inline'; object-src 'none'")])
        self.assertNotIn("unsafe-inline appears", result["csp"]["explanation"])

    def test_non_html_document_controls_are_skipped(self):
        result = checks([("Content-Type", "application/json")])
        self.assertEqual(result["csp"]["status"], "Not applicable")
        self.assertEqual(result["framing"]["status"], "Not applicable")

    def test_referrer_last_recognized_token_and_default(self):
        self.assertEqual(checks([])["referrer"]["status"], "Info")
        result = checks([("Referrer-Policy", "unsafe-url, strict-origin-when-cross-origin, unknown-future-token")])
        self.assertEqual(result["referrer"]["status"], "Pass")

    def test_nosniff_ambiguous_duplicates(self):
        self.assertEqual(checks([("X-Content-Type-Options", " NOSNIFF ")])["nosniff"]["status"], "Pass")
        self.assertEqual(checks([("X-Content-Type-Options", "nosniff"), ("X-Content-Type-Options", "invalid")])["nosniff"]["status"], "Warning")

    def test_legacy_xss_header_is_not_required(self):
        self.assertEqual(checks([])["legacy"]["status"], "Info")
        self.assertEqual(checks([("X-XSS-Protection", "1; mode=block")])["legacy"]["status"], "Review")

    def test_url_validation_rejects_credentials_and_non_http(self):
        for value in ("", "file:///etc/passwd", "https://user:password@example.test", "https://bad host/", "https://example.test:99999/", "https:///", "https://example.test/\r\nInjected: value"):
            with self.subTest(value=value), self.assertRaises(ScanError):
                normalize_url(value)
        self.assertEqual(normalize_url("example.test"), "https://example.test/")
        self.assertEqual(normalize_url("http://localhost:1234/test"), "http://localhost:1234/test")

    def test_export_redacts_secrets_and_escapes_html(self):
        url = "https://example.test/path?token=very-private-token"
        report = build_report(url, url, 403,
                              [("Content-Type", "text/html"), ("Set-Cookie", "session=very-private-cookie"), ("X-Api-Key", "very-private-key"), ("X-Test", '<script>alert("x")</script>')],
                              [{"url": url, "status": 403}], 12)
        serialized = json.dumps(report)
        for secret in ("very-private-token", "very-private-cookie", "very-private-key"):
            self.assertNotIn(secret, serialized)
        rendered = render_html(report)
        self.assertNotIn('<script>alert("x")</script>', rendered)
        self.assertIn("&lt;script&gt;", rendered)
        self.assertIn("HTTP 403", report["limitations"][0])
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "report.json"
            save_report(report, target)
            self.assertEqual(json.loads(target.read_text(encoding="utf-8")), report)
            self.assertEqual(list(Path(folder).glob("*.tmp")), [])

    def test_downgrade_is_detected_even_when_final_is_https(self):
        hops = [{"url": url, "status": 302} for url in ("https://example.test/", "http://example.test/", "https://example.test/final")]
        report = build_report(hops[0]["url"], hops[-1]["url"], 200, [], hops, 1)
        self.assertEqual(report["findings"][0]["status"], "Warning")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/page")
        elif self.path == "/loop":
            self.send_response(302)
            self.send_header("Location", "/loop")
        else:
            self.send_response(404 if self.path == "/missing" else 200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'")
            self.send_header("Content-Security-Policy", "frame-ancestors 'none'")
            self.send_header("Set-Cookie", "sensitive=must-not-export")
        self.end_headers()


class FetchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = "http://127.0.0.1:" + str(cls.server.server_port)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def test_fetch_records_redirects_and_preserves_duplicate_headers(self):
        report = scan(self.base + "/redirect")
        self.assertEqual([hop["status"] for hop in report["redirect_chain"]], [302, 200])
        self.assertEqual(len([h for h in report["response_headers"] if h[0] == "Content-Security-Policy"]), 2)
        self.assertNotIn("must-not-export", json.dumps(report))
        self.assertEqual(next(f for f in report["findings"] if f["id"] == "framing")["status"], "Pass")

    def test_redirect_loop_is_error_not_fake_report(self):
        with self.assertRaisesRegex(ScanError, "loop"):
            scan(self.base + "/loop")

    def test_http_404_still_has_response_with_scope_note(self):
        report = scan(self.base + "/missing")
        self.assertEqual(report["http_status"], 404)
        self.assertIn("HTTP 404", report["limitations"][0])

    def test_cancelled_scan_never_starts(self):
        event = threading.Event()
        event.set()
        with self.assertRaises(ScanCancelled):
            scan(self.base, event)


if __name__ == "__main__":
    unittest.main()
