# WebSentry

An English-language desktop HTTP security header analyzer with evidence-based
findings and self-contained HTML/JSON reports.

![WebSentry desktop interface](docs/screenshot.png)

## Windows app

Extract the **entire** portable Windows ZIP into a new folder and open
`WebSentry/WebSentry.exe`. Keep `_internal` beside the executable. Python is
included; no separate installation is required.

Enter a website URL and select **Analyze**. A scheme-less hostname defaults to
HTTPS. Select a finding for its observed value, explanation, suggested action
and technical reference. Status filters narrow the finding list.

**Export HTML** creates an offline report that can be opened in a browser or
printed to PDF. **Export JSON** produces machine-readable data. Exports only
become available after a completed scan. Reports are saved to your chosen path;
exporting to an existing filename replaces it after the file dialog confirms.

## Run from source

Python 3.10+ is required; tested with Python 3.14.6 on Windows. On Windows:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe main.py
```

To update the earlier tutorial project, close it and copy these source files
into its folder. Keep the existing `.venv`, then run the last two commands.
`test_checks.py` is now a launcher for the complete test suite. The original
tutorial code is preserved in `learning_original` for reference.

## What it checks

| Control | Interpretation |
| --- | --- |
| HTTPS | Verified HTTPS final response and HTTPS-to-HTTP redirect downgrades |
| HSTS | HTTPS/domain applicability, duplicate headers/directives, numeric max-age, disabled policy and lifetime |
| X-Content-Type-Options | A single expected nosniff value |
| Content-Type | A single declared media type; body/type agreement is not tested |
| CSP | Enforced versus report-only, selected script/object source heuristics and duplicate directives |
| Embedding protection | Enforced frame-ancestors with X-Frame-Options fallback; default-src is not treated as frame-ancestors |
| Referrer-Policy | Last recognized fallback token; browser defaults are acknowledged |
| Permissions-Policy | Contextual feature-permission configuration, not a complete syntax validator |
| Server disclosure | Server, X-Powered-By and X-AspNet-Version information |
| Legacy XSS filter | Deprecated X-XSS-Protection is not a required modern control |

The 180-day HSTS lifetime threshold is a review heuristic, not a protocol
validity rule. Multiple enforced CSP policies combine restrictively; concerns
found in one policy can be mitigated by another. CSP analysis is deliberately
described as a heuristic rather than a full browser-policy evaluation.

### Statuses

- **Pass:** The specific check observed its expected condition.
- **Warning:** A missing or risky configuration was observed.
- **Review:** Interpretation needs syntax or application/deployment context.
- **Info:** Optional hardening or explanatory information.
- **Not applicable:** A check does not apply to this response.

Counts are not an overall site-security score or a vulnerability count.

## Scope and data handling

- One ordinary GET request per redirect hop; maximum eight redirects.
- The response body is not downloaded for analysis. No crawling, browser
  execution, authentication or exploit testing occurs.
- Only the final response headers are assessed. Intermediate responses are
  recorded as a URL/status chain rather than separately scored.
- HTTP error/challenge pages are labeled as that response's results; they do
  not establish the application's normal configuration.
- HTTPS certificate verification remains enabled. Certificate failures stop
  analysis instead of producing a misleading missing-header report.
- Cookies are not replayed between redirect hops. Browser sessions, `.netrc`
  credentials and system proxy settings are not imported.
- Cookie/authorization/token-like response headers and URL query values are
  redacted from displayed/exported results. URL paths remain visible.
- No scan history, account or telemetry is included. Only explicit exports
  save reports. Nothing is uploaded to a WebSentry service.
- Cancellation is cooperative. An in-flight connection must return or time
  out before the worker stops. Connect/read timeouts are not hard total-scan
  deadlines, and operating-system DNS resolution can take longer.

Missing response headers alone do not prove an exploitable vulnerability.
HTML meta policies, browser state, parent-domain/preloaded HSTS and other
resources can change real-world behavior and are not measured here. HTML-only
checks are skipped when the declared content type is not HTML.

## Command line

```powershell
.\.venv\Scripts\python.exe main.py --cli https://example.com
.\.venv\Scripts\python.exe main.py --cli https://example.com --format html --output report.html
```

Use the Python entry point for terminal output; the portable EXE is a windowed
application without an attached console.

## Tests

```powershell
.\.venv\Scripts\python.exe test_checks.py
```

The suite uses synthetic policies and a local HTTP server. It covers disabled
and malformed HSTS, report-only CSP, multiple policies, frame-ancestors/XFO
interaction, non-HTML applicability, MIME protections, referrer fallback,
redirect loops, cancellation, redaction and HTML escaping/atomic exports.

Live smoke checks were also performed against example.com, python.org and MDN.
They are validation targets, not bundled scan results or default accounts.

## Project structure

```text
main.py              Desktop/CLI entry point
engine.py            URL validation, fetching and security checks
gui.py               Desktop interface and background job lifecycle
reports.py           Escaped HTML rendering and atomic JSON/HTML export
tests/               Automated checks with a local fixture server
assets/              Original SVG/PNG/ICO application icon
learning_original/   Earlier tutorial code, retained for study
build_windows.ps1    Portable Windows build
```

Run `build_windows.ps1` to create `dist/WebSentry`. Distribute the entire output
folder. The source runtime dependencies are pinned/constrained in
`requirements.txt`; see `THIRD_PARTY.md` for upstream projects and licenses.

## References

- [OWASP Secure Headers](https://secure-headers-project.owasp.org/response-headers/)
- [MDN HTTP headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers)
- [MDN HSTS](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security)
- [MDN CSP frame-ancestors](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/frame-ancestors)
