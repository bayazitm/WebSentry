from __future__ import annotations

import ipaddress
import re
import time
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

VERSION = "1.0.0"
RULESET = "2026-10-28.1"
MDN = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/"
LIMITATIONS = [
    "Only the final HTTP response headers are assessed; the redirect chain is recorded separately.",
    "No HTML parsing, JavaScript execution, authentication, crawling or exploit testing is performed.",
    "A missing header is a hardening observation, not proof of an exploitable vulnerability.",
    "CSP and Permissions-Policy checks are heuristics, not complete browser policy validators.",
    "Previously cached HSTS policies, preload lists, parent-domain policies and browser defaults may affect actual protection.",
    "Cookies, sensitive response headers and URL query values are redacted. URL paths remain visible.",
]


class ScanError(Exception):
    pass


class ScanCancelled(ScanError):
    pass


def normalize_url(value):
    value = str(value).strip()
    if not value:
        raise ScanError("Enter a website URL.")
    if any(ord(c) < 33 or ord(c) == 127 for c in value):
        raise ScanError("The URL contains whitespace or control characters.")
    if "://" not in value:
        value = "https://" + value
    try:
        parts = urlsplit(value)
        if parts.scheme.lower() not in {"http", "https"}:
            raise ValueError
        if parts.username is not None or parts.password is not None:
            raise ScanError("URLs containing a username or password are not accepted.")
        host = parts.hostname
        if not host:
            raise ValueError
        port = parts.port
        if port is not None and not 1 <= port <= 65535:
            raise ValueError
        try:
            ipaddress.ip_address(host)
        except ValueError:
            ascii_host = host.encode("idna").decode("ascii").rstrip(".")
            if len(ascii_host) > 253 or not all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label) for label in ascii_host.split(".")):
                raise ValueError
        return urlunsplit((parts.scheme.lower(), parts.netloc, parts.path or "/", parts.query, ""))
    except (ValueError, UnicodeError):
        raise ScanError("Enter a valid HTTP or HTTPS URL, such as https://example.com.") from None


def redact_url(url):
    parts = urlsplit(url)
    query = urlencode([(key, "[redacted]") for key, _ in parse_qsl(parts.query, keep_blank_values=True)])
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))


def safe_headers(pairs):
    result = []
    for name, value in pairs:
        lower = name.lower()
        if any(word in lower for word in ("cookie", "authorization", "token", "secret", "api-key")):
            value = "[redacted]"
        elif lower == "location":
            try:
                value = redact_url(value)
            except ValueError:
                value = "[unreadable location]"
        result.append([name, value])
    return result


def header_map(pairs):
    headers = {}
    for name, value in pairs:
        headers.setdefault(name.lower(), []).append(value)
    return headers


def finding(identifier, header, status, severity, title, observed, explanation, recommendation, source=None):
    return {"id": identifier, "header": header, "status": status, "severity": severity,
            "title": title, "observed": observed, "explanation": explanation,
            "recommendation": recommendation, "reference": source or MDN + header}


def check_hsts(values, url):
    base = dict(identifier="hsts", header="Strict-Transport-Security", observed=values or None)
    if urlsplit(url).scheme != "https":
        return finding(**base, status="Not applicable", severity="Informational", title="HSTS cannot be established over HTTP", explanation="Browsers ignore HSTS headers received over HTTP. Transport is assessed separately.", recommendation="Serve the site over HTTPS, then evaluate its HSTS header.")
    try:
        ipaddress.ip_address(urlsplit(url).hostname)
        return finding(**base, status="Not applicable", severity="Informational", title="HSTS does not apply to IP-address hosts", explanation="Browsers identify HSTS hosts by domain name; an IP literal cannot be an HSTS host.", recommendation="Evaluate the site's domain name instead.")
    except ValueError:
        pass
    if not values:
        return finding(**base, status="Warning", severity="Medium", title="No HSTS header observed", explanation="This response does not establish a new HSTS policy. A browser may still have a cached, parent-domain or preloaded policy.", recommendation="After testing HTTPS readiness, configure a suitable max-age. Do not enable includeSubDomains or preload without checking their operational impact.")
    if len(values) != 1:
        return finding(**base, status="Review", severity="Medium", title="Multiple HSTS headers", explanation="Multiple fields can be interpreted differently or only the first may be processed.", recommendation="Send one unambiguous HSTS field.")
    directives = {}
    malformed = False
    for part in values[0].split(";"):
        if not part.strip():
            continue
        name, sep, value = part.strip().partition("=")
        name = name.strip().lower()
        if not re.fullmatch(r"[A-Za-z0-9!#$%&'*+.^_`|~-]+", name) or name in directives:
            malformed = True
        directives[name] = (sep, value.strip())
    age = directives.get("max-age")
    if not age or not age[0] or not re.fullmatch(r'(?:[0-9]+|"[0-9]+")', age[1]) or len(age[1]) > 20:
        malformed = True
    if any(directives.get(name, ("", ""))[0] for name in ("includesubdomains", "preload")):
        malformed = True
    if malformed:
        return finding(**base, status="Review", severity="Medium", title="HSTS syntax needs review", explanation="A valid, single numeric max-age could not be established, or directives are malformed/duplicated.", recommendation="Use one non-negative integer max-age in seconds. Correct duplicate or malformed directives before deployment.")
    seconds = int(age[1].strip('"'))
    if seconds == 0:
        return finding(**base, status="Warning", severity="Medium", title="HSTS is explicitly disabled", explanation="max-age=0 asks browsers to remove this host's stored HSTS policy. Parent/preload coverage is not measured.", recommendation="If disabling HSTS is unintended, deploy an appropriate positive max-age after verifying HTTPS availability.")
    if seconds < 15552000:
        return finding(**base, status="Review", severity="Low", title="Short HSTS lifetime", explanation=f"max-age is {seconds:,} seconds. This tool uses 180 days as a review threshold, not a protocol validity requirement.", recommendation="A short lifetime can be intentional during rollout. Consider increasing it after validating the deployment.")
    return finding(**base, status="Pass", severity="Informational", title="Positive long-lived HSTS policy observed", explanation=f"A numeric max-age of {seconds:,} seconds was found over verified HTTPS. Subdomain readiness and preload membership were not checked.", recommendation="Maintain HTTPS for the full policy lifetime; review optional subdomain/preload coverage separately.")


def parse_policies(values):
    policies, issues = [], []
    for field in values:
        for serialized in field.split(","):
            directives = {}
            if not serialized.strip():
                issues.append("Empty policy")
            for raw in serialized.split(";"):
                tokens = raw.split()
                if not tokens:
                    continue
                name = tokens[0].lower()
                if not re.fullmatch(r"[a-z][a-z0-9-]*", name):
                    issues.append("Malformed directive name")
                if name in directives:
                    issues.append("Repeated directive: " + name)
                else:
                    directives[name] = tokens[1:]
            policies.append(directives)
    return policies, issues


def assess(final_url, http_status, pairs, chain):
    headers = header_map(pairs)
    get = lambda name: headers.get(name.lower(), [])
    content_type = (get("Content-Type") or [""])[0].split(";", 1)[0].strip().lower()
    html = content_type in {"text/html", "application/xhtml+xml"}
    findings = []
    add = findings.append
    https = urlsplit(final_url).scheme == "https"
    downgrade = any(urlsplit(a["url"]).scheme == "https" and urlsplit(b["url"]).scheme == "http" for a, b in zip(chain, chain[1:]))
    add(finding("transport", "HTTPS", "Warning" if not https or downgrade else "Pass", "Medium" if not https or downgrade else "Informational", "HTTPS downgrade or unencrypted final response" if not https or downgrade else "Final response received over verified HTTPS", redact_url(final_url), "HTTPS certificate verification stayed enabled. This is not a comprehensive TLS/cipher/certificate audit." + (" A redirect downgraded HTTPS to HTTP." if downgrade else ""), "Keep the entire redirect chain on HTTPS." if not https or downgrade else "Continue to maintain valid HTTPS certificates.", "https://developer.mozilla.org/en-US/docs/Web/Security/Transport_Layer_Security"))
    add(check_hsts(get("Strict-Transport-Security"), final_url))
    nosniff = get("X-Content-Type-Options")
    ok = len(nosniff) == 1 and nosniff[0].strip().lower() == "nosniff"
    add(finding("nosniff", "X-Content-Type-Options", "Pass" if ok else "Warning", "Informational" if ok else "Low", "nosniff observed" if ok else "Missing or ambiguous nosniff directive", nosniff or None, "nosniff limits MIME-type guessing. It does not verify that every resource's Content-Type is correct.", "Send one X-Content-Type-Options: nosniff header and correct Content-Type values."))
    types = get("Content-Type")
    type_ok = len(types) == 1 and bool(re.fullmatch(r"[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+", content_type))
    add(finding("content-type", "Content-Type", "Pass" if type_ok else "Review", "Informational" if type_ok else "Low", "Content type declared" if type_ok else "Content type missing or ambiguous", types or None, "The declared media type determines which browser-oriented checks are relevant. The response body is not inspected to validate the declaration.", "Declare one accurate Content-Type for each resource."))
    csp_values = get("Content-Security-Policy")
    policies, csp_issues = parse_policies(csp_values)
    if not html:
        status, severity, title = "Not applicable", "Informational", "Document CSP check skipped for this content type"
        explanation = "This check targets HTML documents. Other resources and documents on the site were not assessed."
    elif not csp_values:
        status, severity, title = "Warning", "Medium", "No enforced CSP header observed"
        explanation = "A report-only policy does not enforce restrictions." if get("Content-Security-Policy-Report-Only") else "This HTML response has no enforced CSP header. A meta policy, if any, is outside this header-only scan."
    else:
        signals = list(csp_issues)
        for policy in policies:
            scripts = policy.get("script-src", policy.get("default-src"))
            elements = policy.get("script-src-elem", scripts)
            for sources in (scripts, elements):
                if sources is None:
                    signals.append("No script-src/default-src fallback for one policy")
                    continue
                nonce_hash = any(token.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for token in sources)
                if "'unsafe-eval'" in sources:
                    signals.append("unsafe-eval is allowed in a script source list")
                if "'unsafe-inline'" in sources and not nonce_hash:
                    signals.append("unsafe-inline appears without a nonce/hash source")
                if any(token in {"*", "http:", "https:", "data:"} for token in sources) and not ("'strict-dynamic'" in sources and nonce_hash):
                    signals.append("Broad script sources require review")
            if "object-src" not in policy and "default-src" not in policy:
                signals.append("No object-src/default-src restriction in one policy")
        signals = list(dict.fromkeys(signals))
        status, severity = ("Review", "Medium") if signals else ("Pass", "Informational")
        title = "CSP requires deployment review" if signals else "Enforced CSP observed; basic checks passed"
        explanation = ("; ".join(signals) + ". " if signals else "No listed heuristic concern was found. ") + "Multiple policies combine restrictively; individual-policy observations may be mitigated by another policy. This is not a complete CSP validator or an XSS test."
    add(finding("csp", "Content-Security-Policy", status, severity, title, csp_values or get("Content-Security-Policy-Report-Only") or None, explanation, "Develop and test a policy matching actual scripts, styles, embedded content and resource origins. Use reporting during rollout; do not blindly paste a restrictive policy."))
    xfo = get("X-Frame-Options")
    frame_values = [p["frame-ancestors"] for p in policies if "frame-ancestors" in p]
    restrictive = any(sources and (sources == ["'none'"] or all(token not in {"*", "http:", "https:", "'none'"} and (token == "'self'" or re.fullmatch(r"(?:https?://)?(?:\*\.)?[A-Za-z0-9.-]+(?::[0-9*]+)?(?:/[^\s]*)?", token)) for token in sources)) for sources in frame_values)
    if not html:
        frame_status, title, explanation = "Not applicable", "Embedding check skipped for non-HTML", "This browser-document check does not apply to the declared content type."
    elif restrictive and not csp_issues:
        frame_status, title, explanation = "Pass", "CSP frame-ancestors restricts embedding", "Modern browsers honor enforced frame-ancestors instead of X-Frame-Options. default-src is not a fallback for frame-ancestors."
    elif frame_values:
        frame_status, title, explanation = "Review", "Embedding policy requires review", "An enforced frame-ancestors directive is present but its restriction could not be established by this heuristic. It may override X-Frame-Options."
    elif len(xfo) == 1 and xfo[0].strip().upper() in {"DENY", "SAMEORIGIN"}:
        frame_status, title, explanation = "Pass", "X-Frame-Options restricts embedding", "DENY or SAMEORIGIN was observed. Whether embedding should be permitted is application-specific."
    else:
        frame_status, title, explanation = "Warning", "No recognized embedding restriction", "Neither an enforced restrictive frame-ancestors directive nor one valid X-Frame-Options value was established. This does not demonstrate clickjacking."
    add(finding("framing", "Embedding protection", frame_status, "Medium" if frame_status in {"Warning", "Review"} else "Informational", title, {"frame-ancestors": frame_values or None, "X-Frame-Options": xfo or None}, explanation, "Choose a frame-ancestors allowlist based on legitimate embedding needs; consider X-Frame-Options for legacy clients.", MDN + "Content-Security-Policy/frame-ancestors"))
    ref = get("Referrer-Policy")
    known = {"no-referrer", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin", "same-origin", "strict-origin", "strict-origin-when-cross-origin", "unsafe-url"}
    tokens = [token.strip().lower() for value in ref for token in value.split(",")]
    effective = next((token for token in reversed(tokens) if token in known), None)
    if not ref:
        rstatus, severity, title, explanation = "Info", "Informational", "No explicit Referrer-Policy", "Modern browsers generally default to strict-origin-when-cross-origin. Absence alone does not mean full referrer URLs are exposed."
    elif effective in {"no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"}:
        rstatus, severity, title, explanation = "Pass", "Informational", "Restrictive referrer policy observed", "The last recognized policy token is " + effective + "."
    elif effective:
        rstatus, severity, title, explanation = "Warning" if effective == "unsafe-url" else "Review", "Low", "Referrer disclosure needs review", "The effective recognized token is " + effective + ". Whether this disclosure is appropriate depends on the application."
    else:
        rstatus, severity, title, explanation = "Review", "Low", "No recognized referrer policy token", "The explicit header could not be interpreted as a known policy by this check."
    add(finding("referrer", "Referrer-Policy", rstatus, severity, title, ref or None, explanation, "Choose an explicit policy matching privacy and navigation requirements; strict-origin-when-cross-origin is a common starting point."))
    permissions = get("Permissions-Policy")
    add(finding("permissions", "Permissions-Policy", "Review" if permissions else "Info", "Informational", "Feature permissions require application context" if permissions else "No explicit feature-permissions policy", permissions or None, "Permissions-Policy controls selected browser features. Header presence does not establish valid syntax, and browser defaults still apply when it is absent.", "Restrict unneeded features such as camera or microphone, while retaining features the application legitimately uses."))
    disclosed = {name: get(name) for name in ("Server", "X-Powered-By", "X-AspNet-Version") if get(name)}
    add(finding("disclosure", "Server information", "Info", "Informational", "Server identifiers exposed" if disclosed else "No common server identifiers observed", disclosed or None, "Technology/version banners can help fingerprint a deployment. Removing them does not fix underlying vulnerabilities.", "Remove unnecessary version details where practical and keep the actual software patched.", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server"))
    xss = get("X-XSS-Protection")
    add(finding("legacy", "X-XSS-Protection", "Review" if xss and any(v.strip() != "0" for v in xss) else "Info", "Low" if xss and any(v.strip() != "0" for v in xss) else "Informational", "Legacy XSS filter is enabled or ambiguous" if xss and any(v.strip() != "0" for v in xss) else "Legacy XSS filter is not enabled", xss or None, "This deprecated header is not required as a modern security control. Some legacy filtering modes can introduce problems.", "Use a tested CSP; do not enable X-XSS-Protection merely to satisfy a header checklist."))
    return findings, content_type


def build_report(requested_url, final_url, http_status, pairs, chain, elapsed_ms):
    findings, content_type = assess(final_url, http_status, pairs, chain)
    counts = Counter(item["status"] for item in findings)
    notes = list(LIMITATIONS)
    if http_status >= 400 or http_status == 304:
        notes.insert(0, f"HTTP {http_status}: these may be an error, challenge or cached-response headers rather than the application's normal page.")
    if not content_type:
        notes.insert(0, "No reliable Content-Type was declared; document-specific checks could not be applied.")
    return {"schema_version": 1, "tool": {"name": "WebSentry", "version": VERSION, "ruleset": RULESET},
            "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "requested_url": redact_url(requested_url), "final_url": redact_url(final_url),
            "http_status": http_status, "content_type": content_type or "Unknown", "elapsed_ms": elapsed_ms,
            "redirect_chain": [{**hop, "url": redact_url(hop["url"])} for hop in chain],
            "response_headers": safe_headers(pairs), "summary": {s: counts[s] for s in ("Pass", "Warning", "Review", "Info", "Not applicable")},
            "findings": findings, "limitations": notes}


def scan(value, cancelled=None, progress=None, timeout=10, max_redirects=8):
    import requests
    requested = normalize_url(value)
    current, seen, chain = requested, set(), []
    started = time.monotonic()
    def check_cancel():
        if cancelled and cancelled.is_set():
            raise ScanCancelled("Scan cancelled.")
    try:
        with requests.Session() as session:
            session.trust_env = False  
            session.headers["User-Agent"] = "WebSentry/" + VERSION + " (HTTP header inspection)"
            for hop in range(max_redirects + 1):
                check_cancel()
                if time.monotonic() - started > 60:
                    raise ScanError("The scan exceeded its redirect time budget.")
                if current in seen:
                    raise ScanError("A redirect loop was detected.")
                seen.add(current)
                if progress:
                    progress("Connecting" if hop == 0 else f"Following redirect {hop}")
                session.cookies.clear()
                with session.get(current, timeout=(timeout, timeout), allow_redirects=False, stream=True, verify=True) as response:
                    pairs = list(response.raw.headers.items())
                    if sum(len(k) + len(v) for k, v in pairs) > 128 * 1024:
                        raise ScanError("The response headers are too large to inspect.")
                    chain.append({"url": response.url, "status": response.status_code})
                    check_cancel()
                    if response.status_code in {301, 302, 303, 307, 308}:
                        locations = response.raw.headers.getlist("Location")
                        if len(locations) != 1 or not locations[0].strip():
                            raise ScanError("A redirect did not provide exactly one usable Location header.")
                        if hop == max_redirects:
                            raise ScanError("Too many redirects (limit: 8).")
                        current = normalize_url(urljoin(response.url, locations[0]))
                        continue
                    if progress:
                        progress("Evaluating response headers")
                    report = build_report(requested, response.url, response.status_code, pairs, chain, round((time.monotonic() - started) * 1000))
                    check_cancel()
                    return report
    except requests.exceptions.SSLError:
        raise ScanError("HTTPS certificate verification failed. The scan stopped; certificate checks were not bypassed.") from None
    except requests.exceptions.Timeout:
        check_cancel()
        raise ScanError("The connection or response timed out. Check the URL and try again.") from None
    except requests.exceptions.RequestException:
        check_cancel()
        raise ScanError("Could not retrieve the URL. Check DNS, connectivity and the address. System proxy/authentication settings are not imported.") from None
    raise ScanError("No final response was received.")
