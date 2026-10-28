import html
import json
import os
import tempfile
from pathlib import Path

COLORS = {"Pass": "#74dfb1", "Warning": "#ffb589", "Review": "#e7ce7a", "Info": "#9fc7ff", "Not applicable": "#a5aaba"}


def esc(value):
    return html.escape(str(value), quote=True)


def evidence(value):
    return "Not observed" if value is None else json.dumps(value, indent=2, ensure_ascii=False) if isinstance(value, (dict, list)) else str(value)


def detail_html(item):
    color = COLORS[item["status"]]
    return f'''<h2>{esc(item['header'])}</h2>
<p style="color:{color}">{esc(item['status'])} · {esc(item['severity'])}</p>
<h3>{esc(item['title'])}</h3><h4>Observed evidence</h4>
<pre>{esc(evidence(item['observed']))}</pre><h4>What this means</h4>
<p>{esc(item['explanation'])}</p><h4>Suggested action</h4>
<p>{esc(item['recommendation'])}</p>
<p><a href="{esc(item['reference'])}">Technical reference ↗</a></p>'''


def render_html(report):
    summary = "".join(f'<div class="stat"><strong style="color:{COLORS[status]}">{count}</strong><span>{esc(status)}</span></div>' for status, count in report["summary"].items())
    findings = "".join(f'<article>{detail_html(item)}</article>' for item in report["findings"])
    rows = "".join(f'<tr><th>{esc(name)}</th><td><pre>{esc(value)}</pre></td></tr>' for name, value in report["response_headers"])
    hops = "".join(f'<li><span class="code">{hop["status"]}</span> {esc(hop["url"])}</li>' for hop in report["redirect_chain"])
    limitations = "".join(f'<li>{esc(note)}</li>' for note in report["limitations"])
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>WebSentry — Header inspection report</title><style>
:root{{color-scheme:dark}}*{{box-sizing:border-box}}body{{margin:0;background:#0e1118;color:#e8edf5;font:15px/1.65 system-ui,Segoe UI,sans-serif}}
main{{max-width:1120px;margin:0 auto;padding:48px 24px}}header{{border-bottom:1px solid #303747;padding-bottom:24px}}h1{{font-size:30px;margin:0}}h2{{font-size:23px}}h3{{font-size:18px}}h4{{font-size:13px;color:#a6b3ca;text-transform:uppercase;letter-spacing:.07em;margin-bottom:8px}}
.muted{{color:#a6b3ca}}.stats{{display:flex;gap:12px;flex-wrap:wrap;margin:28px 0}}.stat{{flex:1;min-width:135px;background:#19202d;border:1px solid #303747;padding:20px;border-radius:14px}}.stat strong{{display:block;font-size:30px}}.stat span{{color:#adb8c9}}
article{{padding:26px;margin:16px 0;background:#151c28;border:1px solid #303747;border-radius:14px}}article h2{{margin-top:0}}a{{color:#bdadff}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#0e141e;border-radius:8px;padding:14px;font:13px/1.6 Consolas,monospace}}table{{border-collapse:collapse;width:100%;table-layout:fixed}}th,td{{text-align:left;padding:8px;vertical-align:top;border-bottom:1px solid #303747;overflow-wrap:anywhere}}th{{width:28%}}td pre{{margin:0}}.code{{color:#bdadff;font-weight:bold}}li{{margin:8px 0;overflow-wrap:anywhere}}.url{{overflow-wrap:anywhere}}footer{{margin-top:40px;color:#a6b3ca;font-size:13px}}
@media print{{:root{{color-scheme:light}}body{{background:white;color:#111}}main{{padding:12px}}article,.stat{{background:white;border-color:#aaa}}pre{{background:#f2f3f5;color:#111}}.muted,h4,.stat span,footer{{color:#444}}article{{break-inside:avoid}}a{{color:#353077}}}}
</style></head><body><main><header><p class="muted">WEB SECURITY / RESPONSE HEADERS</p><h1>WebSentry</h1>
<p class="url">{esc(report['final_url'])}</p><p class="muted">{esc(report['scanned_at'])} · HTTP {report['http_status']} · {esc(report['content_type'])} · {report['elapsed_ms']} ms</p>
<p class="muted url">Requested: {esc(report['requested_url'])}</p></header>
<div class="stats">{summary}</div><p class="muted">Counts describe the configured checks, not an overall security score.</p>
<h2>Findings</h2>{findings}<h2>Request chain</h2><ol>{hops}</ol>
<h2>Response headers</h2><table>{rows}</table><h2>Scope &amp; limitations</h2><ul>{limitations}</ul>
<footer>WebSentry {esc(report['tool']['version'])} · Rules {esc(report['tool']['ruleset'])}<br>Generated locally. This report contains no remote scripts, fonts or images. Print from your browser to save a PDF.</footer>
</main></body></html>'''


def save_report(report, destination, kind="json"):
    destination = Path(destination)
    text = render_html(report) if kind == "html" else json.dumps(report, indent=2, ensure_ascii=False)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n", dir=destination.parent, prefix=".websentry-", suffix=".tmp", delete=False) as stream:
            temporary = stream.name
            stream.write(text)
        os.replace(temporary, destination)
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)
    return destination
