"""
WebOSINT Pro - HTML Report Generator
FIX: _render_dict crashed on non-string keys (int/float from nested dicts)
     Safe-cast all keys to str before any string operations.
"""

import json
import html as _html
from datetime import datetime

he = _html.escape   # shorthand


RISK_BADGE = {
    'critical': '<span class="badge badge-critical">CRITICAL</span>',
    'high':     '<span class="badge badge-high">HIGH</span>',
    'medium':   '<span class="badge badge-medium">MEDIUM</span>',
    'low':      '<span class="badge badge-low">LOW</span>',
    'info':     '<span class="badge badge-info">INFO</span>',
}

RISK_ROW_COLOR = {
    'critical': 'rgba(239,68,68,0.12)',
    'high':     'rgba(249,115,22,0.10)',
    'medium':   'rgba(234,179,8,0.08)',
    'low':      'rgba(34,197,94,0.08)',
    'info':     'transparent',
}


class HTMLReport:
    def __init__(self, results: dict):
        self.results  = results
        self.meta     = results.get('meta', {})
        self.summary  = results.get('summary', {})
        self.findings = results.get('findings', {})
        self.errors   = results.get('errors', {})

    def save(self, path: str) -> str:
        with open(path, 'w', encoding='utf-8') as f:
            f.write(self._build_html())
        return path

    # ──────────────────────────────────────────────────────────────────
    # Top-level builder
    # ──────────────────────────────────────────────────────────────────
    def _build_html(self) -> str:
        target    = self.meta.get('target', 'Unknown')
        generated = datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
        profile   = self.meta.get('profile', 'medium')
        elapsed   = self.meta.get('elapsed_seconds', 0)
        mods_run  = len(self.meta.get('modules_run', []))
        total     = self.summary.get('total_findings', 0)
        risks     = self.summary.get('risk_counts', {})

        summary_cards  = self._build_summary_cards(risks, total, elapsed, mods_run)
        findings_html  = self._build_findings()
        recs_html      = self._build_recommendations()

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WebOSINT Pro – {he(target)}</title>
<style>
:root {{
  --bg:#0f1117; --surface:#1a1d27; --surface2:#222533;
  --border:#2d3148; --text:#e2e8f0; --text-dim:#94a3b8;
  --accent:#6366f1; --critical:#ef4444; --high:#f97316;
  --medium:#eab308; --low:#22c55e; --info:#64748b; --cyan:#06b6d4;
}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;font-size:14px;line-height:1.6}}
.wrap{{max-width:1400px;margin:0 auto;padding:24px}}

/* ── Header ── */
.hdr{{background:linear-gradient(135deg,#1a1d27,#12152a);border:1px solid var(--border);border-radius:12px;padding:32px;margin-bottom:24px}}
.hdr h1{{font-size:26px;font-weight:700;background:linear-gradient(135deg,#6366f1,#06b6d4);-webkit-background-clip:text;-webkit-text-fill-color:transparent}}
.hdr .sub{{color:var(--text-dim);margin-top:4px;font-size:13px}}
.hdr .tgt{{font-size:20px;font-weight:600;color:var(--cyan);margin-top:12px;word-break:break-all}}
.meta-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;margin-top:20px}}
.meta-item{{background:var(--surface2);padding:12px 16px;border-radius:8px}}
.meta-item .lbl{{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--text-dim)}}
.meta-item .val{{font-size:16px;font-weight:600;margin-top:2px}}

/* ── Risk summary cards ── */
.risk-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:14px;margin-bottom:24px}}
.risk-card{{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:16px;text-align:center}}
.risk-card .cnt{{font-size:36px;font-weight:800}}
.risk-card .lbl{{font-size:11px;text-transform:uppercase;letter-spacing:.1em;color:var(--text-dim);margin-top:4px}}
.risk-card.critical .cnt{{color:var(--critical)}} .risk-card.high .cnt{{color:var(--high)}}
.risk-card.medium  .cnt{{color:var(--medium)}}   .risk-card.low  .cnt{{color:var(--low)}}
.risk-card.info    .cnt{{color:var(--info)}}

/* ── Sections ── */
.sec{{background:var(--surface);border:1px solid var(--border);border-radius:10px;margin-bottom:14px;overflow:hidden}}
.sec-hdr{{background:var(--surface2);padding:13px 20px;display:flex;align-items:center;justify-content:space-between;cursor:pointer;border-bottom:1px solid var(--border);user-select:none}}
.sec-hdr h3{{font-size:14px;font-weight:600;text-transform:uppercase;letter-spacing:.05em}}
.sec-hdr .toggle{{font-size:16px;color:var(--text-dim)}}
.sec-body{{padding:20px}}

/* ── Key-value rows ── */
.kv-grid{{display:grid;gap:6px}}
.kv-row{{display:flex;gap:12px;padding:8px 12px;background:var(--surface2);border-radius:6px;align-items:flex-start}}
.kv-key{{color:var(--text-dim);min-width:190px;font-weight:500;flex-shrink:0;font-size:13px}}
.kv-val{{color:var(--text);word-break:break-all;font-size:13px}}

/* ── Badges ── */
.badge{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.05em}}
.badge-critical{{background:rgba(239,68,68,.2);color:var(--critical);border:1px solid var(--critical)}}
.badge-high    {{background:rgba(249,115,22,.2);color:var(--high);border:1px solid var(--high)}}
.badge-medium  {{background:rgba(234,179,8,.2);color:var(--medium);border:1px solid var(--medium)}}
.badge-low     {{background:rgba(34,197,94,.2);color:var(--low);border:1px solid var(--low)}}
.badge-info    {{background:rgba(100,116,139,.2);color:var(--info);border:1px solid var(--info)}}

/* ── Lists ── */
.fl{{list-style:none}}
.fl li{{padding:5px 10px;border-left:3px solid var(--accent);background:var(--surface2);margin-bottom:3px;border-radius:0 5px 5px 0;font-family:monospace;font-size:12px;word-break:break-all}}

/* ── Alert rows ── */
.alert-row{{padding:10px 14px;border-radius:7px;margin-bottom:8px;border-left:4px solid}}
.alert-critical{{background:rgba(239,68,68,.1);border-color:var(--critical)}}
.alert-high    {{background:rgba(249,115,22,.1);border-color:var(--high)}}
.alert-medium  {{background:rgba(234,179,8,.1);border-color:var(--medium)}}

/* ── Table ── */
table{{width:100%;border-collapse:collapse}}
th{{background:var(--surface2);padding:9px 12px;text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--text-dim);border-bottom:1px solid var(--border)}}
td{{padding:9px 12px;border-bottom:1px solid var(--border);font-family:monospace;font-size:12px;word-break:break-all}}
tr:hover td{{background:var(--surface2)}}

/* ── Code ── */
code{{background:var(--surface2);padding:2px 6px;border-radius:4px;font-family:monospace;font-size:12px;color:var(--cyan)}}
pre{{background:var(--surface2);padding:14px;border-radius:8px;overflow-x:auto;font-size:12px;line-height:1.5}}

/* ── Recs ── */
.rec{{display:flex;gap:14px;padding:11px;background:var(--surface2);border-radius:8px;margin-bottom:7px}}
.rec-body .issue{{font-weight:600}}
.rec-body .fix{{color:var(--text-dim);margin-top:3px;font-size:13px}}
.rec-body .ref{{font-family:monospace;font-size:11px;color:var(--accent);margin-top:3px}}

/* ── Section heading ── */
h2.sec-title{{font-size:17px;margin-bottom:14px;margin-top:28px;color:var(--text-dim)}}

/* ── Footer ── */
.footer{{text-align:center;padding:24px;color:var(--text-dim);font-size:12px;border-top:1px solid var(--border);margin-top:32px}}
.wm{{color:var(--accent);font-weight:600}}

@media(max-width:768px){{
  .meta-grid{{grid-template-columns:repeat(2,1fr)}}
  .kv-row{{flex-direction:column}} .kv-key{{min-width:auto}}
}}
</style>
</head>
<body>
<div class="wrap">

<div class="hdr">
  <h1>🔍 WebOSINT Pro</h1>
  <div class="sub">Web OSINT &amp; Reconnaissance Report</div>
  <div class="tgt">⊳ {he(target)}</div>
  <div class="meta-grid">
    <div class="meta-item"><div class="lbl">Profile</div><div class="val">{he(profile.upper())}</div></div>
    <div class="meta-item"><div class="lbl">Generated</div><div class="val" style="font-size:12px">{generated}</div></div>
    <div class="meta-item"><div class="lbl">Duration</div><div class="val">{elapsed:.1f}s</div></div>
    <div class="meta-item"><div class="lbl">Modules Run</div><div class="val">{mods_run}</div></div>
    <div class="meta-item"><div class="lbl">Total Findings</div><div class="val">{total}</div></div>
  </div>
</div>

<h2 class="sec-title">⚡ Risk Summary</h2>
{summary_cards}

{recs_html}

<h2 class="sec-title">📋 Detailed Findings</h2>
{findings_html}

<div class="footer">
  <span class="wm">WebOSINT Pro v1.0.0</span> &nbsp;|&nbsp; {generated} &nbsp;|&nbsp; Authorized testing only
</div>
</div>

<script>
document.querySelectorAll('.sec-hdr').forEach(h => {{
  h.addEventListener('click', () => {{
    const b = h.nextElementSibling;
    const t = h.querySelector('.toggle');
    const hidden = b.style.display === 'none';
    b.style.display = hidden ? 'block' : 'none';
    t.textContent   = hidden ? '▲' : '▼';
  }});
}});
</script>
</body>
</html>"""

    # ──────────────────────────────────────────────────────────────────
    # Summary cards
    # ──────────────────────────────────────────────────────────────────
    def _build_summary_cards(self, risks, total, elapsed, mods):
        levels = [('critical','🔴'),('high','🟠'),('medium','🟡'),('low','🟢'),('info','⚪')]
        cards  = ''.join(
            f'<div class="risk-card {lvl}">'
            f'<div class="cnt">{risks.get(lvl,0)}</div>'
            f'<div class="lbl">{em} {lvl.upper()}</div>'
            f'</div>'
            for lvl, em in levels
        )
        return f'<div class="risk-grid">{cards}</div>'

    # ──────────────────────────────────────────────────────────────────
    # Findings
    # ──────────────────────────────────────────────────────────────────
    def _build_findings(self) -> str:
        out = ''
        for mod_name, data in self.findings.items():
            if data is None:
                continue
            content = self._render_finding_data(data)
            # Risk badge in header if any _risk keys
            risk_badge = ''
            if isinstance(data, dict):
                for k, v in data.items():
                    k = str(k)
                    if k.startswith('_risk'):
                        risk_badge = RISK_BADGE.get(str(v).lower(), '')
                        break
            out += f"""
<div class="sec">
  <div class="sec-hdr">
    <h3>🔷 {he(mod_name.replace('_',' ').upper())} {risk_badge}</h3>
    <span class="toggle">▲</span>
  </div>
  <div class="sec-body">{content}</div>
</div>"""

        # Errors section
        if self.errors:
            rows = ''.join(
                f'<div class="kv-row"><div class="kv-key">{he(m)}</div>'
                f'<div class="kv-val" style="color:var(--critical)">{he(str(e))}</div></div>'
                for m, e in self.errors.items()
            )
            out += f"""
<div class="sec">
  <div class="sec-hdr" style="border-left:3px solid var(--critical)">
    <h3>⚠ Module Errors ({len(self.errors)})</h3>
    <span class="toggle">▲</span>
  </div>
  <div class="sec-body"><div class="kv-grid">{rows}</div></div>
</div>"""

        return out

    def _render_finding_data(self, data) -> str:
        if isinstance(data, dict):
            return self._render_dict(data)
        if isinstance(data, list):
            return self._render_list(data)
        return f'<code>{he(str(data))}</code>'

    def _render_dict(self, data: dict, depth: int = 0) -> str:
        """
        BUG FIX: always cast key to str before any string method calls.
        dict keys can be int/float when modules return port numbers, indices, etc.
        """
        out        = '<div class="kv-grid">'
        risk_rows  = ''

        for raw_key, v in data.items():
            k = str(raw_key)           # ← FIX: safe cast, never crashes on int keys

            # Internal risk tags → collect for bottom
            if k.startswith('_risk'):
                lvl        = str(v).lower()
                badge      = RISK_BADGE.get(lvl, '')
                label      = k[6:].replace('_', ' ').title()
                bg         = RISK_ROW_COLOR.get(lvl, 'transparent')
                risk_rows += (
                    f'<div class="kv-row" style="background:{bg}">'
                    f'<div class="kv-key">⚠ {he(label)}</div>'
                    f'<div class="kv-val">{badge}</div></div>'
                )
                continue

            if k.startswith('_'):      # other private keys — skip display
                continue

            key_label = he(k.replace('_', ' ').title())
            val_html  = self._render_value(v, depth)
            if val_html is None:       # skip None / empty
                continue

            out += (
                f'<div class="kv-row">'
                f'<div class="kv-key">{key_label}</div>'
                f'<div class="kv-val">{val_html}</div>'
                f'</div>'
            )

        out += risk_rows + '</div>'
        return out

    def _render_value(self, v, depth: int) -> str | None:
        """Return rendered HTML for a value, or None to skip."""
        if v is None or v == '' or v == [] or v == {}:
            return None

        if isinstance(v, bool):
            color = 'var(--low)' if v else 'var(--critical)'
            icon  = '✓' if v else '✗'
            return f'<span style="color:{color}">{icon} {v}</span>'

        if isinstance(v, (int, float)):
            return f'<code>{he(str(v))}</code>'

        if isinstance(v, list):
            if not v:
                return None
            # Flatten list of dicts into a nested table; list of scalars as bullets
            if all(isinstance(i, dict) for i in v[:3]):
                return self._render_list_of_dicts(v[:50])
            items = ''.join(
                f'<li>{he(str(i))}</li>' for i in v[:50]
            )
            suffix = (f'<span style="color:var(--text-dim)"> … +{len(v)-50} more</span>'
                      if len(v) > 50 else '')
            return f'<ul class="fl">{items}</ul>{suffix}'

        if isinstance(v, dict):
            if not v:
                return None
            if depth >= 3:             # cap nesting depth
                return f'<code>{he(str(v)[:300])}</code>'
            return self._render_dict(v, depth + 1)

        # Scalar string
        s = str(v)
        if not s.strip():
            return None
        return f'<code>{he(s[:600])}</code>'

    def _render_list_of_dicts(self, items: list) -> str:
        """Render a list of dicts as a readable HTML table."""
        if not items:
            return ''
        # Collect all keys across rows
        keys = []
        for row in items:
            for k in row:
                sk = str(k)
                if sk not in keys:
                    keys.append(sk)
        keys = keys[:12]  # cap columns

        head = ''.join(f'<th>{he(k.replace("_"," ").title())}</th>' for k in keys)
        body = ''
        for row in items:
            cells = ''.join(
                f'<td>{he(str(row.get(k, row.get(int(k) if k.isdigit() else k, ""))))}</td>'
                for k in keys
            )
            body += f'<tr>{cells}</tr>'
        return f'<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>'

    def _render_list(self, data: list) -> str:
        if not data:
            return '<span style="color:var(--text-dim)">empty</span>'
        if all(isinstance(i, dict) for i in data[:3]):
            return self._render_list_of_dicts(data[:100])
        items = ''.join(f'<li>{he(str(i))}</li>' for i in data[:100])
        return f'<ul class="fl">{items}</ul>'

    # ──────────────────────────────────────────────────────────────────
    # Recommendations
    # ──────────────────────────────────────────────────────────────────
    def _build_recommendations(self) -> str:
        cve_data = self.findings.get('cve', {})
        recs     = list(cve_data.get('recommendations', [])) if isinstance(cve_data, dict) else []

        # Infer from _risk flags across all modules
        for mod_name, data in self.findings.items():
            if not isinstance(data, dict):
                continue
            for k, v in data.items():
                k = str(k)
                if k.startswith('_risk') and str(v) in ('critical', 'high', 'medium'):
                    label = k[6:].replace('_', ' ').title()
                    recs.append({
                        'priority':    str(v).upper(),
                        'issue':       label,
                        'fix':         f'Review and remediate: {label} in module [{mod_name}]',
                        'reference':   mod_name,
                    })

        if not recs:
            return ''

        order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        recs.sort(key=lambda x: order.get(str(x.get('priority', 'LOW')).upper(), 5))

        rows = ''
        for rec in recs[:30]:
            pri   = str(rec.get('priority', 'INFO')).upper()
            badge = RISK_BADGE.get(pri.lower(), f'<span class="badge">{he(pri)}</span>')
            issue = he(str(rec.get('issue', '')))
            fix   = he(str(rec.get('fix', rec.get('recommendation', ''))))
            ref   = he(str(rec.get('reference', rec.get('ref', ''))))
            rows += (
                f'<div class="rec">'
                f'<div class="rec-pri">{badge}</div>'
                f'<div class="rec-body">'
                f'<div class="issue">{issue}</div>'
                f'<div class="fix">{fix}</div>'
                f'<div class="ref">{ref}</div>'
                f'</div></div>'
            )

        return f"""
<h2 class="sec-title">🛠 Recommendations ({len(recs)})</h2>
<div class="sec">
  <div class="sec-hdr"><h3>📌 Remediation Priorities</h3><span class="toggle">▲</span></div>
  <div class="sec-body">{rows}</div>
</div>"""
