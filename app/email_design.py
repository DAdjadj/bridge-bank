"""Layout for Bridge Bank's alert emails, in HTML and plain text.

Ported from the licence server's customer emails (license-api, src/email.js)
so a sync alert looks like every other Bridge Bank email: the navy blueprint
header with the bridge drawing, then the facts in the title block of an
engineering drawing. Each alert is described once as content (title, intro,
facts, accounts, steps, button) and rendered twice from it, HTML and plain
text, so the two never drift apart.

Email-safe on purpose: tables, inline styles, PNG images only (Gmail shows
no SVG), and one <style> block that adds dark mode in the mail apps that
support it (Apple Mail, iOS Mail, Outlook for Mac). Images load from the
licence server, the same files the licence emails use.
"""
import html as _html
import re

ASSET_BASE = "https://api.bridgebank.app/static/email/"
ASSET_VERSION = "1"

SANS = "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif"
MONO = "'SF Mono',SFMono-Regular,Menlo,Consolas,'Liberation Mono',monospace"

NAME = "Bridge Bank"
SITE = "bridgebank.app"
TERMS = "https://bridgebank.app/terms"
PRIVACY = "https://bridgebank.app/privacy"

ACCENT = "#2563eb"
ON_ACCENT = "#ffffff"
LINK = "#2563eb"
INK = "#0b1530"
TEXT = "#3e4c68"
MUTED = "#64718b"
LINE = "#dde4ef"
PAGE = "#f6f8fc"
CARD = "#ffffff"
BAD = "#c02626"
NAVY = "#0a1a3a"
HEAD_TEXT = "#a9bde3"
HEAD_LINK = "#8fb6ff"
DARK = {"page": "#060d1f", "card": "#0b1730", "soft": "#0f1e3d", "line": "#1d2e52", "ink": "#eaf1ff",
        "text": "#b4c4e4", "muted": "#7d8fb3", "link": "#8fb6ff", "bad": "#f87171"}


def asset(name: str) -> str:
    return f"{ASSET_BASE}{name}?v={ASSET_VERSION}"


# ── Text helpers ─────────────────────────────────────────────────

def esc(s) -> str:
    return _html.escape("" if s is None else str(s), quote=True).replace("&#x27;", "'")


# Content strings may carry [links](https://...). HTML gets an <a>, text gets "words (address)".
_LINK = re.compile(r"\[([^\]]+)\]\(([^)\s]+)\)")


def md(s, link=LINK, cls="lk") -> str:
    return _LINK.sub(lambda m: f'<a class="{cls}" href="{m.group(2)}" style="color:{link};text-decoration:underline">{m.group(1)}</a>', esc(s))


def plain(s) -> str:
    def repl(m):
        txt, href = m.group(1), m.group(2)
        if href == f"mailto:{txt}":
            return txt
        if txt == re.sub(r"^https?://", "", href):
            return href
        return f"{txt} ({href})"
    return _LINK.sub(repl, "" if s is None else str(s))


# ── Document ─────────────────────────────────────────────────────

def _dark_css() -> str:
    d = DARK
    return f"""<style>
:root{{color-scheme:light dark;supported-color-schemes:light dark}}
@media (prefers-color-scheme:dark){{
.pg{{background:{d['page']}!important}}
.cd{{background:{d['card']}!important;border-color:{d['line']}!important}}
.sf{{background:{d['soft']}!important;border-color:{d['line']}!important}}
.ln{{border-color:{d['line']}!important}}
.ik{{color:{d['ink']}!important}}
.tx{{color:{d['text']}!important}}
.mu{{color:{d['muted']}!important}}
.lk{{color:{d['link']}!important}}
.num{{color:{d['link']}!important}}
.bad{{color:{d['bad']}!important}}
}}
@media (max-width:480px){{.px{{padding-left:22px!important;padding-right:22px!important}}.h1{{font-size:25px!important}}.sm-hide{{display:none!important}}}}
</style>"""


def _page(e: dict, inner: str) -> str:
    hidden = "&#8204;&nbsp;" * 70
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark"><meta name="supported-color-schemes" content="light dark"><meta name="x-apple-disable-message-reformatting">
<title>{esc(e.get('subject') or e.get('title'))}</title>
{_dark_css()}</head>
<body class="pg" style="margin:0;padding:0;background:{PAGE};-webkit-text-size-adjust:100%">
<div style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent;mso-hide:all">{esc(e.get('preheader') or '')}{hidden}</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" class="pg" style="background:{PAGE}"><tr><td align="center" style="padding:36px 12px">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:560px">
{inner}
</table></td></tr></table>
</body></html>"""


# ── Shared parts ─────────────────────────────────────────────────

def _para(s, size=16, mb=18, color=TEXT, cls="tx") -> str:
    return f'<p class="{cls}" style="margin:0 0 {mb}px;font:{size}px/1.6 {SANS};color:{color}">{md(s)}</p>'


def _brand(right: str = "") -> str:
    right_cell = f'<td class="sm-hide" align="right" style="vertical-align:middle">{right}</td>' if right else ""
    return f"""<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>
<td style="vertical-align:middle"><table role="presentation" cellpadding="0" cellspacing="0"><tr>
<td style="padding-right:10px;vertical-align:middle"><img src="{asset('bridge-bank.png')}" width="30" height="30" alt="" style="display:block;border:0;border-radius:7px"></td>
<td style="vertical-align:middle;font:600 16px/1.2 {SANS};letter-spacing:-0.2px;color:#eaf1ff">{NAME}</td>
</tr></table></td>
{right_cell}
</tr></table>"""


def _cell(f: dict, attrs: str) -> str:
    value_font = f"600 15px/1.35 {MONO};letter-spacing:.3px;word-break:break-all" if f.get("mono") else f"500 14px/1.35 {SANS}"
    return f"""<td class="ln" {attrs} style="border:1.5px solid {NAVY};padding:10px 12px;vertical-align:top">
<div class="mu" style="font:500 10.5px/1 {MONO};letter-spacing:1.1px;color:{MUTED};text-transform:uppercase;margin-bottom:7px">{esc(f['label'])}</div>
<div class="{'bad' if f.get('bad') else 'ik'}" style="font:{value_font};color:{BAD if f.get('bad') else INK}">{esc(f['value'])}</div></td>"""


def title_block(facts: list) -> str:
    """The title block of an engineering drawing: wide facts get a row each, the rest share one row."""
    wide = [f for f in facts if f.get("mono") or f.get("wide")]
    small = [f for f in facts if not (f.get("mono") or f.get("wide"))]
    span = max(len(small), 1)
    rows = "".join("<tr>" + _cell(f, 'colspan="%d"' % span) + "</tr>" for f in wide)
    if small:
        rows += "<tr>" + "".join(_cell(f, f'width="{100 // span}%"') for f in small) + "</tr>"
    return f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;margin:0 0 28px">{rows}</table>'


def parts_list(accounts: list) -> str:
    """The parts list of the same drawing: one row per account and what the sync did with it."""
    if not accounts:
        return ""
    head = lambda txt, align="left": (f'<td class="ln mu" align="{align}" style="border:1.5px solid {NAVY};padding:8px 12px;'
                                      f'font:500 10.5px/1 {MONO};letter-spacing:1.1px;color:{MUTED};text-transform:uppercase">{txt}</td>')
    rows = []
    for i, a in enumerate(accounts):
        bad = a.get("ok") is False
        result_cls, result_color = ("bad", BAD) if bad else ("ik", INK)
        name = f'<div class="ik" style="font:500 14px/1.4 {SANS};color:{INK}">{esc(a["name"])}</div>' if a.get("name") else ""
        detail = (f'<div class="{result_cls}" style="{"margin-top:5px;" if name else ""}font:13px/1.5 {SANS};color:{result_color};word-break:break-word">{esc(a["detail"])}</div>'
                  if a.get("detail") else "")
        rows.append(f"""<tr>
<td class="ln num" width="34" style="border:1.5px solid {NAVY};padding:11px 0 11px 12px;vertical-align:top;font:600 13px/1.4 {MONO};color:{LINK}">{i + 1:02d}</td>
<td class="ln" style="border:1.5px solid {NAVY};padding:11px 12px;vertical-align:top">{name}{detail}</td>
<td class="ln {result_cls}" align="right" style="border:1.5px solid {NAVY};padding:11px 12px;vertical-align:top;white-space:nowrap;font:600 13px/1.4 {MONO};color:{result_color}">{esc(a['result'])}</td></tr>""")
    return (f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;margin:0 0 28px">'
            f'<tr>{head("No.")}{head("Account")}{head("Result", "right")}</tr>{"".join(rows)}</table>')


def _steps(e: dict) -> str:
    if not e.get("steps"):
        return ""
    title = (f'<div class="ik" style="font:600 15px/1.4 {SANS};color:{INK};margin:0 0 14px">{esc(e["steps_title"])}</div>'
             if e.get("steps_title") else "")
    rows = "".join(f"""<tr>
<td width="36" style="vertical-align:top;padding:0 0 14px"><div class="num" style="font:600 13px/22px {MONO};color:{LINK}">{i + 1:02d}</div></td>
<td class="tx" style="vertical-align:top;padding:1px 0 14px;font:15px/1.55 {SANS};color:{TEXT}">{md(s)}</td></tr>""" for i, s in enumerate(e["steps"]))
    return f'{title}<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:0 0 14px">{rows}</table>'


def _button(c: dict, secondary=False, last=True) -> str:
    r = 8
    style = f"border:1.5px solid {LINE};border-radius:{r}px" if secondary else f"background:{ACCENT};border-radius:{r}px"
    mb = 10 if c.get("sub") else (30 if last else 12)
    sub = (f'<div class="mu" style="font:13.5px/1.55 {SANS};color:{MUTED};margin:0 0 {30 if last else 16}px">{md(c["sub"])}</div>'
           if c.get("sub") else "")
    return f"""<table role="presentation" cellpadding="0" cellspacing="0" style="margin:4px 0 {mb}px"><tr>
<td class="{'ln' if secondary else 'btn'}" style="{style}" align="center"><a href="{esc(c['href'])}" style="display:inline-block;padding:13px 24px;font:600 15px/1.2 {SANS};color:{INK if secondary else ON_ACCENT};text-decoration:none;border-radius:{r}px"><span class="{'ik' if secondary else ''}">{esc(c['label'])}</span></a></td>
</tr></table>{sub}"""


def _ctas(e: dict) -> list:
    return [c for c in (e.get("ctas") or ([e["cta"]] if e.get("cta") else [])) if c and c.get("href")]


def _buttons(e: dict) -> str:
    cs = _ctas(e)
    return "".join(_button(c, secondary=i > 0, last=i == len(cs) - 1) for i, c in enumerate(cs))


def _footer(e: dict) -> str:
    a = lambda href, txt: f'<a class="mu" href="{esc(href)}" style="color:{MUTED};text-decoration:underline">{txt}</a>'
    links = [NAME, a(f"https://{SITE}", SITE), a(TERMS, "Terms"), a(PRIVACY, "Privacy")]
    fine = "".join(f'<p class="mu" style="margin:0 0 10px;font:13px/1.6 {SANS};color:{MUTED}">{md(s)}</p>' for s in e.get("fine") or [])
    why = (f'<p class="mu" style="margin:0 0 6px;font:12.5px/1.6 {SANS};color:{MUTED}">{md(e["reason"], MUTED, "mu")}</p>'
           if e.get("reason") else "")
    return f"""<tr><td class="px" style="padding:24px 8px 0">
{fine}
<p class="mu" style="margin:{18 if fine else 0}px 0 6px;font:12.5px/1.6 {SANS};color:{MUTED}">{" &nbsp;·&nbsp; ".join(links)}</p>
{why}
<table role="presentation" cellpadding="0" cellspacing="0" style="margin-top:14px"><tr>
<td style="vertical-align:middle"><a href="https://david-alves.com"><img src="{asset('da-mark.png')}" width="24" height="16" alt="DA" style="display:block;border:0"></a></td>
<td class="mu" style="vertical-align:middle;padding-left:7px;font:12px/1 {SANS};color:{MUTED}">Made by David Alves</td></tr></table>
</td></tr>"""


def _blueprint(e: dict) -> str:
    """The card: navy blueprint header with the bridge drawing, then the body."""
    grid = asset("bb-grid.png")
    chip = (f'<span style="font:500 11px/1 {MONO};letter-spacing:1.2px;color:{HEAD_LINK};text-transform:uppercase">{esc(e["chip"])}</span>'
            if e.get("chip") else "")
    intro = e.get("intro") or []
    lede = (f'<p style="margin:12px 0 0;font:16px/1.55 {SANS};color:{HEAD_TEXT}">{md(intro[0], HEAD_LINK)}</p>' if intro else "")
    head = f"""<tr><td bgcolor="{NAVY}" background="{grid}" class="px" style="background-color:{NAVY};background-image:url('{grid}');border-radius:15px 15px 0 0;padding:26px 32px 0">
{_brand(chip)}
<div style="height:34px"></div>
<h1 class="h1" style="margin:0;font:700 28px/1.15 {SANS};letter-spacing:-0.6px;color:#ffffff">{esc(e['title'])}</h1>
{lede}
<div style="height:24px"></div>
<img src="{asset('bb-bridge.png')}" width="496" alt="" style="display:block;width:100%;max-width:496px;height:auto;border:0">
</td></tr>"""
    body = "".join(_para(s) for s in intro[1:])
    if e.get("facts"):
        body += title_block(e["facts"])
    body += parts_list(e.get("accounts") or [])
    body += "".join(_para(s, size=15, color=MUTED, cls="mu") for s in e.get("notes") or [])
    body += _steps(e) + _buttons(e)
    body += "".join(_para(s) for s in e.get("after") or [])
    return f"""<tr><td class="cd" style="background:{CARD};border:1px solid {LINE};border-radius:16px">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0">{head}
<tr><td class="px" style="padding:30px 32px 8px">{body}</td></tr></table></td></tr>"""


def render_html(e: dict) -> str:
    return _page(e, _blueprint(e) + _footer(e))


def render_text(e: dict) -> str:
    out = [e["title"]]
    out += [plain(s) for s in e.get("intro") or []]
    facts = [f for f in e.get("facts") or [] if not f.get("text_skip")]
    if facts:
        out.append("\n".join(f"{f['label']}: {f['value']}" for f in facts))
    accounts = e.get("accounts") or []
    if accounts:
        out.append("By account:\n" + "\n".join(
            (f"- {a['name']}: {a['result']}" if a.get("name") else f"- {a['result']}") + (f". {a['detail']}" if a.get("detail") else "") for a in accounts))
    out += [plain(s) for s in e.get("notes") or []]
    if e.get("steps"):
        head = f"{e['steps_title']}:\n" if e.get("steps_title") else ""
        out.append(head + "\n".join(f"{i + 1}. {plain(s)}" for i, s in enumerate(e["steps"])))
    for c in _ctas(e):
        out.append(f"{c['label']}: {c['href']}" + (f"\n{plain(c['sub'])}" if c.get("sub") else ""))
    out += [plain(s) for s in e.get("after") or []]
    out += [plain(s) for s in e.get("fine") or []]
    out.append(f"--\n{NAME}: https://{SITE}" + (f"\n{plain(e['reason'])}" if e.get("reason") else ""))
    return re.sub(r"\n{3,}", "\n\n", "\n\n".join(out))
