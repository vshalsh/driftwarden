# ruff: noqa: E501  (long literal regexes and HTML fragments in assertions)
"""L-013 system tests (independent): the self-contained HTML report.

Black-box on ``render_html`` / the CLI, driven through real Chromium (Playwright) for the
rendering criteria: WCAG AA contrast in both themes, offline, phone width, no-JS, XSS; plus
fact parity with the Markdown reporter (tampered reports included), CLI, size and
determinism. Run serially; never the full suite.
"""

from __future__ import annotations

import copy
import json
import os
import random
import re
import shutil
import subprocess
import sys
import time
from contextlib import contextmanager
from html import unescape
from html.parser import HTMLParser
from importlib import resources
from pathlib import Path
from urllib.parse import unquote, urlparse

import pytest
from typer.testing import CliRunner

sys.path.insert(0, str(Path(__file__).parent))
from driftwarden.cli import app  # noqa: E402
from driftwarden.report import render_markdown  # noqa: E402
from driftwarden.report.html import PROJECT_URL, render_html  # noqa: E402
from driftwarden.report.model import Report  # noqa: E402
from test_l012_system import (  # noqa: E402
    _delete_g2,
    _edit_path,
    _fake_claim,
    _flip_mismatch,
    claim_of,
    clone_claim,
    fx,
    gen_report,
    inject,
    make_pyshop,
    path_payload,
    rep,
    subst,
    violated,
)

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = Path(__file__).parent / "artifacts"
SHA = "c80cc5a0effcd4597b75533195e1bbde44020a32"
runner = CliRunner()
CONTRAST_RESULTS: dict[str, dict] = {}


# =========================================================================== helpers


def asset(name: str) -> str:
    return resources.files("driftwarden.report.html").joinpath(name).read_text(encoding="utf-8")


def rich_dict() -> dict:
    """The golden pyshop report widened to touch every visual element: drifting, in_change
    true/false/None, PR mode, timeline (verified and not), notes, not-judged, cnv, drafts."""
    d = fx()
    c2 = claim_of(d, "ADR-0002.c1")
    c2["verdict"]["status"] = "DRIFTING"
    claim_of(d, "ADR-0001.c1")["in_change"] = True
    c2["in_change"] = False
    claim_of(d, "ADR-0005.c1")["in_change"] = True
    claim_of(d, "ADR-0004.c1")["in_change"] = False
    d["metadata"]["changed_paths"] = ["requirements.txt", "src/shop/reports.py"]
    for item in d["could_not_verify"][:2]:
        item["in_change"] = True
    d["notes"] = ["Scan note one.", "Scan note two with `code` and a long tail " + "word " * 30]
    d["timeline"] = [
        {
            "claim_id": "ADR-0001.c1",
            "first_violating_commit": "a" * 40,
            "parent": "b" * 40,
            "date": "2026-02-03",
            "subject": "Add pymongo for the legacy catalog",
            "grounding": "VERIFIED",
        },
        {"claim_id": "ADR-0005.c1", "grounding": "MISMATCH"},
    ]
    # a not-judged claim
    nj = clone_claim(claim_of(d, "ADR-0004.c1"), "ADR-0004.c9")
    nj.update(judged=False, not_judged_reason="decision is superseded", verdict=None)
    d["claims"].append(nj)
    return d


def rich_report() -> Report:
    return rep(rich_dict())


def resum(d: dict) -> dict:
    """Make ``summary`` consistent with the claims, as a real scan would write it."""
    by: dict[str, int] = {"DRIFTING": 0, "HOLDING": 0, "UNKNOWN": 0, "VIOLATED": 0}
    for c in d["claims"]:
        v = c.get("verdict")
        if v and c.get("judged", True):
            by[v["status"]] = by.get(v["status"], 0) + 1
    s = d["summary"]
    s["by_status"] = by
    s["unknown"] = by["UNKNOWN"]
    s["claims"] = len(d["claims"])
    s["claims_judged"] = sum(by.values())
    s["could_not_verify"] = len(d["could_not_verify"])
    s["undocumented"] = len(d["undocumented"])
    s["drafts"] = len(d["drafts"])
    decided = by["VIOLATED"] + by["DRIFTING"] + by["HOLDING"]
    s["drift_score"] = (by["VIOLATED"] + by["DRIFTING"]) / decided if decided else None
    return d


def long_dict() -> dict:
    """Rich report with a 400-char path, a 5,000-char snippet and a 300-char ADR title."""
    d = rich_dict()
    long_path = "src/" + "a" * 396
    deep = "/".join(["segment_" + "b" * 20] * 15) + "/file.py"
    d = subst(
        d,
        {
            "src/shop/legacy/catalog.py": long_path,
            "src/shop/reports.py": "src/" + deep,
            "pymongo==4.6.1": "Q" * 5000,
            "from pymongo import MongoClient": "from " + "z" * 5000,
        },
    )
    for dec in d["decisions"]:
        dec["title"] = ("T" * 300) if dec["id"] == "ADR-0001" else ("Long title " * 30).strip()
    d["metadata"]["repo"] = "r" * 300
    d["notes"] = ["N" * 600]
    for dr in d["drafts"]:
        dr["markdown"] = "# " + "D" * 800 + "\n\n" + ("x" * 5000) + "\n"
    return d


class Doc(HTMLParser):
    def __init__(self, html: str) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: list[tuple[str, dict]] = []
        self.scripts: list[str] = []
        self._s = False
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))
        if tag == "script":
            self._s = True
            self.scripts.append("")

    def handle_endtag(self, tag):
        if tag == "script":
            self._s = False

    def handle_data(self, data):
        if self._s:
            self.scripts[-1] += data

    def attrs(self, name):
        return [(t, a[name]) for t, a in self.tags if name in a and a[name] is not None]


# ---- parity extraction -------------------------------------------------------

SECTION_KEYS = {
    "Violated": "violated",
    "Drifting": "drifting",
    "Holding": "holding",
    "Unknown": "unknown",
    "Could not verify": "cnv",
    "Undocumented decisions": "undocumented",
}


def _unesc(s: str) -> str:
    return re.sub(r"\\(.)", r"\1", s)


def md_split(md: str) -> dict[str, str]:
    """``## Name (n)`` -> body, ignoring headings inside fenced code (draft ADRs)."""
    secs: dict[str, list[str]] = {}
    cur = None
    fence = None
    for line in md.splitlines():
        m = re.match(r"^(`{3,}|~{3,})", line)
        if m and fence is None:
            fence = m.group(1)
        elif fence and line.startswith(fence) and line.strip() == fence:
            fence = None
        elif fence is None:
            h = re.match(r"^#{2,3} (.+?)(?: \(\d+\))?$", line)
            if h:
                cur = h.group(1)
                secs[cur] = []
                continue
        if cur is not None:
            secs[cur].append(line)
    return {k: "\n".join(v) for k, v in secs.items()}


def md_facts(md: str) -> dict:
    secs = md_split(md)
    pairs: set[tuple] = set()
    counts: dict[str, int] = {}
    heads = {}
    fence = False
    for line in md.splitlines():
        if re.match(r"^`{3,}", line):
            fence = not fence
        m = None if fence else re.match(r"^#{2,3} (.+?) \((\d+)\)$", line)
        if m:
            heads[m.group(1)] = m.group(2)
    for name, key in SECTION_KEYS.items():
        counts[key] = int(heads.get(name, "0"))
        body = secs.get(name, "")
        if key == "undocumented":
            for m in re.finditer(r"^\*\*(UD-[^*]+?)\*\*:", body, flags=re.M):
                pairs.add((key, _unesc(m.group(1)), None))
        elif key == "cnv":
            for m in re.finditer(r"^- \*\*(\S+) (.+?)\*\*(.*)$", body, flags=re.M):
                tag = (
                    "in"
                    if "in this change" in m.group(3)
                    else ("before" if "present before this change" in m.group(3) else None)
                )
                pairs.add((key, _unesc(m.group(2)), tag))
        else:
            for m in re.finditer(r"^- \*\*(.+?)\*\* \((.*)$", body, flags=re.M):
                rest = m.group(2)
                tag = (
                    "in"
                    if rest.rstrip().endswith("**in this change**")
                    else (
                        "before" if rest.rstrip().endswith("present before this change") else None
                    )
                )
                pairs.add((key, _unesc(m.group(1)), tag))
    score = re.search(r"\| Drift score \| (\S+) \|", md)
    return {
        "pairs": pairs,
        "counts": counts,
        "score": None if not score or score.group(1) == "n/a" else float(score.group(1)[:-1]),
        "exit": int(re.search(r"\| Exit code \| (\d+) \|", md).group(1)),
        "drafts": len(re.findall(r"^<summary>Draft ADR for ", md, flags=re.M)),
        "notes": len(re.findall(r"^- ", secs.get("Notes", ""), flags=re.M)),
    }


def _section(html: str, sid: str) -> str:
    m = re.search(rf'<section id="{sid}".*?</section>', html, flags=re.S)
    return m.group(0) if m else ""


def html_facts(html: str) -> dict:
    pairs: set[tuple] = set()
    counts: dict[str, int] = {}
    chip = {
        "violated": "violated",
        "drifting": "drifting",
        "could-not-verify": "cnv",
        "undocumented": "undocumented",
        "holding": "holding",
        "unknown": "unknown",
    }
    for anchor, key in chip.items():
        m = re.search(rf'<a href="#{anchor}">.*?<span class="dw-count">(\d+)</span>', html, re.S)
        counts[key] = int(m.group(1)) if m else -1

    def tag_of(chunk: str):
        if "Present before this change" in chunk:
            return "before"
        if "In this change" in chunk:
            return "in"
        return None

    for sid in ("violated", "drifting"):
        for card in re.findall(r'<article class="dw-card.*?</article>', _section(html, sid), re.S):
            cid = re.search(r"<dt>Claim</dt><dd><code class=\"dw-mono\">(.*?)</code>", card, re.S)
            pairs.add((sid, unescape(cid.group(1)), tag_of(card.split("<h3")[0])))
    for sid in ("holding", "unknown"):
        for li in re.findall(r'<li class="dw-row.*?</li>', _section(html, sid), re.S):
            cid = re.search(r'<code class="dw-mono">(.*?)</code>', li, re.S)
            pairs.add((sid, unescape(cid.group(1)), tag_of(li.split('<code class="dw-mono">')[0])))
    for card in re.findall(
        r'<article class="dw-card.*?</article>', _section(html, "could-not-verify"), re.S
    ):
        h = re.search(
            r'<h3[^>]*><span class="dw-kind">(.*?)</span> <span class="dw-mono dw-id">(.*?)</span>',
            card,
            re.S,
        )
        pairs.add(("cnv", unescape(h.group(2)), tag_of(card.split("<h3")[0])))
    for card in re.findall(
        r'<article class="dw-card.*?</article>', _section(html, "undocumented"), re.S
    ):
        h = re.search(r'<h3[^>]*><span class="dw-mono dw-id">(.*?)</span>', card, re.S)
        pairs.add(("undocumented", unescape(h.group(1)), None))
    score = re.search(r'<strong class="dw-score__value">(.*?)</strong>', html)
    return {
        "pairs": pairs,
        "counts": counts,
        "score": None if score.group(1) == "n/a" else float(score.group(1)[:-1]),
        "exit": int(
            re.search(r"<dt>Exit code</dt><dd><code class=\"dw-mono\">(\d+)</code>", html).group(1)
        ),
        "drafts": html.count('class="dw-draft"'),
        "notes": len(re.findall(r"<li>", _section(html, "notes"))),
    }


def parity_problems(report: Report, link_base=None, score: bool = True) -> list[str]:
    md = md_facts(render_markdown(report, link_base=link_base))
    ht = html_facts(render_html(report, link_base=link_base))
    out: list[str] = []
    if md["pairs"] != ht["pairs"]:
        out.append(
            f"(section,id,change) md-only={sorted(md['pairs'] - ht['pairs'], key=str)} "
            f"html-only={sorted(ht['pairs'] - md['pairs'], key=str)}"
        )
    if md["counts"] != ht["counts"]:
        out.append(f"counts md={md['counts']} html={ht['counts']}")
    ms, hs = md["score"], ht["score"]
    if score and ((ms is None) != (hs is None) or (ms is not None and abs(ms - hs) > 0.51)):
        out.append(f"drift score md={ms} html={hs}")
    for k in ("exit", "drafts", "notes"):
        if md[k] != ht[k]:
            out.append(f"{k} md={md[k]} html={ht[k]}")
    return out


# ---- browser -----------------------------------------------------------------


@pytest.fixture(scope="module")
def browser():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        pytest.skip("playwright not installed")
    os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH", "/opt/pw-browsers")
    exe = os.environ.get("DW_CHROMIUM") or "/opt/pw-browsers/chromium"
    pw = sync_playwright().start()
    try:
        b = pw.chromium.launch(
            executable_path=exe if Path(exe).exists() else None,
            args=[
                "--disable-background-networking",
                "--no-first-run",
                "--disable-sync",
                "--disable-dev-shm-usage",
            ],
        )
    except Exception as e:  # noqa: BLE001
        pw.stop()
        pytest.skip(f"chromium not available: {e}")
    yield b
    b.close()
    pw.stop()


def write_page(tmp_path_factory, name: str, html: str) -> Path:
    p = tmp_path_factory.mktemp(name) / "report.html"
    p.write_text(html, encoding="utf-8")
    return p


@pytest.fixture(scope="module")
def rich_file(tmp_path_factory):
    return write_page(tmp_path_factory, "rich", render_html(rich_report(), link_base=".."))


@pytest.fixture(scope="module")
def long_file(tmp_path_factory):
    return write_page(tmp_path_factory, "long", render_html(rep(long_dict()), link_base=".."))


class Opened:
    def __init__(self, ctx, page, errors, requests, dialogs):
        self.ctx, self.page, self.errors, self.requests, self.dialogs = (
            ctx,
            page,
            errors,
            requests,
            dialogs,
        )


@contextmanager
def opened(
    browser, path: Path, width=1280, scheme="light", js=True, offline=False, name="x", height=900
):
    ctx = browser.new_context(
        viewport={"width": width, "height": height},
        color_scheme=scheme,
        java_script_enabled=js,
        offline=offline,
    )
    page = ctx.new_page()
    errors: list[str] = []
    requests: list[str] = []
    dialogs: list[str] = []
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.on("request", lambda r: requests.append(r.url))
    page.on("dialog", lambda dlg: (dialogs.append(dlg.message), dlg.dismiss()))
    page.goto(path.as_uri())
    page.wait_for_load_state("load")
    o = Opened(ctx, page, errors, requests, dialogs)
    try:
        yield o
    except BaseException:
        ARTIFACTS.mkdir(exist_ok=True)
        try:
            page.screenshot(
                path=str(ARTIFACTS / f"l013sys-FAIL-{name}-{scheme}-{width}.png"), full_page=True
            )
        except Exception:  # noqa: BLE001
            pass
        raise
    finally:
        ctx.close()


# =========================================================================== 1. contrast

CONTRAST_JS = r"""
() => {
  const cv = document.createElement('canvas'); cv.width = cv.height = 1;
  const cx = cv.getContext('2d', {willReadFrequently: true});
  const parse = (c) => { cx.clearRect(0,0,1,1); cx.fillStyle = '#000'; cx.fillStyle = c;
    cx.fillRect(0,0,1,1); const d = cx.getImageData(0,0,1,1).data; return [d[0],d[1],d[2],d[3]/255]; };
  const over = (top, bot) => { const a = top[3];
    return [0,1,2].map(i => top[i]*a + bot[i]*(1-a)).concat([1]); };
  const lum = (c) => { const f = v => { v/=255; return v<=0.03928 ? v/12.92 : Math.pow((v+0.055)/1.055, 2.4); };
    return 0.2126*f(c[0]) + 0.7152*f(c[1]) + 0.0722*f(c[2]); };
  const ratio = (a, b) => { const la = lum(a), lb = lum(b); return (Math.max(la,lb)+0.05)/(Math.min(la,lb)+0.05); };
  const canvasBase = parse(getComputedStyle(document.documentElement).backgroundColor);
  const base = canvasBase[3] > 0 ? canvasBase.slice(0,3).concat([1]) : [255,255,255,1];
  const bgOf = (el) => { const layers = []; for (let e = el; e; e = e.parentElement) {
      const c = parse(getComputedStyle(e).backgroundColor); if (c[3] > 0) layers.push(c); if (c[3] >= 1) break; }
    let acc = base; for (let i = layers.length-1; i >= 0; i--) acc = over(layers[i], acc); return acc; };
  const opacityOf = (el) => { let o = 1; for (let e = el; e; e = e.parentElement) o *= parseFloat(getComputedStyle(e).opacity); return o; };
  const own0 = (el) => el.tagName.toLowerCase() + (el.className && typeof el.className === 'string' ? '.' + el.className.trim().split(/\s+/).join('.') : '');
  const key = (el) => { const c = el.parentElement && el.parentElement.closest('.dw-badge, .dw-change, .dw-ground, .dw-card--unverified, .dw-card--undocumented, .dw-draft, .dw-table, .dw-fold, .dw-empty, .dw-mismatch');
    return own0(el) + (c ? ' @' + own0(c) : ''); };
  const out = {text: [], ui: [], placeholder: []};
  const seen = new Set();
  const all = document.body.querySelectorAll('*');
  for (const el of all) {
    const cs = getComputedStyle(el);
    if (['SCRIPT','STYLE','SVG','SYMBOL','USE','PATH','CIRCLE'].includes(el.tagName.toUpperCase())) continue;
    if (el.closest('svg')) continue;
    const r = el.getClientRects(); if (!r.length || cs.visibility === 'hidden' || cs.display === 'none') continue;
    const own = [...el.childNodes].filter(n => n.nodeType === 3 && n.textContent.trim()).map(n => n.textContent.trim()).join(' ');
    const bg = bgOf(el);
    if (own && !(r[0].width <= 1 && r[0].height <= 1)) {
      let fg = parse(cs.color); const op = opacityOf(el); fg[3] = fg[3] * op; const eff = over(fg, bg);
      const size = parseFloat(cs.fontSize), weight = parseInt(cs.fontWeight) || 400;
      const large = size >= 24 || (size >= 18.66 && weight >= 700);
      const k = key(el) + '|' + eff.map(Math.round).join(',') + '|' + bg.map(Math.round).join(',');
      if (!seen.has(k)) { seen.add(k);
        out.text.push({key: key(el), sample: own.slice(0, 40), fg: eff.slice(0,3).map(Math.round), bg: bg.slice(0,3).map(Math.round),
                       ratio: ratio(eff, bg), size, weight, large, decoration: cs.textDecorationLine}); }
    }
    // component borders / outlines
    const bw = parseFloat(cs.borderTopWidth) + parseFloat(cs.borderBottomWidth) + parseFloat(cs.borderLeftWidth) + parseFloat(cs.borderRightWidth);
    if (bw > 0 && cs.borderTopStyle !== 'none') {
      const parentBg = el.parentElement ? bgOf(el.parentElement) : base;
      const bc = over(parse(cs.borderTopColor), parentBg);
      const k = 'b|' + key(el) + '|' + bc.map(Math.round).join(',') + '|' + parentBg.map(Math.round).join(',');
      if (!seen.has(k)) { seen.add(k);
        out.ui.push({kind: 'border', key: key(el), color: bc.slice(0,3).map(Math.round), bg: parentBg.slice(0,3).map(Math.round),
                     ratio: ratio(bc, parentBg), ownBg: bg.slice(0,3).map(Math.round), ratioOwn: ratio(bc, bg)}); }
    }
    if (el.tagName === 'INPUT') {
      const ph = getComputedStyle(el, '::placeholder'); const fg = over(parse(ph.color), bg);
      out.placeholder.push({key: key(el), fg: fg.slice(0,3).map(Math.round), bg: bg.slice(0,3).map(Math.round), ratio: ratio(fg, bg), opacity: ph.opacity});
    }
  }
  return out;
}
"""

FOCUS_JS = r"""
() => {
  const cv = document.createElement('canvas'); cv.width = cv.height = 1;
  const cx = cv.getContext('2d', {willReadFrequently: true});
  const parse = (c) => { cx.clearRect(0,0,1,1); cx.fillStyle = '#000'; cx.fillStyle = c; cx.fillRect(0,0,1,1);
    const d = cx.getImageData(0,0,1,1).data; return [d[0],d[1],d[2],d[3]/255]; };
  const over = (top, bot) => { const a = top[3]; return [0,1,2].map(i => top[i]*a + bot[i]*(1-a)).concat([1]); };
  const lum = (c) => { const f = v => { v/=255; return v<=0.03928 ? v/12.92 : Math.pow((v+0.055)/1.055, 2.4); };
    return 0.2126*f(c[0]) + 0.7152*f(c[1]) + 0.0722*f(c[2]); };
  const ratio = (a, b) => { const la = lum(a), lb = lum(b); return (Math.max(la,lb)+0.05)/(Math.min(la,lb)+0.05); };
  const bgOf = (el) => { const layers = []; for (let e = el; e; e = e.parentElement) {
      const c = parse(getComputedStyle(e).backgroundColor); if (c[3] > 0) layers.push(c); if (c[3] >= 1) break; }
    let acc = parse(getComputedStyle(document.body).backgroundColor); acc[3] = 1;
    for (let i = layers.length-1; i >= 0; i--) acc = over(layers[i], acc); return acc; };
  const e = document.activeElement; if (!e || e === document.body) return null;
  const cs = getComputedStyle(e);
  const oc = parse(cs.outlineColor);
  const outside = e.parentElement ? bgOf(e.parentElement) : bgOf(e);
  const eff = over(oc, outside);
  return {key: e.tagName.toLowerCase() + '.' + (e.className || ''), width: parseFloat(cs.outlineWidth), style: cs.outlineStyle,
          offset: cs.outlineOffset, color: eff.slice(0,3).map(Math.round), ratio: ratio(eff, outside), ratioInside: ratio(eff, bgOf(e))};
}
"""


def contrast_scan(page) -> dict:
    page.evaluate("document.querySelectorAll('details').forEach(d => d.open = true)")
    return page.evaluate(CONTRAST_JS)


def collect_focus(page) -> list[dict]:
    seen: dict[str, dict] = {}
    for _ in range(400):
        page.keyboard.press("Tab")
        r = page.evaluate(FOCUS_JS)
        if r is None:
            break
        if r["key"] in seen and r["key"] != "a.dw-skip":
            continue
        seen[r["key"]] = r
    return list(seen.values())


THEMES = [
    ("light", "light", None),
    ("dark", "dark", None),
    ("dark", "light", "dark"),  # forced data-theme beats the OS preference
    ("light", "dark", "light"),
]


def _contrast_all(browser, rich_file) -> dict:
    if "all" in CONTRAST_RESULTS:
        return CONTRAST_RESULTS["all"]
    problems: list[str] = []
    border_problems: list[str] = []
    lowest: dict[str, tuple] = {}
    n_checked = {"light": 0, "dark": 0}
    report: dict[str, list] = {}
    for theme, scheme, forced in THEMES:
        label = f"{theme}{'(forced)' if forced else ''}"
        with opened(browser, rich_file, 1280, scheme, name=f"contrast-{label}") as o:
            if forced:
                o.page.evaluate(f"document.documentElement.setAttribute('data-theme','{forced}')")
            body_bg = o.page.evaluate("getComputedStyle(document.body).backgroundColor")
            assert body_bg == ("rgb(14, 18, 23)" if theme == "dark" else "rgb(255, 255, 255)"), (
                label,
                body_bg,
            )
            res = contrast_scan(o.page)
            focus = collect_focus(o.page)
        for t in res["text"]:
            need = 3.0 if t["large"] else 4.5
            n_checked[theme] += 1
            cur = lowest.get(theme)
            if cur is None or t["ratio"] < cur[0]:
                lowest[theme] = (t["ratio"], t["key"], t["fg"], t["bg"], t["sample"], label)
            if t["ratio"] < need:
                problems.append(
                    f"[{label}] text {t['key']} '{t['sample']}' {t['fg']} on {t['bg']} = "
                    f"{t['ratio']:.2f} < {need}"
                )
        for p in res["placeholder"]:
            if p["ratio"] < 4.5:
                problems.append(
                    f"[{label}] placeholder {p['key']} {p['fg']} on {p['bg']} = {p['ratio']:.2f}"
                )
        for u in res["ui"]:
            comp = re.search(r"dw-(badge|change|btn|chip|ground)|^input|^button", u["key"])
            if comp and u["ratio"] < 3.0:
                border_problems.append(
                    f"[{label}] border of {u['key']} {u['color']} on {u['bg']} = {u['ratio']:.2f} < 3"
                )
        for f in focus:
            if f["style"] == "none" or f["width"] <= 0:
                problems.append(f"[{label}] no visible focus ring on {f['key']}")
            elif min(f["ratio"], f["ratioInside"]) < 3.0:
                problems.append(
                    f"[{label}] focus ring {f['key']} {f['color']} = "
                    f"{min(f['ratio'], f['ratioInside']):.2f} < 3"
                )
        report[label] = {"text": res["text"], "ui": res["ui"], "focus": focus}
    ARTIFACTS.mkdir(exist_ok=True)
    (ARTIFACTS / "l013sys-contrast.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
    for theme in ("light", "dark"):
        r = lowest[theme]
        print(
            f"\nLOWEST {theme}: {r[0]:.2f}:1  {r[1]}  '{r[4]}' fg={r[2]} bg={r[3]} ({r[5]}); "
            f"{n_checked[theme]} distinct text pairs"
        )
    CONTRAST_RESULTS["all"] = {
        "problems": problems,
        "borders": border_problems,
        "n": n_checked,
        "report": report,
    }
    return CONTRAST_RESULTS["all"]


def test_wcag_aa_text_and_focus_contrast_in_both_themes(browser, rich_file):
    res = _contrast_all(browser, rich_file)
    problems, n_checked, report = res["problems"], res["n"], res["report"]
    assert n_checked["light"] > 25 and n_checked["dark"] > 25
    # every element type the brief names was actually measured
    keys = " ".join(t["key"] for t in report["light"]["text"])
    for needle in (
        "dw-badge--violated",
        "dw-badge--drifting",
        "dw-badge--holding",
        "dw-badge--unknown",
        "dw-badge--unverified",
        "dw-badge--undocumented",
        "dw-change",
        "th",
        "code",
        "a",
        "dw-card--unverified",
        "dw-ground",
    ):
        assert needle in keys, needle
    assert not problems, "\n".join(problems)


def test_wcag_non_text_ui_component_boundaries_are_3_to_1(browser, rich_file):
    """WCAG 1.4.11: the borders of buttons, the filter input and chips."""
    res = _contrast_all(browser, rich_file)
    assert not res["borders"], "\n".join(sorted(set(res["borders"])))


def test_could_not_verify_card_and_every_badge_are_in_the_measured_page(browser, rich_file):
    with opened(browser, rich_file, 1280, "light", name="badges") as o:
        for cls in ("violated", "drifting", "holding", "unknown", "unverified", "undocumented"):
            assert o.page.locator(f".dw-badge--{cls}").count() > 0, cls
        assert o.page.locator(".dw-change").count() > 0
        assert o.page.locator(".dw-change--before").count() > 0
        assert o.page.locator("#could-not-verify .dw-card--unverified").count() > 0
        assert o.page.locator("th").count() > 0


# =========================================================================== 2. offline


def test_offline_zero_requests_no_console_errors_all_sections(browser, rich_file):
    p = rich_file
    for scheme in ("light", "dark"):
        with opened(browser, p, 1280, scheme, offline=True, name="offline") as o:
            others = [u for u in o.requests if u != p.as_uri()]
            assert others == [], others
            assert o.errors == [], o.errors
            assert o.dialogs == []
            for sid in (
                "violated",
                "drifting",
                "could-not-verify",
                "undocumented",
                "holding",
                "unknown",
                "not-judged",
                "timeline",
                "grounding",
                "notes",
            ):
                assert o.page.locator(f"#{sid}").count() == 1, sid
                assert o.page.locator(f"#{sid}").is_visible(), sid
            assert o.page.locator("h1").inner_text().strip() == "pyshop"


def test_offline_network_aborted_by_route(browser, rich_file):
    ctx = browser.new_context()
    hits: list[str] = []
    ctx.route(
        re.compile(r"^(?!file:)"), lambda route: (hits.append(route.request.url), route.abort())
    )
    page = ctx.new_page()
    errors = []
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(rich_file.as_uri())
    page.wait_for_load_state("load")
    try:
        assert [h for h in hits if not h.startswith("file:")] == [], hits
        assert errors == [], errors
        assert page.locator("#could-not-verify").is_visible()
    finally:
        ctx.close()


def test_source_has_no_external_references_or_css_urls():
    html = render_html(rich_report(), link_base="..")
    allowed = {PROJECT_URL}
    urls = set(re.findall(r"https?://[^\s\"'<>)]+", html))
    assert urls <= allowed, urls - allowed
    assert "@import" not in html
    assert "url(" not in html
    d = Doc(html)
    assert not [
        t
        for t, a in d.tags
        if t
        in ("link", "iframe", "object", "embed", "img", "form", "base", "audio", "video", "source")
    ]
    for t, a in d.tags:
        for k, v in a.items():
            if k in ("src", "srcset", "action", "poster", "data", "formaction"):
                pytest.fail(f"<{t} {k}={v}>")
    csp = [
        a["content"]
        for t, a in d.tags
        if t == "meta" and a.get("http-equiv", "").lower() == "content-security-policy"
    ]
    assert csp == [
        "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:"
    ]
    # github blob link_base is the only other allowed origin
    blob = "https://github.com/vshalsh/driftwarden/blob/" + SHA
    html2 = render_html(rich_report(), link_base=blob)
    urls2 = set(re.findall(r"https?://[^\s\"'<>)]+", html2))
    assert all(u == PROJECT_URL or u.startswith(blob + "/") for u in urls2), urls2
    assert any(u.startswith(blob + "/") for u in urls2)


# =========================================================================== 3. responsive


@pytest.mark.parametrize("scheme", ["light", "dark"])
@pytest.mark.parametrize("width", [320, 360, 768, 1280])
def test_no_horizontal_overflow_with_long_path_snippet_title(browser, long_file, width, scheme):
    with opened(browser, long_file, width, scheme, name="long") as o:
        info = o.page.evaluate(
            "({sw: document.documentElement.scrollWidth, iw: window.innerWidth,"
            " bw: document.body.scrollWidth})"
        )
        assert info["sw"] <= info["iw"], info
        o.page.evaluate("document.querySelectorAll('details').forEach(d => d.open = true)")
        info = o.page.evaluate(
            "({sw: document.documentElement.scrollWidth, iw: window.innerWidth})"
        )
        assert info["sw"] <= info["iw"], ("details opened", info)
        # the long content is really on the page (not silently dropped)
        txt = o.page.content()
        assert "Q" * 5000 in txt and "T" * 300 in txt and "a" * 396 in txt
        assert o.errors == []


@pytest.mark.parametrize("width", [320, 360, 768, 1280])
def test_no_horizontal_overflow_of_the_rich_report_and_zoom(browser, rich_file, width):
    with opened(browser, rich_file, width, "dark", name="rich-overflow") as o:
        assert o.page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
        # WCAG reflow: 400% zoom at 1280 == 320 css px; also check text spacing is not clipped
        o.page.add_style_tag(
            content="*{line-height:1.5!important;letter-spacing:.12em!important;"
            "word-spacing:.16em!important}"
        )
        assert o.page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")


# =========================================================================== 4. fact parity


def _gen_parity_reports() -> list[tuple[str, Report]]:
    out: list[tuple[str, Report]] = []
    for seed in range(32):
        rng = random.Random(1000 + seed)
        r = gen_report(seed, n=rng.randint(0, 24))
        d = json.loads(r.model_dump_json())
        # every status for sure, in a few reports
        if d["claims"] and seed % 4 == 0:
            for c, st in zip(
                d["claims"], ["VIOLATED", "DRIFTING", "HOLDING", "UNKNOWN"], strict=False
            ):
                c["verdict"]["status"] = st
        # undocumented records and drafts: keep a random subset (0..3) of the golden ones
        keep = rng.randint(0, 3)
        d["undocumented"] = d["undocumented"][:keep]
        d["drafts"] = (
            [x for x in d["drafts"] if x["id"] in {u["id"] for u in d["undocumented"]}]
            if d["drafts"] and "id" in d["drafts"][0]
            else d["drafts"][:keep]
        )
        # PR mode: in_change true / false / None mixture, changed paths set or not
        d["metadata"]["changed_paths"] = ["a.py", "b.py"] if seed % 3 else None
        if seed % 3 == 0:
            for c in d["claims"]:
                c["in_change"] = None
        if rng.random() < 0.5:
            d["notes"] = [f"note {i}" for i in range(rng.randint(1, 3))]
        resum(d)
        out.append((f"gen{seed}", rep(d)))
    # the untouched fixture and the rich one
    out.append(("golden", rep(fx())))
    out.append(("rich", rich_report()))
    out.append(
        (
            "empty",
            rep(
                resum(
                    {
                        **fx(),
                        "claims": [],
                        "could_not_verify": [],
                        "undocumented": [],
                        "drafts": [],
                        "decisions": [],
                    }
                )
            ),
        )
    )
    return out


@pytest.mark.parametrize(
    "name,report", _gen_parity_reports(), ids=lambda x: x if isinstance(x, str) else ""
)
def test_html_states_the_same_facts_as_markdown(name, report):
    problems = parity_problems(report)
    assert not problems, "\n".join(problems)


def _tamper_dict(kind: str) -> dict:
    d = fx()
    if kind == "flip_mismatch":
        _flip_mismatch(d)
    elif kind == "delete_g2":
        _delete_g2(d)
    elif kind == "edit_path":
        _edit_path(d)
    elif kind == "fake_claim":
        _fake_claim(d)
    elif kind == "delete_g3":
        c = violated(d, "ADR-0001.c1")
        c["verdict"]["checks"] = [x for x in c["verdict"]["checks"] if x["check_id"] != "G3"]
    elif kind == "package":
        violated(d, "ADR-0001.c1")["verdict"]["evidence"][0]["dependency"]["package"] = "left-pad"
    elif kind == "extra_evidence":
        c = violated(d, "ADR-0005.c1")
        extra = copy.deepcopy(c["verdict"]["evidence"][1])
        extra["id"] = "e9"
        extra["ref"]["path"] = "src/planted.py"
        c["verdict"]["evidence"].append(extra)
    elif kind == "row_mismatch":
        violated(d, "ADR-0005.c1")["verdict"]["checks"][0]["status"] = "MISMATCH"
    elif kind == "fake_ud":
        fake = copy.deepcopy(d["undocumented"][0])
        fake["id"] = "UD-fake-1"
        fake["checks"] = []
        d["undocumented"].append(fake)
    elif kind == "commit_swap":
        c = violated(d, "ADR-0002.c1")
        for ref in (c["verdict"]["evidence"][0]["ref"], c["verdict"]["checks"][0]["provenance"]):
            ref["commit"] = "f" * 40
    elif kind == "no_checks_all":
        for c in d["claims"]:
            if c["verdict"]:
                c["verdict"]["checks"] = []
    elif kind == "drifting_flip":
        v = claim_of(d, "ADR-0003.c1")["verdict"]
        v.update(status="DRIFTING", grounding="VERIFIED", reasons=[], proposed_status=None)
    else:
        raise AssertionError(kind)
    return d


TAMPERS = [
    "flip_mismatch",
    "delete_g2",
    "edit_path",
    "fake_claim",
    "delete_g3",
    "package",
    "extra_evidence",
    "row_mismatch",
    "fake_ud",
    "commit_swap",
    "no_checks_all",
    "drifting_flip",
]


@pytest.mark.parametrize("kind", TAMPERS)
def test_tampered_reports_have_the_same_facts_in_html_and_markdown(kind):
    r = rep(_tamper_dict(kind))
    problems = parity_problems(r, score=False)
    assert not problems, "\n".join(problems)


@pytest.mark.parametrize("kind", TAMPERS)
def test_tampered_reports_state_the_same_drift_score_in_html_and_markdown(kind):
    """After the report-time re-check demotes a finding, both reports must give one score."""
    r = rep(_tamper_dict(kind))
    md, ht = md_facts(render_markdown(r)), html_facts(render_html(r))
    assert md["score"] == ht["score"] or (
        md["score"] is not None
        and ht["score"] is not None
        and abs(md["score"] - ht["score"]) <= 0.51
    ), f"markdown says {md['score']}, html says {ht['score']} (counts {md['counts']})"


@pytest.mark.parametrize("kind", TAMPERS)
def test_tampered_reports_never_show_a_demoted_item_as_a_finding_in_html(kind):
    d = _tamper_dict(kind)
    html = render_html(rep(d))
    md = md_facts(render_markdown(rep(d)))
    cnv_md = {i for s, i, _ in md["pairs"] if s == "cnv"}
    for sid in ("violated", "drifting", "holding", "unknown"):
        shown = {i for s, i, _ in html_facts(html)["pairs"] if s == sid}
        # an id the Markdown lists as Could not verify is never also a finding in the HTML
        assert not (shown & {i for i in cnv_md if "/" not in i and "." in i}), (sid, shown & cnv_md)


def test_parity_summary_of_all_generated_reports():
    reps = _gen_parity_reports() + [(f"tamper-{k}", rep(_tamper_dict(k))) for k in TAMPERS]
    bad = {n: parity_problems(r, score=False) for n, r in reps}
    bad = {n: p for n, p in bad.items() if p}
    print(f"\nPARITY: {len(reps)} reports, {len(bad)} mismatching: {sorted(bad)}")
    assert not bad, json.dumps(bad, indent=1)[:4000]
    assert len(reps) >= 30


def test_parity_pr_mode_flags_match_per_item():
    r = rich_report()
    md, ht = md_facts(render_markdown(r)), html_facts(render_html(r))
    flags = {(s, i): t for s, i, t in ht["pairs"]}
    assert flags[("violated", "ADR-0001.c1")] == "in"
    assert flags[("drifting", "ADR-0002.c1")] == "before"
    assert md["pairs"] == ht["pairs"]


# =========================================================================== 5. XSS

PAYLOADS = {
    "script": "<script>window.__pwned=1</script>",
    "img": '"><img src=x onerror="window.__pwned=1">',
    "js_url": "javascript:window.__pwned=1",
    "textarea": "</textarea><script>window.__pwned=1</script>",
    "jinja": "{{ 7*7 }} {% if 1 %}X{% endif %}",
    "dollar": "${7*7} #{7*7} ${{7*7}}",
    "svg": '<svg onload="window.__pwned=1"><script>window.__pwned=1</script></svg>',
    "css": 'x" style="width:expression(window.__pwned=1)" onfocus="window.__pwned=1" autofocus="',
    "rtl": "abc‮evil.exe⁦x⁩‏ end",
    "nul": "a\x00b<scr\x00ipt>window.__pwned=1</scr\x00ipt>",
    "close_all": "</pre></code></details></section></article></main><script>window.__pwned=1</script>",
    "style": "</style><style>*{display:none}</style>",
    "entity": "&lt;script&gt;window.__pwned=1&lt;/script&gt; &#x3C;img src=x onerror=window.__pwned=1&#x3E;",
    "meta": '<meta http-equiv="refresh" content="0;url=javascript:window.__pwned=1">',
    "all": '<script>window.__pwned=1</script> "><img src=x onerror=window.__pwned=1> '
    "javascript:window.__pwned=1 </textarea> {{ 7*7 }} ${} <svg onload=window.__pwned=1> "
    "style=expression(1) ‮ \x00",
}


def inject_all(payload: str) -> dict:
    """Payload in every user-controlled field the HTML page prints."""
    d = inject(payload)
    pp = path_payload(payload)
    for c in d["claims"]:
        if c["claim"]["kind"] == "only":
            c["claim"]["rule"] = {"category": payload, "only": [payload]}
        for e in c["verdict"]["evidence"]:
            e["technology"] = payload
        c["verdict"]["notes"] = [payload] if "notes" in c["verdict"] else []
    for u in d["undocumented"]:
        u["searched_terms"] = [payload]
        for e in u.get("evidence", []):
            e["technology"] = payload
    d["timeline"][0]["subject"] = payload
    d["metadata"]["changed_paths"] = [pp]
    d["metadata"]["provider"] = payload
    d["metadata"]["model"] = payload
    d["decisions"][0]["not_judged_reason"] = payload if d["decisions"] else None
    return d


@pytest.mark.parametrize("name", sorted(PAYLOADS))
def test_hostile_payload_is_inert_in_the_dom(name, browser, tmp_path):
    payload = PAYLOADS[name]
    d = inject_all(payload)
    report = rep(d)
    for lb in (None, "..", "https://github.com/vshalsh/driftwarden/blob/" + SHA):
        html = render_html(report, link_base=lb)
        doc = Doc(html)
        # no event handlers, no inline style attributes carrying expressions
        for t, a in doc.tags:
            for k, v in a.items():
                assert not k.lower().startswith("on"), (t, k, v)
                if k == "style":
                    pytest.fail(f"inline style on <{t}>: {v}")
        assert len(doc.scripts) == 2, len(doc.scripts)
        assert doc.scripts[0].strip() == asset("head.js").strip()
        assert doc.scripts[1].strip() == asset("report.js").strip()
        for t, v in doc.attrs("href"):
            ok = (
                v.startswith("#")
                or v == PROJECT_URL
                or v.startswith("https://github.com/vshalsh/driftwarden/blob/" + SHA + "/")
                or (
                    re.match(r"^[A-Za-z0-9._~%/-]+(#L\d+(-L\d+)?)?$", v)
                    and ":" not in v.split("#")[0]
                    and not v.startswith("//")
                )
            )
            assert ok, (t, v)
    path = tmp_path / "x.html"
    path.write_text(render_html(report, link_base=".."), encoding="utf-8")
    with opened(browser, path, 1280, "dark", name=f"xss-{name}") as o:
        o.page.evaluate("document.querySelectorAll('details').forEach(d => d.open = true)")
        o.page.wait_for_timeout(100)
        assert o.page.evaluate("window.__pwned") is None
        assert o.dialogs == []
        assert [u for u in o.requests if u != path.as_uri()] == []
        assert o.errors == [], o.errors
        # structure intact: nothing escaped into a new element
        assert o.page.locator("script:not([data-x])").count() == 2
        assert o.page.locator("[onerror],[onload],[onfocus],[onclick]").count() == 0
        assert o.page.locator("img,iframe,object,embed,meta[http-equiv=refresh]").count() == 0
        for sid in ("violated", "could-not-verify", "undocumented", "grounding"):
            assert o.page.locator(f"#{sid}").is_visible()
        assert o.page.locator("main section").count() >= 6
        # interact with every control: still nothing fires
        o.page.fill("[data-dw-search]", payload[:40])
        o.page.click("[data-dw-theme]")
        o.page.click("[data-dw-expand]")
        o.page.click("[data-dw-collapse]")
        for b in o.page.locator("[data-dw-copy]").all():
            if b.is_visible():
                b.click()
        assert o.page.evaluate("window.__pwned") is None and o.dialogs == []
        # no mixed-in visible raw bidi/control characters
        text = o.page.evaluate("document.body.innerText")
        assert not re.search("[‪-‮⁦-⁩‎‏؜\x00]", text)


def test_bidi_and_control_characters_are_shown_as_u_plus_codes():
    d = inject_all(PAYLOADS["rtl"])
    html = render_html(rep(d))
    assert not re.search("[‪-‮⁦-⁩‎‏؜]", html)
    for code_ in ("[U+202E]", "[U+2066]", "[U+2069]", "[U+200F]"):
        assert code_ in html, code_
    d = inject_all(PAYLOADS["nul"])
    html = render_html(rep(d))
    assert "\x00" not in html and "[U+0000]" in html


@pytest.mark.parametrize(
    "bad",
    [
        "javascript:alert(1)",
        "JaVaScRiPt:alert(1)",
        "//evil.example/x",
        "http://evil.example/x",
        "https://evil.example/x",
        "data:text/html,<script>1</script>",
        "\\\\evil\\share",
        "/etc/passwd",
        "../../etc/passwd",
        "vbscript:x",
        " javascript:alert(1)",
        "a b/c.md",
        "docs/adr/x.md\nonclick=1",
        "file:///etc/passwd",
    ],
)
def test_adr_path_that_looks_like_a_url_never_becomes_an_active_link(bad):
    d = fx()
    d = subst(d, {"docs/adr/0001-postgresql-only.md": bad})
    html = render_html(rep(d), link_base="..")
    for _t, v in Doc(html).attrs("href"):
        low = v.strip().lower()
        assert (
            not low.startswith(("javascript:", "vbscript:", "data:", "http:", "file:", "//"))
            or v == PROJECT_URL
        ), v
        assert "evil" not in v and "etc/passwd" not in v and not v.startswith("/"), v
        assert ".." not in v.replace("../", "", 1) or v.startswith("../"), v


def test_link_base_values_that_are_not_safe_produce_no_link():
    r = rich_report()
    for lb in (
        "javascript:alert(1)",
        "//evil.example",
        "http://evil.example",
        "a b",
        "..\\x",
        '"onmouseover="x',
        "../../..",
        "https://evil.example/x y",
    ):
        hrefs = [v for _, v in Doc(render_html(r, link_base=lb)).attrs("href")]
        for v in hrefs:
            assert v.startswith("#") or v == PROJECT_URL or re.match(r"^(\.\./)*[\w./%-]+#?", v), v
            assert not v.lower().startswith(("javascript:", "http:", "//")), v
        assert not any("evil" in v or "onmouseover" in v for v in hrefs), (lb, hrefs)


# =========================================================================== 6. without JS


def test_without_javascript_all_content_is_visible_and_no_control_is_broken(browser, rich_file):
    with opened(browser, rich_file, 360, "dark", js=False, name="nojs") as o:
        pg = o.page
        for sid in (
            "violated",
            "drifting",
            "could-not-verify",
            "undocumented",
            "holding",
            "unknown",
            "timeline",
            "grounding",
            "notes",
        ):
            assert pg.locator(f"#{sid}").is_visible(), sid
        # every card and every table is visible and has size
        for sel in (".dw-card", ".dw-table", ".dw-chips li", ".dw-score"):
            for el in pg.locator(sel).all():
                assert el.is_visible(), sel
                bb = el.bounding_box()
                assert bb and bb["width"] > 0 and bb["height"] > 0, sel
        # JS-only controls are hidden rather than shown dead
        for el in pg.locator("[data-dw-controls] button, [data-dw-copy], [data-dw-search]").all():
            assert not el.is_visible()
        # elements removed from layout: only closed <details> bodies, JS controls, the sprite
        hidden = pg.evaluate("""() => [...document.body.querySelectorAll('*')].filter(e => {
            if (e.closest('svg')) return false; const cs = getComputedStyle(e);
            return e.tagName !== 'SCRIPT' && cs.display === 'none' && !e.closest('details:not([open])') && !e.hasAttribute('hidden')
              && !e.closest('[hidden]'); }).map(e => e.tagName + '.' + e.className)""")
        assert hidden == [], hidden
        # holding / unknown / draft open by plain HTML (no script)
        pg.click("#holding summary")
        assert pg.locator("#holding .dw-row").first.is_visible()
        pg.click("#unknown summary")
        assert pg.locator("#unknown .dw-row").first.is_visible()
        pg.locator("#undocumented details.dw-draft summary").first.click()
        assert pg.locator("#undocumented .dw-draft__md").first.is_visible()
        # chip anchors really navigate to existing targets
        for href in pg.eval_on_selector_all(
            ".dw-chips a", "els => els.map(e => e.getAttribute('href'))"
        ):
            assert pg.locator(href).count() == 1, href
            pg.click(f".dw-chips a[href='{href}']")
            assert pg.evaluate("location.hash") == href
        pg.goto(rich_file.as_uri())
        pg.keyboard.press("Tab")
        assert pg.evaluate("document.activeElement.className") == "dw-skip"
        assert pg.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
        assert o.errors == [] and [u for u in o.requests if u != rich_file.as_uri()] == []


def test_with_javascript_controls_work(browser, rich_file):
    with opened(browser, rich_file, 1280, "light", name="js") as o:
        pg = o.page
        assert pg.locator("[data-dw-search]").is_visible()
        vis = lambda: len([e for e in pg.locator(".dw-filterable").all() if e.is_visible()])  # noqa: E731
        total = vis()
        pg.fill("[data-dw-search]", "ADR-0005")
        assert 0 < vis() < total
        pg.fill("[data-dw-search]", "zzz-no-such-text-zzz")
        assert not [e for e in pg.locator(".dw-filterable").all() if e.is_visible()]
        pg.fill("[data-dw-search]", "")
        assert vis() == total
        pg.click("[data-dw-expand]")
        assert all(d.get_attribute("open") is not None for d in pg.locator("details").all())
        pg.click("[data-dw-collapse]")
        assert all(d.get_attribute("open") is None for d in pg.locator("details").all())
        seen = {pg.evaluate("getComputedStyle(document.body).backgroundColor")}
        for _ in range(3):  # system -> light -> dark -> system
            pg.click("[data-dw-theme]")
            seen.add(pg.evaluate("getComputedStyle(document.body).backgroundColor"))
        assert seen == {"rgb(255, 255, 255)", "rgb(14, 18, 23)"}, seen
        assert o.errors == []


# =========================================================================== 7. CLI


def _scan(tmp_path: Path, *extra: str):
    repo = make_pyshop(tmp_path)
    res = runner.invoke(
        app, ["scan", str(repo), "--mode", "offline", "--format", "json,md,html", *extra]
    )
    assert res.exit_code in (0, 1, 3), res.output
    return repo, repo / ".driftwarden"


def test_cli_scan_writes_html_whose_adr_links_resolve(tmp_path):
    repo, out = _scan(tmp_path)
    page = out / "driftwarden.html"
    assert page.is_file()
    html = page.read_text(encoding="utf-8")
    links = [v for t, v in Doc(html).attrs("href") if not v.startswith("#") and v != PROJECT_URL]
    assert links, "no ADR links"
    for v in links:
        u = urlparse(v)
        assert not u.scheme and not u.netloc, v
        target = (out / unquote(u.path)).resolve()
        assert target.is_file(), (v, target)
        assert target.is_relative_to(repo.resolve()), v
        assert u.fragment.startswith("L"), v
    # Markdown links agree with the HTML links
    md = (out / "driftwarden.md").read_text(encoding="utf-8")
    for v in links:
        assert f"]({v})" in md, v
    assert git_status_clean_except_out(repo)


def git_status_clean_except_out(repo: Path) -> bool:
    out = subprocess.run(
        ["git", "status", "--porcelain"], cwd=repo, capture_output=True, text=True
    ).stdout
    return all(".driftwarden" in line for line in out.splitlines())


def test_cli_report_from_saved_json_matches_the_scan_html(tmp_path):
    repo, out = _scan(tmp_path)
    scan_html = (out / "driftwarden.html").read_text(encoding="utf-8")
    shutil.copy(out / "driftwarden.json", out / "saved.json")
    (out / "driftwarden.html").unlink()
    res = runner.invoke(
        app, ["report", str(out / "saved.json"), "--format", "html", "--repo", str(repo)]
    )
    assert res.exit_code == 0, res.output
    again = (out / "driftwarden.html").read_text(encoding="utf-8")
    norm = lambda s: re.sub(r'(<time datetime=")[^"]*(">)[^<]*', r"\1\2", s)  # noqa: E731
    assert norm(again) == norm(scan_html), "report from saved.json differs from the scan's html"
    # run with cwd == repo and --repo . as written in the brief
    (out / "driftwarden.html").unlink()
    cwd = os.getcwd()
    try:
        os.chdir(repo)
        res = runner.invoke(
            app, ["report", ".driftwarden/saved.json", "--format", "html", "--repo", "."]
        )
    finally:
        os.chdir(cwd)
    assert res.exit_code == 0, res.output
    assert norm((out / "driftwarden.html").read_text(encoding="utf-8")) == norm(scan_html)


@pytest.mark.parametrize("tamper", ["delete_g2", "flip", "path"])
def test_cli_tampered_saved_json_shows_demoted_items_in_could_not_verify(tmp_path, tamper):
    repo, out = _scan(tmp_path)
    d = json.loads((out / "driftwarden.json").read_text(encoding="utf-8"))
    vio = [c for c in d["claims"] if c["verdict"] and c["verdict"]["status"] == "VIOLATED"]
    cid = vio[0]["claim"]["id"]
    if tamper == "delete_g2":
        vio[0]["verdict"]["checks"] = [
            x for x in vio[0]["verdict"]["checks"] if x["check_id"] != "G2"
        ]
    elif tamper == "path":
        vio[0]["verdict"]["evidence"][0]["ref"]["path"] = "src/not/there.py"
    else:
        vio[0]["verdict"]["checks"] = []
    saved = tmp_path / "tampered.json"
    saved.write_text(json.dumps(d), encoding="utf-8")
    o2 = tmp_path / "o2"
    res = runner.invoke(
        app, ["report", str(saved), "--format", "html,md", "--out", str(o2), "--repo", str(repo)]
    )
    assert res.exit_code == 0, res.output
    html = (o2 / "driftwarden.html").read_text(encoding="utf-8")
    f = html_facts(html)
    secs = {s for s, i, _ in f["pairs"] if i == cid}
    assert secs == {"cnv"}, (cid, secs)
    card = [
        c
        for c in re.findall(
            r'<article class="dw-card.*?</article>', _section(html, "could-not-verify"), re.S
        )
        if f">{cid}<" in c
    ]
    assert card and "<li>" in card[0], "demoted item shows no reason"
    assert md_facts((o2 / "driftwarden.md").read_text(encoding="utf-8"))["pairs"] == f["pairs"]
    assert "src/not/there.py" not in "".join(
        _section(html, s) for s in ("violated", "drifting", "holding", "unknown")
    )


def test_cli_html_only_format_writes_only_html(tmp_path):
    repo = make_pyshop(tmp_path)
    res = runner.invoke(app, ["scan", str(repo), "--mode", "offline", "--format", "html"])
    assert res.exit_code in (0, 1, 3), res.output
    assert sorted(
        p.name
        for p in (repo / ".driftwarden").iterdir()
        if p.is_file() and p.suffix in (".html", ".md", ".json", ".sarif")
    ) == ["driftwarden.html"]


# =========================================================================== 8. size and performance


def test_one_thousand_findings_under_5mb_and_2s():
    r = gen_report(7, n=1000)
    assert len(r.claims) == 1000
    best = 1e9
    for _ in range(2):
        t = time.perf_counter()
        html = render_html(r)
        best = min(best, time.perf_counter() - t)
    size = len(html.encode("utf-8"))
    print(f"\nPERF: 1000 findings -> {size / 1e6:.2f} MB in {best:.2f}s")
    assert size < 5_000_000, size
    assert best < 2.0, best


def test_one_thousand_findings_page_opens_in_a_browser(browser, tmp_path):
    r = gen_report(7, n=1000)
    p = tmp_path / "big.html"
    p.write_text(render_html(r), encoding="utf-8")
    t = time.perf_counter()
    with opened(browser, p, 360, "dark", name="big") as o:
        load = time.perf_counter() - t
        assert o.page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
        assert o.errors == []
    print(f"\nPERF: 1000-finding page loaded in {load:.2f}s")
    assert load < 10


# =========================================================================== 9. determinism


def test_same_report_gives_identical_bytes():
    r = rich_report()
    a = render_html(r, link_base="..")
    assert (
        a
        == render_html(r, link_base="..")
        == render_html(Report.model_validate_json(r.model_dump_json()), link_base="..")
    )
    hostile = rep(inject_all(PAYLOADS["all"]))
    assert render_html(hostile) == render_html(hostile)


def test_identical_bytes_across_processes_with_different_hash_seeds(tmp_path):
    f = tmp_path / "r.json"
    f.write_text(rich_report().model_dump_json(), encoding="utf-8")
    code = (
        "import sys,hashlib;from driftwarden.report.model import Report;"
        "from driftwarden.report.html import render_html;"
        "r=Report.model_validate_json(open(sys.argv[1],encoding='utf-8').read());"
        "print(hashlib.sha256(render_html(r,link_base='..').encode()).hexdigest())"
    )
    digests = set()
    for seed in ("0", "1", "12345"):
        env = {**os.environ, "PYTHONHASHSEED": seed}
        digests.add(
            subprocess.run(
                [sys.executable, "-c", code, str(f)],
                capture_output=True,
                text=True,
                env=env,
                check=True,
            ).stdout.strip()
        )
    assert len(digests) == 1, digests


def test_tokens_css_is_byte_identical_to_design_tokens():
    assert (ROOT / "design" / "tokens.css").read_bytes() == resources.files(
        "driftwarden.report.html"
    ).joinpath("tokens.css").read_bytes()
    assert asset("tokens.css") in render_html(rich_report())
