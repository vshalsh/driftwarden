# DriftWarden — Design Tokens

Industry-sourced palette research and the derived design tokens for DriftWarden's HTML report, PR comments, SARIF-adjacent UI and drift timeline. Research date: 2026-10-23. Owner: Fable (PM / design direction).

The companion file `design/tokens.css` carries the same tokens as CSS custom properties.

---

## 1. Industry & user seat

**Industry:** developer tooling — code quality, static analysis, DevSecOps and architecture governance.

**Users:** software architects, staff/principal engineers, platform teams and engineering managers. They meet DriftWarden *inside or next to GitHub*: a PR comment, a code-scanning alert, an HTML report opened from a CI artifact, a timeline linked from an ADR.

**Consequences for the design:**

- The report must sit comfortably beside GitHub's own chrome without looking like a GitHub clone. Neutrals should be close cousins of GitHub's; the brand hue must be clearly *not* GitHub blue.
- Status colours carry the product's meaning. "Holding / drifting / violated" is a traffic-light the whole industry already reads (Sonar ratings, CodeScene code health, Backstage status). DriftWarden adds two states nobody else has: **undocumented** (a decision exists in the code with no ADR) and **unverified** (DriftWarden's grounding check could not trace the finding back to evidence). These two must never be confused with the traffic-light states.
- Dark mode is first-class. Every reference product except Sonar's docs ships a dark theme by default.

---

## 2. Sites consulted

| # | Site / product | URL(s) |
|---|---|---|
| 1 | GitHub Primer design system — colour primitives (light page, dark CSS build) | https://primer.style/primitives/colors · https://cdn.jsdelivr.net/npm/@primer/primitives@10.4.0/dist/css/functional/themes/dark.css |
| 2 | SonarQube Server docs — metrics, ratings and issues | https://docs.sonarsource.com/sonarqube-server/latest/user-guide/code-metrics/metrics-definition/ · https://docs.sonarsource.com/sonarqube-server/latest/user-guide/issues/ |
| 3 | Semgrep — site and brand assets | https://semgrep.dev/ · https://brandfetch.com/semgrep.dev |
| 4 | Snyk — brand assets and marketing design-system README | https://brandfetch.com/snyk.io · https://cdn.jsdelivr.net/npm/@snyk-mktg/brand-ui@3.3.2/README.md |
| 5 | Backstage default theme (as documented by Red Hat Developer Hub) | https://docs.redhat.com/zh-cn/documentation/red_hat_developer_hub/1.7/html/customizing_red_hat_developer_hub/ref-customize-rhdh-default-backstage_customizing-appearance |
| 6 | CodeScene — Code Health guide | https://codescene.cs.lth.se/docs/guides/technical/code-health.html |

---

## 3. Observations per site

**GitHub Primer.** The anchor reference because our output lives next to it. Light: canvas `#ffffff`, text `#1f2328`, muted text `#59636e`, border `#d1d9e0`, inset `#f6f8fa`. Dark: canvas `#0d1117`, muted surface `#151b23`, text `#f0f6fc`, muted `#9198a1`, border `#3d444d`. Semantic set is blue accent `#0969da`/`#4493f8`, success green `#1a7f37`/`#3fb950`, attention amber `#9a6700`/`#d29922`, danger red `#d1242f`/`#f85149`, done purple `#8250df`/`#ab7df8`. Neutrals are cool, slightly blue-tinted greys; density is compact (14px body, 32px row heights); tone is factual and unemotional. Lesson: match the *temperature* of these neutrals and the *lightness steps* of the semantic colours, but do not reuse the hues.

**SonarQube.** Severity is expressed as letter ratings A–E and Blocker/High/Medium/Low/Info; no hex values are published in the docs, but the product UI uses a green→red gradient for ratings, with Info rendered in blue-grey. The docs are terse, instructional and link-dense. Lesson: a five-step ordinal scale is familiar to our users; DriftWarden's three traffic-light states plus two "epistemic" states (undocumented, unverified) are a deliberate contrast to a one-dimensional severity ladder.

**Semgrep.** Brand colours are a mint-teal green `#13BF95`, a sky blue `#73C0FC` and a dark slate `#384240`. The site is illustration-led, confident, "builders and agents" copy, strong headline hierarchy. Lesson: teal-green reads as "security/analysis" in this space without being GitHub blue — but we must stay clear of Semgrep's bright mint by going deeper and cooler.

**Snyk.** Brand is a saturated denim blue `#145DEB` on a near-black navy `#01011E`, with a pale lavender-white `#F6F4FA` surface. Their marketing design system is tiered (palette tokens → semantic labels such as `--action`, `--success`, `--fail`), uses Inter, and names colours (midnight, coral, mint). Lesson: tiered tokens (base → semantic) are the industry norm and we follow it; strong blue-on-navy is Snyk's territory, so our dark canvas is a neutral graphite, not navy.

**Backstage.** Default theme: primary `#1F5493` (light) / `#9CC9FF` (dark), app background `#F8F8F8` / `#333333`, sidebar `#171717`, status OK `#1DB954`, warning `#FF9800`, error `#E22134`, pending `#FFED51`. Text `#000` with subtle `#6E6E6E`. Material-UI density, lots of cards. Lesson: Backstage's bright, saturated status colours fail AA as text on light surfaces; we keep status hues but tune lightness so each one passes as text, not just as a dot.

**CodeScene.** Code Health is a 1–10 score bucketed into Green (healthy), Yellow (complex / maintenance issues) and Red (severe). No hex values published. Lesson: the three-bucket mental model maps directly onto holding / drifting / violated, and users in this space already trust it. We keep it and avoid inventing a fourth "severity" colour.

---

## 4. Derived tokens

Design intent in one sentence: **graphite neutrals borrowed in temperature from GitHub, a deep teal primary that says "analysis and governance" without being Sonar-, Snyk- or GitHub-blue, a rust accent for human-attention moments (undocumented decision drafts, calls-to-action), and five status colours in which the two epistemic states (undocumented = indigo, unverified = violet) are hue-separated from the traffic light.**

Naming: `--dw-*`. Base scale tokens are `--dw-neutral-N`; semantic tokens reference intent (`--dw-status-violated-fg`), never a colour name.

### 4.1 Neutral scale (shared base; both themes pick from it)

| Token | Value | Rationale |
|---|---|---|
| `--dw-neutral-0` | `#FFFFFF` | Light canvas. |
| `--dw-neutral-50` | `#F4F6F8` | Light muted surface / code block (Primer inset is `#f6f8fa`; ours is one step cooler). |
| `--dw-neutral-100` | `#EAEEF2` | Light inset / table header. |
| `--dw-neutral-200` | `#D3DAE1` | Light border. |
| `--dw-neutral-300` | `#B0BAC5` | Disabled text, light dividers on dark. |
| `--dw-neutral-400` | `#8A95A1` | Dark subtle text. |
| `--dw-neutral-500` | `#67737F` | Light subtle text / captions (darkened from `#6F7B88` to pass AA — see §5). |
| `--dw-neutral-600` | `#5A6673` | Light muted text. |
| `--dw-neutral-700` | `#363F4A` | Dark border. |
| `--dw-neutral-800` | `#171D24` | Light body text. |
| `--dw-neutral-850` | `#161C23` | Dark muted surface / code block. |
| `--dw-neutral-900` | `#0E1217` | Dark canvas (a hair warmer than Primer's `#0d1117`). |
| `--dw-neutral-950` | `#090C10` | Dark inset. |

(Thirteen stops so both themes have proper surface/border/text steps; the nine "named" steps a UI will mostly use are 0, 50, 100, 200, 500, 600, 800, 850, 900.)

### 4.2 Light theme

| Token | Value | Rationale |
|---|---|---|
| `--dw-bg` | `#FFFFFF` | Report canvas, matches GitHub page background so an embedded report does not "float". |
| `--dw-bg-muted` | `#F4F6F8` | Cards, code blocks, timeline lanes. |
| `--dw-bg-inset` | `#EAEEF2` | Table headers, sunken panels. |
| `--dw-border` | `#D3DAE1` | Hairlines; same weight as Primer's. |
| `--dw-fg` | `#171D24` | Body text; cool near-black. |
| `--dw-fg-muted` | `#5A6673` | Secondary text, metadata, timestamps. |
| `--dw-fg-subtle` | `#67737F` | Captions, placeholder, de-emphasised file paths. |
| `--dw-primary` | `#0B6E6A` | Deep teal: brand, links, focus ring, selected tab. Distinct from GitHub `#0969da`, Snyk `#145DEB`, Semgrep `#13BF95`. |
| `--dw-primary-hover` | `#085955` | Hover/active for primary. |
| `--dw-on-primary` | `#FFFFFF` | Label on solid primary buttons. |
| `--dw-accent` | `#A4461A` | Rust: "attention from a human" — draft ADR CTA, undocumented-decision banner stripe, timeline "now" marker. |
| `--dw-on-accent` | `#FFFFFF` | Label on solid accent. |
| `--dw-accent-2` | `#3451C6` | Indigo: secondary accent used for charts, selected timeline range, and as the base of the *undocumented* status. |
| `--dw-link` | `#0B6E6A` | Same as primary; underlined on hover only. |
| `--dw-status-holding-fg` | `#1A7A3C` | Decision holds / check passed. Green, darker than Primer success so it passes on tint. |
| `--dw-status-holding-bg` | `#E3F5E8` | Tint for badges/rows. |
| `--dw-status-drifting-fg` | `#8A5A00` | Drift detected but no hard violation. Deep amber, readable as text. |
| `--dw-status-drifting-bg` | `#FCF1D8` | Tint. |
| `--dw-status-violated-fg` | `#C0202B` | ADR constraint broken. Red. |
| `--dw-status-violated-bg` | `#FCE6E7` | Tint. |
| `--dw-status-undocumented-fg` | `#2456C8` | Decision found in code with no ADR. Indigo-blue: "information, not judgement". |
| `--dw-status-undocumented-bg` | `#E4ECFB` | Tint. |
| `--dw-status-unverified-fg` | `#6B40B8` | Grounding failed: DriftWarden cannot trace the claim to evidence. Violet — far from red on the hue wheel so it is never read as "violated". |
| `--dw-status-unverified-bg` | `#EFE7FA` | Tint. |
| `--dw-code-bg` | `#F4F6F8` | Inline code and `file:line` chips. |
| `--dw-focus` | `#0B6E6A` | 2px outline, 2px offset. |

### 4.3 Dark theme

| Token | Value | Rationale |
|---|---|---|
| `--dw-bg` | `#0E1217` | Graphite canvas, sits beside GitHub dark `#0d1117`. |
| `--dw-bg-muted` | `#161C23` | Cards, code blocks. |
| `--dw-bg-inset` | `#090C10` | Sunken panels. |
| `--dw-border` | `#363F4A` | Hairlines, visible but quiet. |
| `--dw-fg` | `#E8EDF2` | Body text; slightly below pure white to avoid glare. |
| `--dw-fg-muted` | `#98A3AF` | Secondary text. |
| `--dw-fg-subtle` | `#8A95A1` | Captions. |
| `--dw-primary` | `#3CC0B6` | Teal lifted for dark; still clearly our hue. |
| `--dw-primary-hover` | `#5FD1C8` | Hover. |
| `--dw-on-primary` | `#06201E` | Dark label on light teal button. |
| `--dw-accent` | `#E58A5B` | Rust lifted to a warm copper. |
| `--dw-on-accent` | `#2A1409` | Dark label on accent. |
| `--dw-accent-2` | `#8FA6FF` | Indigo lifted. |
| `--dw-link` | `#3CC0B6` | Same as primary. |
| `--dw-status-holding-fg` | `#4CC46A` | Green on dark. |
| `--dw-status-holding-bg` | `#10301C` | Tint. |
| `--dw-status-drifting-fg` | `#E0A531` | Amber on dark. |
| `--dw-status-drifting-bg` | `#33270C` | Tint. |
| `--dw-status-violated-fg` | `#FF6B65` | Red on dark. |
| `--dw-status-violated-bg` | `#3A1518` | Tint. |
| `--dw-status-undocumented-fg` | `#7FA3FF` | Indigo-blue on dark. |
| `--dw-status-undocumented-bg` | `#13213F` | Tint. |
| `--dw-status-unverified-fg` | `#B79CF5` | Violet on dark. |
| `--dw-status-unverified-bg` | `#271A42` | Tint. |
| `--dw-code-bg` | `#161C23` | Code chips. |
| `--dw-focus` | `#3CC0B6` | Focus ring. |

### 4.4 Status semantics (for engineers wiring the report)

| State | Meaning | Hue | Icon shape (never colour alone) |
|---|---|---|---|
| holding | ADR constraint verified and satisfied | green | filled circle / check |
| drifting | Divergence from an ADR, below violation threshold | amber | half-filled circle |
| violated | ADR constraint broken | red | octagon / cross |
| undocumented | Architectural decision inferred from code, no ADR exists | indigo | dashed circle / document-plus |
| unverified | Grounding check failed; finding not traceable to evidence | violet | question-mark in diamond |

Always pair colour with icon and label. In PR comments (GitHub Markdown, no CSS) use the label text and a Unicode glyph; the palette applies to the HTML report and timeline.

---

## 5. Contrast check (WCAG 2.x AA, computed)

Ratios were computed with the WCAG relative-luminance formula (sRGB linearisation, L = 0.2126R + 0.7152G + 0.0722B, ratio = (L1+0.05)/(L2+0.05)) in a small Python script. Threshold: 4.5:1 for body text. One token failed on first pass — light `--dw-fg-subtle` at `#6F7B88` scored 4.32:1 — and was darkened to `#67737F` (4.84:1). Every pair below now passes.

**Light theme**

| Pair | Foreground | Background | Ratio | AA (4.5:1) |
|---|---|---|---|---|
| body text on canvas | `#171D24` | `#FFFFFF` | 16.97:1 | pass |
| body text on muted surface | `#171D24` | `#F4F6F8` | 15.66:1 | pass |
| body text on inset surface | `#171D24` | `#EAEEF2` | 14.55:1 | pass |
| muted text on canvas | `#5A6673` | `#FFFFFF` | 5.86:1 | pass |
| muted text on muted surface | `#5A6673` | `#F4F6F8` | 5.41:1 | pass |
| subtle text / captions on canvas | `#67737F` | `#FFFFFF` | 4.84:1 | pass |
| primary as text / link on canvas | `#0B6E6A` | `#FFFFFF` | 6.08:1 | pass |
| button label on primary | `#FFFFFF` | `#0B6E6A` | 6.08:1 | pass |
| accent as text on canvas | `#A4461A` | `#FFFFFF` | 6.05:1 | pass |
| label on accent | `#FFFFFF` | `#A4461A` | 6.05:1 | pass |
| accent-2 text on canvas | `#3451C6` | `#FFFFFF` | 6.69:1 | pass |
| holding text on canvas | `#1A7A3C` | `#FFFFFF` | 5.39:1 | pass |
| holding text on holding tint | `#1A7A3C` | `#E3F5E8` | 4.75:1 | pass |
| drifting text on canvas | `#8A5A00` | `#FFFFFF` | 5.93:1 | pass |
| drifting text on drifting tint | `#8A5A00` | `#FCF1D8` | 5.28:1 | pass |
| violated text on canvas | `#C0202B` | `#FFFFFF` | 6.03:1 | pass |
| violated text on violated tint | `#C0202B` | `#FCE6E7` | 5.06:1 | pass |
| undocumented text on canvas | `#2456C8` | `#FFFFFF` | 6.48:1 | pass |
| undocumented text on undocumented tint | `#2456C8` | `#E4ECFB` | 5.46:1 | pass |
| unverified text on canvas | `#6B40B8` | `#FFFFFF` | 6.88:1 | pass |
| unverified text on unverified tint | `#6B40B8` | `#EFE7FA` | 5.73:1 | pass |
| code text on code block | `#171D24` | `#F4F6F8` | 15.66:1 | pass |

**Dark theme**

| Pair | Foreground | Background | Ratio | AA (4.5:1) |
|---|---|---|---|---|
| body text on canvas | `#E8EDF2` | `#0E1217` | 15.95:1 | pass |
| body text on muted surface | `#E8EDF2` | `#161C23` | 14.56:1 | pass |
| body text on inset surface | `#E8EDF2` | `#090C10` | 16.63:1 | pass |
| muted text on canvas | `#98A3AF` | `#0E1217` | 7.33:1 | pass |
| muted text on muted surface | `#98A3AF` | `#161C23` | 6.69:1 | pass |
| subtle text / captions on canvas | `#8A95A1` | `#0E1217` | 6.17:1 | pass |
| primary as text / link on canvas | `#3CC0B6` | `#0E1217` | 8.42:1 | pass |
| button label on primary | `#06201E` | `#3CC0B6` | 7.63:1 | pass |
| accent as text on canvas | `#E58A5B` | `#0E1217` | 7.26:1 | pass |
| label on accent | `#2A1409` | `#E58A5B` | 6.75:1 | pass |
| accent-2 text on canvas | `#8FA6FF` | `#0E1217` | 8.11:1 | pass |
| holding text on canvas | `#4CC46A` | `#0E1217` | 8.42:1 | pass |
| holding text on holding tint | `#4CC46A` | `#10301C` | 6.44:1 | pass |
| drifting text on canvas | `#E0A531` | `#0E1217` | 8.59:1 | pass |
| drifting text on drifting tint | `#E0A531` | `#33270C` | 6.68:1 | pass |
| violated text on canvas | `#FF6B65` | `#0E1217` | 6.75:1 | pass |
| violated text on violated tint | `#FF6B65` | `#3A1518` | 5.80:1 | pass |
| undocumented text on canvas | `#7FA3FF` | `#0E1217` | 7.68:1 | pass |
| undocumented text on undocumented tint | `#7FA3FF` | `#13213F` | 6.52:1 | pass |
| unverified text on canvas | `#B79CF5` | `#0E1217` | 8.13:1 | pass |
| unverified text on unverified tint | `#B79CF5` | `#271A42` | 6.92:1 | pass |
| code text on code block | `#E8EDF2` | `#161C23` | 14.56:1 | pass |

**Added during L-013 (HTML report), computed the same way:**

| Pair | Light | Dark | AA |
|---|---|---|---|
| muted text on inset surface | 5.03:1 | 7.64:1 | pass |
| status fg on muted surface (lowest of the five) | 4.98:1 | 6.16:1 | pass |
| link text on code block (`--dw-link` on `--dw-code-bg`) | 5.61:1 | 7.68:1 | pass |
| in-change badge (`--dw-accent` on `--dw-bg`) | 6.05:1 | 7.26:1 | pass |
| "before this change" chip text (`--dw-fg-muted` on `--dw-bg`) | 5.86:1 | 7.33:1 | pass |
| control borders, non-text 3:1 (`--dw-neutral-500` on canvas / muted) | 4.84 / 4.47:1 | 3.88 / 3.54:1 | pass (≥ 3:1) |

Decorative dividers keep `--dw-border` (1.41:1 light, 1.76:1 dark), which is allowed because they are not UI components (WCAG 1.4.11).

Rule for future tokens: any new text/background pair must be run through the same script before merge. Status *backgrounds* used only as tints behind their own fg are covered above; status colours used as solid fills (e.g. timeline bars) must carry a label in `--dw-fg` or `--dw-bg`, not the status fg, unless re-checked.

---

## 6. Typography

| Role | Stack | Why |
|---|---|---|
| UI / body | `"Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif` | Inter (SIL OFL, Google Fonts) is the de-facto developer-tool UI face (Snyk's own stack uses it); tall x-height, tabular numerals via `font-feature-settings: "tnum"`. Falls back to the GitHub-like system stack when offline, which matters for an HTML artifact opened from CI. |
| Code, `file:line`, hashes, ADR IDs | `"JetBrains Mono", ui-monospace, "SFMono-Regular", Menlo, Consolas, "Liberation Mono", monospace` | JetBrains Mono (SIL OFL, Google Fonts) is designed for long reading of code, distinguishes 0/O and 1/l/I, and has a slightly larger body than Inter at the same size so `font-size: 0.92em` aligns the two. |

Sizes (report): body 14px / 1.5; small 12px / 1.4; code 13px; H1 24px/600; H2 18px/600; H3 15px/600. Weights 400/500/600 only. Load from Google Fonts with `display=swap`; never block render on fonts.

---

## 7. Density & tone

- **Density: compact, GitHub-grade.** 14px body, 32px table rows, 8px base spacing unit (4/8/12/16/24/32). Findings tables show file path, rule, status badge and one-line message in a single row; details expand inline. Architects scan hundreds of findings; whitespace is for grouping, not decoration.
- **Hierarchy by weight and neutral steps, not colour.** Colour is reserved for status and primary actions. A page should be legible with status colours removed.
- **Tone: factual, evidence-first.** Every finding states *what* drifted, *which ADR* it drifted from, and *where* (file:line, commit). No exclamation marks, no "Oops". Unverified findings say plainly "DriftWarden could not ground this finding in repository evidence" and are listed last.
- **Timeline:** horizontal, one lane per ADR, status colour as the lane fill at 100 % with the label in `--dw-fg`/`--dw-bg`; drift events as 2px ticks; the "now" marker uses `--dw-accent`.
- **PR comments:** plain GitHub Markdown; status conveyed by label text plus glyph; link to the HTML report for colour.

---

## 8. Do not

1. Do not use GitHub's `#0969da`/`#4493f8` blue, Snyk's `#145DEB`, Semgrep's `#13BF95`, or Backstage's `#1F5493` anywhere; our primary is teal `#0B6E6A`/`#3CC0B6`.
2. Do not use red for anything other than *violated*. Unverified is violet; undocumented is indigo. Never let the three bleed together via opacity or gradients.
3. Do not convey status by colour alone — always icon shape plus label (see §4.4).
4. Do not use bright saturated status colours as text on light surfaces (the Backstage `#1DB954`/`#FF9800` pattern); use the AA-checked `-fg` tokens.
5. Do not use pure black `#000000` or pure white text on the dark canvas; use `--dw-fg`.
6. Do not introduce a navy or blue-tinted dark canvas; dark mode is neutral graphite so status hues stay true.
7. Do not add a fifth severity level or an A–E grade. DriftWarden reports state (holding / drifting / violated) and epistemic status (undocumented / unverified), not a numeric score.
8. Do not use the accent (rust) for errors or status; it marks human-attention actions and the timeline "now" marker only.
9. Do not ship a new text/background pair without re-running the contrast script and recording the ratio here.
10. Do not use decorative gradients, drop shadows beyond 1px hairlines, or illustration in the report; the report is a working document, not a landing page.
