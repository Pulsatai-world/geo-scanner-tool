// Generates the published methodology checklist from the check registry.
//   node build-checklist.mjs [out.html]
//
// The registry is the only input. The checklist therefore cannot describe a check the scanner
// does not run, or omit one it does — which is the entire reason it is generated rather than
// written. A methodology document maintained by hand is accurate on the day it is written and
// quietly wrong a month later.
import { checksByLayer, CHECKS } from './netlify/functions/lib/check-registry.js';
import { pick } from './netlify/functions/lib/i18n.js';
import { writeFileSync } from 'node:fs';

const out = process.argv[2] || 'geo-checklist.html';
// Layer metadata became bilingual when the scanner did; without resolving it the headings
// rendered as [object Object]. Per-check text is still English — see the note in the page.
const lang = process.argv[3] === 'en' ? 'en' : 'es';
const L = v => pick(v, lang);
const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const layers = checksByLayer();
const total = Object.keys(CHECKS).length;
const scoredCount = Object.values(CHECKS).filter(c => c.scored !== false).length;

const rows = layer => layer.checks.map((c, i) => `
  <tr>
    <td class="n">${i + 1}</td>
    <td class="ck"><b>${esc(L(c.title))}</b><span class="id">${esc(c.id)}</span>${c.scored === false ? '<span class="unscored">not scored</span>' : ''}</td>
    <td>${esc(c.measures)}</td>
    <td class="rule">${esc(c.rule)}</td>
    <td class="why">${esc(c.why)}</td>
  </tr>`).join('');

const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>GEO Technical Readiness — What We Check</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Montserrat:wght@600;700;800&family=Manrope:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap">
<style>
:root{--violet-600:#6d4fe0;--violet-50:#f6f3fe;--violet-700:#4834b0;
--emerald-500:#1ea97c;
--ink-950:#08090c;--ink-700:#2a313d;--ink-600:#3d4653;--ink-500:#566172;--ink-400:#757f8f;
--ink-200:#c3c8d0;--ink-100:#e3e6ea;--ink-50:#f4f6f8;
--fd:"Montserrat","Helvetica Neue",Arial,sans-serif;--fb:"Manrope","Helvetica Neue",Arial,sans-serif;--fm:"JetBrains Mono",ui-monospace,Menlo,monospace}
*{box-sizing:border-box}
@page{size:A4 landscape;margin:12mm}
body{font-family:var(--fb);color:var(--ink-700);margin:0;padding:0 28px 70px;background:#fff;font-size:14px;line-height:1.55;-webkit-print-color-adjust:exact;print-color-adjust:exact}
.wrap{max-width:1180px;margin:0 auto}
header{padding:44px 0 22px;border-bottom:2.5px solid var(--ink-950);margin-bottom:26px}
.brand{display:flex;align-items:center;gap:9px;font-family:var(--fm);font-size:11px;letter-spacing:.17em;text-transform:uppercase;color:var(--ink-500);font-weight:600;margin-bottom:14px}
.dot{width:8px;height:8px;border-radius:50%;background:var(--emerald-500)}
h1{font-family:var(--fd);font-size:38px;font-weight:800;letter-spacing:-.025em;line-height:1.03;color:var(--ink-950);margin:0 0 8px;max-width:20ch}
.lede{font-size:16px;color:var(--ink-500);max-width:70ch;margin:0}
.stats{display:flex;gap:34px;margin-top:20px;flex-wrap:wrap}
.stat .v{font-family:var(--fd);font-size:26px;font-weight:800;color:var(--violet-600);line-height:1}
.stat .l{font-family:var(--fm);font-size:10px;letter-spacing:.09em;text-transform:uppercase;color:var(--ink-400);margin-top:4px}
.principle{background:var(--violet-50);border-left:4px solid var(--violet-600);border-radius:0 10px 10px 0;padding:18px 22px;margin:26px 0 34px}
.principle h2{font-family:var(--fd);font-size:16px;margin:0 0 7px;color:var(--ink-950)}
.principle p{margin:0 0 9px}.principle p:last-child{margin:0}
.layer{margin-bottom:38px;page-break-inside:avoid}
.lhead{display:flex;justify-content:space-between;align-items:flex-start;gap:20px;border-bottom:1px solid var(--ink-200);padding-bottom:11px;margin-bottom:6px;flex-wrap:wrap}
h2.lt{font-family:var(--fd);font-size:22px;font-weight:700;color:var(--ink-950);margin:0;letter-spacing:-.015em}
.lq{font-size:15px;color:var(--violet-600);font-weight:600;margin-top:3px}
.lmeta{text-align:right;font-size:12px;color:var(--ink-500);flex:none}
.lmeta b{display:block;font-family:var(--fm);font-size:10px;letter-spacing:.09em;text-transform:uppercase;color:var(--ink-400);font-weight:600}
.lsum{font-size:13.5px;color:var(--ink-600);margin:9px 0 4px;max-width:95ch}
.lown{font-size:13px;color:var(--ink-600);margin-bottom:13px}
.lown b{color:var(--ink-950)}
table{width:100%;border-collapse:collapse;font-size:12.5px}
thead th{background:var(--ink-50);text-align:left;padding:9px 11px;font-family:var(--fm);font-size:9.5px;letter-spacing:.11em;text-transform:uppercase;color:var(--ink-500);border-bottom:1px solid var(--ink-200);font-weight:600}
td{padding:11px;border-bottom:1px solid var(--ink-100);vertical-align:top}
tr{page-break-inside:avoid}
.n{font-family:var(--fm);color:var(--ink-400);width:26px;font-size:11px}
.ck{width:19%}
.ck b{color:var(--ink-950);display:block;font-family:var(--fd);font-size:13px}
.id{font-family:var(--fm);font-size:10px;color:var(--ink-400);display:block;margin-top:2px}
.unscored{display:inline-block;margin-top:5px;font-family:var(--fm);font-size:9px;letter-spacing:.07em;text-transform:uppercase;background:var(--ink-100);color:var(--ink-600);padding:2px 7px;border-radius:99px}
.rule{width:27%;color:var(--ink-950)}
.why{width:27%;color:var(--ink-500)}
footer{margin-top:44px;padding-top:16px;border-top:1px solid var(--ink-200);font-family:var(--fm);font-size:10px;letter-spacing:.06em;color:var(--ink-400);display:flex;justify-content:space-between;flex-wrap:wrap;gap:10px}
</style></head><body><div class="wrap">

<header>
  <div class="brand"><span class="dot"></span>Akore Labs · GEO Methodology</div>
  <h1>What we check, and how each verdict is decided</h1>
  <p class="lede">The complete set of factors assessed in a GEO technical readiness scan, with the explicit rule behind every result.</p>
  <div class="stats">
    <div class="stat"><div class="v">${total}</div><div class="l">Factors checked</div></div>
    <div class="stat"><div class="v">${layers.length}</div><div class="l">Layers</div></div>
    <div class="stat"><div class="v">${scoredCount}</div><div class="l">Contribute to the score</div></div>
    <div class="stat"><div class="v">${total - scoredCount}</div><div class="l">Context only, never scored</div></div>
  </div>
</header>

<div class="principle">
  <h2>Why the rules are published</h2>
  <p>Generative engine optimisation is one machine reading another. A verdict about a page should therefore be reproducible by anyone holding the same page — so every check below states the exact rule that decides it. Not &ldquo;the content should be substantial&rdquo;, but &ldquo;under 300 words fails, under 600 warns&rdquo;.</p>
  <p>Three things follow. Two scans of an unchanged site return the same result, which is what makes progress between audits measurable rather than anecdotal. Nothing rests on the judgement of whoever happened to run the scan. And where a factor genuinely cannot be settled remotely — anything behind a CDN&rsquo;s bot protection, most obviously — it is reported as <b>unverified</b> and excluded from the score entirely, rather than guessed at and presented as fact.</p>
  <p>This document is generated directly from the scanner&rsquo;s own check registry. It cannot describe a check the tool does not run, or omit one it does.</p>
</div>

${layers.map(l => `
<div class="layer">
  <div class="lhead">
    <div>
      <h2 class="lt">${esc(L(l.title))}</h2>
      <div class="lq">${esc(L(l.question))}</div>
    </div>
    <div class="lmeta">
      <b>Checks</b>${l.checks.length}
      <b style="margin-top:7px">Scoring</b>${l.scored ? 'counts toward score' : 'reported separately'}
    </div>
  </div>
  <p class="lsum">${esc(L(l.summary))}</p>
  <p class="lown"><b>Who can act on it:</b> ${esc(L(l.owner))}</p>
  <table>
    <thead><tr><th></th><th>Factor</th><th>What is measured</th><th>Rule</th><th>Why it matters for citation</th></tr></thead>
    <tbody>${rows(l)}</tbody>
  </table>
</div>`).join('')}

<footer>
  <span>Akore Labs — GEO Technical Readiness methodology</span>
  <span>Generated from the scanner check registry · ${new Date().toISOString().slice(0, 10)}</span>
</footer>
</div></body></html>`;

writeFileSync(out, html);
console.log(`checklist written: ${out} — ${total} checks across ${layers.length} layers`);
