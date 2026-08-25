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

// Page chrome, written natively in Mexican Spanish rather than translated.
const TX = {
  brand:      { es: 'Akore Labs · Metodología GEO', en: 'Akore Labs · GEO Methodology' },
  h1:         { es: 'Qué revisamos, y cómo se decide cada veredicto', en: 'What we check, and how each verdict is decided' },
  lede:       { es: 'El conjunto completo de factores que evaluamos en un diagnóstico técnico GEO, con la regla explícita detrás de cada resultado.', en: 'The complete set of factors assessed in a GEO technical readiness scan, with the explicit rule behind every result.' },
  statFactors:{ es: 'Factores revisados', en: 'Factors checked' },
  statLayers: { es: 'Capas', en: 'Layers' },
  statScored: { es: 'Cuentan para la calificación', en: 'Contribute to the score' },
  statContext:{ es: 'Solo contexto, nunca califican', en: 'Context only, never scored' },
  whyTitle:   { es: 'Por qué publicamos las reglas', en: 'Why the rules are published' },
  why1:       { es: 'La optimización para motores generativos es una máquina leyendo a otra. Un veredicto sobre una página debería, por tanto, poder reproducirlo cualquiera que tenga esa misma página delante: por eso cada revisión de abajo indica la regla exacta que la decide. No «el contenido debería tener valor», sino «por debajo de 300 palabras no cumple, por debajo de 600 marca atención».', en: 'Generative engine optimisation is one machine reading another. A verdict about a page should therefore be reproducible by anyone holding the same page — so every check below states the exact rule that decides it.' },
  why2:       { es: 'De ahí se siguen tres cosas. Dos análisis de un sitio web que no ha cambiado devuelven el mismo resultado, que es lo que permite medir el avance entre auditorías en lugar de contarlo de memoria. Nada depende del criterio de quien haya corrido el análisis. Y cuando un factor realmente no puede resolverse en remoto —lo más evidente, cualquier cosa detrás de la protección de bots de un CDN— se informa como <b>sin verificar</b> y queda fuera de la calificación, en lugar de suponerlo y presentarlo como un hecho.', en: 'Three things follow. Two scans of an unchanged site return the same result, which is what makes progress between audits measurable rather than anecdotal. Nothing rests on the judgement of whoever happened to run the scan. And where a factor genuinely cannot be settled remotely it is reported as <b>unverified</b> and excluded from the score entirely.' },
  why3:       { es: 'Este documento se genera directamente del registro de revisiones del propio escáner. No puede describir una revisión que la herramienta no haga, ni omitir ninguna que sí haga.', en: 'This document is generated directly from the scanner own check registry. It cannot describe a check the tool does not run, or omit one it does.' },
  colFactor:  { es: 'Factor', en: 'Factor' },
  colMeasured:{ es: 'Qué se mide', en: 'What is measured' },
  colRule:    { es: 'Regla', en: 'Rule' },
  colWhy:     { es: 'Por qué importa para ser citado', en: 'Why it matters for citation' },
  lblChecks:  { es: 'Revisiones', en: 'Checks' },
  lblScoring: { es: 'Calificación', en: 'Scoring' },
  counts:     { es: 'cuenta para la calificación', en: 'counts toward score' },
  separate:   { es: 'se informa aparte', en: 'reported separately' },
  whoActs:    { es: 'Quién puede resolverlo', en: 'Who can act on it' },
  notScored:  { es: 'no califica', en: 'not scored' },
  footer:     { es: 'Akore Labs — Metodología de diagnóstico técnico GEO', en: 'Akore Labs — GEO Technical Readiness methodology' },
  generated:  { es: 'Generado desde el registro de revisiones del escáner', en: 'Generated from the scanner check registry' }
};
const X = k => (TX[k] || {})[lang] || (TX[k] || {}).es || k;
const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const layers = checksByLayer();
const total = Object.keys(CHECKS).length;
const scoredCount = Object.values(CHECKS).filter(c => c.scored !== false).length;

const rows = layer => layer.checks.map((c, i) => `
  <div class="chk">
    <div class="chk-head">
      <span class="chk-n">${i + 1}</span>
      <span class="chk-name">${esc(L(c.title))}</span>
      <span class="chk-id">${esc(c.id)}</span>
      ${c.scored === false ? `<span class="unscored">${X('notScored')}</span>` : ''}
    </div>
    <dl class="chk-body">
      <dt>${X('colMeasured')}</dt><dd>${esc(L(c.measures))}</dd>
      <dt>${X('colRule')}</dt><dd class="rule">${esc(L(c.rule))}</dd>
      <dt>${X('colWhy')}</dt><dd class="why">${esc(L(c.why))}</dd>
    </dl>
  </div>`).join('');

const html = `<!doctype html>
<html lang="${lang}"><head><meta charset="utf-8">
<title>${lang === 'es' ? 'Metodología GEO — Qué revisamos' : 'GEO Technical Readiness — What We Check'}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Montserrat:wght@600;700;800&family=Manrope:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap">
<style>
:root{--violet-600:#6d4fe0;--violet-50:#f6f3fe;--violet-700:#4834b0;
--emerald-500:#1ea97c;
--ink-950:#08090c;--ink-700:#2a313d;--ink-600:#3d4653;--ink-500:#566172;--ink-400:#757f8f;
--ink-200:#c3c8d0;--ink-100:#e3e6ea;--ink-50:#f4f6f8;
--fd:"Montserrat","Helvetica Neue",Arial,sans-serif;--fb:"Manrope","Helvetica Neue",Arial,sans-serif;--fm:"JetBrains Mono",ui-monospace,Menlo,monospace}
*{box-sizing:border-box}
@page{size:A4;margin:18mm 14mm}
body{font-family:var(--fb);color:var(--ink-700);margin:0;padding:0 28px 70px;background:#fff;font-size:14px;line-height:1.55;-webkit-print-color-adjust:exact;print-color-adjust:exact}
.wrap{max-width:900px;margin:0 auto}
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
.layer{margin-bottom:38px;page-break-inside:auto}
.lhead{display:flex;justify-content:space-between;align-items:flex-start;gap:20px;border-bottom:1px solid var(--ink-200);padding-bottom:11px;margin-bottom:6px;flex-wrap:wrap}
h2.lt{font-family:var(--fd);font-size:22px;font-weight:700;color:var(--ink-950);margin:0;letter-spacing:-.015em}
.lq{font-size:15px;color:var(--violet-600);font-weight:600;margin-top:3px}
.lmeta{text-align:right;font-size:12px;color:var(--ink-500);flex:none}
.lmeta b{display:block;font-family:var(--fm);font-size:10px;letter-spacing:.09em;text-transform:uppercase;color:var(--ink-400);font-weight:600}
.lsum{font-size:13.5px;color:var(--ink-600);margin:9px 0 4px;max-width:95ch}
.lown{font-size:13px;color:var(--ink-600);margin-bottom:13px}
.lown b{color:var(--ink-950)}
.lintro{break-inside:avoid;page-break-inside:avoid}
/* One block per check. A five-column table of prose cannot fit A4 portrait, and the reader
   should not have to switch their print dialog to landscape to read the document. */
.checks{display:flex;flex-direction:column;gap:12px}
.chk{border:1px solid var(--ink-100);border-radius:9px;padding:13px 15px;background:#fff;break-inside:avoid;page-break-inside:avoid}
.chk-head{display:flex;align-items:baseline;gap:9px;flex-wrap:wrap;margin-bottom:9px;padding-bottom:8px;border-bottom:1px solid var(--ink-100)}
.chk-n{font-family:var(--fm);font-size:10.5px;color:var(--ink-400);min-width:16px}
.chk-name{font-family:var(--fd);font-size:13.5px;font-weight:700;color:var(--ink-950);flex:1 1 auto}
.chk-id{font-family:var(--fm);font-size:10px;color:var(--ink-400)}
.chk-body{display:grid;grid-template-columns:max-content 1fr;gap:5px 16px;margin:0}
.chk-body dt{font-family:var(--fm);font-size:8.6px;letter-spacing:.1em;text-transform:uppercase;color:var(--ink-400);font-weight:600;padding-top:2px;white-space:nowrap}
.chk-body dd{margin:0;font-size:12px;line-height:1.5;color:var(--ink-600)}
.chk-body dd.rule{color:var(--ink-950)}
.chk-body dd.why{color:var(--ink-500)}
@media (max-width:560px){ .chk-body{grid-template-columns:1fr;gap:2px} .chk-body dt{padding-top:7px} }
.unscored{display:inline-block;margin-top:5px;font-family:var(--fm);font-size:9px;letter-spacing:.07em;text-transform:uppercase;background:var(--ink-100);color:var(--ink-600);padding:2px 7px;border-radius:99px}
@media print{
  /* Portrait by default, so nothing depends on the reader changing their print dialog. */
  body{padding:0;font-size:10pt}
  .wrap{max-width:none;width:100%}
  h1{font-size:24pt}
  .lede{font-size:11pt}
  .chk{break-inside:avoid;page-break-inside:avoid}
  .chk-head{break-after:avoid;page-break-after:avoid}
  .chk-body dd{font-size:8.8pt;line-height:1.45}
  .chk{padding:10px 12px}
  .chk-head{margin-bottom:7px;padding-bottom:6px}
  .chk-body{gap:4px 13px}
  /* Never strand a layer heading at the foot of a page. */
  .lintro{break-inside:avoid;page-break-inside:avoid;break-after:avoid;page-break-after:avoid}
  h1,h2,.principle h2{break-after:avoid;page-break-after:avoid}
  p,dd{orphans:3;widows:3}
  .principle{break-inside:avoid;page-break-inside:avoid}
  .layer{break-inside:auto;page-break-inside:auto}
  header{break-after:avoid}
}
footer{margin-top:44px;padding-top:16px;border-top:1px solid var(--ink-200);font-family:var(--fm);font-size:10px;letter-spacing:.06em;color:var(--ink-400);display:flex;justify-content:space-between;flex-wrap:wrap;gap:10px}
</style></head><body><div class="wrap">

<header>
  <div class="brand"><span class="dot"></span>${X('brand')}</div>
  <h1>${X('h1')}</h1>
  <p class="lede">${X('lede')}</p>
  <div class="stats">
    <div class="stat"><div class="v">${total}</div><div class="l">${X('statFactors')}</div></div>
    <div class="stat"><div class="v">${layers.length}</div><div class="l">${X('statLayers')}</div></div>
    <div class="stat"><div class="v">${scoredCount}</div><div class="l">${X('statScored')}</div></div>
    <div class="stat"><div class="v">${total - scoredCount}</div><div class="l">${X('statContext')}</div></div>
  </div>
</header>

<div class="principle">
  <h2>${X('whyTitle')}</h2>
  <p>${X('why1')}</p>
  <p>${X('why2')}</p>
  <p>${X('why3')}</p>
</div>

${layers.map(l => `
<div class="layer">
  <div class="lintro">
  <div class="lhead">
    <div>
      <h2 class="lt">${esc(L(l.title))}</h2>
      <div class="lq">${esc(L(l.question))}</div>
    </div>
    <div class="lmeta">
      <b>${X('lblChecks')}</b>${l.checks.length}
      <b style="margin-top:7px">${X('lblScoring')}</b>${l.scored ? X('counts') : X('separate')}
    </div>
  </div>
  <p class="lsum">${esc(L(l.summary))}</p>
  <p class="lown"><b>${X('whoActs')}:</b> ${esc(L(l.owner))}</p>
  </div>
  <div class="checks">${rows(l)}</div>
</div>`).join('')}

<footer>
  <span>${X('footer')}</span>
  <span>${X('generated')} · ${new Date().toISOString().slice(0, 10)}</span>
</footer>
</div></body></html>`;

writeFileSync(out, html);
console.log(`checklist written: ${out} — ${total} checks across ${layers.length} layers`);
