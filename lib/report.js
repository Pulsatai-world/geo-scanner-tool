// Builds a client-facing GEO technical readiness report from a scan payload.
//
// Used by scan.js (--html / --pdf) and by Hieronymus's /api/geo-report, which serves it straight
// to the browser — so it has to read well on screen and print well to PDF from the same markup.
// The page is laid out as a sheet on a tinted ground: on screen that gives the content real
// margins instead of running edge to edge, and in print the ground drops away and the sheet
// becomes the page.
//
// Spanish is the default and is written natively, matching the scanner's own output. Every figure
// is read from the scan payload — nothing here asserts a fact the scan did not measure — and
// where the scan could not establish something the report says so rather than filling the gap.

import { localize } from '../netlify/functions/lib/i18n.js';

const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

const TX = {
  brand:        { es: 'Akore Labs · Preparación técnica GEO', en: 'Akore Labs · GEO Technical Readiness' },
  sub:          { es: 'Evaluación técnica en página para la visibilidad en motores generativos', en: 'On-page technical assessment for generative engine visibility' },
  scanned:      { es: 'Analizado', en: 'Scanned' },
  pagesAnalysed:{ es: 'Páginas analizadas', en: 'Pages analysed' },
  checksRun:    { es: 'Comprobaciones', en: 'Checks run' },
  rubric:       { es: 'Baremo', en: 'Rubric' },
  readiness:    { es: 'Preparación en página', en: 'On-Page Readiness' },
  incomplete:   { es: 'Análisis incompleto', en: 'Scan incomplete' },
  noScore:      { es: 'Sin puntuación:<br>sitio no accesible', en: 'No score —<br>site not reachable' },
  noScoreCap:   { es: 'No se ha medido nada, así que no se informa ninguna puntuación.', en: 'Nothing was measured, so no score is reported.' },
  scoreCap:     { es: 'Media de las capas puntuables sobre {n} página(s). El acceso se informa aparte.', en: 'Measures on-page factors across the {n} page(s) analysed. Crawlability is reported separately.' },
  notInScore:   { es: 'se informa aparte', en: 'reported separately' },
  execSummary:  { es: 'Resumen ejecutivo', en: 'Executive summary' },
  unreachHead:  { es: 'El escáner no ha podido acceder al sitio; no se informa puntuación.', en: 'The scanner could not reach this site — no score is reported.' },
  unreachNote:  { es: '<b>Esto no es un hallazgo sobre el sitio.</b> No se ha medido nada, así que nada en este informe debe leerse como una valoración de su calidad.', en: '<b>This is not a finding about the site.</b> Nothing was measured, so nothing in this report should be read as an assessment of its quality.' },
  headlineThin: { es: 'Nada bloquea a los rastreadores de IA. Lo que ocurre es que hay muy poco que encontrar.', en: 'Nothing is blocking AI crawlers. There is very little for them to find.' },
  headlineNorm: { es: 'Evaluación técnica en página', en: 'On-page technical assessment' },
  summaryLine:  { es: 'El sitio era accesible y se han podido analizar {p} página(s) con {c} comprobaciones. {b}', en: 'The site was reachable and {p} page(s) could be analysed across {c} checks. {b}' },
  noBlockers:   { es: 'No se han encontrado bloqueos de rastreo.', en: 'No crawlability blockers were found.' },
  someBlockers: { es: '{n} bloqueo(s) de rastreo requieren atención antes que nada.', en: '{n} crawlability blocker(s) require attention before anything else.' },
  depthLine:    { es: 'Profundidad de contenido: <b>{w} palabras</b> de contenido principal en la portada, con <b>{s}</b>. Los motores generativos citan material concreto y con sustancia, así que la profundidad y la estructura determinan cuánto hay de donde tirar.', en: 'Content depth: <b>{w} words</b> of main content on the homepage, with <b>{s}</b>. Generative engines cite specific, substantive material, so depth and structure determine how much there is to draw on.' },
  noSchema:     { es: 'ningún dato estructurado', en: 'no structured data' },
  someSchema:   { es: '{n} tipo(s) de datos estructurados', en: '{n} structured data type(s)' },
  statPages:    { es: 'Páginas analizadas', en: 'Pages analysed' },
  statWords:    { es: 'Palabras de contenido principal', en: 'Words of main content' },
  statSchema:   { es: 'Tipos de datos estructurados', en: 'Structured data types' },
  statKeyPages: { es: 'Tipos de página clave presentes', en: 'Key page types present' },
  crawlTitle:   { es: 'Acceso y rastreo', en: 'Crawlability & access' },
  crawlLede:    { es: 'Si los rastreadores y los motores de búsqueda pueden alcanzar y leer el sitio. Se informa aparte de la puntuación porque depende del hosting y de la red, no del trabajo en página.', en: 'Whether AI crawlers and search engines can reach and read the site. Reported separately from the score because it is hosting and network territory rather than on-page work.' },
  manualTitle:  { es: 'Requiere verificación manual', en: 'Requires manual verification' },
  findingsTitle:{ es: 'Hallazgos y correcciones', en: 'Findings & remediation' },
  findingsLede: { es: '{n} punto(s) que requieren acción, agrupados por área. Cada uno indica el cambio concreto necesario.', en: '{n} item(s) requiring action, grouped by area. Each carries the specific change needed.' },
  detailTitle:  { es: 'Resultados detallados', en: 'Detailed check results' },
  detailLede:   { es: 'Resultados completos en página y de accesibilidad para agentes en {u}.', en: 'Full on-page and agentic-accessibility results for {u}.' },
  methodTitle:  { es: 'Método y limitaciones', en: 'Method & limitations' },
  method1:      { es: 'Las comprobaciones se realizan sobre el HTML que devuelve cada servidor, con siete user-agents (un navegador, GPTBot, ClaudeBot, Googlebot, OAI-SearchBot, PerplexityBot y uno genérico), con un máximo de {c} peticiones simultáneas y un tiempo de espera de {t} segundos. robots.txt se evalúa contra 18 identificadores de rastreadores, separando los que recuperan páginas en el momento de responder de los que recogen contenido para entrenamiento. El tiempo de respuesta es el más rápido de dos muestras aisladas: una señal orientativa, no un perfil de rendimiento.', en: 'Checks are performed against the HTML each server returns, using seven user-agents (a standard browser, GPTBot, ClaudeBot, Googlebot, OAI-SearchBot, PerplexityBot and a plain default), at a maximum of {c} concurrent requests with a {t}-second timeout. robots.txt is evaluated against 18 crawler tokens, separated into those that fetch pages live at answer time and those that collect content for model training. Response time is the fastest of two isolated samples and is a directional signal, not a performance profile.' },
  method2:      { es: 'Lo que no se ha podido establecer se informa como <b>sin verificar</b> y queda excluido de la puntuación, en lugar de suponerse. Cuando un sitio está detrás de un CDN o un WAF, la prueba de user-agents no puede confirmar si los rastreadores de IA tienen paso, porque esos servicios identifican a los bots verificados por rango de IP y no por la cadena de user-agent: esos casos se marcan para confirmación manual.', en: 'Checks that could not be established are reported as <b>unverified</b> rather than as passes or failures, and are excluded from the score entirely. Where a site sits behind a CDN or WAF, user-agent testing cannot confirm whether AI crawlers are permitted, because those services identify verified bots by source IP range rather than user-agent string — such cases are flagged for manual confirmation.' },
  method3:      { es: 'Esta evaluación cubre <b>únicamente factores técnicos en página</b>. No mide la visibilidad actual en respuestas de IA, la presencia de la entidad fuera del sitio ni la cuota de voz frente a competidores: eso se mide por separado en la auditoría de visibilidad posterior.', en: 'This assessment covers <b>on-site technical factors only</b>. It does not measure current visibility in AI answers, off-site entity presence, or competitive share of voice — each measured separately in the visibility audit that follows.' },
  howToFix:     { es: 'Cómo resolverlo', en: 'How to fix' },
  thCheck:      { es: 'Comprobación', en: 'Check' },
  thStatus:     { es: 'Estado', en: 'Status' },
  thDetail:     { es: 'Detalle', en: 'Detail' },
  pillUnver:    { es: 'SIN VERIFICAR', en: 'UNVERIFIED' },
  footer:       { es: 'Akore Labs — Informe de preparación técnica GEO', en: 'Akore Labs — GEO Technical Readiness Report' }
};
const PILL = {
  es: { PASS: 'CORRECTO', WARNING: 'AVISO', FAIL: 'FALLO', INFO: 'INFO' },
  en: { PASS: 'PASS', WARNING: 'WARNING', FAIL: 'FAIL', INFO: 'INFO' }
};

export function buildReportHtml(rawData, lang = 'es') {
  // Resolved once, up front: every bilingual field in the payload becomes a plain string for the
  // chosen language, so no template expression can accidentally miss one and print an object.
  const data = localize(rawData, lang);
  const T = (k, vars = {}) => String((TX[k] || {})[lang] ?? (TX[k] || {}).es ?? '')
    .replace(/\{(\w+)\}/g, (_, v) => (vars[v] ?? ''));

  const host = (() => { try { return new URL(data.input.url).hostname; } catch { return data.input.url; } })();
  const scanDate = new Date(data.scannedAt).toLocaleDateString(lang === 'es' ? 'es-ES' : 'en-GB', { day: 'numeric', month: 'long', year: 'numeric' });

  const s = data.score;
  const q = data.scanQuality || {};
  const homepage = data.section2.pages[0];
  const wordCount = homepage ? homepage.wordCount : 0;
  const schemaTypes = homepage ? homepage.schemaTypes : [];
  const pagesFound = data.pageDiscovery.categories.filter(c => c.found).length;
  const unverified = data.section1.checks.filter(c => c.status === 'INCONCLUSIVE');

  const findings = data.prioritizedFindings.filter(f => f.priority !== 'unverified');
  const bySection = {};
  findings.forEach(f => { (bySection[f.section] = bySection[f.section] || []).push(f); });

  const totalChecks = data.section1.checks.length
    + data.section2.pages.reduce((n, p) => n + p.checks.length, 0)
    + data.section4.pages.reduce((n, p) => n + p.checks.length, 0);

  const pillText = st => st === 'INCONCLUSIVE' ? T('pillUnver') : ((PILL[lang] || PILL.es)[st] || st);
  const pill = st => `<span class="pill pill-${st}">${pillText(st)}</span>`;
  const rows = checks => checks.map(c => `
    <tr><td class="c-name">${esc(c.title)}</td><td class="c-status">${pill(c.status)}</td><td class="c-detail">${esc(c.detail)}</td></tr>`).join('');

  const findingBlocks = Object.entries(bySection).map(([section, items]) => `
    <div class="fgroup"><h3>${esc(section)}</h3>
      ${items.map(f => `
        <div class="fcard f-${f.status}">
          <div class="fhead"><span class="ftitle">${esc(f.title)}</span>${pill(f.status)}</div>
          <p class="fdetail">${esc(f.detail)}</p>
          ${f.howToFix ? `<div class="ffix"><b>${T('howToFix')}</b> ${esc(f.howToFix)}</div>` : ''}
        </div>`).join('')}
    </div>`).join('');

  // Layer scores, not the retired section names — those reported the same figure twice.
  const layerCards = (data.layers || []).map(l => `
    <div class="sub${l.scored ? '' : ' muted'}">
      <div class="l">${esc(String(l.title).replace(/^(?:Layer|Capa) \d+ — /, ''))}</div>
      <div class="v">${l.score === null ? '—' : l.score}</div>
      ${l.scored ? '' : `<div class="n">${T('notInScore')}</div>`}
    </div>`).join('');

  const thin = schemaTypes.length === 0 && wordCount < 800;
  const summary = !data.reachable ? `
    <div class="callout warn">
      <h4>${T('unreachHead')}</h4>
      <p>${esc((data.section1.checks.find(c => c.id === 'site-reachability') || {}).detail || '')}</p>
      <p>${T('unreachNote')}</p>
    </div>` : `
    <div class="callout">
      <h4>${thin ? T('headlineThin') : T('headlineNorm')}</h4>
      <p>${T('summaryLine', { p: q.pagesAnalyzed, c: totalChecks, b: s.blockers.count === 0 ? T('noBlockers') : T('someBlockers', { n: s.blockers.count }) })}</p>
      <p>${T('depthLine', { w: wordCount, s: schemaTypes.length === 0 ? T('noSchema') : T('someSchema', { n: schemaTypes.length }) })}</p>
    </div>
    <div class="stats">
      <div class="stat"><div class="v">${q.pagesAnalyzed}</div><div class="l">${T('statPages')}</div></div>
      <div class="stat"><div class="v">${wordCount}</div><div class="l">${T('statWords')}</div></div>
      <div class="stat"><div class="v">${schemaTypes.length}</div><div class="l">${T('statSchema')}</div></div>
      <div class="stat"><div class="v">${pagesFound}/5</div><div class="l">${T('statKeyPages')}</div></div>
    </div>`;

  return `<!doctype html>
<html lang="${lang}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(host)} — ${lang === 'es' ? 'Preparación técnica GEO' : 'GEO Technical Readiness'}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@600;700;800&family=Manrope:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<style>
:root{
  --violet-600:#6d4fe0; --violet-50:#f6f3fe;
  --emerald-700:#0f7d5b; --emerald-500:#1ea97c; --emerald-100:#d5f4e8; --emerald-50:#eefaf4;
  --ink-950:#08090c; --ink-800:#1a1f28; --ink-700:#2a313d; --ink-600:#3d4653; --ink-500:#566172;
  --ink-400:#757f8f; --ink-300:#969aa3; --ink-200:#c3c8d0; --ink-100:#e3e6ea; --ink-50:#f4f6f8;
  --warning:#d99312; --warning-100:#f8ecd0; --danger:#d94a4a; --danger-100:#f7dcdc;
  --fd:"Montserrat","Helvetica Neue",Arial,sans-serif;
  --fb:"Manrope","Helvetica Neue",Arial,sans-serif;
  --fm:"JetBrains Mono",ui-monospace,Menlo,monospace;
}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
/* On screen the report is a sheet on a tinted ground — that is what gives the content real
   margins instead of running edge to edge. In print the ground drops away and the sheet is
   the page. */
body{background:var(--ink-50);font-family:var(--fb);color:var(--ink-700);font-size:14px;line-height:1.6;-webkit-font-smoothing:antialiased}
.sheet{max-width:940px;margin:32px auto;background:#fff;border:1px solid var(--ink-100);border-radius:14px;box-shadow:0 6px 24px rgba(16,19,25,.07);padding:44px 52px 52px}
h1,h2,h3,h4{font-family:var(--fd);color:var(--ink-950);margin:0}
p{margin:0 0 10px}
b,strong{color:var(--ink-950);font-weight:700}

.masthead{border-bottom:2.5px solid var(--ink-950);padding-bottom:14px;margin-bottom:22px}
.brandrow{display:flex;align-items:center;gap:8px;margin-bottom:14px}
.dot{width:8px;height:8px;border-radius:50%;background:var(--emerald-500)}
.brand{font-family:var(--fm);font-size:10.5px;letter-spacing:.16em;text-transform:uppercase;color:var(--ink-500);font-weight:600}
h1{font-size:30px;font-weight:800;letter-spacing:-.025em;line-height:1.06;margin-bottom:6px;word-break:break-word}
.sub{font-size:15px;color:var(--ink-500);font-weight:500}
.metarow{display:flex;gap:26px;margin-top:14px;font-family:var(--fm);font-size:10.5px;letter-spacing:.05em;color:var(--ink-400);flex-wrap:wrap}
.metarow b{color:var(--ink-700);font-weight:500}

.scoreband{display:flex;gap:14px;margin-bottom:20px;flex-wrap:wrap;page-break-inside:avoid}
.scorebox{background:var(--ink-950);color:#fff;border-radius:11px;padding:20px 24px;min-width:230px;flex:0 0 auto;display:flex;flex-direction:column;justify-content:center}
.scorelabel{font-family:var(--fm);font-size:9.5px;letter-spacing:.15em;text-transform:uppercase;color:#b9b2dd;margin-bottom:6px}
.scorenum{font-family:var(--fd);font-size:46px;font-weight:800;line-height:.85;color:var(--emerald-500);letter-spacing:-.03em}
.scoreden{font-size:13px;color:#b9b2dd;font-weight:600}
.scorecap{font-size:11px;color:#e6e2f5;margin-top:9px;line-height:1.45;max-width:34ch}
.noscore{font-family:var(--fd);font-size:19px;font-weight:800;color:#e0b23b;line-height:1.2}
.subscores{flex:1 1 340px;display:grid;grid-template-columns:repeat(auto-fit,minmax(118px,1fr));gap:10px}
.sub{border:1px solid var(--ink-100);border-radius:10px;padding:14px;display:flex;flex-direction:column;gap:4px;justify-content:center;background:#fff}
.sub .l{font-family:var(--fm);font-size:9px;letter-spacing:.09em;text-transform:uppercase;color:var(--ink-400);line-height:1.35}
.sub .v{font-family:var(--fd);font-size:24px;font-weight:800;color:var(--violet-600);line-height:1}
.sub.muted .v{color:var(--ink-300)}
.sub .n{font-size:9px;color:var(--ink-400)}

section{margin-top:30px}
h2{font-size:19px;font-weight:700;letter-spacing:-.015em;margin-bottom:6px;padding-bottom:7px;border-bottom:1px solid var(--ink-200)}
.lede{font-size:13px;color:var(--ink-500);margin-bottom:14px}
.callout{border-left:4px solid var(--violet-600);background:var(--violet-50);border-radius:0 9px 9px 0;padding:16px 20px;margin:14px 0;page-break-inside:avoid}
.callout.warn{border-left-color:var(--warning);background:var(--warning-100)}
.callout p:last-child{margin-bottom:0}
.callout h4{font-size:14.5px;margin-bottom:7px;line-height:1.4}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:14px 0;page-break-inside:avoid}
.stat{border:1px solid var(--ink-100);border-radius:10px;padding:14px 16px;background:var(--ink-50)}
.stat .v{font-family:var(--fd);font-size:22px;font-weight:800;color:var(--ink-950);line-height:1.05}
.stat .l{font-size:10.5px;color:var(--ink-500);margin-top:4px;line-height:1.4}

.pill{display:inline-block;font-family:var(--fm);font-size:9px;font-weight:600;letter-spacing:.08em;padding:3px 8px;border-radius:99px;white-space:nowrap}
.pill-PASS{background:var(--emerald-100);color:var(--emerald-700)}
.pill-WARNING{background:var(--warning-100);color:#8a6a12}
.pill-FAIL{background:var(--danger-100);color:#b03a3a}
.pill-INCONCLUSIVE{background:var(--ink-100);color:var(--ink-600)}
.pill-INFO{background:var(--violet-50);color:var(--violet-600)}

.fgroup{margin-bottom:16px}
.fgroup h3{font-size:14px;font-weight:700;color:var(--ink-800);margin-bottom:9px}
.fcard{border:1px solid var(--ink-100);border-left:4px solid var(--ink-300);border-radius:0 9px 9px 0;padding:13px 16px;margin-bottom:10px;page-break-inside:avoid}
.fcard.f-FAIL{border-left-color:var(--danger);background:#fdf7f7}
.fcard.f-WARNING{border-left-color:var(--warning);background:#fdfaf3}
.fhead{display:flex;justify-content:space-between;align-items:baseline;gap:12px;margin-bottom:6px}
.ftitle{font-family:var(--fd);font-size:13.5px;font-weight:700;color:var(--ink-950)}
.fdetail{font-size:12.5px;margin-bottom:8px;color:var(--ink-600)}
.ffix{font-size:12px;background:var(--emerald-50);border-radius:7px;padding:10px 12px;color:var(--ink-700);line-height:1.55}
.ffix b{display:block;font-family:var(--fm);font-size:9px;letter-spacing:.11em;text-transform:uppercase;color:var(--emerald-700);margin-bottom:4px}

.tablewrap{overflow-x:auto;border:1px solid var(--ink-100);border-radius:10px}
table{width:100%;border-collapse:collapse;font-size:12px;min-width:520px}
thead th{background:var(--ink-50);text-align:left;padding:9px 12px;font-family:var(--fm);font-size:9px;letter-spacing:.1em;text-transform:uppercase;color:var(--ink-500);border-bottom:1px solid var(--ink-200);font-weight:600}
td{padding:10px 12px;border-bottom:1px solid var(--ink-100);vertical-align:top}
tr{page-break-inside:avoid}
tbody tr:last-child td{border-bottom:none}
.c-name{font-weight:600;color:var(--ink-950);width:24%}
.c-status{width:12%}
.c-detail{color:var(--ink-600);line-height:1.5}

.note{font-size:12px;color:var(--ink-500);line-height:1.6}
footer{margin-top:34px;padding-top:14px;border-top:1px solid var(--ink-200);font-family:var(--fm);font-size:9.5px;letter-spacing:.06em;color:var(--ink-400);display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px}

@media (max-width:720px){ .sheet{margin:0;border-radius:0;border:none;padding:26px 18px 40px} h1{font-size:24px} }

@page{size:A4;margin:13mm}
@media print{
  body{background:#fff;font-size:10.2pt}
  .sheet{max-width:none;margin:0;border:none;border-radius:0;box-shadow:none;padding:0}
  h1{font-size:23pt}
  .scorenum{font-size:38pt}
  .tablewrap{overflow:visible}
  h2,h3,.lede{page-break-after:avoid}
}
</style></head><body><div class="sheet">

<div class="masthead">
  <div class="brandrow"><span class="dot"></span><span class="brand">${T('brand')}</span></div>
  <h1>${esc(host)}</h1>
  <div class="sub">${T('sub')}</div>
  <div class="metarow">
    <span>${T('scanned')} <b>${esc(scanDate)}</b></span>
    <span>${T('pagesAnalysed')} <b>${q.pagesAnalyzed ?? 0}</b></span>
    <span>${T('checksRun')} <b>${totalChecks}</b></span>
    <span>${T('rubric')} <b>v${s.rubricVersion}</b></span>
  </div>
</div>

<div class="scoreband">
  <div class="scorebox">
    <div class="scorelabel">${data.reachable && s.overall !== null ? T('readiness') : T('incomplete')}</div>
    ${data.reachable && s.overall !== null
      ? `<div><span class="scorenum">${s.overall}</span> <span class="scoreden">/ 100</span></div>
         <div class="scorecap">${T('scoreCap', { n: q.pagesAnalyzed })}</div>`
      : `<div class="noscore">${T('noScore')}</div>
         <div class="scorecap">${T('noScoreCap')}</div>`}
  </div>
  <div class="subscores">${layerCards}</div>
</div>

<section>
  <h2>${T('execSummary')}</h2>
  ${summary}
</section>

<section>
  <h2>${T('crawlTitle')}</h2>
  <p class="lede">${T('crawlLede')}</p>
  <div class="tablewrap"><table><thead><tr><th>${T('thCheck')}</th><th>${T('thStatus')}</th><th>${T('thDetail')}</th></tr></thead>
  <tbody>${rows(data.section1.checks)}</tbody></table></div>
  ${unverified.length ? `<div class="callout" style="margin-top:14px">
    <h4>${T('manualTitle')}</h4>
    ${unverified.map(c => `<p><b>${esc(c.title)}.</b> ${esc(c.detail)}${c.howToFix ? ` <i>${esc(c.howToFix)}</i>` : ''}</p>`).join('')}
  </div>` : ''}
</section>

${findings.length ? `<section>
  <h2>${T('findingsTitle')}</h2>
  <p class="lede">${T('findingsLede', { n: findings.length })}</p>
  ${findingBlocks}
</section>` : ''}

${homepage ? `<section>
  <h2>${T('detailTitle')}</h2>
  <p class="lede">${T('detailLede', { u: esc(homepage.url) })}</p>
  <div class="tablewrap"><table><thead><tr><th>${T('thCheck')}</th><th>${T('thStatus')}</th><th>${T('thDetail')}</th></tr></thead>
  <tbody>${rows(homepage.checks)}${data.section4.pages[0] ? rows(data.section4.pages[0].checks) : ''}</tbody></table></div>
</section>` : ''}

<section>
  <h2>${T('methodTitle')}</h2>
  <p class="note">${T('method1', { c: q.maxConcurrency, t: Math.round((q.timeoutMs || 20000) / 1000) })}</p>
  <p class="note" style="margin-top:8px">${T('method2')}</p>
  <p class="note" style="margin-top:8px">${T('method3')}</p>
</section>

<footer>
  <span>${T('footer')}</span>
  <span>${esc(host)} · ${esc(scanDate)}</span>
</footer>
</div></body></html>`;
}
