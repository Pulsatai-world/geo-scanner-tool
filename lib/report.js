// Builds a print-ready GEO technical readiness report from a scan payload.
// Used by scan.js (--html / --pdf). Lives in the repo rather than being generated ad hoc, so a
// client report can be reproduced exactly from a stored scan result.
//
// Every figure is read from the scan payload — nothing here asserts a fact the scan did not
// measure. Where the scan could not establish something, the report says so rather than filling
// the gap.

const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

export function buildReportHtml(data) {
  const host = (() => { try { return new URL(data.input.url).hostname; } catch { return data.input.url; } })();
  const scanDate = new Date(data.scannedAt).toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' });

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

  const pill = st => `<span class="pill pill-${st}">${st === 'INCONCLUSIVE' ? 'UNVERIFIED' : st}</span>`;
  const checkRows = checks => checks.map(c => `
    <tr><td class="c-name">${esc(c.title)}</td><td class="c-status">${pill(c.status)}</td><td class="c-detail">${esc(c.detail)}</td></tr>`).join('');

  const findingBlocks = Object.entries(bySection).map(([section, items]) => `
    <div class="fgroup"><h3>${esc(section)}</h3>
      ${items.map(f => `
        <div class="fcard f-${f.status}">
          <div class="fhead"><span class="ftitle">${esc(f.title)}</span>${pill(f.status)}</div>
          <p class="fdetail">${esc(f.detail)}</p>
          ${f.howToFix ? `<div class="ffix"><b>How to fix</b> ${esc(f.howToFix)}</div>` : ''}
        </div>`).join('')}
    </div>`).join('');

  // The unreachable case gets a different opening entirely: no score, and an explicit statement
  // that nothing here is a judgement about the site.
  const summary = !data.reachable ? `
    <div class="callout warn">
      <h4>The scanner could not reach this site — no score is reported.</h4>
      <p>${esc((data.section1.checks.find(c => c.id === 'site-reachability') || {}).detail || '')}</p>
      <p><b>This is not a finding about the site.</b> Nothing was measured, so nothing in this report should be read as an assessment of its quality.</p>
    </div>` : `
    <div class="callout">
      <h4>${schemaTypes.length === 0 && wordCount < 800 ? 'Nothing is blocking AI crawlers. There is very little for them to find.' : 'On-page technical assessment'}</h4>
      <p>The site was reachable and ${q.pagesAnalyzed} page${q.pagesAnalyzed === 1 ? '' : 's'} could be analysed across ${totalChecks} checks. ${s.blockers.count === 0 ? 'No crawlability blockers were found.' : `${s.blockers.count} crawlability blocker${s.blockers.count === 1 ? '' : 's'} require attention before anything else.`}</p>
      <p>Content depth: <b>${wordCount} words</b> of main content on the homepage, with <b>${schemaTypes.length === 0 ? 'no structured data' : schemaTypes.length + ' structured data type(s)'}</b>. Generative engines cite specific, substantive material, so depth and structure determine how much there is to draw on.</p>
    </div>
    <div class="stats">
      <div class="stat"><div class="v">${q.pagesAnalyzed}</div><div class="l">Page${q.pagesAnalyzed === 1 ? '' : 's'} analysed</div></div>
      <div class="stat"><div class="v">${wordCount}</div><div class="l">Words of main content</div></div>
      <div class="stat"><div class="v">${schemaTypes.length}</div><div class="l">Structured data types</div></div>
      <div class="stat"><div class="v">${pagesFound}/5</div><div class="l">Key page types present</div></div>
    </div>`;

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>GEO Technical Readiness — ${esc(host)}</title>
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
  --font-display:"Montserrat","Helvetica Neue",Arial,sans-serif;
  --font-body:"Manrope","Helvetica Neue",Arial,sans-serif;
  --font-mono:"JetBrains Mono",ui-monospace,Menlo,monospace;
}
*{box-sizing:border-box}
@page{size:A4;margin:14mm 13mm 16mm}
html,body{margin:0;padding:0}
body{font-family:var(--font-body);color:var(--ink-700);font-size:10.2pt;line-height:1.5;background:#fff;-webkit-print-color-adjust:exact;print-color-adjust:exact}
h1,h2,h3,h4{font-family:var(--font-display);color:var(--ink-950);margin:0}
p{margin:0 0 9px}
b,strong{color:var(--ink-950);font-weight:700}
.masthead{border-bottom:2.5pt solid var(--ink-950);padding-bottom:11px;margin-bottom:18px}
.brandrow{display:flex;align-items:center;gap:8px;margin-bottom:12px}
.dot{width:8px;height:8px;border-radius:50%;background:var(--emerald-500)}
.brand{font-family:var(--font-mono);font-size:7.6pt;letter-spacing:.18em;text-transform:uppercase;color:var(--ink-500);font-weight:600}
h1{font-size:23pt;font-weight:800;letter-spacing:-.025em;line-height:1.05;margin-bottom:5px}
.sub{font-size:11pt;color:var(--ink-500);font-weight:500}
.metarow{display:flex;gap:26px;margin-top:12px;font-family:var(--font-mono);font-size:7.8pt;letter-spacing:.05em;color:var(--ink-400);flex-wrap:wrap}
.metarow b{color:var(--ink-700);font-weight:500}
.scoreband{display:flex;gap:16px;margin-bottom:16px;page-break-inside:avoid}
.scorebox{background:var(--ink-950);color:#fff;border-radius:9px;padding:16px 20px;min-width:175px;display:flex;flex-direction:column;justify-content:center}
.scorelabel{font-family:var(--font-mono);font-size:6.9pt;letter-spacing:.15em;text-transform:uppercase;color:#b9b2dd;margin-bottom:5px}
.scorenum{font-family:var(--font-display);font-size:38pt;font-weight:800;line-height:.85;color:var(--emerald-500);letter-spacing:-.03em}
.scoreden{font-size:10pt;color:#b9b2dd;font-weight:600}
.scorecap{font-size:8.2pt;color:#e6e2f5;margin-top:7px;line-height:1.35}
.noscore{font-family:var(--font-display);font-size:14pt;font-weight:800;color:#e0b23b;line-height:1.15}
.subscores{flex:1;display:grid;grid-template-columns:repeat(4,1fr);gap:9px}
.sub{border:1px solid var(--ink-100);border-radius:8px;padding:10px 11px;display:flex;flex-direction:column;gap:3px}
.sub .l{font-family:var(--font-mono);font-size:6.6pt;letter-spacing:.09em;text-transform:uppercase;color:var(--ink-400);line-height:1.3}
.sub .v{font-family:var(--font-display);font-size:19pt;font-weight:800;color:var(--violet-600);line-height:1}
.sub.muted .v{color:var(--ink-300)}
.sub .n{font-size:7pt;color:var(--ink-400)}
section{margin-top:20px}
h2{font-size:13pt;font-weight:700;letter-spacing:-.01em;margin-bottom:4px;padding-bottom:5px;border-bottom:1px solid var(--ink-200)}
.lede{font-size:9.6pt;color:var(--ink-500);margin-bottom:11px}
.callout{border-left:3pt solid var(--violet-600);background:var(--violet-50);border-radius:0 7px 7px 0;padding:12px 15px;margin:11px 0;page-break-inside:avoid}
.callout.warn{border-left-color:var(--warning);background:var(--warning-100)}
.callout p:last-child{margin-bottom:0}
.callout h4{font-size:10pt;margin-bottom:5px}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:9px;margin:12px 0;page-break-inside:avoid}
.stat{border:1px solid var(--ink-100);border-radius:8px;padding:10px 12px;background:var(--ink-50)}
.stat .v{font-family:var(--font-display);font-size:16pt;font-weight:800;color:var(--ink-950);line-height:1.05}
.stat .l{font-size:7.6pt;color:var(--ink-500);margin-top:3px;line-height:1.35}
.pill{display:inline-block;font-family:var(--font-mono);font-size:6.6pt;font-weight:600;letter-spacing:.09em;padding:2.5px 7px;border-radius:99px;white-space:nowrap}
.pill-PASS{background:var(--emerald-100);color:var(--emerald-700)}
.pill-WARNING{background:var(--warning-100);color:#8a6a12}
.pill-FAIL{background:var(--danger-100);color:#b03a3a}
.pill-INCONCLUSIVE{background:var(--ink-100);color:var(--ink-600)}
.fgroup{margin-bottom:13px}
.fgroup h3{font-size:10.2pt;font-weight:700;color:var(--ink-800);margin-bottom:7px}
.fcard{border:1px solid var(--ink-100);border-left:3pt solid var(--ink-300);border-radius:0 7px 7px 0;padding:10px 13px;margin-bottom:7px;page-break-inside:avoid}
.fcard.f-FAIL{border-left-color:var(--danger);background:#fdf7f7}
.fcard.f-WARNING{border-left-color:var(--warning);background:#fdfaf3}
.fhead{display:flex;justify-content:space-between;align-items:baseline;gap:10px;margin-bottom:4px}
.ftitle{font-family:var(--font-display);font-size:9.8pt;font-weight:700;color:var(--ink-950)}
.fdetail{font-size:9.2pt;margin-bottom:6px;color:var(--ink-600)}
.ffix{font-size:8.8pt;background:var(--emerald-50);border-radius:5px;padding:8px 10px;color:var(--ink-700);line-height:1.45}
.ffix b{display:block;font-family:var(--font-mono);font-size:6.8pt;letter-spacing:.11em;text-transform:uppercase;color:var(--emerald-700);margin-bottom:3px}
table{width:100%;border-collapse:collapse;font-size:8.8pt}
thead th{background:var(--ink-50);text-align:left;padding:7px 9px;font-family:var(--font-mono);font-size:6.8pt;letter-spacing:.1em;text-transform:uppercase;color:var(--ink-500);border-bottom:1px solid var(--ink-200);font-weight:600}
td{padding:7px 9px;border-bottom:1px solid var(--ink-100);vertical-align:top}
tr{page-break-inside:avoid}
.c-name{font-weight:600;color:var(--ink-950);width:23%}
.c-status{width:11%}
.c-detail{color:var(--ink-600);line-height:1.42}
.pagebreak{page-break-before:always}
footer{margin-top:22px;padding-top:9px;border-top:1px solid var(--ink-200);font-family:var(--font-mono);font-size:6.9pt;letter-spacing:.06em;color:var(--ink-400);display:flex;justify-content:space-between}
.note{font-size:8.4pt;color:var(--ink-500);line-height:1.5}
</style></head><body>

<div class="masthead">
  <div class="brandrow"><span class="dot"></span><span class="brand">Akore Labs · GEO Technical Readiness</span></div>
  <h1>${esc(host)}</h1>
  <div class="sub">On-page technical assessment for generative engine visibility</div>
  <div class="metarow">
    <span>Scanned <b>${esc(scanDate)}</b></span>
    <span>Pages analysed <b>${q.pagesAnalyzed ?? 0}</b></span>
    <span>Checks run <b>${totalChecks}</b></span>
    <span>Rubric <b>v${s.rubricVersion}</b></span>
  </div>
</div>

<div class="scoreband">
  <div class="scorebox">
    <div class="scorelabel">${data.reachable && s.overall !== null ? 'On-Page Readiness' : 'Scan incomplete'}</div>
    ${data.reachable && s.overall !== null
      ? `<div><span class="scorenum">${s.overall}</span> <span class="scoreden">/ 100</span></div>
         <div class="scorecap">Measures on-page factors across the ${q.pagesAnalyzed} page${q.pagesAnalyzed === 1 ? '' : 's'} analysed. Crawlability is reported separately.</div>`
      : `<div class="noscore">No score —<br>site not reachable</div>
         <div class="scorecap">Nothing was measured, so no score is reported.</div>`}
  </div>
  <div class="subscores">
    <div class="sub"><div class="l">On-Page<br>Signals</div><div class="v">${s.sections.onPage ?? '—'}</div></div>
    <div class="sub"><div class="l">Agentic<br>Browsing</div><div class="v">${s.sections.agenticBrowsing ?? '—'}</div></div>
    <div class="sub"><div class="l">Content<br>Specificity</div><div class="v">${s.sections.contentSpecificity ?? '—'}</div></div>
    <div class="sub muted"><div class="l">Crawlability</div><div class="v">${s.sections.crawlability ?? '—'}</div><div class="n">reported separately</div></div>
  </div>
</div>

<section>
  <h2>Executive summary</h2>
  ${summary}
</section>

<section>
  <h2>Crawlability &amp; access</h2>
  <p class="lede">Whether AI crawlers and search engines can reach and read the site. Reported separately from the score because it is hosting and network territory rather than on-page work.</p>
  <table><thead><tr><th>Check</th><th>Status</th><th>Detail</th></tr></thead>
  <tbody>${checkRows(data.section1.checks)}</tbody></table>
  ${unverified.length ? `<div class="callout" style="margin-top:12px">
    <h4>Requires manual verification</h4>
    ${unverified.map(c => `<p><b>${esc(c.title)}.</b> ${esc(c.detail)}${c.howToFix ? ` <i>${esc(c.howToFix)}</i>` : ''}</p>`).join('')}
  </div>` : ''}
</section>

${findings.length ? `<section class="pagebreak">
  <h2>Findings &amp; remediation</h2>
  <p class="lede">${findings.length} item${findings.length === 1 ? '' : 's'} requiring action, grouped by area. Each carries the specific change needed.</p>
  ${findingBlocks}
</section>` : ''}

${homepage ? `<section class="pagebreak">
  <h2>Detailed check results</h2>
  <p class="lede">Full on-page and agentic-accessibility results for ${esc(homepage.url)}.</p>
  <table><thead><tr><th>Check</th><th>Status</th><th>Detail</th></tr></thead>
  <tbody>${checkRows(homepage.checks)}${data.section4.pages[0] ? checkRows(data.section4.pages[0].checks) : ''}</tbody></table>
</section>` : ''}

<section>
  <h2>Method &amp; limitations</h2>
  <p class="note">Checks are performed against the HTML each server returns, using seven user-agents (a standard browser, GPTBot, ClaudeBot, Googlebot, OAI-SearchBot, PerplexityBot and a plain default), at a maximum of ${q.maxConcurrency} concurrent requests with a ${Math.round((q.timeoutMs || 20000) / 1000)}-second timeout. robots.txt is evaluated against 18 crawler tokens, separated into those that fetch pages live at answer time and those that collect content for model training. Response time is the fastest of two isolated samples and is a directional signal, not a performance profile.</p>
  <p class="note" style="margin-top:7px">Checks that could not be established are reported as <b>unverified</b> rather than as passes or failures, and are excluded from the score entirely. Where a site sits behind a CDN or WAF, user-agent testing cannot confirm whether AI crawlers are permitted, because those services identify verified bots by source IP range rather than user-agent string — such cases are flagged for manual confirmation.</p>
  <p class="note" style="margin-top:7px">This assessment covers <b>on-site technical factors only</b>. It does not measure current visibility in AI answers, off-site entity presence, or competitive share of voice — each measured separately in the visibility audit that follows.</p>
</section>

<footer>
  <span>Akore Labs — GEO Technical Readiness Report</span>
  <span>${esc(host)} · ${esc(scanDate)}</span>
</footer>
</body></html>`;
}
