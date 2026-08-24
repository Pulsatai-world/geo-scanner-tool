#!/usr/bin/env node
//
// Local scan runner.
//
// The hosted scanner runs on Netlify, which means every request leaves from a cloud IP. Edge bot
// protection — Cloudflare's in particular — challenges cloud IPs probabilistically, so a site
// that is perfectly healthy can be refused on one scan and served on the next. That is not
// something the scanner can fix from inside a cloud function; the requests are being judged on
// where they come from, not what they contain.
//
// Running the identical engine from a normal machine sidesteps it completely: the requests leave
// from a residential connection and are treated as ordinary traffic. Same checks, same scoring,
// same output shape as the hosted version — only the origin of the requests differs.
//
// Usage:
//   node scan.js <url>
//   node scan.js <url> --json report.json
//   node scan.js <url> --html report.html --pdf report.pdf
//   node scan.js <url> --pages /about,/services
//   node scan.js <url> --pdf --style report   (branded print layout instead)
//   node scan.js <url> --max-pages 30           (page budget; default 20, max 50)
//   node scan.js <url> --save                   (record a snapshot, show the change since last)
//   node scan.js <url> --vs a.com,b.com         (benchmark against competitors)
//   node scan.js <url> --lang en                (output language; default es)
//
// Two report styles are available. The default matches the hosted tool exactly, because it
// renders the result through index.html itself rather than imitating it. --style report uses the
// standalone print layout in lib/report.js, which is denser and built for handing to a client.
//
import { runScan } from './netlify/functions/lib/scan-engine.js';
import { buildReportHtml } from './lib/report.js';
import { buildWebStyleHtml } from './lib/web-report.js';
import { saveSnapshot, previousSnapshot, snapshot, diff } from './lib/history.js';
import { benchmark } from './lib/benchmark.js';
import { pick, DEFAULT_LOCALE, LOCALES } from './netlify/functions/lib/i18n.js';
import { dirname, resolve as resolvePath } from 'node:path';
import { fileURLToPath } from 'node:url';
import { writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';

const argv = process.argv.slice(2);
const url = argv.find(a => !a.startsWith('--'));
const flag = name => {
  const i = argv.indexOf('--' + name);
  return i >= 0 ? (argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[i + 1] : true) : null;
};

if (!url) {
  console.error('Usage: node scan.js <url> [--json out.json] [--html out.html] [--pdf out.pdf] [--pages /a,/b]');
  process.exit(1);
}

const pagesArg = flag('pages');
const extraPages = typeof pagesArg === 'string' ? pagesArg.split(',').map(p => p.trim()).filter(Boolean) : [];

// Chrome ships on both Windows and macOS in predictable places; we only need it for --pdf, and
// only look for it when that flag is actually used.
const CHROME_PATHS = [
  'C:/Program Files/Google/Chrome/Application/chrome.exe',
  'C:/Program Files (x86)/Google/Chrome/Application/chrome.exe',
  'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  '/usr/bin/google-chrome'
];

// The scan result carries both languages; this only decides what gets printed and written.
const LANG = (() => {
  const v = String(flag('lang') || DEFAULT_LOCALE).toLowerCase();
  return LOCALES.includes(v) ? v : DEFAULT_LOCALE;
})();
const L = v => pick(v, LANG);
const pad = (s, n) => String(s).padEnd(n);
const STATUS_MARK = { PASS: 'ok  ', WARNING: 'warn', FAIL: 'FAIL', INCONCLUSIVE: '  ? ', INFO: 'info' };

(async () => {
  const started = Date.now();
  console.log(`\nScanning ${url} ...`);
  console.log('(running locally — requests leave from this machine, not a cloud IP)\n');

  let result;
  try {
    result = await runScan({ url, extraPages, maxPages: Number(flag('max-pages')) || undefined });
  } catch (err) {
    console.error('Scan could not start:', err.message);
    process.exit(1);
  }

  const elapsed = ((Date.now() - started) / 1000).toFixed(1);

  if (!result.reachable) {
    console.log(LANG === 'es' ? 'EL SITIO TAMPOCO ES ACCESIBLE desde este equipo.' : 'SITE NOT REACHABLE from this machine either.');
    const reach = result.section1.checks.find(c => c.id === 'site-reachability');
    if (reach) {
      console.log('\n' + L(reach.detail));
      if (reach.howToFix) console.log('\n' + (LANG === 'es' ? 'Qué hacer: ' : 'What to do: ') + L(reach.howToFix));
    }
    console.log(`\nNo score is reported — nothing was measured. (${elapsed}s)\n`);
  } else {
    const s = result.score;
    console.log(LANG === 'es' ? `PREPARACIÓN GEO EN PÁGINA: ${s.overall}/100` : `ON-PAGE GEO READINESS: ${s.overall}/100`);
    (result.layers || []).forEach(l => console.log(`  ${pad(L(l.title), 34)} ${l.score === null ? ' —' : String(l.score).padStart(3)}${l.scored ? '' : (LANG === 'es' ? '   (no puntúa)' : '   (not in score)')}`));
    console.log(LANG === 'es'
      ? `  ${result.scanQuality.pagesAnalyzed} página(s) analizada(s) · ${s.blockers.count} bloqueo(s) · ${s.unverified.count} sin verificar · ${elapsed}s\n`
      : `  ${result.scanQuality.pagesAnalyzed} page(s) analysed · ${s.blockers.count} blocker(s) · ${s.unverified.count} unverified · ${elapsed}s\n`);

    console.log(LANG === 'es' ? 'ACCESO Y RASTREO' : 'CRAWLABILITY');
    for (const c of result.section1.checks) console.log(`  [${STATUS_MARK[c.status] || c.status}] ${L(c.title)}`);

    const actionable = result.prioritizedFindings.filter(f => f.priority !== 'unverified');
    if (actionable.length) {
      console.log(`\nFINDINGS (${actionable.length})`);
      for (const f of actionable) console.log(`  [${STATUS_MARK[f.status] || ''}] ${pad(L(f.section), 34)} ${L(f.title)}`);
    }

    const unver = result.prioritizedFindings.filter(f => f.priority === 'unverified');
    if (unver.length) {
      console.log(`\nNEEDS MANUAL VERIFICATION (${unver.length}) — not client findings`);
      for (const f of unver) console.log(`  - ${L(f.title)}`);
    }
    console.log('');
  }

  // History and benchmarking run after the console summary, so the scan result is already on
  // screen even if a later competitor scan fails.
  if (flag('save')) {
    const path = saveSnapshot(result);
    const delta = diff(snapshot(result), previousSnapshot(url));
    console.log('Snapshot saved: ' + path);
    if (!delta) {
      console.log('  No earlier snapshot to compare against — this is the baseline.\n');
    } else if (!delta.comparable) {
      console.log('  ' + delta.reason + '\n');
    } else {
      const sign = n => (n > 0 ? '+' + n : String(n));
      console.log('CHANGE SINCE ' + delta.previousDate.slice(0, 10));
      console.log('  overall ' + delta.overall.from + ' -> ' + delta.overall.to + '  ' + sign(delta.overall.delta));
      delta.layers.forEach(l => console.log('  ' + l.title.padEnd(34) + ' ' + (l.from === null ? '—' : l.from) + ' -> ' + (l.to === null ? '—' : l.to) + (l.delta === null ? '' : '  ' + sign(l.delta))));
      if (delta.improved.length) { console.log('  improved:'); delta.improved.forEach(c => console.log('    ' + c.key + '  ' + c.from + ' -> ' + c.to)); }
      if (delta.regressed.length) { console.log('  regressed:'); delta.regressed.forEach(c => console.log('    ' + c.key + '  ' + c.from + ' -> ' + c.to)); }
      if (delta.added.length || delta.removed.length) console.log('  ' + delta.added.length + ' check(s) newly assessed, ' + delta.removed.length + ' no longer assessed');
      console.log('');
    }
  }

  const vs = flag('vs');
  if (typeof vs === 'string' && result.reachable) {
    const rivals = vs.split(',').map(v => v.trim()).filter(Boolean);
    console.log('Benchmarking against ' + rivals.length + ' competitor(s) — this takes a while...\n');
    const bm = await benchmark(runScan, result, rivals);
    result.benchmark = bm;
    console.log('COMPETITIVE POSITION: ' + (bm.position ? bm.position + ' of ' + bm.of : 'n/a'));
    [bm.subject, ...bm.competitors].forEach(e => {
      const mark = e.url === bm.subject.url ? '>' : ' ';
      const val = (e.overall === null || e.overall === undefined) ? 'unreachable' : String(e.overall);
      console.log('  ' + mark + ' ' + val.padStart(11) + '   ' + e.url);
    });
    if (bm.layerStanding.length) {
      console.log('');
      bm.layerStanding.forEach(l => {
        const best = (l.best && l.best.url !== bm.subject.url) ? '   best: ' + l.best.score + ' — ' + l.best.url : '';
        console.log('  ' + l.title.padEnd(34) + ' rank ' + l.rank + ' of ' + l.of + best);
      });
    }
    if (bm.unreachable.length) console.log('\n  not reachable: ' + bm.unreachable.join(', '));
    console.log('');
  }

  const slug = (() => { try { return new URL(url).hostname.replace(/^www\./, '').replace(/[^a-z0-9.-]/gi, '-'); } catch { return 'site'; } })();
  const stamp = new Date().toISOString().slice(0, 10);
  const defaultName = ext => `geo-report-${slug}-${stamp}.${ext}`;

  const jsonOut = flag('json');
  if (jsonOut) {
    const path = typeof jsonOut === 'string' ? jsonOut : defaultName('json');
    writeFileSync(path, JSON.stringify(result, null, 2));
    console.log('JSON written:  ' + path);
  }

  const htmlOut = flag('html');
  const pdfOut = flag('pdf');
  if (htmlOut || pdfOut) {
    const htmlPath = typeof htmlOut === 'string' ? htmlOut : defaultName('html');
    const style = flag('style');
    const repoRoot = dirname(fileURLToPath(import.meta.url));
    const markup = style === 'report'
      ? buildReportHtml(result, LANG)
      : buildWebStyleHtml(result, repoRoot, LANG);
    writeFileSync(htmlPath, markup);
    console.log('HTML written:  ' + htmlPath);

    if (pdfOut) {
      // Both paths are made absolute before they reach Chrome. Chrome resolves a relative
      // --print-to-pdf against its own working directory rather than ours, so a relative path
      // silently wrote the file somewhere else while this reported success.
      const pdfPath = resolvePath(typeof pdfOut === 'string' ? pdfOut : defaultName('pdf')).replace(/\\/g, '/');
      const absHtml = resolvePath(htmlPath).replace(/\\/g, '/');
      const chrome = CHROME_PATHS.find(p => existsSync(p));
      if (!chrome) {
        console.log('PDF skipped:   no Chrome or Edge found. Open the HTML and print to PDF instead.');
      } else {
        try {
          execFileSync(chrome, ['--headless', '--disable-gpu', '--no-pdf-header-footer',
            `--print-to-pdf=${pdfPath}`, '--virtual-time-budget=15000', `file:///${absHtml}`], { stdio: 'ignore' });
        } catch { /* fall through to the existence check, which reports the real outcome */ }
        // Never claim the file was written without confirming it exists — Chrome can fail
        // silently, and a missing report that was announced as written is worse than an error.
        if (existsSync(pdfPath)) console.log('PDF written:   ' + pdfPath);
        else console.log('PDF FAILED:    Chrome did not produce ' + pdfPath + '. Open the HTML above and print to PDF instead.');
      }
    }
  }
})();
