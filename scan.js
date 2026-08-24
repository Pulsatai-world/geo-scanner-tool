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
//
// Two report styles are available. The default matches the hosted tool exactly, because it
// renders the result through index.html itself rather than imitating it. --style report uses the
// standalone print layout in lib/report.js, which is denser and built for handing to a client.
//
import { runScan } from './netlify/functions/lib/scan-engine.js';
import { buildReportHtml } from './lib/report.js';
import { buildWebStyleHtml } from './lib/web-report.js';
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

const pad = (s, n) => String(s).padEnd(n);
const STATUS_MARK = { PASS: 'ok  ', WARNING: 'warn', FAIL: 'FAIL', INCONCLUSIVE: '  ? ', INFO: 'info' };

(async () => {
  const started = Date.now();
  console.log(`\nScanning ${url} ...`);
  console.log('(running locally — requests leave from this machine, not a cloud IP)\n');

  let result;
  try {
    result = await runScan({ url, extraPages });
  } catch (err) {
    console.error('Scan could not start:', err.message);
    process.exit(1);
  }

  const elapsed = ((Date.now() - started) / 1000).toFixed(1);

  if (!result.reachable) {
    console.log('SITE NOT REACHABLE from this machine either.');
    const reach = result.section1.checks.find(c => c.id === 'site-reachability');
    if (reach) {
      console.log('\n' + reach.detail);
      if (reach.howToFix) console.log('\nWhat to do: ' + reach.howToFix);
    }
    console.log(`\nNo score is reported — nothing was measured. (${elapsed}s)\n`);
  } else {
    const s = result.score;
    console.log(`ON-PAGE GEO READINESS: ${s.overall}/100`);
    console.log(`  on-page ${s.sections.onPage ?? '—'}   agentic ${s.sections.agenticBrowsing ?? '—'}   content ${s.sections.contentSpecificity ?? '—'}   crawlability ${s.sections.crawlability ?? '—'} (not in score)`);
    console.log(`  ${result.scanQuality.pagesAnalyzed} page(s) analysed · ${s.blockers.count} blocker(s) · ${s.unverified.count} unverified · ${elapsed}s\n`);

    console.log('CRAWLABILITY');
    for (const c of result.section1.checks) console.log(`  [${STATUS_MARK[c.status] || c.status}] ${c.title}`);

    const actionable = result.prioritizedFindings.filter(f => f.priority !== 'unverified');
    if (actionable.length) {
      console.log(`\nFINDINGS (${actionable.length})`);
      for (const f of actionable) console.log(`  [${STATUS_MARK[f.status] || ''}] ${pad(f.section, 34)} ${f.title}`);
    }

    const unver = result.prioritizedFindings.filter(f => f.priority === 'unverified');
    if (unver.length) {
      console.log(`\nNEEDS MANUAL VERIFICATION (${unver.length}) — not client findings`);
      for (const f of unver) console.log(`  - ${f.title}`);
    }
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
      ? buildReportHtml(result)
      : buildWebStyleHtml(result, repoRoot);
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
