// Converts a generated report or checklist into an artifact-ready fragment.
//   node build-artifact.mjs <in.html> <out.html> "<Title>"
//
// Two conversions matter. First, the published page must be static: the report renders its
// content from injected JSON at runtime, so the DOM is captured after that has run and every
// script is then dropped. A shared link should not depend on JavaScript executing, and should
// carry no code that could try to call an API it can no longer reach.
//
// Second, interactive chrome is removed. The report is built from the scanner's own page, which
// carries a scan form and export buttons — controls that do nothing on a shared link and would
// invite a reader to click them. They are already marked .no-print for the PDF, so the same
// marker identifies them here.
import { readFileSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { load } from 'cheerio';

const [input, output, title] = process.argv.slice(2);
if (!input || !output) {
  console.error('Usage: node build-artifact.mjs <in.html> <out.html> "<Title>"');
  process.exit(1);
}

const CHROME_PATHS = [
  'C:/Program Files/Google/Chrome/Application/chrome.exe',
  'C:/Program Files (x86)/Google/Chrome/Application/chrome.exe',
  'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  '/usr/bin/google-chrome'
];

const abs = resolve(input).replace(/\\/g, '/');
let html;
const chrome = CHROME_PATHS.find(p => existsSync(p));
if (chrome) {
  // --dump-dom returns the DOM after scripts have run, which is what makes the output static.
  html = execFileSync(chrome, ['--headless', '--disable-gpu', '--virtual-time-budget=15000', '--dump-dom', `file:///${abs}`], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
} else {
  console.warn('No Chrome found — falling back to the raw file, which may not be pre-rendered.');
  html = readFileSync(input, 'utf8');
}

// Parsed rather than pattern-matched. The scan form is a card of nested divs, and a regex for
// its closing tag matches the wrong one — an earlier attempt left the form in the published page.
const $ = load(html);

const styles = $('style').map((_, el) => $(el).html()).get().join('\n');
const fontLinks = $('link[href*="fonts.googleapis.com"], link[href*="fonts.gstatic.com"]')
  .map((_, el) => $.html(el)).get().join('\n');

$('script').remove();
$('.no-print').remove();          // scan form and export buttons
$('link, style, meta, title').remove();

const body = $('body').html() || '';

writeFileSync(output, `<title>${title || 'GEO Report'}</title>
${fontLinks}
<style>
${styles}
/* Published as a static page: the scanner's own controls are removed, so nothing here invites a
   click that cannot work. Background is painted explicitly rather than inherited from the host. */
body{background:var(--ice, #f4f6f8);padding-bottom:48px}
</style>
${body}`);

const kb = (readFileSync(output).length / 1024).toFixed(0);
console.log(`artifact fragment written: ${output} (${kb} KB) — ${chrome ? 'pre-rendered' : 'raw'}`);
