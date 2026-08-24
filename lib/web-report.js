// Renders a scan result through the actual web UI (index.html), so a locally generated PDF is
// visually identical to the one the hosted tool produces from its Export PDF button.
//
// This deliberately reuses index.html rather than reimplementing its look. index.html already
// carries a print stylesheet — .no-print hides the scan form and the export buttons, shadows are
// dropped, cards avoid breaking across pages — so driving the real page and printing it gives an
// exact match by construction. Maintaining a second template that merely imitates the first would
// drift out of sync the first time either changed.
//
// The page is made self-contained on the way through: its stylesheet and logo are referenced by
// absolute path (/styles/..., /brand/...), which resolve on the deployed site but not from a
// local file, so both are inlined. The result is a single portable HTML file that can be printed,
// emailed, or opened anywhere.

import { readFileSync } from 'node:fs';
import { join } from 'node:path';

export function buildWebStyleHtml(result, repoRoot) {
  let html = readFileSync(join(repoRoot, 'index.html'), 'utf8');

  // Inline the shared token stylesheet.
  try {
    const css = readFileSync(join(repoRoot, 'styles', 'akore-tokens.css'), 'utf8');
    html = html.replace(/<link[^>]+href="\/styles\/akore-tokens\.css"[^>]*>/i, `<style>\n${css}\n</style>`);
  } catch { /* fall back to the linked path; the page still renders, unstyled tokens aside */ }

  // Inline the logo as a data URI.
  try {
    const logo = readFileSync(join(repoRoot, 'brand', 'logo-horizontal-dark.png')).toString('base64');
    html = html.replace(/src="\/brand\/logo-horizontal-dark\.png"/i, `src="data:image/png;base64,${logo}"`);
  } catch { /* logo simply won't appear */ }

  // Hand the page its data and let its own renderer draw it. Escaping "<" is required: the raw
  // payload carries excerpts of fetched HTML and robots.txt, and an unescaped "</script>" inside
  // them would terminate this block early and break the page.
  const payload = JSON.stringify(result).replace(/</g, '\\u003c');
  const boot = `
<script>
  document.addEventListener('DOMContentLoaded', function () {
    try {
      renderResults(${payload});
    } catch (err) {
      document.body.insertAdjacentHTML('afterbegin',
        '<pre style="padding:20px;color:#b03a3a;font:13px monospace">Could not render report: ' + err.message + '</pre>');
    }
  });
</script>`;

  return html.replace(/<\/body>/i, boot + '\n</body>');
}
