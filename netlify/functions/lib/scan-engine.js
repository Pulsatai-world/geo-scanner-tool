import * as cheerio from 'cheerio';
import robotsParser from 'robots-parser';

// ── User-agents under test ──
// Deliberately includes GPTBot/ClaudeBot alongside a plain browser UA — this is the check that
// catches server-level bot-blocking a human would otherwise spend an hour hunting for in cPanel.
const USER_AGENTS = {
  browser: { label: 'Generic Browser', ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36' },
  gptbot: { label: 'GPTBot', ua: 'Mozilla/5.0 (compatible; GPTBot/1.1; +https://openai.com/gptbot)' },
  claudebot: { label: 'ClaudeBot', ua: 'Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)' },
  googlebot: { label: 'Googlebot', ua: 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' },
  bare: { label: 'Plain Default UA', ua: 'GEO-Scanner/1.0' }
};

const FETCH_TIMEOUT_MS = 9000;

async function fetchSafe(url, uaString, timeoutMs = FETCH_TIMEOUT_MS) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const started = Date.now();
  try {
    const res = await fetch(url, {
      headers: { 'User-Agent': uaString, 'Accept': 'text/html,application/xhtml+xml,application/xml,text/xml,*/*' },
      redirect: 'follow',
      signal: controller.signal
    });
    const text = await res.text();
    return { ok: true, status: res.status, headers: res.headers, text, ms: Date.now() - started };
  } catch (err) {
    return { ok: false, status: 0, headers: null, text: '', ms: Date.now() - started, error: err.message };
  } finally {
    clearTimeout(timer);
  }
}

function normalizeUrl(input) {
  let u = String(input || '').trim();
  if (!/^https?:\/\//i.test(u)) u = 'https://' + u;
  return new URL(u);
}

// ── Section 1: Crawlability ──

async function checkRobots(origin) {
  const robotsUrl = origin + '/robots.txt';
  const res = await fetchSafe(robotsUrl, USER_AGENTS.browser.ua);
  if (!res.ok || res.status >= 400) {
    return {
      id: 'robots-txt',
      title: 'robots.txt',
      status: 'WARNING',
      detail: res.status >= 400 ? `robots.txt returned HTTP ${res.status} — no explicit rules found, so all bots are implicitly allowed.` : `Could not fetch robots.txt (${res.error || 'unknown error'}).`,
      howToFix: 'Not necessarily a problem — a missing robots.txt means all bots are allowed by default. If you want explicit control (declaring a sitemap, blocking specific paths), add a robots.txt file at the site root.',
      raw: { url: robotsUrl, status: res.status }
    };
  }
  const robots = robotsParser(robotsUrl, res.text);
  const bots = ['GPTBot', 'ClaudeBot', 'anthropic-ai', 'Googlebot', '*'];
  const blocking = [];
  for (const bot of bots) {
    const allowedHome = robots.isAllowed(origin + '/', bot);
    if (allowedHome === false) blocking.push(bot);
  }
  const sitemaps = robots.getSitemaps ? robots.getSitemaps() : [];
  let status = 'PASS';
  let detail = 'robots.txt found and does not block the homepage for any AI crawler or Googlebot.';
  let howToFix;
  if (blocking.length) {
    status = 'FAIL';
    detail = `robots.txt blocks the homepage for: ${blocking.join(', ')}. This is a Layer-1 crawlability blocker — these engines cannot see the site at all.`;
    howToFix = 'Edit robots.txt to remove the Disallow rules blocking these user-agents, or add explicit Allow rules for them. If the site doesn\'t use a custom robots.txt, check your hosting panel or security plugin (e.g. Wordfence, a Cloudflare bot-fight rule) — server-level bot blocking often originates there, not in robots.txt itself.';
  }
  return {
    id: 'robots-txt',
    title: 'robots.txt rules',
    status,
    detail,
    howToFix,
    raw: { url: robotsUrl, blockingUserAgents: blocking, sitemapsDeclared: sitemaps, bodyExcerpt: res.text.slice(0, 4000) }
  };
}

async function checkMultiUA(pageUrl) {
  const entries = Object.entries(USER_AGENTS);
  // One fetch per user-agent, run in parallel — the browser-UA response is reused as the
  // homepage source for every other check, so the homepage is never fetched twice.
  const raw = await Promise.all(entries.map(async ([key, cfg]) => {
    const r = await fetchSafe(pageUrl, cfg.ua);
    return { key, cfg, r };
  }));
  const results = raw.map(({ key, cfg, r }) => ({ key, label: cfg.label, ua: cfg.ua, status: r.status, ok: r.ok, ms: r.ms, bodyLength: r.text.length, blocked: !r.ok || r.status === 403 || r.status === 429 || r.status >= 500, error: r.error }));
  const browserFetch = raw.find(x => x.key === 'browser').r;
  const baseline = results.find(r => r.key === 'browser');
  const blockedBots = results.filter(r => r.key !== 'browser' && r.blocked);
  const suspiciousSizeDiff = results.filter(r => r.key !== 'browser' && r.ok && baseline?.ok && baseline.bodyLength > 0 && Math.abs(r.bodyLength - baseline.bodyLength) / baseline.bodyLength > 0.6);
  let status = 'PASS';
  let detail = 'All tested user-agents (browser, GPTBot, ClaudeBot, Googlebot, plain default) received the same, successful response.';
  let howToFix;
  if (!baseline?.ok) {
    status = 'FAIL';
    detail = `The homepage did not respond at all for any user-agent, including a plain browser UA (${baseline?.error || 'no response'}). The site itself is unreachable right now — this blocks every crawler, not just AI bots.`;
    howToFix = 'Confirm the site is actually up (try loading it in a browser right now) and check hosting/server status. If it loads fine for you, the server may be rejecting automated requests entirely — check firewall/WAF logs.';
  } else if (blockedBots.length) {
    status = 'FAIL';
    detail = `Blocked or errored for: ${blockedBots.map(b => `${b.label} (HTTP ${b.status || 'no response'})`).join(', ')} while the browser UA succeeded (HTTP ${baseline?.status}). This points to server-level bot-blocking (firewall/WAF rule, hosting panel "block bad bots" setting) — the exact failure mode a manual check is slow to diagnose.`;
    howToFix = 'Check your hosting firewall/WAF and any "block bad bots" or bot-fight-mode settings in your hosting control panel or CDN (Cloudflare, Sucuri, etc) — these often block AI crawler user-agents by default under generic bot-protection rules. Add GPTBot, ClaudeBot, and Googlebot to an allowlist.';
  } else if (suspiciousSizeDiff.length) {
    status = 'WARNING';
    detail = `Response size differs sharply by user-agent for: ${suspiciousSizeDiff.map(b => b.label).join(', ')} — worth a manual look in case a bot is served a stripped-down or cloaked page.`;
    howToFix = 'Confirm you\'re not unintentionally serving different content by user-agent (cloaking, which AI engines and search engines both penalize) — check for caching layers or bot-detection middleware that could be altering the response for specific UAs.';
  }
  return { check: { id: 'multi-ua', title: 'Multi-user-agent crawl test', status, detail, howToFix, raw: { results } }, browserFetch };
}

function checkXRobotsTag(headers) {
  const val = headers ? headers.get('x-robots-tag') : null;
  if (!val) {
    return { id: 'x-robots-tag', title: 'X-Robots-Tag header', status: 'PASS', detail: 'No X-Robots-Tag header present — this server-level blocking mechanism is not in play.', raw: { value: null } };
  }
  const blocking = /noindex|none/i.test(val);
  return {
    id: 'x-robots-tag',
    title: 'X-Robots-Tag header',
    status: blocking ? 'FAIL' : 'WARNING',
    detail: blocking
      ? `X-Robots-Tag: "${val}" — this HTTP header blocks indexing at the server level, separately from robots.txt and any meta tag. Easy to miss without checking headers directly.`
      : `X-Robots-Tag present ("${val}") but does not appear to block indexing.`,
    howToFix: blocking
      ? 'Remove the noindex directive from the X-Robots-Tag response header — this is usually set in server config (.htaccess, nginx.conf) or a security/SEO plugin, not in page HTML, so check those before the CMS editor.'
      : 'No action needed unless this value is unintentional — confirm the X-Robots-Tag shown above is deliberate.',
    raw: { value: val }
  };
}

function checkNoindexMeta($) {
  const metaRobots = $('meta[name="robots"]').attr('content') || '';
  const metaGooglebot = $('meta[name="googlebot"]').attr('content') || '';
  const combined = `${metaRobots} ${metaGooglebot}`.trim();
  const blocking = /noindex/i.test(combined);
  return {
    id: 'noindex-meta',
    title: 'Meta robots noindex tag',
    status: blocking ? 'FAIL' : 'PASS',
    detail: blocking
      ? `A <meta name="robots"> (or googlebot) tag with "noindex" is present in <head>. This is a distinct, third blocking mechanism from robots.txt and X-Robots-Tag — often left on accidentally after a staging-to-production migration or a WordPress "discourage search engines" setting.`
      : 'No noindex meta tag found in <head>.',
    howToFix: blocking
      ? 'Remove the <meta name="robots" content="noindex"> tag from the page\'s <head>. In WordPress: Settings → Reading → uncheck "Discourage search engines from indexing this site." In other CMSes/SEO plugins, check for an equivalent per-page or site-wide noindex toggle.'
      : undefined,
    raw: { metaRobots, metaGooglebot }
  };
}

async function checkSitemap(origin) {
  const sitemapUrl = origin + '/sitemap.xml';
  const res = await fetchSafe(sitemapUrl, USER_AGENTS.browser.ua);
  if (!res.ok || res.status >= 400) {
    return { id: 'sitemap', title: 'sitemap.xml', status: 'WARNING', detail: `sitemap.xml not found or unreachable (HTTP ${res.status || 'no response'}). Not fatal, but a missing sitemap makes discovery slower for every crawler.`, howToFix: 'Generate a sitemap.xml (most CMS/SEO plugins like Yoast, RankMath, or a static site generator can do this automatically) and reference it in robots.txt.', raw: { url: sitemapUrl, status: res.status } };
  }
  const looksXml = /^\s*<\?xml/i.test(res.text) || /<urlset/i.test(res.text) || /<sitemapindex/i.test(res.text);
  if (!looksXml) {
    return { id: 'sitemap', title: 'sitemap.xml', status: 'FAIL', detail: 'A file exists at /sitemap.xml but it is not valid XML (no <urlset> or <sitemapindex> root). Likely a misconfigured route or a 404 page served with a 200 status.', howToFix: 'Confirm sitemap.xml returns valid XML with a proper <urlset> or <sitemapindex> root and at least one <loc> entry — check your sitemap generator/plugin configuration or routing rules.', raw: { url: sitemapUrl } };
  }
  const urlCount = (res.text.match(/<loc>/gi) || []).length;
  const isIndex = /<sitemapindex/i.test(res.text);
  let status = 'PASS';
  let detail = `Valid ${isIndex ? 'sitemap index' : 'sitemap'} with ${urlCount} URL${urlCount === 1 ? '' : 's'} listed.`;
  let howToFix;
  if (urlCount === 0) {
    status = 'FAIL';
    detail = 'sitemap.xml is valid XML but contains zero <loc> entries — effectively empty.';
    howToFix = 'Check why your sitemap generator/plugin is producing an empty file — often a misconfiguration (wrong post type/content filter) rather than a genuine absence of pages.';
  } else if (urlCount < 3 && !isIndex) {
    status = 'WARNING';
    detail = `Sitemap only lists ${urlCount} URL${urlCount === 1 ? '' : 's'} — unusually small; confirm it is being generated/updated correctly.`;
    howToFix = 'Confirm the sitemap generator is including all published pages, not just a subset (a common bug after a CMS or plugin migration).';
  }
  return { id: 'sitemap', title: 'sitemap.xml', status, detail, howToFix, raw: { url: sitemapUrl, urlCount, isIndex } };
}

// Deliberately measured by its own isolated fetch (see runScan below), not reused from the
// multi-user-agent test or bundled into the same parallel wave as robots.txt/sitemap/extra pages.
// Running all of those concurrently against the same origin creates a burst of simultaneous
// connections no real single visitor or crawler would ever generate — enough to trip rate
// limiting or simply queue behind each other on modest hosting, which was producing wildly
// inconsistent readings for the same site between scans. One clean, uncontended request is a
// truer (though still single-sample) signal. This is why the scan now runs as a background
// function — the isolated fetch plus the rest of the pipeline can genuinely take longer than a
// regular synchronous function's ~10s execution ceiling on a slow site, and a slow site is
// exactly the case this check needs to report honestly rather than crash on.
function checkResponseTime(timingFetch) {
  const ms = timingFetch.ms;
  const speedFix = 'Check for unoptimized images, unminified CSS/JS, or missing caching — consider running the page through Google PageSpeed Insights for a detailed breakdown of exactly what\'s slow.';
  const sampleNote = 'Measured as a single isolated request, with nothing else contending for the origin at the same time — more trustworthy than a request fired alongside a burst of others, but still just one sample. Treat it as a directional signal, not a precise measurement; for an authoritative, repeated-sample breakdown, cross-check with Google PageSpeed Insights.';

  if (!timingFetch.ok) {
    return {
      id: 'response-time',
      title: 'Response time (single-request sample)',
      status: 'FAIL',
      detail: `Homepage did not respond within ${Math.round(ms / 1000)}s (${timingFetch.error || 'no response'}), even in isolation with nothing else contending for the server. Treat this as a hard crawlability failure, not just a slow page.`,
      howToFix: speedFix,
      raw: { ms, error: timingFetch.error }
    };
  }

  // Slow-but-reachable deliberately caps at WARNING, never FAIL — a single timing sample
  // shouldn't be able to gate the whole crawlability score the way a genuine block or a fully
  // unreachable homepage does. FAIL above is reserved for the site not responding at all.
  const status = ms > 2000 ? 'WARNING' : 'PASS';
  const detail = status === 'WARNING'
    ? `Homepage took ${ms}ms to respond — on the slow side. ${sampleNote}`
    : `Homepage responded in ${ms}ms. ${sampleNote}`;

  return {
    id: 'response-time',
    title: 'Response time (single-request sample)',
    status,
    detail,
    howToFix: status === 'WARNING' ? speedFix : undefined,
    raw: { ms }
  };
}

// ── Key Page Discovery ──
// Before the per-page checks run, parse the homepage's nav/header/footer links for the handful
// of page types our own methodology treats as highest-impact for GEO (About and FAQ especially).
// Found pages are fetched and folded into the same per-page pipeline extraPages already uses —
// this is also what makes the Section 3 boilerplate/duplicate-content check actually useful,
// since it needs multiple real pages to compare and previously almost never got them.

const PAGE_DISCOVERY_PATTERNS = {
  about: { label: 'About', patterns: ['quienes-somos', 'quiénes-somos', 'sobre-nosotros', 'about-us', 'nosotros', 'about'] },
  faq: { label: 'FAQ', patterns: ['preguntas-frecuentes', 'preguntas', 'faqs', 'faq'] },
  contact: { label: 'Contact', patterns: ['contactanos', 'contáctanos', 'contact-us', 'contacto', 'contact'] },
  services: { label: 'Services', patterns: ['servicios', 'services'] },
  blog: { label: 'Blog', patterns: ['articulos', 'artículos', 'insights', 'noticias', 'blog'] }
};

// Highest-impact page types per our own client methodology — called out specifically in findings.
const HIGH_IMPACT_DISCOVERY_CATEGORIES = new Set(['about', 'faq']);

function normalizeUrlForCompare(u) {
  try {
    const p = new URL(u);
    const host = p.hostname.replace(/^www\./, ''); // www/non-www treated as the same page — a
    // real site (shalitaoboereeds.com) surfaced this: the homepage URL had no "www." while its
    // own nav links resolved to "www.shalitaoboereeds.com", so a manually-added extra page and
    // the auto-discovered page for the same URL were being treated as different pages and both
    // fetched/analyzed — double-counting one page instead of deduping it.
    let path = p.pathname;
    if (path.length > 1 && path.endsWith('/')) path = path.slice(0, -1);
    return `${p.protocol}//${host}${p.port ? ':' + p.port : ''}${path}${p.search}`.toLowerCase();
  } catch {
    return String(u || '').toLowerCase();
  }
}

// Pure link-matching — no fetching, no report text. Returns { about: {found,url,label}, ... }.
function discoverKeyPages($home, homepageUrl) {
  const homepageHost = new URL(homepageUrl).hostname.replace(/^www\./, '');
  const homepageNormalized = normalizeUrlForCompare(homepageUrl);
  const links = [];
  $home('nav a, header a, footer a').each((_, el) => {
    const href = $home(el).attr('href');
    if (!href) return;
    let resolved;
    try { resolved = new URL(href, homepageUrl); } catch { return; }
    if (!/^https?:$/.test(resolved.protocol)) return; // skip mailto:, tel:, javascript:, etc.
    if (resolved.hostname.replace(/^www\./, '') !== homepageHost) return; // same-site only
    resolved.hash = '';
    if (normalizeUrlForCompare(resolved.href) === homepageNormalized) return; // skip self-links
    links.push({ href: resolved.href, text: $home(el).text().trim().toLowerCase(), slug: resolved.pathname.toLowerCase() });
  });

  const categories = {};
  for (const [id, cfg] of Object.entries(PAGE_DISCOVERY_PATTERNS)) {
    const match = links.find(link => cfg.patterns.some(p => link.slug.includes(p) || link.text.includes(p)));
    categories[id] = { id, label: cfg.label, found: !!match, url: match ? match.href : null };
  }
  return categories;
}

// Turns the raw match data into report-ready entries (status/detail/howToFix), and marks
// categories whose page was already covered by a user-supplied extra page.
function buildPageDiscoveryReport(categories, alreadyCoveredUrls) {
  return Object.values(categories).map(c => {
    const alreadyIncluded = c.found && alreadyCoveredUrls.has(normalizeUrlForCompare(c.url));
    const impactNote = HIGH_IMPACT_DISCOVERY_CATEGORIES.has(c.id) ? ' This is one of the two highest-impact page types for GEO per our own methodology.' : '';
    return {
      id: c.id,
      title: `${c.label} page`,
      status: c.found ? 'PASS' : 'WARNING',
      found: c.found,
      url: c.url,
      detail: c.found
        ? `Found at ${c.url}${alreadyIncluded ? ' (already covered by a manually-added page).' : ' — automatically added to the scan.'}`
        : `No ${c.label} page found linked from the site's nav, header, or footer.${impactNote}`,
      howToFix: c.found ? undefined : `Add a clearly-linked ${c.label} page from the main navigation or footer — automated discovery couldn't find one, which means AI engines likely can't either.`,
      raw: { matchedUrl: c.url }
    };
  });
}

// ── Section 2: On-page GEO signals ──

const COMMON_SCHEMA_TYPES = ['Organization', 'LocalBusiness', 'WebSite', 'Service', 'FAQPage', 'Product', 'Article', 'BreadcrumbList'];

function extractSchemaTypes($) {
  const types = new Set();
  $('script[type="application/ld+json"]').each((_, el) => {
    const raw = $(el).contents().text();
    try {
      const data = JSON.parse(raw);
      collectTypes(data, types);
    } catch {
      // malformed JSON-LD block — ignore, doesn't count as a found type
    }
  });
  return Array.from(types);
}
function collectTypes(node, set) {
  if (Array.isArray(node)) { node.forEach(n => collectTypes(n, set)); return; }
  if (node && typeof node === 'object') {
    if (node['@type']) {
      const t = node['@type'];
      (Array.isArray(t) ? t : [t]).forEach(x => set.add(String(x)));
    }
    if (Array.isArray(node['@graph'])) collectTypes(node['@graph'], set);
    Object.values(node).forEach(v => { if (v && typeof v === 'object') collectTypes(v, set); });
  }
}

function analyzeHeadings($) {
  const headings = [];
  $('h1,h2,h3,h4,h5,h6').each((_, el) => {
    const level = Number(el.tagName.slice(1));
    const text = $(el).text().trim().replace(/\s+/g, ' ').slice(0, 120);
    headings.push({ level, text });
  });
  const h1Count = headings.filter(h => h.level === 1).length;
  let skippedLevel = false;
  let prev = 0;
  for (const h of headings) {
    if (prev && h.level > prev + 1) skippedLevel = true;
    prev = h.level;
  }
  return { headings, h1Count, skippedLevel };
}

function analyzeCanonical($, pageUrl) {
  const href = $('link[rel="canonical"]').attr('href') || '';
  if (!href) return { present: false, href: '', selfReferencing: false, crossDomain: false };
  let resolved;
  try { resolved = new URL(href, pageUrl); } catch { return { present: true, href, selfReferencing: false, crossDomain: true, invalid: true }; }
  const crossDomain = resolved.hostname.replace(/^www\./, '') !== new URL(pageUrl).hostname.replace(/^www\./, '');
  return { present: true, href: resolved.href, selfReferencing: resolved.href.split('#')[0] === pageUrl.split('#')[0], crossDomain };
}

function analyzeImages($) {
  const imgs = $('img');
  const total = imgs.length;
  let withAlt = 0;
  imgs.each((_, el) => { if (($(el).attr('alt') || '').trim().length > 0) withAlt++; });
  return { total, withAlt, pct: total ? Math.round((withAlt / total) * 100) : null };
}

// ── New Section 2 checks (page discovery add-on) ──

function normalizeForMatch(s) {
  return String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').replace(/\s+/g, ' ').trim();
}

// Generic JSON-LD @type search — used by the contact-info check below.
function containsSchemaType(node, typeName) {
  if (Array.isArray(node)) return node.some(n => containsSchemaType(n, typeName));
  if (node && typeof node === 'object') {
    const types = node['@type'] ? (Array.isArray(node['@type']) ? node['@type'] : [node['@type']]) : [];
    if (types.includes(typeName)) return true;
    return Object.values(node).some(v => v && typeof v === 'object' && containsSchemaType(v, typeName));
  }
  return false;
}

function extractFaqPairs($) {
  const pairs = [];
  const collect = (node) => {
    if (Array.isArray(node)) { node.forEach(collect); return; }
    if (node && typeof node === 'object') {
      const types = node['@type'] ? (Array.isArray(node['@type']) ? node['@type'] : [node['@type']]) : [];
      if (types.includes('FAQPage') && Array.isArray(node.mainEntity)) {
        node.mainEntity.forEach(q => {
          if (q && typeof q === 'object') {
            const question = typeof q.name === 'string' ? q.name : '';
            const answer = q.acceptedAnswer && typeof q.acceptedAnswer.text === 'string' ? q.acceptedAnswer.text : '';
            if (question || answer) pairs.push({ question, answer });
          }
        });
      }
      Object.values(node).forEach(v => { if (v && typeof v === 'object') collect(v); });
    }
  };
  $('script[type="application/ld+json"]').each((_, el) => {
    try { collect(JSON.parse($(el).contents().text())); } catch { /* malformed JSON-LD — ignore */ }
  });
  return pairs;
}

// 1. FAQPage schema vs. visible content match — only applies when FAQPage schema is actually
// present on the page (returns null otherwise, so pages with no FAQ schema don't get an
// irrelevant check row).
function checkFaqSchemaMatch($, mainText) {
  const pairs = extractFaqPairs($);
  if (!pairs.length) return null;
  const normalizedMain = normalizeForMatch(mainText);
  let matched = 0;
  pairs.forEach(p => {
    // Match on a meaningful prefix of the question rather than the full string, to tolerate
    // minor visible-text differences (punctuation, a trailing "?") without requiring an exact
    // full-string match.
    const qSnippet = normalizeForMatch(p.question).split(' ').slice(0, 8).join(' ');
    if (qSnippet && normalizedMain.includes(qSnippet)) matched++;
  });
  const ratio = matched / pairs.length;
  const status = ratio >= 0.7 ? 'PASS' : 'WARNING';
  return {
    id: 'faq-schema-match',
    title: 'FAQPage schema vs. visible content match',
    status,
    detail: status === 'PASS'
      ? `${matched}/${pairs.length} FAQPage schema question(s) match text visible on the page.`
      : `Only ${matched}/${pairs.length} FAQPage schema question(s) could be matched to visible content on the page.`,
    howToFix: status === 'PASS' ? undefined : 'Make sure FAQPage schema mirrors real, visible Q&A content on the page — schema that doesn\'t match what a visitor actually sees can be flagged as low-quality or manipulative by AI engines.',
    raw: { totalQuestions: pairs.length, matched }
  };
}

// 2. Author/credential attribution
function containsAuthorPerson(node) {
  if (Array.isArray(node)) return node.some(containsAuthorPerson);
  if (node && typeof node === 'object') {
    for (const key of ['author', 'creator']) {
      if (node[key] != null) {
        const items = Array.isArray(node[key]) ? node[key] : [node[key]];
        for (const item of items) {
          if (typeof item === 'string' && item.trim()) return true;
          if (item && typeof item === 'object' && typeof item.name === 'string' && item.name.trim()) return true;
        }
      }
    }
    return Object.values(node).some(v => v && typeof v === 'object' && containsAuthorPerson(v));
  }
  return false;
}

function checkAuthorAttribution($, mainText) {
  const hasRelAuthor = $('[rel~="author"]').length > 0;
  let hasPersonSchema = false;
  $('script[type="application/ld+json"]').each((_, el) => {
    try { if (containsAuthorPerson(JSON.parse($(el).contents().text()))) hasPersonSchema = true; } catch { /* ignore */ }
  });
  // "by ", "written by", "autor:", "por " followed by what looks like a name — narrower than a
  // bare substring match on "by"/"por" to avoid flagging ordinary prose as a byline.
  const hasByline = /\b(?:by|written by|autor:|por)\s+[A-Z][a-zA-Z'-]+/.test(mainText);
  const found = hasRelAuthor || hasPersonSchema || hasByline;
  return {
    id: 'author-attribution',
    title: 'Author/credential attribution',
    status: found ? 'PASS' : 'WARNING',
    detail: found ? 'Author attribution found (byline, rel="author" link, and/or Person schema tied to authorship).' : 'No author attribution found — no byline, rel="author" link, or Person schema tied to authorship.',
    howToFix: found ? undefined : 'Add named author attribution to the page — a byline, an author schema entry, or both. Named, credentialed sources are weighted more heavily by AI engines than unattributed corporate copy.',
    raw: { hasRelAuthor, hasPersonSchema, hasByline }
  };
}

// 3. First-250-words specificity — reuses the same entity/number/year heuristic as Section 3's
// whole-page specificity check (see detectEntities below), applied only to the opening of the
// page's main content.
function checkFirstWordsSpecificity(mainText) {
  const words = mainText.split(/\s+/).filter(Boolean);
  if (!words.length) return null; // no content at all — Section 3's word-count check covers this
  const first250 = words.slice(0, 250).join(' ');
  const entities = detectEntities(first250);
  const status = (entities.properNounCount >= 3 || entities.numberCount >= 3) ? 'PASS' : 'WARNING';
  return {
    id: 'first-250-specificity',
    title: 'First-250-words specificity',
    status,
    detail: status === 'PASS'
      ? `The first ~250 words contain ${entities.properNounCount} proper-noun-like phrase(s) and ${entities.numberCount} number(s) — specific detail appears early.`
      : `The first ~250 words read as generic (${entities.properNounCount} proper nouns, ${entities.numberCount} numbers), even if the page has more specific content further down.`,
    howToFix: status === 'PASS' ? undefined : 'Move your most specific, concrete details (names, numbers, credentials) into the first 250-300 words. AI extraction tools weight the beginning of a page\'s content more heavily than text buried further down.',
    raw: { wordsChecked: Math.min(words.length, 250), properNounCount: entities.properNounCount, numberCount: entities.numberCount }
  };
}

// 4. Contact info machine-readability — only applies when the page appears to display contact
// info at all (a phone- or email-shaped string in the visible text, or an existing
// tel:/mailto:/ContactPoint signal); a page that never discusses contact info isn't a fair target
// for this check.
function pageHasPlainTextContactInfo(mainText) {
  const emailPattern = /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/i;
  const phonePattern = /(\+?\d[\d\s().-]{7,}\d)/;
  return emailPattern.test(mainText) || phonePattern.test(mainText);
}

function checkContactMachineReadability($, mainText) {
  const telLinks = $('a[href^="tel:"]').length;
  const mailtoLinks = $('a[href^="mailto:"]').length;
  let hasContactPointSchema = false;
  $('script[type="application/ld+json"]').each((_, el) => {
    try { if (containsSchemaType(JSON.parse($(el).contents().text()), 'ContactPoint')) hasContactPointSchema = true; } catch { /* ignore */ }
  });
  const found = telLinks > 0 || mailtoLinks > 0 || hasContactPointSchema;
  if (!found && !pageHasPlainTextContactInfo(mainText)) return null; // no contact info of any kind on this page
  return {
    id: 'contact-machine-readable',
    title: 'Contact info machine-readability',
    status: found ? 'PASS' : 'WARNING',
    detail: found
      ? `Machine-readable contact method(s) found: ${telLinks} tel: link(s), ${mailtoLinks} mailto: link(s)${hasContactPointSchema ? ', ContactPoint schema present' : ''}.`
      : 'Contact info appears to be present as plain text only — no tel:/mailto: links or ContactPoint schema found.',
    howToFix: found ? undefined : 'Wrap phone numbers in tel: links and emails in mailto: links, and add ContactPoint schema. This lets AI agents (and mobile users) actually act on the contact info, not just read it.',
    raw: { telLinks, mailtoLinks, hasContactPointSchema }
  };
}

function analyzePage(pageUrl, html) {
  const $ = cheerio.load(html);
  const title = $('title').first().text().trim();
  const metaDescription = $('meta[name="description"]').attr('content') || '';
  const schemaTypes = extractSchemaTypes($);
  const missingCommonSchema = COMMON_SCHEMA_TYPES.filter(t => !schemaTypes.includes(t));
  const headingInfo = analyzeHeadings($);
  const canonical = analyzeCanonical($, pageUrl);
  const og = {
    title: $('meta[property="og:title"]').attr('content') || '',
    description: $('meta[property="og:description"]').attr('content') || '',
    type: $('meta[property="og:type"]').attr('content') || ''
  };
  const images = analyzeImages($);

  // Main content text, stripped of nav/boilerplate chrome — used by both word count and Section 3
  const $content = cheerio.load(html);
  $content('script,style,nav,footer,header,noscript,svg,iframe').remove();
  const mainText = $content('body').text().replace(/\s+/g, ' ').trim();

  const checks = [];
  checks.push({ id: 'title', title: 'Title tag', status: !title ? 'FAIL' : (title.length > 60 ? 'WARNING' : 'PASS'), detail: !title ? 'Missing <title> tag.' : `"${title}" — ${title.length} characters${title.length > 60 ? ' (over the ~60 char guideline; may get truncated in results).' : '.'}`, howToFix: !title ? 'Add a unique, descriptive <title> tag to this page — it\'s one of the most basic and important on-page signals for both search and AI engines.' : (title.length > 60 ? 'Shorten the title tag to under ~60 characters so it isn\'t truncated in search results and AI citations.' : undefined), raw: { title, length: title.length } });
  checks.push({ id: 'meta-description', title: 'Meta description', status: !metaDescription ? 'FAIL' : (metaDescription.length > 160 ? 'WARNING' : 'PASS'), detail: !metaDescription ? 'Missing meta description.' : `${metaDescription.length} characters${metaDescription.length > 160 ? ' (over the ~160 char guideline; may get truncated.)' : '.'}`, howToFix: !metaDescription ? 'Add a unique meta description summarizing the page\'s content and value proposition.' : (metaDescription.length > 160 ? 'Trim the meta description to under ~155-160 characters so it doesn\'t get truncated in search results. Keep the core value proposition and a call to action.' : undefined), raw: { metaDescription, length: metaDescription.length } });
  checks.push({ id: 'schema', title: 'Schema.org / JSON-LD', status: schemaTypes.length === 0 ? 'FAIL' : (missingCommonSchema.length > 4 ? 'WARNING' : 'PASS'), detail: schemaTypes.length === 0 ? 'No JSON-LD structured data found on this page.' : `Found: ${schemaTypes.join(', ')}. Missing common types: ${missingCommonSchema.join(', ') || 'none'}.`, howToFix: schemaTypes.length === 0 ? 'Add JSON-LD structured data (schema.org) appropriate to this page\'s content — at minimum Organization and WebSite site-wide, plus FAQPage if there\'s FAQ content, Service/Product/LocalBusiness where relevant. This is one of the highest-leverage signals for AI citation.' : (missingCommonSchema.length > 4 ? `Consider adding schema for: ${missingCommonSchema.join(', ')} — whichever are actually relevant to this page's content.` : undefined), raw: { present: schemaTypes, missing: missingCommonSchema } });
  checks.push({ id: 'headings', title: 'Heading structure', status: headingInfo.h1Count === 1 && !headingInfo.skippedLevel ? 'PASS' : (headingInfo.h1Count === 0 ? 'FAIL' : 'WARNING'), detail: headingInfo.h1Count === 0 ? 'No <h1> found on the page.' : headingInfo.h1Count > 1 ? `${headingInfo.h1Count} <h1> tags found — should be exactly one.` : headingInfo.skippedLevel ? 'Exactly one <h1>, but the heading hierarchy skips a level somewhere (e.g. H1 straight to H3/H4).' : 'Exactly one <h1> and no skipped heading levels.', howToFix: (headingInfo.h1Count === 1 && !headingInfo.skippedLevel) ? undefined : 'Use exactly one <h1> per page representing the main topic, and don\'t skip heading levels (H1 → H2 → H3) — use CSS instead of heading level to control visual size.', raw: headingInfo });
  checks.push({ id: 'canonical', title: 'Canonical tag', status: !canonical.present ? 'WARNING' : (canonical.crossDomain ? 'FAIL' : 'PASS'), detail: !canonical.present ? 'No canonical tag present.' : canonical.crossDomain ? `Canonical points to a different domain/host (${canonical.href}) — a common bug after site migrations, leaving canonicals pointed at staging.` : canonical.selfReferencing ? 'Canonical tag is present and self-referencing.' : `Canonical present and points elsewhere on the same domain (${canonical.href}) — confirm this is intentional.`, howToFix: !canonical.present ? 'Add a self-referencing <link rel="canonical"> tag pointing to this exact page\'s URL — this prevents duplicate-content confusion.' : (canonical.crossDomain ? 'Update the canonical tag to point to this page\'s own production URL, not a staging/different domain — a common leftover from site migrations that can suppress the live page from being indexed.' : undefined), raw: canonical });
  const ogMissing = ['title', 'description', 'type'].filter(k => !og[k]);
  checks.push({ id: 'open-graph', title: 'Open Graph tags', status: ogMissing.length === 0 ? 'PASS' : (ogMissing.length === 3 ? 'FAIL' : 'WARNING'), detail: ogMissing.length === 0 ? 'og:title, og:description and og:type all present.' : `Missing: ${ogMissing.map(k => 'og:' + k).join(', ')}.`, howToFix: ogMissing.length === 0 ? undefined : `Add the missing Open Graph tags (${ogMissing.map(k => 'og:' + k).join(', ')}) — these control how the page appears when shared/cited, including by some AI tools that fetch preview metadata.`, raw: og });
  checks.push({ id: 'image-alt', title: 'Image alt text coverage', status: images.total === 0 ? 'PASS' : (images.pct >= 80 ? 'PASS' : images.pct >= 40 ? 'WARNING' : 'FAIL'), detail: images.total === 0 ? 'No <img> tags on this page.' : `${images.withAlt}/${images.total} images (${images.pct}%) have non-empty alt text.`, howToFix: (images.total === 0 || images.pct >= 80) ? undefined : 'Add descriptive alt text to images missing it — this helps both accessibility tools and AI engines understand image content, especially on product/service pages.', raw: images });
  // Added checks (page discovery add-on) — each returns null when not applicable to this page
  // (e.g. no FAQ schema present) rather than forcing an irrelevant row.
  [checkFaqSchemaMatch($, mainText), checkAuthorAttribution($, mainText), checkFirstWordsSpecificity(mainText), checkContactMachineReadability($, mainText)]
    .filter(Boolean)
    .forEach(c => checks.push(c));

  const mainCheck = checkMainLandmark($);
  const headingSeqCheck = checkHeadingHierarchySequential(headingInfo);
  const formCheck = checkFormLabels($);
  const a11yHealthCheck = computeAccessibilityTreeHealth(mainCheck, headingSeqCheck, formCheck, images);
  const agenticChecks = [mainCheck, headingSeqCheck, formCheck, a11yHealthCheck];

  return { url: pageUrl, title, metaDescription, schemaTypes, headingInfo, canonical, og, images, mainText, wordCount: mainText ? mainText.split(/\s+/).filter(Boolean).length : 0, checks, agenticChecks };
}

// ── Section 4: Agentic Browsing / AI Agent Accessibility ──
// Chrome Lighthouse recently added an "Agentic Browsing" category — checks intended to "ensure
// high-quality, browsable websites for AI agents." These are the checks achievable from static
// HTML parsing alone. Deliberately NOT attempted here:
//  - Cumulative Layout Shift (CLS): needs real paint-timing measurement from a rendered page,
//    which means a headless browser (e.g. Playwright) in the function — a meaningfully bigger
//    architecture change. Flagged as a possible v2 addition; not faked or approximated.
//  - WebMCP integration validation: Google's own spec for this is still under development: skip
//    entirely until it stabilizes.

function checkMainLandmark($) {
  const hasMain = $('main').length > 0 || $('[role="main"]').length > 0;
  return {
    id: 'main-landmark',
    title: 'Main landmark presence',
    status: hasMain ? 'PASS' : 'FAIL',
    detail: hasMain ? 'A <main> element (or role="main") is present.' : 'No <main> element or role="main" landmark found.',
    howToFix: hasMain ? undefined : 'Wrap the primary content of the page in a <main> tag. This helps both assistive technology and AI crawlers identify the core content versus navigation/sidebar/footer.',
    raw: { hasMain }
  };
}

function checkHeadingHierarchySequential(headingInfo) {
  const status = headingInfo.skippedLevel ? 'WARNING' : 'PASS';
  return {
    id: 'heading-hierarchy',
    title: 'Heading hierarchy (sequential order)',
    status,
    detail: headingInfo.skippedLevel ? 'One or more heading levels are skipped when descending the outline (e.g. H1 straight to H3, with no H2 between).' : 'Heading levels descend sequentially with no skips.',
    howToFix: headingInfo.skippedLevel ? 'Headings should descend one level at a time (H1 → H2 → H3), even if visually you want smaller text — use CSS for visual size, not heading level, to indicate structure to crawlers and assistive tech.' : undefined,
    raw: { headings: headingInfo.headings }
  };
}

function checkFormLabels($) {
  const fields = $('input,select,textarea').filter((_, el) => {
    const type = ($(el).attr('type') || '').toLowerCase();
    return !['hidden', 'submit', 'button', 'image', 'reset'].includes(type);
  });
  const unlabeled = [];
  fields.each((_, el) => {
    const $el = $(el);
    const id = $el.attr('id');
    const hasFor = id && $(`label[for="${id}"]`).length > 0;
    const hasAriaLabel = !!$el.attr('aria-label');
    const hasAriaLabelledby = !!$el.attr('aria-labelledby');
    const wrappedInLabel = $el.closest('label').length > 0;
    if (!hasFor && !hasAriaLabel && !hasAriaLabelledby && !wrappedInLabel) {
      unlabeled.push({ tag: el.tagName, type: $el.attr('type') || null, name: $el.attr('name') || null, id: id || null });
    }
  });
  const total = fields.length;
  const status = unlabeled.length === 0 ? 'PASS' : 'FAIL';
  return {
    id: 'form-labels',
    title: 'Form label association',
    status,
    detail: total === 0 ? 'No form fields on this page.' : unlabeled.length === 0 ? `All ${total} form field(s) have an associated label.` : `${unlabeled.length}/${total} form field(s) missing a label: ${unlabeled.map(u => u.name || u.id || u.type || u.tag).join(', ')}.`,
    howToFix: unlabeled.length === 0 ? undefined : 'Add a <label for="[id]"> matching each form field\'s id, or an aria-label attribute directly on the field. Unlabeled form fields are invisible to screen readers and likely poorly understood by AI agents trying to interact with the page.',
    raw: { total, unlabeled }
  };
}

function computeAccessibilityTreeHealth(mainCheck, headingSeqCheck, formCheck, images) {
  // Best-effort composite PROXY, not a replication of Chrome's real accessibility tree — that
  // requires an actual rendered DOM. Forms are excluded from the average when a page has none,
  // rather than counting an absence of forms as a free pass.
  const parts = [mainCheck.status === 'PASS' ? 100 : 0, headingSeqCheck.status === 'PASS' ? 100 : 55];
  if (formCheck.raw.total > 0) parts.push(formCheck.status === 'PASS' ? 100 : 0);
  parts.push(images.pct == null ? 100 : images.pct);
  const score = Math.round(parts.reduce((a, b) => a + b, 0) / parts.length);
  const status = score >= 80 ? 'PASS' : score >= 50 ? 'WARNING' : 'FAIL';
  return {
    id: 'a11y-tree-health',
    title: 'Accessibility Tree Health (composite estimate)',
    status,
    detail: `Composite estimate: ${score}/100, based on main-landmark presence, heading hierarchy, form labeling, and image alt coverage. Based on structural signals from static HTML only — for Chrome's full accessibility tree audit, cross-check with Google PageSpeed Insights.`,
    howToFix: status === 'PASS' ? undefined : 'Address the individual checks above (main landmark, heading hierarchy, form labels, image alt text) — this composite score moves as those improve.',
    raw: { score }
  };
}

// ── Section 3: Content specificity (best-effort heuristics) ──

function detectEntities(text) {
  const properNouns = (text.match(/\b[A-Z][a-zA-Z'-]+(?:\s+[A-Z][a-zA-Z'-]+){0,3}\b/g) || []).filter(s => s.split(' ').length > 1 || s.length > 3);
  const numbers = text.match(/\b\d[\d,]*(?:\.\d+)?%?\b/g) || [];
  const years = text.match(/\b(19|20)\d{2}\b/g) || [];
  return {
    properNounSamples: Array.from(new Set(properNouns)).slice(0, 15),
    properNounCount: properNouns.length,
    numberCount: numbers.length,
    yearCount: years.length
  };
}

function shingles(text, n = 5) {
  const words = text.toLowerCase().split(/\s+/).filter(Boolean);
  const set = new Set();
  for (let i = 0; i + n <= words.length; i++) set.add(words.slice(i, i + n).join(' '));
  return set;
}
function jaccard(a, b) {
  if (!a.size || !b.size) return 0;
  let inter = 0;
  for (const x of a) if (b.has(x)) inter++;
  const union = a.size + b.size - inter;
  return union ? inter / union : 0;
}

function analyzeContentSpecificity(pages) {
  const perPage = pages.map(p => {
    const entities = detectEntities(p.mainText);
    let status = 'PASS';
    let detail = `${entities.properNounCount} proper-noun-like phrases, ${entities.numberCount} numbers, ${entities.yearCount} year references found in ${p.wordCount} words of main content.`;
    if (entities.properNounCount < 3 && entities.numberCount < 3) {
      status = 'WARNING';
      detail = `Very few specific, citable facts detected (${entities.properNounCount} proper nouns, ${entities.numberCount} numbers) — content reads as generic. AI engines favor specific, citable content over boilerplate marketing copy.`;
    }
    const wordCountCheck = p.wordCount < 150
      ? { status: 'WARNING', detail: `Only ${p.wordCount} words of main content — thin, though not a hard fail on its own.`, howToFix: 'Expand thin pages with more substantive, specific content — very short pages give AI engines little to cite.' }
      : { status: 'PASS', detail: `${p.wordCount} words of main content.` };
    return { url: p.url, entities, checks: [
      { id: 'entities', title: 'Named entity / specificity signal', status, detail, howToFix: status === 'PASS' ? undefined : 'Add more specific facts — real numbers, dates, named entities (people, places, product names) — rather than generic marketing language. AI engines favor citable, specific content over vague claims.', raw: entities },
      { id: 'word-count', title: 'Word count', status: wordCountCheck.status, detail: wordCountCheck.detail, howToFix: wordCountCheck.howToFix, raw: { wordCount: p.wordCount } }
    ] };
  });

  // Boilerplate detection: pairwise shingle similarity across pages with meaningful content
  const shingleSets = pages.map(p => shingles(p.mainText));
  const boilerplatePairs = [];
  for (let i = 0; i < pages.length; i++) {
    for (let j = i + 1; j < pages.length; j++) {
      if (pages[i].mainText.length < 200 || pages[j].mainText.length < 200) continue;
      const sim = jaccard(shingleSets[i], shingleSets[j]);
      if (sim > 0.6) boilerplatePairs.push({ a: pages[i].url, b: pages[j].url, similarity: Math.round(sim * 100) });
    }
  }
  const boilerplateCheck = {
    id: 'boilerplate',
    title: 'Boilerplate / templated content',
    status: boilerplatePairs.length ? 'WARNING' : 'PASS',
    detail: boilerplatePairs.length
      ? `${boilerplatePairs.length} page pair(s) share heavily overlapping content (${boilerplatePairs.map(p => p.similarity + '%').join(', ')}) — a sign of templated, low-value pages (this is exactly the pattern found in directory-listing-style sites).`
      : (pages.length > 1 ? 'No significant content overlap detected between the scanned pages.' : 'Only one page was available to compare — automatic key-page discovery found no About/FAQ/Contact/Services/Blog page, and no additional pages were provided manually. Add pages via the Advanced section, or check that the site\'s navigation uses standard link text/URL patterns.'),
    howToFix: boilerplatePairs.length ? 'Differentiate templated pages with unique, page-specific content — especially for directory/listing-style pages where a shared template can make every page nearly identical.' : undefined,
    raw: { pairs: boilerplatePairs }
  };

  return { perPage, boilerplateCheck };
}

// ── Scoring ──

function scoreChecks(checks) {
  if (!checks.length) return null;
  const points = { PASS: 100, WARNING: 55, FAIL: 0 };
  const total = checks.reduce((sum, c) => sum + points[c.status], 0);
  return Math.round(total / checks.length);
}

function computeScore(section1Checks, section2Pages, section4Pages, section3) {
  const s1 = scoreChecks(section1Checks);
  const s2Scores = section2Pages.map(p => scoreChecks(p.checks));
  const s2 = s2Scores.length ? Math.round(s2Scores.reduce((a, b) => a + b, 0) / s2Scores.length) : null;
  const s4Scores = section4Pages.map(p => scoreChecks(p.checks));
  const s4 = s4Scores.length ? Math.round(s4Scores.reduce((a, b) => a + b, 0) / s4Scores.length) : null;
  const s3AllChecks = [...section3.perPage.flatMap(p => p.checks), section3.boilerplateCheck];
  const s3 = scoreChecks(s3AllChecks);

  const criticalFails = section1Checks.filter(c => c.status === 'FAIL');
  const weights = { section1: 0.45, section2: 0.25, section4: 0.20, section3: 0.10 };
  let overall = Math.round((s1 ?? 0) * weights.section1 + (s2 ?? 0) * weights.section2 + (s4 ?? 0) * weights.section4 + (s3 ?? 0) * weights.section3);

  let gated = false;
  if (criticalFails.length > 0) {
    gated = true;
    overall = Math.min(overall, 25);
  }

  return {
    overall,
    gated,
    sections: {
      crawlability: s1,
      onPage: s2,
      agenticBrowsing: s4,
      contentSpecificity: s3
    },
    criticalFailCount: criticalFails.length
  };
}

function buildPrioritizedFindings(section1Checks, pageDiscovery, section2Pages, section4Pages, section3) {
  const findings = [];
  section1Checks.filter(c => c.status !== 'PASS').forEach(c => findings.push({ priority: 'critical', section: 'Crawlability', title: c.title, detail: c.detail, howToFix: c.howToFix }));
  pageDiscovery.categories.filter(c => c.status !== 'PASS').forEach(c => findings.push({ priority: 'discovery', section: 'Key Page Discovery', title: c.title, detail: c.detail, howToFix: c.howToFix }));
  section2Pages.forEach(p => p.checks.filter(c => c.status !== 'PASS').forEach(c => findings.push({ priority: 'on-page', section: 'On-Page GEO Signals', page: p.url, title: c.title, detail: c.detail, howToFix: c.howToFix })));
  section4Pages.forEach(p => p.checks.filter(c => c.status !== 'PASS').forEach(c => findings.push({ priority: 'agentic', section: 'Agentic Browsing / AI Agent Accessibility', page: p.url, title: c.title, detail: c.detail, howToFix: c.howToFix })));
  section3.perPage.forEach(p => p.checks.filter(c => c.status !== 'PASS').forEach(c => findings.push({ priority: 'content', section: 'Content Specificity', page: p.url, title: c.title, detail: c.detail, howToFix: c.howToFix })));
  if (section3.boilerplateCheck.status !== 'PASS') findings.push({ priority: 'content', section: 'Content Specificity', title: section3.boilerplateCheck.title, detail: section3.boilerplateCheck.detail, howToFix: section3.boilerplateCheck.howToFix });
  const order = { critical: 0, discovery: 1, 'on-page': 2, agentic: 3, content: 4 };
  return findings.sort((a, b) => order[a.priority] - order[b.priority]);
}

// ── Entry point ──
// Runs the full scan pipeline and returns the result object, or throws on a genuinely invalid
// request (bad URL). Kept independent of any HTTP/Response wrapping so it can be driven by a
// background function (see run-scan-background.js) instead of a synchronous request/response
// cycle — this scan can legitimately take longer than a regular function's execution ceiling on
// a slow site, and a slow site is exactly the case this tool needs to diagnose, not crash on.

export async function runScan({ url, extraPages }) {
  const parsed = normalizeUrl(url);
  const origin = parsed.origin;
  const homepageUrl = parsed.href;

  const cleanExtraPages = Array.isArray(extraPages)
    ? extraPages.filter(Boolean).slice(0, 5).map(p => { try { return new URL(p, origin).href; } catch { return null; } }).filter(Boolean)
    : [];

  // Response time is measured FIRST and ALONE — awaited by itself before anything else touches
  // the origin. Bundling it into the parallel wave below meant it was timed while 7 other
  // requests hit the same server simultaneously, which is enough to trip rate limiting or just
  // queue on modest hosting — producing wildly inconsistent readings for the same site between
  // scans. This costs real wall-clock time, deliberately: accuracy here matters more than
  // shaving seconds off the scan.
  const timingFetch = await fetchSafe(homepageUrl, USER_AGENTS.browser.ua);

  // Everything else runs as ONE parallel wave — robots.txt, sitemap.xml, the 5-user-agent
  // homepage test (whose browser-UA response is reused as the homepage source below, so the
  // homepage's HTML is never fetched twice), and every extra page.
  const [robotsResult, sitemapResult, multiUA, extraPageFetches] = await Promise.all([
    checkRobots(origin),
    checkSitemap(origin),
    checkMultiUA(homepageUrl),
    Promise.all(cleanExtraPages.map(async u => ({ url: u, ...(await fetchSafe(u, USER_AGENTS.browser.ua)) })))
  ]);

  const homepageFetch = multiUA.browserFetch;
  const section1Checks = [robotsResult];

  let $home = null;
  if (homepageFetch.ok) {
    $home = cheerio.load(homepageFetch.text);
    section1Checks.push(
      multiUA.check,
      checkXRobotsTag(homepageFetch.headers),
      checkNoindexMeta($home),
      sitemapResult,
      checkResponseTime(timingFetch)
    );
  } else {
    // Homepage never responded (timeout, DNS failure, connection refused, etc). That is itself
    // the most severe possible Layer-1 finding — report it as one, rather than erroring the
    // whole scan and telling the user nothing. X-Robots-Tag / noindex genuinely cannot be
    // determined with no page fetched, so they're omitted rather than falsely marked PASS.
    section1Checks.push(multiUA.check, sitemapResult, checkResponseTime(timingFetch));
  }

  // Key Page Discovery: parse the homepage's nav/header/footer for About/FAQ/Contact/Services/
  // Blog links, then fetch whichever were found (deduped against user-supplied extra pages) —
  // this can only run once the homepage HTML is in hand, so it's a second sequential wave rather
  // than folded into the batch above.
  const alreadyCovered = new Set([homepageUrl, ...cleanExtraPages].map(normalizeUrlForCompare));
  let pageDiscovery;
  let discoveredFetches = [];
  if ($home) {
    const categories = discoverKeyPages($home, homepageUrl);
    const toFetch = Object.values(categories).filter(c => c.found && !alreadyCovered.has(normalizeUrlForCompare(c.url)));
    discoveredFetches = await Promise.all(toFetch.map(async c => ({ url: c.url, ...(await fetchSafe(c.url, USER_AGENTS.browser.ua)) })));
    pageDiscovery = { title: 'Key Page Discovery', skipped: false, categories: buildPageDiscoveryReport(categories, alreadyCovered) };
  } else {
    // Homepage was unreachable — there's no nav/header/footer to parse, so discovery can't run.
    pageDiscovery = {
      title: 'Key Page Discovery',
      skipped: true,
      categories: Object.entries(PAGE_DISCOVERY_PATTERNS).map(([id, cfg]) => ({
        id, title: `${cfg.label} page`, status: 'WARNING', found: false, url: null,
        detail: 'Could not check — the homepage was unreachable, so its navigation links could not be parsed.',
        howToFix: undefined, raw: {}
      }))
    };
  }

  // Section 2 + 3 + 4 source pages: homepage (if it loaded) + any extra pages that loaded +
  // any auto-discovered pages that loaded.
  const pageFetches = [
    { url: homepageUrl, html: homepageFetch.text, ok: homepageFetch.ok, status: homepageFetch.status },
    ...extraPageFetches.map(p => ({ url: p.url, html: p.text, ok: p.ok, status: p.status })),
    ...discoveredFetches.map(p => ({ url: p.url, html: p.text, ok: p.ok, status: p.status }))
  ];

  const validPages = pageFetches.filter(p => p.ok && p.html);
  const skippedPages = pageFetches.filter(p => !p.ok).map(p => ({ url: p.url, status: p.status }));

  const analyzedPages = validPages.map(p => analyzePage(p.url, p.html));
  const section3 = analyzeContentSpecificity(analyzedPages);

  const section2Pages = analyzedPages.map(p => ({ url: p.url, title: p.title, metaDescription: p.metaDescription, schemaTypes: p.schemaTypes, headingInfo: p.headingInfo, canonical: p.canonical, og: p.og, images: p.images, wordCount: p.wordCount, checks: p.checks }));
  const section4Pages = analyzedPages.map(p => ({ url: p.url, checks: p.agenticChecks }));

  const score = computeScore(section1Checks, section2Pages, section4Pages, section3);
  const prioritizedFindings = buildPrioritizedFindings(section1Checks, pageDiscovery, section2Pages, section4Pages, section3);

  return {
    scannedAt: new Date().toISOString(),
    input: { url: homepageUrl, extraPages: cleanExtraPages },
    skippedPages,
    score,
    section1: { title: 'Crawlability Layer', checks: section1Checks },
    pageDiscovery,
    section2: { title: 'On-Page GEO Signals', pages: section2Pages },
    section4: { title: 'Agentic Browsing / AI Agent Accessibility', pages: section4Pages },
    section3: { title: 'Content Specificity Signals', perPage: section3.perPage.map(p => ({ url: p.url, checks: p.checks })), boilerplate: section3.boilerplateCheck },
    prioritizedFindings
  };
}
