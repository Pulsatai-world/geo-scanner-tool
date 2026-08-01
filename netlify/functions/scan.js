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

async function fetchSafe(url, uaString) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
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
  if (blocking.length) {
    status = 'FAIL';
    detail = `robots.txt blocks the homepage for: ${blocking.join(', ')}. This is a Layer-1 crawlability blocker — these engines cannot see the site at all.`;
  }
  return {
    id: 'robots-txt',
    title: 'robots.txt rules',
    status,
    detail,
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
  if (!baseline?.ok) {
    status = 'FAIL';
    detail = `The homepage did not respond at all for any user-agent, including a plain browser UA (${baseline?.error || 'no response'}). The site itself is unreachable right now — this blocks every crawler, not just AI bots.`;
  } else if (blockedBots.length) {
    status = 'FAIL';
    detail = `Blocked or errored for: ${blockedBots.map(b => `${b.label} (HTTP ${b.status || 'no response'})`).join(', ')} while the browser UA succeeded (HTTP ${baseline?.status}). This points to server-level bot-blocking (firewall/WAF rule, hosting panel "block bad bots" setting) — the exact failure mode a manual check is slow to diagnose.`;
  } else if (suspiciousSizeDiff.length) {
    status = 'WARNING';
    detail = `Response size differs sharply by user-agent for: ${suspiciousSizeDiff.map(b => b.label).join(', ')} — worth a manual look in case a bot is served a stripped-down or cloaked page.`;
  }
  return { check: { id: 'multi-ua', title: 'Multi-user-agent crawl test', status, detail, raw: { results } }, browserFetch };
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
    raw: { metaRobots, metaGooglebot }
  };
}

async function checkSitemap(origin) {
  const sitemapUrl = origin + '/sitemap.xml';
  const res = await fetchSafe(sitemapUrl, USER_AGENTS.browser.ua);
  if (!res.ok || res.status >= 400) {
    return { id: 'sitemap', title: 'sitemap.xml', status: 'WARNING', detail: `sitemap.xml not found or unreachable (HTTP ${res.status || 'no response'}). Not fatal, but a missing sitemap makes discovery slower for every crawler.`, raw: { url: sitemapUrl, status: res.status } };
  }
  const looksXml = /^\s*<\?xml/i.test(res.text) || /<urlset/i.test(res.text) || /<sitemapindex/i.test(res.text);
  if (!looksXml) {
    return { id: 'sitemap', title: 'sitemap.xml', status: 'FAIL', detail: 'A file exists at /sitemap.xml but it is not valid XML (no <urlset> or <sitemapindex> root). Likely a misconfigured route or a 404 page served with a 200 status.', raw: { url: sitemapUrl } };
  }
  const urlCount = (res.text.match(/<loc>/gi) || []).length;
  const isIndex = /<sitemapindex/i.test(res.text);
  let status = 'PASS';
  let detail = `Valid ${isIndex ? 'sitemap index' : 'sitemap'} with ${urlCount} URL${urlCount === 1 ? '' : 's'} listed.`;
  if (urlCount === 0) {
    status = 'FAIL';
    detail = 'sitemap.xml is valid XML but contains zero <loc> entries — effectively empty.';
  } else if (urlCount < 3 && !isIndex) {
    status = 'WARNING';
    detail = `Sitemap only lists ${urlCount} URL${urlCount === 1 ? '' : 's'} — unusually small; confirm it is being generated/updated correctly.`;
  }
  return { id: 'sitemap', title: 'sitemap.xml', status, detail, raw: { url: sitemapUrl, urlCount, isIndex } };
}

function checkResponseTime(homepageFetch) {
  const ms = homepageFetch.ms;
  if (!homepageFetch.ok) {
    return { id: 'response-time', title: 'Response time', status: 'FAIL', detail: `Homepage did not respond within ${Math.round(ms / 1000)}s (${homepageFetch.error || 'no response'}) — treat this as a hard crawlability failure, not just a slow page.`, raw: { ms, error: homepageFetch.error } };
  }
  let status = 'PASS';
  let detail = `Homepage responded in ${ms}ms.`;
  if (ms > 3000) {
    status = 'FAIL';
    detail = `Homepage took ${ms}ms to respond — slow enough to risk crawl budget and timeouts from some bots.`;
  } else if (ms > 1200) {
    status = 'WARNING';
    detail = `Homepage took ${ms}ms to respond — on the slow side.`;
  }
  return { id: 'response-time', title: 'Response time', status, detail, raw: { ms } };
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
  checks.push({ id: 'title', title: 'Title tag', status: !title ? 'FAIL' : (title.length > 60 ? 'WARNING' : 'PASS'), detail: !title ? 'Missing <title> tag.' : `"${title}" — ${title.length} characters${title.length > 60 ? ' (over the ~60 char guideline; may get truncated in results).' : '.'}`, raw: { title, length: title.length } });
  checks.push({ id: 'meta-description', title: 'Meta description', status: !metaDescription ? 'FAIL' : (metaDescription.length > 160 ? 'WARNING' : 'PASS'), detail: !metaDescription ? 'Missing meta description.' : `${metaDescription.length} characters${metaDescription.length > 160 ? ' (over the ~160 char guideline; may get truncated.)' : '.'}`, raw: { metaDescription, length: metaDescription.length } });
  checks.push({ id: 'schema', title: 'Schema.org / JSON-LD', status: schemaTypes.length === 0 ? 'FAIL' : (missingCommonSchema.length > 4 ? 'WARNING' : 'PASS'), detail: schemaTypes.length === 0 ? 'No JSON-LD structured data found on this page.' : `Found: ${schemaTypes.join(', ')}. Missing common types: ${missingCommonSchema.join(', ') || 'none'}.`, raw: { present: schemaTypes, missing: missingCommonSchema } });
  checks.push({ id: 'headings', title: 'Heading structure', status: headingInfo.h1Count === 1 && !headingInfo.skippedLevel ? 'PASS' : (headingInfo.h1Count === 0 ? 'FAIL' : 'WARNING'), detail: headingInfo.h1Count === 0 ? 'No <h1> found on the page.' : headingInfo.h1Count > 1 ? `${headingInfo.h1Count} <h1> tags found — should be exactly one.` : headingInfo.skippedLevel ? 'Exactly one <h1>, but the heading hierarchy skips a level somewhere (e.g. H1 straight to H3/H4).' : 'Exactly one <h1> and no skipped heading levels.', raw: headingInfo });
  checks.push({ id: 'canonical', title: 'Canonical tag', status: !canonical.present ? 'WARNING' : (canonical.crossDomain ? 'FAIL' : 'PASS'), detail: !canonical.present ? 'No canonical tag present.' : canonical.crossDomain ? `Canonical points to a different domain/host (${canonical.href}) — a common bug after site migrations, leaving canonicals pointed at staging.` : canonical.selfReferencing ? 'Canonical tag is present and self-referencing.' : `Canonical present and points elsewhere on the same domain (${canonical.href}) — confirm this is intentional.`, raw: canonical });
  const ogMissing = ['title', 'description', 'type'].filter(k => !og[k]);
  checks.push({ id: 'open-graph', title: 'Open Graph tags', status: ogMissing.length === 0 ? 'PASS' : (ogMissing.length === 3 ? 'FAIL' : 'WARNING'), detail: ogMissing.length === 0 ? 'og:title, og:description and og:type all present.' : `Missing: ${ogMissing.map(k => 'og:' + k).join(', ')}.`, raw: og });
  checks.push({ id: 'image-alt', title: 'Image alt text coverage', status: images.total === 0 ? 'PASS' : (images.pct >= 80 ? 'PASS' : images.pct >= 40 ? 'WARNING' : 'FAIL'), detail: images.total === 0 ? 'No <img> tags on this page.' : `${images.withAlt}/${images.total} images (${images.pct}%) have non-empty alt text.`, raw: images });

  return { url: pageUrl, title, metaDescription, schemaTypes, headingInfo, canonical, og, images, mainText, wordCount: mainText ? mainText.split(/\s+/).filter(Boolean).length : 0, checks };
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
      ? { status: 'WARNING', detail: `Only ${p.wordCount} words of main content — thin, though not a hard fail on its own.` }
      : { status: 'PASS', detail: `${p.wordCount} words of main content.` };
    return { url: p.url, entities, checks: [
      { id: 'entities', title: 'Named entity / specificity signal', status, detail, raw: entities },
      { id: 'word-count', title: 'Word count', status: wordCountCheck.status, detail: wordCountCheck.detail, raw: { wordCount: p.wordCount } }
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
      : (pages.length > 1 ? 'No significant content overlap detected between the scanned pages.' : 'Only one page scanned — boilerplate comparison needs at least two pages.'),
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

function computeScore(section1Checks, section2Pages, section3) {
  const s1 = scoreChecks(section1Checks);
  const s2Scores = section2Pages.map(p => scoreChecks(p.checks));
  const s2 = s2Scores.length ? Math.round(s2Scores.reduce((a, b) => a + b, 0) / s2Scores.length) : null;
  const s3AllChecks = [...section3.perPage.flatMap(p => p.checks), section3.boilerplateCheck];
  const s3 = scoreChecks(s3AllChecks);

  const criticalFails = section1Checks.filter(c => c.status === 'FAIL');
  const weights = { section1: 0.5, section2: 0.35, section3: 0.15 };
  let overall = Math.round((s1 ?? 0) * weights.section1 + (s2 ?? 0) * weights.section2 + (s3 ?? 0) * weights.section3);

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
      contentSpecificity: s3
    },
    criticalFailCount: criticalFails.length
  };
}

function buildPrioritizedFindings(section1Checks, section2Pages, section3) {
  const findings = [];
  section1Checks.filter(c => c.status !== 'PASS').forEach(c => findings.push({ priority: 'critical', section: 'Crawlability', title: c.title, detail: c.detail }));
  section2Pages.forEach(p => p.checks.filter(c => c.status !== 'PASS').forEach(c => findings.push({ priority: 'on-page', section: 'On-Page GEO Signals', page: p.url, title: c.title, detail: c.detail })));
  section3.perPage.forEach(p => p.checks.filter(c => c.status !== 'PASS').forEach(c => findings.push({ priority: 'content', section: 'Content Specificity', page: p.url, title: c.title, detail: c.detail })));
  if (section3.boilerplateCheck.status !== 'PASS') findings.push({ priority: 'content', section: 'Content Specificity', title: section3.boilerplateCheck.title, detail: section3.boilerplateCheck.detail });
  const order = { critical: 0, 'on-page': 1, content: 2 };
  return findings.sort((a, b) => order[a.priority] - order[b.priority]);
}

// ── Section 5: optional Claude narrative ──

async function generateNarrative(apiKey, summary) {
  const prompt = `You are writing the opening "hallazgo principal" line of a GEO (Generative Engine Optimization) technical audit for a non-technical business owner. Given this structured JSON of findings, write ONE clear sentence in Spanish stating the single most important problem blocking this site from being crawled and cited by AI engines (or, if there is no blocking issue, the single most important improvement opportunity). Be concrete and specific to what's in the data — do not write generic filler. Return ONLY the sentence, no preamble, no quotes.

DATA:
${JSON.stringify(summary).slice(0, 12000)}`;

  const res = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01'
    },
    body: JSON.stringify({
      model: 'claude-opus-5',
      max_tokens: 300,
      output_config: { effort: 'low' },
      messages: [{ role: 'user', content: prompt }]
    })
  });
  const rawText = await res.text();
  let data;
  try { data = JSON.parse(rawText); } catch { throw new Error('Claude API returned a non-JSON response.'); }
  if (!res.ok) throw new Error(data.error?.message || `Claude API error ${res.status}`);
  if (data.stop_reason === 'refusal') throw new Error('Claude declined to summarize this request.');
  const text = (data.content || []).filter(b => b.type === 'text').map(b => b.text).join('\n').trim();
  if (!text) throw new Error('Claude returned an empty response.');
  return text;
}

// ── Main handler ──

export default async (request) => {
  if (request.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'Method Not Allowed' }), { status: 405, headers: { 'Content-Type': 'application/json' } });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return new Response(JSON.stringify({ error: 'Invalid JSON body' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
  }

  let parsed;
  try {
    parsed = normalizeUrl(body.url);
  } catch {
    return new Response(JSON.stringify({ error: 'Invalid URL' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
  }
  const origin = parsed.origin;
  const homepageUrl = parsed.href;

  const extraPages = Array.isArray(body.extraPages)
    ? body.extraPages.filter(Boolean).slice(0, 5).map(p => { try { return new URL(p, origin).href; } catch { return null; } }).filter(Boolean)
    : [];

  try {
    // Everything runs as ONE parallel wave — robots.txt, sitemap.xml, the 5-user-agent homepage
    // test (whose browser-UA response is reused as the homepage source below, so the homepage is
    // never fetched twice), and every extra page. Total wall-clock is bounded by the slowest
    // single request, not the sum of them, which matters given Netlify's function time limit.
    const [robotsResult, sitemapResult, multiUA, extraPageFetches] = await Promise.all([
      checkRobots(origin),
      checkSitemap(origin),
      checkMultiUA(homepageUrl),
      Promise.all(extraPages.map(async u => ({ url: u, ...(await fetchSafe(u, USER_AGENTS.browser.ua)) })))
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
        checkResponseTime(homepageFetch)
      );
    } else {
      // Homepage never responded (timeout, DNS failure, connection refused, etc). That is itself
      // the most severe possible Layer-1 finding — report it as one, rather than erroring the
      // whole scan and telling the user nothing. X-Robots-Tag / noindex genuinely cannot be
      // determined with no page fetched, so they're omitted rather than falsely marked PASS.
      section1Checks.push(multiUA.check, sitemapResult, checkResponseTime(homepageFetch));
    }

    // Section 2 + 3 source pages: homepage (if it loaded) + any extra pages that loaded
    const pageFetches = [
      { url: homepageUrl, html: homepageFetch.text, ok: homepageFetch.ok, status: homepageFetch.status },
      ...extraPageFetches.map(p => ({ url: p.url, html: p.text, ok: p.ok, status: p.status }))
    ];

    const validPages = pageFetches.filter(p => p.ok && p.html);
    const skippedPages = pageFetches.filter(p => !p.ok).map(p => ({ url: p.url, status: p.status }));

    const analyzedPages = validPages.map(p => analyzePage(p.url, p.html));
    const section3 = analyzeContentSpecificity(analyzedPages);

    const section2Pages = analyzedPages.map(p => ({ url: p.url, title: p.title, metaDescription: p.metaDescription, schemaTypes: p.schemaTypes, headingInfo: p.headingInfo, canonical: p.canonical, og: p.og, images: p.images, wordCount: p.wordCount, checks: p.checks }));

    const score = computeScore(section1Checks, section2Pages, section3);
    const prioritizedFindings = buildPrioritizedFindings(section1Checks, section2Pages, section3);

    const result = {
      scannedAt: new Date().toISOString(),
      input: { url: homepageUrl, extraPages },
      skippedPages,
      score,
      section1: { title: 'Crawlability Layer', checks: section1Checks },
      section2: { title: 'On-Page GEO Signals', pages: section2Pages },
      section3: { title: 'Content Specificity Signals', perPage: section3.perPage.map(p => ({ url: p.url, checks: p.checks })), boilerplate: section3.boilerplateCheck },
      prioritizedFindings
    };

    if (body.claudeApiKey && String(body.claudeApiKey).trim()) {
      try {
        const narrative = await generateNarrative(String(body.claudeApiKey).trim(), {
          url: homepageUrl,
          score,
          criticalFindings: prioritizedFindings.filter(f => f.priority === 'critical'),
          topOnPageFindings: prioritizedFindings.filter(f => f.priority === 'on-page').slice(0, 8)
        });
        result.narrative = narrative;
      } catch (err) {
        result.narrativeError = err.message;
      }
    }

    return new Response(JSON.stringify(result), { status: 200, headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' } });
  } catch (err) {
    return new Response(JSON.stringify({ error: err.message || 'Unexpected error running scan' }), { status: 500, headers: { 'Content-Type': 'application/json' } });
  }
};
