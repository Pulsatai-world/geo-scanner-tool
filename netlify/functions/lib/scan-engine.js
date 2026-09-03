import * as cheerio from 'cheerio';
import robotsParser from 'robots-parser';
import { LAYERS, CHECKS } from './check-registry.js';
import { t } from './i18n.js';

// ── User-agents under test ──
// Deliberately includes GPTBot/ClaudeBot alongside a plain browser UA — this is the check that
// catches server-level bot-blocking a human would otherwise spend an hour hunting for in cPanel.
const USER_AGENTS = {
  browser: { label: 'Generic Browser', ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36' },
  gptbot: { label: 'GPTBot', ua: 'Mozilla/5.0 (compatible; GPTBot/1.1; +https://openai.com/gptbot)' },
  claudebot: { label: 'ClaudeBot', ua: 'Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)' },
  googlebot: { label: 'Googlebot', ua: 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' },
  // Retrieval bots — these fetch a page at the moment someone asks a question, and are what
  // actually determine whether a site can be cited in an AI answer. A host-level rule that
  // blocks by user-agent string (mod_security, Wordfence, a "bad bot" list) will refuse these
  // outright, and that is worth catching even though it cannot detect IP-based edge blocking.
  oaisearchbot: { label: 'OAI-SearchBot', ua: 'Mozilla/5.0 (compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot)' },
  perplexitybot: { label: 'PerplexityBot', ua: 'Mozilla/5.0 (compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)' },
  bare: { label: 'Plain Default UA', ua: 'GEO-Scanner/1.0' }
};

// 20s, not 9s. Measured against real client hosting: a modest shared host serving a heavy
// WordPress homepage answers in ~2s uncontended but degrades past 10s under even mild
// concurrency. A 9s ceiling turned "slow" into "unreachable", which the scoring layer then
// treated as a hard failure — the single largest source of false results this tool produced.
const FETCH_TIMEOUT_MS = 20000;

// Never open more than this many sockets against one origin at once. See runScan for the
// measurements behind the number: on a serialising shared host, response time scaled roughly
// linearly with concurrency (1 req ≈ 2.0s, 3 ≈ 5.1s, 5 ≈ 10.3s) until every request in a
// 7-wide burst timed out — while the same requests issued two-at-a-time all succeeded. The
// scan is a diagnostic, not a load test; it must not create the condition it reports on.
const MAX_CONCURRENT_FETCHES = 2;

// Small gap between waves. Costs a second or two overall and keeps us clearly under the
// request-rate thresholds that make WAFs and fail2ban-style tools start refusing connections.
const INTER_WAVE_DELAY_MS = 250;

const sleep = ms => new Promise(r => setTimeout(r, ms));

// Runs fn over items with a hard concurrency ceiling, preserving input order in the results.
async function mapLimited(items, fn, limit = MAX_CONCURRENT_FETCHES) {
  const results = new Array(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i], i);
      if (next < items.length) await sleep(INTER_WAVE_DELAY_MS);
    }
  });
  await Promise.all(workers);
  return results;
}

// Node's fetch rejects with a bare "fetch failed" for everything from a refused connection to
// an expired certificate; the real reason is on err.cause.code. Without this, a Cloudflare bot
// rule refusing our egress IP and a slow server timing out were indistinguishable in the
// report — they need completely different advice, so they must be told apart here.
const FETCH_ERROR_KINDS = {
  ECONNREFUSED: { kind: 'refused', label: 'connection refused by the server' },
  ECONNRESET: { kind: 'refused', label: 'connection reset by the server' },
  ENOTFOUND: { kind: 'dns', label: 'hostname did not resolve (DNS)' },
  EAI_AGAIN: { kind: 'dns', label: 'temporary DNS resolution failure' },
  ENETUNREACH: { kind: 'network', label: 'network unreachable from the scanner' },
  EHOSTUNREACH: { kind: 'network', label: 'host unreachable from the scanner' },
  EPROTO: { kind: 'tls', label: 'TLS/SSL protocol error' },
  CERT_HAS_EXPIRED: { kind: 'tls', label: 'the site\'s TLS certificate has expired' },
  UNABLE_TO_VERIFY_LEAF_SIGNATURE: { kind: 'tls', label: 'incomplete TLS certificate chain' },
  DEPTH_ZERO_SELF_SIGNED_CERT: { kind: 'tls', label: 'self-signed TLS certificate' },
  UND_ERR_CONNECT_TIMEOUT: { kind: 'timeout', label: 'connection attempt timed out' }
};

function classifyFetchError(err, timedOut, ms) {
  if (timedOut) {
    return { kind: 'timeout', code: 'TIMEOUT', label: `no response within ${Math.round(ms / 1000)}s` };
  }
  const code = err?.cause?.code || err?.code || null;
  const mapped = code ? FETCH_ERROR_KINDS[code] : null;
  if (mapped) return { kind: mapped.kind, code, label: mapped.label };
  return { kind: 'unknown', code: code || null, label: err?.cause?.message || err?.message || 'unknown network error' };
}

// Errors worth a second attempt. All three fail in roughly zero milliseconds, so a retry costs
// nothing measurable — and edge bot protection (Cloudflare Bot Fight Mode in particular)
// challenges requests probabilistically rather than blocking outright, so the same origin can
// refuse one connection and serve the next. Observed directly on a client site: a scan refused
// at every user-agent in the morning completed cleanly an hour later with nothing changed.
// DNS and TLS failures are deliberately excluded — those are settled facts that a retry will
// not change, and retrying them just doubles the wait before an honest answer.
// A response that arrived is not the same as a page that can be read. fetchSafe reports ok:true
// for any answer it received, 403 and 429 included.
const isOk2xx = r => !!(r && r.ok && r.status >= 200 && r.status < 300);

const RETRYABLE_ERROR_KINDS = new Set(['refused', 'network', 'unknown']);
const RETRY_BACKOFF_MS = [1500, 4000];

async function fetchSafe(url, uaString, timeoutMs = FETCH_TIMEOUT_MS) {
  let res = await fetchOnce(url, uaString, timeoutMs);
  let attempts = 1;
  for (const backoff of RETRY_BACKOFF_MS) {
    if (res.ok || !RETRYABLE_ERROR_KINDS.has(res.errorKind)) break;
    await sleep(backoff);
    res = await fetchOnce(url, uaString, timeoutMs);
    attempts++;
  }
  // Record the attempt count, so a site that only responds intermittently stays visible as such
  // in the raw output rather than being silently smoothed over.
  if (attempts > 1) return { ...res, attempts, recoveredAfterRetry: res.ok };
  return res;
}

async function fetchOnce(url, uaString, timeoutMs = FETCH_TIMEOUT_MS) {
  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => { timedOut = true; controller.abort(); }, timeoutMs);
  const started = Date.now();
  try {
    const res = await fetch(url, {
      headers: {
        'User-Agent': uaString,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9,es;q=0.8',
        'Accept-Encoding': 'gzip, deflate, br',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1'
      },
      redirect: 'follow',
      signal: controller.signal
    });
    const text = await res.text();
    return { ok: true, status: res.status, headers: res.headers, text, ms: Date.now() - started };
  } catch (err) {
    const ms = Date.now() - started;
    const cls = classifyFetchError(err, timedOut, ms);
    return { ok: false, status: 0, headers: null, text: '', ms, error: cls.label, errorCode: cls.code, errorKind: cls.kind };
  } finally {
    clearTimeout(timer);
  }
}

// A failure that says nothing about the site itself, only about our ability to reach it from
// this particular network. These must never be scored as site defects — a refused connection
// is most often a WAF rejecting our cloud egress IP, and the site works fine for everyone else.
function isTransportFailure(res) {
  return !res.ok && ['refused', 'dns', 'network', 'tls', 'timeout', 'unknown'].includes(res.errorKind);
}

function normalizeUrl(input) {
  let u = String(input || '').trim();
  if (!/^https?:\/\//i.test(u)) u = 'https://' + u;
  return new URL(u);
}

// ── Section 1: Crawlability ──

// ── AI crawler taxonomy ──
// The distinction that matters for GEO is training vs retrieval, and the old check collapsed it.
//
//   retrieval  — fetches a page live, at the moment someone asks a question. If these are blocked
//                the site cannot appear in AI answers at all. This is the category that governs
//                AI visibility, and blocking it is almost always accidental.
//   training   — collects content for model training. Blocking these is a legitimate content
//                licensing decision with a real but slower-acting visibility cost, so it is
//                reported as a warning rather than a failure.
//   search     — conventional search crawling, still the substrate for several AI surfaces.
//
// Google-Extended deserves specific mention: it governs whether Google may use the site for
// Gemini and Vertex grounding, it is not a crawler in its own right, and the one-click "block AI
// crawlers" toggles in Yoast and RankMath set it. Owners routinely enable that without realising
// they have removed themselves from Gemini. It is invisible in a browser and easy to miss by
// hand — exactly the failure this tool exists to surface.
const AI_CRAWLERS = [
  { token: 'OAI-SearchBot', label: 'OAI-SearchBot', engine: 'ChatGPT', category: 'retrieval' },
  { token: 'ChatGPT-User', label: 'ChatGPT-User', engine: 'ChatGPT', category: 'retrieval' },
  { token: 'Claude-User', label: 'Claude-User', engine: 'Claude', category: 'retrieval' },
  { token: 'Claude-SearchBot', label: 'Claude-SearchBot', engine: 'Claude', category: 'retrieval' },
  { token: 'PerplexityBot', label: 'PerplexityBot', engine: 'Perplexity', category: 'retrieval' },
  { token: 'Perplexity-User', label: 'Perplexity-User', engine: 'Perplexity', category: 'retrieval' },
  { token: 'Google-Extended', label: 'Google-Extended', engine: 'Gemini', category: 'retrieval' },
  { token: 'GPTBot', label: 'GPTBot', engine: 'ChatGPT', category: 'training' },
  { token: 'ClaudeBot', label: 'ClaudeBot', engine: 'Claude', category: 'training' },
  { token: 'anthropic-ai', label: 'anthropic-ai', engine: 'Claude', category: 'training' },
  { token: 'CCBot', label: 'CCBot', engine: 'Common Crawl', category: 'training' },
  { token: 'Applebot-Extended', label: 'Applebot-Extended', engine: 'Apple Intelligence', category: 'training' },
  { token: 'Meta-ExternalAgent', label: 'Meta-ExternalAgent', engine: 'Meta AI', category: 'training' },
  { token: 'Bytespider', label: 'Bytespider', engine: 'ByteDance', category: 'training' },
  { token: 'Amazonbot', label: 'Amazonbot', engine: 'Amazon', category: 'training' },
  { token: 'Googlebot', label: 'Googlebot', engine: 'Google Search', category: 'search' },
  { token: 'Bingbot', label: 'Bingbot', engine: 'Bing / Copilot', category: 'search' },
  { token: '*', label: 'All crawlers (*)', engine: 'every engine', category: 'search' }
];

const CATEGORY_LABEL = { retrieval: 'live retrieval', training: 'model training', search: 'search indexing' };

async function checkRobots(origin, ua = USER_AGENTS.browser.ua) {
  const robotsUrl = origin + '/robots.txt';
  const res = await fetchSafe(robotsUrl, ua);
  // A genuine 404 and a refused connection are completely different findings. The first means
  // "no rules, all bots allowed" (benign). The second means we learned nothing at all.
  if (isTransportFailure(res)) {
    return {
      id: 'robots-txt',
      title: t('Reglas de robots.txt para rastreadores de IA', 'robots.txt AI crawler rules'),
      status: 'INCONCLUSIVE',
      detail: t(
        `No se ha podido acceder a robots.txt: ${res.error}. Esto no dice nada sobre el archivo en sí; el escáner no ha podido completar una petición a este servidor.`,
        `Could not reach robots.txt — ${res.error}. This says nothing about the file itself; the scanner could not complete a request to this origin.`
      ),
      howToFix: t(
        'No implica ninguna acción sobre el sitio web. Repite el escaneo y, si persiste, abre esta URL a mano en el navegador para confirmar si el archivo existe.',
        'No action implied for the site. Re-run the scan, and if it persists, fetch this URL manually from a browser to confirm whether the file exists.'
      ),
      raw: { url: robotsUrl, errorKind: res.errorKind, errorCode: res.errorCode }
    };
  }
  if (RATE_LIMIT_STATUSES.has(res.status)) {
    // Rate limited, not absent. Saying "no rules, so every AI crawler is allowed" would be an
    // assurance about crawler access that this scan has no basis for.
    return {
      id: 'robots-txt',
      title: t('Reglas de robots.txt para rastreadores de IA', 'robots.txt AI crawler rules'),
      status: 'INCONCLUSIVE',
      detail: t(
        `No se ha podido leer robots.txt: el servidor respondió HTTP ${res.status} (límite de peticiones). No sabemos qué reglas contiene, así que no se puede afirmar nada sobre el acceso de los rastreadores de IA.`,
        `robots.txt could not be read — the server responded HTTP ${res.status} (rate limited). Its rules are unknown, so nothing can be concluded about AI crawler access.`
      ),
      howToFix: t(
        'Vuelve a correr el análisis más tarde. Si se repite, el alojamiento está limitando la frecuencia de peticiones y conviene pedir que lo suban para los rastreadores de IA.',
        'Re-run the scan later. If it persists, the host is rate limiting requests and it is worth asking them to raise the limit for AI crawlers.'
      ),
      raw: { url: robotsUrl, status: res.status }
    };
  }
  if (res.status >= 400) {
    return {
      id: 'robots-txt',
      title: t('Reglas de robots.txt para rastreadores de IA', 'robots.txt AI crawler rules'),
      status: 'WARNING',
      detail: t(
        `robots.txt devuelve HTTP ${res.status}: no hay reglas explícitas, así que todos los rastreadores, incluidos todos los motores de IA, están permitidos de forma implícita.`,
        `robots.txt returned HTTP ${res.status} — no explicit rules found, so all crawlers including every AI engine are implicitly allowed.`
      ),
      howToFix: t(
        'No es necesariamente un problema: la ausencia de robots.txt significa que todos los bots están permitidos por defecto. Si quieres control explícito (declarar el sitemap, bloquear rutas concretas), añade un archivo robots.txt en la raíz del sitio web.',
        'Not necessarily a problem — a missing robots.txt means all bots are allowed by default. If you want explicit control (declaring a sitemap, blocking specific paths), add a robots.txt file at the site root.'
      ),
      raw: { url: robotsUrl, status: res.status }
    };
  }

  const robots = robotsParser(robotsUrl, res.text);
  const evaluated = AI_CRAWLERS.map(bot => ({
    ...bot,
    blocked: robots.isAllowed(origin + '/', bot.token) === false
  }));

  const blocked = evaluated.filter(b => b.blocked);
  const blockedRetrieval = blocked.filter(b => b.category === 'retrieval');
  const blockedTraining = blocked.filter(b => b.category === 'training');
  const blockedSearch = blocked.filter(b => b.category === 'search');

  const sitemaps = robots.getSitemaps ? robots.getSitemaps() : [];
  const listed = arr => arr.map(b => b.label).join(', ');
  const engines = arr => [...new Set(arr.map(b => b.engine))].join(', ');

  let status = 'PASS';
  let detail = t(
    `robots.txt encontrado. Ninguno de los ${AI_CRAWLERS.length} identificadores de rastreadores de IA, de recuperación y de búsqueda comprobados está bloqueado en la portada.`,
    `robots.txt found. None of the ${AI_CRAWLERS.length} AI, retrieval and search crawler tokens checked are blocked from the homepage.`
  );
  let howToFix;

  if (blockedRetrieval.length || blockedSearch.length) {
    // Retrieval and search blocks are hard failures: they remove the site from AI answers and
    // search results outright.
    status = 'FAIL';
    const partsEs = []; const partsEn = [];
    if (blockedRetrieval.length) {
      partsEs.push(`la recuperación en vivo está bloqueada para ${listed(blockedRetrieval)}, de modo que el sitio web no puede citarse en las respuestas de ${engines(blockedRetrieval)}`);
      partsEn.push(`live retrieval blocked for ${listed(blockedRetrieval)}, so the site cannot be cited in answers from ${engines(blockedRetrieval)}`);
    }
    if (blockedSearch.length) {
      partsEs.push(`la indexación de búsqueda está bloqueada para ${listed(blockedSearch)}`);
      partsEn.push(`search indexing blocked for ${listed(blockedSearch)}`);
    }
    if (blockedTraining.length) {
      partsEs.push(`el entrenamiento de modelos también está bloqueado para ${listed(blockedTraining)}`);
      partsEn.push(`model training also blocked for ${listed(blockedTraining)}`);
    }
    detail = t(`robots.txt bloquea la portada: ${partsEs.join('; ')}.`, `robots.txt blocks the homepage: ${partsEn.join('; ')}.`);
    const hasGE = blockedRetrieval.some(b => b.token === 'Google-Extended');
    const geEs = hasGE ? 'Google-Extended es el identificador que autoriza el uso del sitio web en Gemini y Vertex; lo activa sin querer la casilla de «bloquear rastreadores de IA» de plugins de SEO como Yoast o RankMath, así que empieza por ahí. ' : '';
    const geEn = hasGE ? 'Google-Extended is the token that permits Gemini and Vertex grounding — it is commonly set without intent by the "block AI crawlers" toggle in SEO plugins such as Yoast and RankMath, so check there first. ' : '';
    howToFix = t(
      `Elimina de robots.txt las reglas Disallow para ${listed([...blockedRetrieval, ...blockedSearch])}, o añade reglas Allow explícitas. ${geEs}Si el sitio web no tiene un robots.txt escrito a mano, estas reglas las genera un plugin de SEO, el propio CMS o una función de robots gestionados del CDN: corrígelo en ese origen, o el archivo se volverá a generar igual.`,
      `Remove the Disallow rules for ${listed([...blockedRetrieval, ...blockedSearch])} in robots.txt, or add explicit Allow rules. ${geEn}If the site has no hand-written robots.txt, these rules are being generated by an SEO plugin, the CMS, or a CDN managed-robots feature — fix it at that source, or the file will simply be regenerated.`
    );
  } else if (blockedTraining.length) {
    // Training-only blocks are a legitimate licensing choice, so this warns and names the
    // trade-off rather than treating it as a defect to correct.
    status = 'WARNING';
    detail = t(
      `robots.txt bloquea los rastreadores de entrenamiento: ${listed(blockedTraining)}. La recuperación en vivo y el rastreo de búsqueda siguen abiertos, así que el sitio web aún puede citarse en respuestas de IA, pero no quedará representado en el conocimiento base de ${engines(blockedTraining)}.`,
      `robots.txt blocks model-training crawlers: ${listed(blockedTraining)}. Live retrieval and search crawling remain open, so the site can still be cited in AI answers — but it will not be represented in the underlying model knowledge of ${engines(blockedTraining)}.`
    );
    howToFix = t(
      'No hace falta actuar si es deliberado: bloquear los rastreadores de entrenamiento es una postura razonable en materia de licencias de contenido, y no afecta a los rastreadores de recuperación, que son los que determinan la visibilidad en IA. Si no fue deliberado, revisa el plugin de SEO o el ajuste del CDN que generó estas reglas.',
      'No action needed if this is deliberate — blocking training crawlers is a reasonable content-licensing position, and the retrieval crawlers that drive AI visibility are unaffected. If it was not deliberate, check the SEO plugin or CDN setting that generated these rules.'
    );
  }

  return {
    id: 'robots-txt',
    title: t('Reglas de robots.txt para rastreadores de IA', 'robots.txt AI crawler rules'),
    status,
    detail,
    howToFix,
    raw: {
      url: robotsUrl,
      crawlersChecked: AI_CRAWLERS.length,
      blocked: blocked.map(b => ({ token: b.token, engine: b.engine, category: CATEGORY_LABEL[b.category] })),
      byCategory: { retrieval: blockedRetrieval.map(b => b.token), training: blockedTraining.map(b => b.token), search: blockedSearch.map(b => b.token) },
      sitemapsDeclared: sitemaps,
      bodyExcerpt: res.text.slice(0, 4000)
    }
  };
}
// The browser-UA result is passed in rather than fetched again: runScan already makes exactly
// one isolated browser-UA request to time the homepage, and that response doubles as both the
// crawl-test baseline and the HTML source for every on-page check. The remaining user-agents
// are then issued at MAX_CONCURRENT_FETCHES, never as one burst.
//
// The verdict logic is deliberately conservative. A bot user-agent is only reported as blocked
// when the server answered with an explicit refusal status while the browser UA succeeded —
// that combination is a deliberate server decision. A timeout or a dropped connection is not
// evidence of bot-blocking; it is evidence of an unreliable connection, and treating the two as
// equivalent is what previously let one stray timeout gate an entire scan.
// Statuses that represent a deliberate, persistent policy decision to refuse a crawler. 402 is
// included because Cloudflare pay-per-crawl answers AI crawlers it wants payment from with
// Payment Required, which to a crawler is a refusal like any other.
//
// 429 is deliberately NOT here. It means "you are asking too often", not "you are not
// permitted" — a transient condition a scan can trigger itself. Observed live: after repeated
// scans of one client site the host answered every named-crawler UA with 429 "Rate limit
// exceeded" and Retry-After: 3600 while the browser UA still returned 200. The old logic called
// that a deliberate decision to reject AI crawlers. It was our own traffic.
const EXPLICIT_BLOCK_STATUSES = new Set([401, 402, 403, 405, 451]);
const RATE_LIMIT_STATUSES = new Set([429, 503]);

async function checkMultiUA(pageUrl, browserFetch) {
  const others = Object.entries(USER_AGENTS).filter(([key]) => key !== 'browser');
  const fetched = await mapLimited(others, async ([key, cfg]) => ({ key, cfg, r: await fetchSafe(pageUrl, cfg.ua) }));
  const raw = [{ key: 'browser', cfg: USER_AGENTS.browser, r: browserFetch }, ...fetched];

  const results = raw.map(({ key, cfg, r }) => ({
    key, label: cfg.label, ua: cfg.ua, status: r.status, ok: r.ok, ms: r.ms,
    bodyLength: r.text.length, error: r.error, errorKind: r.errorKind,
    explicitlyBlocked: EXPLICIT_BLOCK_STATUSES.has(r.status),
    rateLimited: RATE_LIMIT_STATUSES.has(r.status),
    retryAfter: r.headers ? r.headers.get('retry-after') : null,
    serverError: r.status >= 500,
    transportFailed: isTransportFailure(r)
  }));

  const baseline = results.find(r => r.key === 'browser');
  const bots = results.filter(r => r.key !== 'browser');

  // Baseline itself failed at the transport layer: we learned nothing about bot access at all.
  // runScan turns this into the site-reachability check instead of a verdict about the site.
  if (baseline.transportFailed) {
    return {
      check: {
        id: 'multi-ua',
        title: t('Prueba de rastreo con varios user-agents', 'Multi-user-agent crawl test'),
        status: 'INCONCLUSIVE',
        detail: t(
          `Ningún user-agent ha completado la petición, tampoco el de un navegador normal (${baseline.error}). Como la petición de control también ha fallado, esto no dice nada sobre si los rastreadores de IA están bloqueados en concreto: solo que el escáner no ha podido alcanzar el servidor.`,
          `No user-agent completed a request, including a plain browser UA (${baseline.error}). Because the control request failed too, this tells us nothing about whether AI crawlers specifically are blocked — only that the scanner could not reach the origin.`
        ),
        howToFix: t(
          'Consulta la revisión de accesibilidad del sitio web para ver qué se ha podido determinar sobre la conectividad. No lo interpretes como prueba de bloqueo de bots.',
          'See the site-reachability check for what could be determined about connectivity. Do not treat this as evidence of bot-blocking.'
        ),
        raw: { results }
      },
      unreachable: true,
      errorKinds: results.map(r => r.errorKind).filter(Boolean),
      sampleError: baseline.error
    };
  }

  const explicitBlocks = bots.filter(b => b.explicitlyBlocked);
  const rateLimited = bots.filter(b => b.rateLimited);
  const serverErrors = bots.filter(b => b.serverError && !b.rateLimited);
  const flaky = bots.filter(b => b.transportFailed);
  const suspiciousSizeDiff = bots.filter(b => b.ok && baseline.bodyLength > 0 && Math.abs(b.bodyLength - baseline.bodyLength) / baseline.bodyLength > 0.6);

  let status = 'PASS';
  let detail = t(
    `Los ${results.length} user-agents probados (navegador, GPTBot, ClaudeBot, Googlebot, OAI-SearchBot, PerplexityBot y uno genérico) han recibido la misma respuesta correcta.`,
    `All ${results.length} tested user-agents (browser, GPTBot, ClaudeBot, Googlebot, OAI-SearchBot, PerplexityBot, plain default) received the same, successful response.`
  );
  let howToFix;

  // Checked before the bot branches: when the browser itself was refused, every one of them
  // would describe the comparison backwards.
  const browserRefused = !(baseline.ok && baseline.status >= 200 && baseline.status < 300);
  const botsThatRead = bots.filter(b => b.ok && b.status >= 200 && b.status < 300);

  if (browserRefused && botsThatRead.length) {
    // Not a bot-blocking finding — the opposite. Reported as a warning because the site is
    // readable by the engines that matter, while a human on the wrong network may be refused.
    status = 'WARNING';
    detail = t(
      `El servidor rechaza al user-agent de navegador (HTTP ${baseline.status}) pero responde con normalidad a ${botsThatRead.map(b => b.label).join(', ')}. Es lo contrario de lo habitual: la IA sí puede leer el sitio web. El análisis se hizo con una de esas identidades. Conviene revisarlo, porque una regla que rechaza peticiones con aspecto de navegador puede estar dejando fuera a visitantes reales en ciertas redes.`,
      `The server refuses a browser user-agent (HTTP ${baseline.status}) but answers ${botsThatRead.map(b => b.label).join(', ')} normally. That is the reverse of the usual arrangement: AI can read this site. The scan was performed as one of those identities. Worth reviewing, because a rule that refuses browser-shaped requests may also be turning away real visitors on some networks.`
    );
    howToFix = t(
      'Revisa con quien administra el servidor qué regla rechaza las peticiones con user-agent de navegador. Suele ser una protección contra bots configurada al revés: confía en los rastreadores que se identifican y desconfía de todo lo demás. Comprueba también que el sitio web abra con normalidad desde una red móvil o una VPN.',
      'Ask whoever runs the server which rule refuses browser user-agents. It is usually bot protection configured backwards: trusting crawlers that identify themselves and distrusting everything else. Check the site also opens normally from a mobile network or a VPN.'
    );
  } else if (explicitBlocks.length) {
    status = 'FAIL';
    detail = t(
      `El servidor ha rechazado explícitamente: ${explicitBlocks.map(b => `${b.label} (HTTP ${b.status})`).join(', ')}, mientras que el user-agent de navegador sí ha funcionado (HTTP ${baseline.status}). Un estado de rechazo explícito junto a una petición de navegador que funciona es una decisión deliberada del servidor de rechazar a estos rastreadores.`,
      `The server explicitly refused: ${explicitBlocks.map(b => `${b.label} (HTTP ${b.status})`).join(', ')}, while the browser UA succeeded (HTTP ${baseline.status}). An explicit refusal status alongside a working browser request is a deliberate server-side decision to reject these crawlers.`
    );
    howToFix = t(
      'Revisa el firewall o WAF de tu hosting y cualquier ajuste de «bloquear bots maliciosos» o modo de lucha contra bots en el panel de control o en el CDN (Cloudflare, Sucuri, etc.). Suelen bloquear por defecto los user-agents de rastreadores de IA bajo reglas genéricas de protección. Añade GPTBot, ClaudeBot y Googlebot a la lista de permitidos.',
      'Check your hosting firewall/WAF and any "block bad bots" or bot-fight-mode settings in your hosting control panel or CDN (Cloudflare, Sucuri, etc) — these often block AI crawler user-agents by default under generic bot-protection rules. Add GPTBot, ClaudeBot, and Googlebot to an allowlist.'
    );
  } else if (rateLimited.length) {
    // Rate limiting is reported honestly as inconclusive-leaning: it is transient, it may have
    // been caused by this scan, and it is never evidence of an AI-crawler policy.
    status = 'WARNING';
    const ra = rateLimited.map(b => b.retryAfter).find(Boolean);
    detail = t(
      `Límite de peticiones (HTTP ${rateLimited[0].status}) para: ${rateLimited.map(b => b.label).join(', ')}, mientras que el user-agent de navegador sí ha funcionado (HTTP ${baseline.status})${ra ? `. El servidor pide esperar unos ${Math.round(Number(ra) / 60) || 1} minuto(s) (Retry-After: ${ra})` : ''}. Es un límite de frecuencia de peticiones, no una decisión de rechazar rastreadores de IA, y el propio escaneo puede provocarlo, así que no se trata como un hallazgo de bloqueo de bots.`,
      `Rate limited (HTTP ${rateLimited[0].status}) for: ${rateLimited.map(b => b.label).join(', ')}, while the browser UA succeeded (HTTP ${baseline.status})${ra ? `. The server asked for a ${Math.round(Number(ra) / 60) || 1}-minute wait (Retry-After: ${ra})` : ''}. This is a request-rate limit, not a decision to reject AI crawlers — and it can be triggered by scanning itself, so it is not treated as a bot-blocking finding.`
    );
    howToFix = t(
      'Repite el escaneo cuando pase la ventana de espera. Si los user-agents de rastreadores conocidos siguen limitados mientras que el de navegador no, el hosting aplica un límite específico para rastreadores que conviene plantear: pídeles que lo eleven o lo retiren para GPTBot, ClaudeBot, OAI-SearchBot y PerplexityBot, ya que un límite agresivo ralentiza o impide la indexación por IA.',
      'Re-run the scan after the retry window has passed. If named crawler user-agents are still rate limited while a browser is not, the host has a crawler-specific rate limit worth raising — ask them to raise or remove it for GPTBot, ClaudeBot, OAI-SearchBot and PerplexityBot, since aggressive rate limiting slows or prevents AI indexing.'
    );
  } else if (serverErrors.length) {
    status = 'WARNING';
    detail = t(
      `Errores de servidor para: ${serverErrors.map(b => `${b.label} (HTTP ${b.status})`).join(', ')}, mientras que el user-agent de navegador sí ha funcionado. Un 5xx apunta más a un fallo del servidor que a un bloqueo deliberado, pero deja fuera a estos rastreadores igual de eficazmente.`,
      `Server errors for: ${serverErrors.map(b => `${b.label} (HTTP ${b.status})`).join(', ')} while the browser UA succeeded. A 5xx is more likely a server fault than a deliberate block, but it keeps these crawlers out just as effectively.`
    );
    howToFix = t(
      'Revisa los registros de error del servidor buscando peticiones con estos user-agents. Un error de aplicación que solo se produce para ciertos UA suele indicar que el middleware de detección de bots está fallando en lugar de rechazar limpiamente.',
      'Check server error logs for requests carrying these user-agent strings — an application error triggered only for certain UAs often points at bot-detection middleware failing rather than rejecting cleanly.'
    );
  } else if (flaky.length) {
    status = 'WARNING';
    detail = t(
      `La conexión no se ha completado para: ${flaky.map(b => `${b.label} (${b.error})`).join(', ')}, aunque el user-agent de navegador sí ha funcionado. No se interpreta como prueba de bloqueo de bots —un servidor lo señalaría con un estado de rechazo, no cortando la conexión—, pero conviene repetir el escaneo para ver si se reproduce.`,
      `Connection did not complete for: ${flaky.map(b => `${b.label} (${b.error})`).join(', ')}, though the browser UA succeeded. This is not treated as evidence of bot-blocking — a server would signal that with a refusal status, not a dropped connection — but it is worth a re-run to see whether it repeats.`
    );
    howToFix = t(
      'Repite el escaneo. Si los mismos user-agents fallan una y otra vez mientras el de navegador sigue funcionando, investiga si hay límites de frecuencia o filtrado a nivel de conexión en el hosting o el CDN.',
      'Re-run the scan. If the same user-agents fail repeatedly while the browser UA keeps succeeding, investigate rate limiting or connection-level filtering at the host or CDN.'
    );
  } else if (suspiciousSizeDiff.length) {
    status = 'WARNING';
    detail = t(
      `El tamaño de la respuesta varía mucho según el user-agent para: ${suspiciousSizeDiff.map(b => b.label).join(', ')}. Conviene revisarlo a mano por si a algún bot se le está sirviendo una página recortada o distinta.`,
      `Response size differs sharply by user-agent for: ${suspiciousSizeDiff.map(b => b.label).join(', ')} — worth a manual look in case a bot is served a stripped-down or cloaked page.`
    );
    howToFix = t(
      'Confirma que no estás sirviendo contenido distinto según el user-agent sin querer (cloaking, algo que penalizan tanto los motores de IA como los buscadores). Revisa capas de caché o middleware de detección de bots que puedan estar alterando la respuesta para ciertos UA.',
      'Confirm you\'re not unintentionally serving different content by user-agent (cloaking, which AI engines and search engines both penalize) — check for caching layers or bot-detection middleware that could be altering the response for specific UAs.'
    );
  }

  return { check: { id: 'multi-ua', title: t('Prueba de rastreo con varios user-agents', 'Multi-user-agent crawl test'), status, detail, howToFix, raw: { results } }, unreachable: false };
}

function checkXRobotsTag(headers) {
  const val = headers ? headers.get('x-robots-tag') : null;
  if (!val) {
    return { id: 'x-robots-tag', title: t('Encabezado X-Robots-Tag', 'X-Robots-Tag header'), status: 'PASS', detail: t('No hay encabezado X-Robots-Tag: este mecanismo de bloqueo a nivel de servidor no está en juego.', 'No X-Robots-Tag header present — this server-level blocking mechanism is not in play.'), raw: { value: null } };
  }
  const blocking = /noindex|none/i.test(val);
  return {
    id: 'x-robots-tag',
    title: t('Encabezado X-Robots-Tag', 'X-Robots-Tag header'),
    status: blocking ? 'FAIL' : 'WARNING',
    detail: blocking
      ? t(
          `X-Robots-Tag: «${val}». Esta encabezado HTTP bloquea la indexación a nivel de servidor, al margen de robots.txt y de cualquier meta etiqueta. Es fácil pasarla por alto si no se revisan los encabezados directamente.`,
          `X-Robots-Tag: "${val}" — this HTTP header blocks indexing at the server level, separately from robots.txt and any meta tag. Easy to miss without checking headers directly.`
        )
      : t(
          `Hay encabezado X-Robots-Tag («${val}»), pero no parece bloquear la indexación.`,
          `X-Robots-Tag present ("${val}") but does not appear to block indexing.`
        ),
    howToFix: blocking
      ? t(
          'Elimina la directiva noindex de la encabezado de respuesta X-Robots-Tag. Suele configurarse en el servidor (.htaccess, nginx.conf) o en un plugin de seguridad o SEO, no en el HTML de la página, así que revisa ahí antes que en el editor del CMS.',
          'Remove the noindex directive from the X-Robots-Tag response header — this is usually set in server config (.htaccess, nginx.conf) or a security/SEO plugin, not in page HTML, so check those before the CMS editor.'
        )
      : t(
          'No hace falta actuar salvo que este valor sea involuntario: confirma que la X-Robots-Tag mostrada es deliberada.',
          'No action needed unless this value is unintentional — confirm the X-Robots-Tag shown above is deliberate.'
        ),
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
    title: t('Meta etiqueta robots noindex', 'Meta robots noindex tag'),
    status: blocking ? 'FAIL' : 'PASS',
    detail: blocking
      ? t(
          'Hay una etiqueta <meta name="robots"> (o googlebot) con «noindex» en el <head>. Es un tercer mecanismo de bloqueo, distinto de robots.txt y de X-Robots-Tag, y a menudo queda activado sin querer tras pasar de pruebas a producción o por el ajuste de WordPress «Disuadir a los motores de búsqueda».',
          'A <meta name="robots"> (or googlebot) tag with "noindex" is present in <head>. This is a distinct, third blocking mechanism from robots.txt and X-Robots-Tag — often left on accidentally after a staging-to-production migration or a WordPress "discourage search engines" setting.'
        )
      : t('No se encuentra ninguna meta etiqueta noindex en el <head>.', 'No noindex meta tag found in <head>.'),
    howToFix: blocking
      ? t(
          'Elimina la etiqueta <meta name="robots" content="noindex"> del <head> de la página. En WordPress: Ajustes → Lectura → desmarca «Disuadir a los motores de búsqueda de indexar este sitio web». En otros CMS o plugins de SEO, busca el equivalente por página o para todo el sitio web.',
          'Remove the <meta name="robots" content="noindex"> tag from the page\'s <head>. In WordPress: Settings → Reading → uncheck "Discourage search engines from indexing this site." In other CMSes/SEO plugins, check for an equivalent per-page or site-wide noindex toggle.'
        )
      : undefined,
    raw: { metaRobots, metaGooglebot }
  };
}

// Candidate sitemap locations, tried in order after anything robots.txt actually declares.
// The old check only ever looked at /sitemap.xml, so a site with a perfectly good sitemap at
// /sitemap_index.xml (the Yoast default) or /wp-sitemap.xml (WordPress core since 5.5) was
// reported as having none — a false finding handed straight to the client.
const SITEMAP_CANDIDATES = ['/sitemap.xml', '/sitemap_index.xml', '/wp-sitemap.xml', '/sitemap-index.xml', '/sitemap1.xml'];

function parseSitemapBody(url, text) {
  const looksXml = /^\s*<\?xml/i.test(text) || /<urlset/i.test(text) || /<sitemapindex/i.test(text);
  if (!looksXml) return { valid: false, url };
  return {
    valid: true,
    url,
    urlCount: (text.match(/<loc>/gi) || []).length,
    isIndex: /<sitemapindex/i.test(text)
  };
}

async function checkSitemap(origin, declaredSitemaps = [], ua = USER_AGENTS.browser.ua) {
  // Anything robots.txt declares is authoritative and gets tried first — a site that publishes
  // its sitemap at a non-standard path and says so is correctly configured, and guessing paths
  // before reading the declaration would report it as broken.
  const declared = declaredSitemaps.filter(u => typeof u === 'string' && /^https?:\/\//i.test(u));
  const candidates = [...declared, ...SITEMAP_CANDIDATES.map(p => origin + p)];
  const seen = new Set();
  const attempts = [];
  let transportFailures = 0;

  for (const url of candidates) {
    const key = url.replace(/\/+$/, '').toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);

    const res = await fetchSafe(url, ua);
    if (isTransportFailure(res)) { transportFailures++; attempts.push({ url, error: res.error }); continue; }
    if (res.status >= 400) { attempts.push({ url, status: res.status }); continue; }

    const parsed = parseSitemapBody(url, res.text);
    if (!parsed.valid) { attempts.push({ url, status: res.status, note: 'not valid XML' }); continue; }

    const wasDeclared = declared.some(d => d.replace(/\/+$/, '').toLowerCase() === key);
    let status = 'PASS';
    let detail = t(
      `${parsed.isIndex ? 'Índice de sitemaps' : 'Sitemap'} válido en ${url}, con ${parsed.urlCount} URL${parsed.urlCount === 1 ? '' : 's'} listada${parsed.urlCount === 1 ? '' : 's'}${wasDeclared ? ' y declarado en robots.txt' : ''}.`,
      `Valid ${parsed.isIndex ? 'sitemap index' : 'sitemap'} at ${url} with ${parsed.urlCount} URL${parsed.urlCount === 1 ? '' : 's'} listed${wasDeclared ? ', declared in robots.txt' : ''}.`
    );
    let howToFix;
    if (parsed.urlCount === 0) {
      status = 'FAIL';
      detail = t(
        `El sitemap de ${url} es XML válido pero no contiene ninguna entrada <loc>: está vacío en la práctica.`,
        `The sitemap at ${url} is valid XML but contains zero <loc> entries — effectively empty.`
      );
      howToFix = t(
        'Revisa por qué el generador o plugin de sitemaps está produciendo un archivo vacío. Suele ser una mala configuración (tipo de contenido o filtro equivocado) más que una ausencia real de páginas.',
        'Check why your sitemap generator/plugin is producing an empty file — often a misconfiguration (wrong post type/content filter) rather than a genuine absence of pages.'
      );
    } else if (parsed.urlCount < 3 && !parsed.isIndex) {
      status = 'WARNING';
      detail = t(
        `El sitemap de ${url} solo lista ${parsed.urlCount} URL${parsed.urlCount === 1 ? '' : 's'}, una cifra inusualmente baja; confirma que se genera y se actualiza correctamente.`,
        `The sitemap at ${url} lists only ${parsed.urlCount} URL${parsed.urlCount === 1 ? '' : 's'} — unusually small; confirm it is being generated and updated correctly.`
      );
      howToFix = t(
        'Confirma que el generador de sitemaps incluye todas las páginas publicadas y no solo una parte (un fallo habitual tras migrar de CMS o de plugin).',
        'Confirm the sitemap generator is including all published pages, not just a subset (a common bug after a CMS or plugin migration).'
      );
    } else if (!wasDeclared) {
      howToFix = t(
        `El sitemap funciona, pero no está declarado en robots.txt. Añade «Sitemap: ${url}» a robots.txt para que los rastreadores lo encuentren sin tener que adivinarlo.`,
        `The sitemap works but is not declared in robots.txt. Add "Sitemap: ${url}" to robots.txt so crawlers find it without guessing.`
      );
    }
    return { id: 'sitemap', title: t('Sitemap XML', 'XML sitemap'), status, detail, howToFix, raw: { url, urlCount: parsed.urlCount, isIndex: parsed.isIndex, declaredInRobots: wasDeclared, attempts } };
  }

  // Nothing valid found. If every attempt died at the transport layer we learned nothing at all,
  // so that is unverified rather than a missing-sitemap finding.
  if (transportFailures === attempts.length && attempts.length > 0) {
    return { id: 'sitemap', title: t('Sitemap XML', 'XML sitemap'), status: 'INCONCLUSIVE', detail: t('No se ha podido acceder a ninguna ubicación de sitemap: todas las peticiones a este servidor han fallado a nivel de conexión. Se desconoce si existe un sitemap.', 'Could not reach any sitemap location — every request to this origin failed at the connection level. Whether a sitemap exists is unknown.'), howToFix: t('No implica ninguna acción sobre el sitio web. Repite el escaneo, o abre la URL del sitemap a mano para confirmarlo.', 'No action implied for the site. Re-run the scan, or open the sitemap URL manually to confirm.'), raw: { attempts } };
  }

  // If every candidate was rate limited we never saw whether a sitemap exists.
  const allRateLimited = attempts.length > 0 && attempts.every(a => RATE_LIMIT_STATUSES.has(a.status));
  if (allRateLimited) {
    return {
      id: 'sitemap',
      title: t('Sitemap XML', 'XML sitemap'),
      status: 'INCONCLUSIVE',
      detail: t(
        `No se ha podido comprobar si hay sitemap: las ${attempts.length} ubicación(es) probadas respondieron con un límite de peticiones (HTTP 429/503). Puede que exista un sitemap y no hayamos podido verlo.`,
        `Whether a sitemap exists could not be checked — all ${attempts.length} location(s) tried responded with a rate limit (HTTP 429/503). A sitemap may well exist and simply not have been reachable.`
      ),
      howToFix: t(
        'Vuelve a correr el análisis más tarde, cuando haya pasado la ventana de espera del servidor.',
        'Re-run the scan later, once the server has lifted its retry window.'
      ),
      raw: { attempts, declaredInRobots: declared, rateLimited: true }
    };
  }

  return {
    id: 'sitemap',
    title: t('Sitemap XML', 'XML sitemap'),
    status: 'WARNING',
    detail: t(
      `No se encuentra ningún sitemap XML. Se han comprobado ${attempts.length} ubicación${attempts.length === 1 ? '' : 'es'}${declared.length ? ', incluida la declarada en robots.txt' : ''}: ${attempts.map(a => a.url.replace(origin, '')).join(', ')}. No es grave, pero su ausencia hace más lento el descubrimiento para todos los rastreadores.`,
      `No XML sitemap found. Checked ${attempts.length} location${attempts.length === 1 ? '' : 's'}${declared.length ? ' including the one declared in robots.txt' : ''}: ${attempts.map(a => a.url.replace(origin, '')).join(', ')}. Not fatal, but a missing sitemap makes discovery slower for every crawler.`
    ),
    howToFix: t(
      'Genera un sitemap.xml (Yoast, RankMath, el propio WordPress o cualquier generador de sitios web estáticos pueden hacerlo automáticamente) y decláralo en robots.txt con una línea «Sitemap:».',
      'Generate a sitemap.xml (Yoast, RankMath, WordPress core, or any static site generator can do this automatically) and declare it in robots.txt with a "Sitemap:" line.'
    ),
    raw: { attempts, declaredInRobots: declared }
  };
}

// ── llms.txt ──
// An emerging convention (llmstxt.org): a markdown file at the site root that gives AI systems a
// curated map of the site's most useful content. Adoption is still early and no major engine has
// committed to honouring it, so its absence is never scored as a defect — this reports presence
// only, as an informational signal and a cheap differentiator to raise with a client.
async function checkLlmsTxt(origin, ua = USER_AGENTS.browser.ua) {
  const url = origin + '/llms.txt';
  const res = await fetchSafe(url, ua);
  if (isTransportFailure(res)) return null; // silent: never invent a row from a network failure
  const found = res.status < 400 && /^\s*#/m.test(res.text) && res.text.length > 20;
  return {
    id: 'llms-txt',
    title: t('llms.txt (estándar emergente)', 'llms.txt (emerging standard)'),
    status: found ? 'PASS' : 'INCONCLUSIVE',
    detail: found
      ? t(
          `Hay un archivo llms.txt publicado en ${url} (${res.text.length} bytes), que ofrece a los sistemas de IA una guía seleccionada del contenido principal del sitio web.`,
          `An llms.txt file is published at ${url} (${res.text.length} bytes), giving AI systems a curated guide to the site's key content.`
        )
      : t(
          'No se encuentra archivo llms.txt. Es una convención emergente, no un requisito consolidado, y ningún motor de IA importante se ha comprometido todavía a respetarla, así que no cuenta en contra del sitio web ni afecta a la puntuación.',
          'No llms.txt file found. This is an emerging convention rather than an established requirement, and no major AI engine has committed to honouring it yet — so this is not counted against the site and carries no score.'
        ),
    howToFix: found ? undefined : t(
      'Opcional, y sobre todo interesante como señal de anticipación: publica /llms.txt como un índice en markdown de tus páginas más valiosas, con una línea de descripción de cada una. Poco esfuerzo, ningún inconveniente, y demuestra ante el cliente una preparación deliberada para la IA.',
      'Optional, and worth doing mainly as an early-mover signal: publish /llms.txt as a markdown index of your most valuable pages with a one-line description of each. Low effort, no downside, and it demonstrates deliberate AI-readiness to a client.'
    ),
    raw: { url, status: res.status, found }
  };
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
// Threshold sits at 2500ms rather than 2000ms, and the input is the fastest of two isolated
// samples rather than a single one. Both changes exist for the same reason: a continuous
// measurement scored against a hard boundary flaps. A real client site answering at ~2.0-2.3s
// was crossing the old 2000ms line between consecutive scans and moving the crawlability score
// 94 → 100 with nothing about the site having changed. Taking the best of two samples reports
// the server's uncontended capability and discards a one-off blip; the wider band keeps typical
// hosting clear of the edge. Re-audits compare like with like, which is the whole point.
const SLOW_RESPONSE_MS = 2500;

function checkResponseTime(timingFetch, timingSamples) {
  const okSamples = (timingSamples || []).filter(s => s.ok).map(s => s.ms);
  const ms = okSamples.length ? Math.min(...okSamples) : timingFetch.ms;
  const speedFix = t(
    'Revisa imágenes sin optimizar, CSS o JavaScript sin minificar y la ausencia de caché. Pasar la página por Google PageSpeed Insights da el desglose detallado de qué es exactamente lo que ralentiza.',
    'Check for unoptimized images, unminified CSS/JS, or missing caching — consider running the page through Google PageSpeed Insights for a detailed breakdown of exactly what\'s slow.'
  );
  const sampleNoteEs = `La más rápida de ${okSamples.length || 1} petición(es) aisladas, cada una lanzada sin nada más compitiendo por el servidor. Mide la capacidad del servidor sin contención y es lo bastante estable para comparar entre auditorías, pero no es un perfil de rendimiento completo: contrasta con Google PageSpeed Insights para un desglose con muestras repetidas.`;
  const sampleNote = `Fastest of ${okSamples.length || 1} isolated request(s), each issued with nothing else contending for the origin. This measures the server's uncontended capability and is stable enough to compare across re-audits, but it is not a full performance profile — cross-check with Google PageSpeed Insights for a repeated-sample breakdown.`;

  // Speed is unmeasurable without a completed request. This previously returned FAIL, which
  // then tripped the critical-fail gate and clamped the whole scan — meaning a network problem
  // on our side published itself as a verdict about the client's site. It is now INCONCLUSIVE
  // and carries no score, in either direction.
  if (!timingFetch.ok) {
    return {
      id: 'response-time',
      title: t('Tiempo de respuesta', 'Response time (single-request sample)'),
      status: 'INCONCLUSIVE',
      detail: t(
        `No se ha podido medir el tiempo de respuesta: ${timingFetch.error}. De una petición que nunca se completó no cabe extraer ninguna conclusión sobre velocidad.`,
        `Response time could not be measured — ${timingFetch.error}. No timing conclusion can be drawn from a request that never completed.`
      ),
      howToFix: t(
        'No implica ninguna acción sobre el sitio web. Consulta la revisión de accesibilidad para ver qué ha podido determinar el escáner sobre la conectividad.',
        'No action implied for the site. See the site-reachability check for what the scanner was able to determine about connectivity.'
      ),
      raw: { ms: timingFetch.ms, error: timingFetch.error, errorKind: timingFetch.errorKind, errorCode: timingFetch.errorCode }
    };
  }

  // Slow-but-reachable caps at WARNING, never FAIL. A timing sample should not be able to gate
  // anything — and with the timeout now at 20s, genuinely slow sites land here and get reported
  // as slow, instead of being silently reclassified as unreachable at the 9s mark.
  const status = ms > SLOW_RESPONSE_MS ? 'WARNING' : 'PASS';
  const detail = status === 'WARNING'
    ? t(`La portada ha tardado ${ms} ms en responder, algo lento. ${sampleNoteEs}`, `Homepage took ${ms}ms to respond — on the slow side. ${sampleNote}`)
    : t(`La portada ha respondido en ${ms} ms. ${sampleNoteEs}`, `Homepage responded in ${ms}ms. ${sampleNote}`);

  return {
    id: 'response-time',
    title: t('Tiempo de respuesta', 'Response time (single-request sample)'),
    status,
    detail,
    howToFix: status === 'WARNING' ? speedFix : undefined,
    raw: { ms }
  };
}

// ── Site reachability ──
// Replaces the old implicit "multi-UA said everything failed, so the site is down" inference.
// When every user-agent fails with a transport error, the honest report is that the scanner
// could not reach the origin — the site may well be fine for everyone else, which is exactly
// what happened on a Cloudflare-fronted client site that scored 23/100 while serving traffic
// normally. The advice depends entirely on the error kind, so it branches on that.
function buildUnreachableCheck(kinds, sampleError) {
  const kindSet = new Set(kinds);
  let esDetail = `El escáner no ha podido completar ninguna petición a este sitio web desde su red (${sampleError}).`;
  let enDetail = `The scanner could not complete a request to this site from its network (${sampleError}).`;
  let howToFix;

  if (kindSet.has('refused')) {
    esDetail += ' Una conexión rechazada o reiniciada es característica de una protección frente a bots en la capa de red que rechaza la IP de nube del escáner, no de un sitio web caído. Los sitios web en este estado suelen atender a los visitantes normales sin ningún problema.';
    enDetail += ' A refused or reset connection is characteristic of edge bot-protection rejecting the scanner\'s cloud IP — not of a site being down. Sites in this state usually serve normal visitors without any issue.';
    howToFix = t(
      'Confirma que el sitio web carga en un navegador (con toda probabilidad, sí). Después revisa la protección frente a bots en la capa de red —Cloudflare, Seguridad → Bots, o el ajuste equivalente de WAF o «bloquear bots maliciosos» en tu hosting— y añade el escáner a la lista de permitidos antes de repetir. No debe hacerse ningún cambio en el sitio web a partir de este resultado.',
      'Confirm the site loads in a browser (it very likely does). Then check for edge bot protection — Cloudflare Security → Bots, or the equivalent WAF/"block bad bots" setting at your host — and allowlist the scanner before re-running. No on-site change should be made on the strength of this result.'
    );
  } else if (kindSet.has('dns')) {
    esDetail += ' El nombre de host no ha resuelto, lo que apunta a un problema de DNS más que al servidor web.';
    enDetail += ' The hostname did not resolve, which points at a DNS problem rather than the web server.';
    howToFix = t(
      'Comprueba que los registros DNS del dominio están publicados y que el nombre de host está bien escrito, incluida la forma con y sin www.',
      'Verify the domain\'s DNS records are published and the hostname is spelled correctly, including the www/non-www form.'
    );
  } else if (kindSet.has('tls')) {
    esDetail += ' El handshake TLS ha fallado, así que la conexión nunca llegó a la aplicación.';
    enDetail += ' The TLS handshake failed, so the connection never reached the application.';
    howToFix = t(
      'Revisa el certificado TLS del sitio web: caducidad, nombre de host que no coincide o cadena intermedia incompleta. Ten en cuenta que los navegadores toleran problemas de cadena que los clientes automatizados y los rastreadores rechazan.',
      'Check the site\'s TLS certificate — expiry, hostname mismatch, or an incomplete intermediate chain. Note that browsers tolerate some chain problems that automated clients and crawlers reject.'
    );
  } else if (kindSet.has('timeout')) {
    esDetail += ` Todas las peticiones seguían sin respuesta pasados ${Math.round(FETCH_TIMEOUT_MS / 1000)} s. El servidor es alcanzable en principio, pero no responde en un tiempo viable.`;
    enDetail += ` Every request was still unanswered after ${Math.round(FETCH_TIMEOUT_MS / 1000)}s. The server is reachable in principle but not responding in a workable time.`;
    howToFix = t(
      'Revisa la carga del servidor y los recursos del hosting. Un sitio web tan lento es un problema real de rastreabilidad: tanto los rastreadores de IA como los buscadores abandonan la petición mucho antes de ese punto.',
      'Check server load and hosting resources. A site this slow is a genuine crawlability problem: AI crawlers and search engines both abandon requests well before this point.'
    );
  } else {
    howToFix = t(
      'Confirma que el sitio web carga en un navegador y repite el escaneo. Si a la segunda funciona, el fallo original fue puntual y puede descartarse.',
      'Confirm the site loads in a browser, then re-run the scan. If it succeeds on retry, the original failure was transient and can be disregarded.'
    );
  }

  return {
    id: 'site-reachability',
    title: t('Accesibilidad del sitio web desde el escáner', 'Site reachability from the scanner'),
    status: 'INCONCLUSIVE',
    detail: t(esDetail, enDetail),
    howToFix,
    raw: { errorKinds: Array.from(kindSet) }
  };
}

// ── Hosting platform detection ──
// Which platform a site is built on decides who is able to fix what, and the report is close to
// useless without it. A site on a managed builder sits behind that builder's CDN, not one the
// client controls — so telling the owner of a Lovable or Wix site to open their Cloudflare
// dashboard and adjust bot settings sends them looking for a dashboard they will never find.
// Detecting the platform lets the edge-protection advice name a route the client can actually
// take, and flags where the real constraint is the platform rather than the site.
const PLATFORMS = [
  {
    id: 'lovable', noteEs: "Lovable es un creador de sitios web con IA que aloja el sitio web publicado en su propia infraestructura.", controlEs: "El propietario del sitio web no tiene acceso a los ajustes de CDN ni de protección frente a bots: pertenecen a Lovable. Para controlarlos hay que publicar el sitio web en un dominio enrutado a través de su propio CDN, o exportarlo y alojarlo en otro sitio web.", label: 'Lovable',
    managed: true,
    test: ({ html }) => /gpteng\.co|lovable-badge|lovable\.dev\/projects|\/~flock\.js/i.test(html),
    note: 'Lovable is an AI site builder that hosts the published site on its own infrastructure.',
    control: 'Site owners have no access to the CDN or bot-protection settings — those belong to Lovable. To control them, the site has to be published to a domain you route through your own CDN, or exported and hosted elsewhere.'
  },
  {
    id: 'wix', noteEs: "Wix aloja el sitio web en su propia infraestructura.", controlEs: "Los ajustes de CDN y de protección frente a bots los gestiona Wix y no están expuestos al propietario. El control en materia de SEO se limita a lo que ofrece el panel de Wix.", label: 'Wix', managed: true,
    test: ({ html, headers }) => /static\.parastorage\.com|wix-?code|X-Wix-/i.test(html) || /wix/i.test(headers['x-wix-request-id'] || ''),
    note: 'Wix hosts the site on its own infrastructure.',
    control: 'CDN and bot-protection settings are managed by Wix and are not exposed to site owners. SEO-facing controls are limited to what the Wix SEO panel offers.'
  },
  {
    id: 'squarespace', noteEs: "Squarespace aloja el sitio web en su propia infraestructura.", controlEs: "Los ajustes de CDN y bots los gestiona Squarespace. El robots.txt es parcialmente editable desde sus opciones de SEO; la capa de red, no.", label: 'Squarespace', managed: true,
    test: ({ html, headers }) => /static1\.squarespace\.com|squarespace\.com\/universal/i.test(html) || /squarespace/i.test(headers.server || ''),
    note: 'Squarespace hosts the site on its own infrastructure.',
    control: 'CDN and bot settings are managed by Squarespace. robots.txt is partially editable through their SEO settings; the edge layer is not.'
  },
  {
    id: 'framer', noteEs: "Framer aloja el sitio web publicado en su propia infraestructura.", controlEs: "Los ajustes de red y de bots pertenecen a Framer y no son configurables por sitio web.", label: 'Framer', managed: true,
    test: ({ html }) => /framerusercontent\.com|framer\.com\/m\//i.test(html),
    note: 'Framer hosts the published site on its own infrastructure.',
    control: 'Edge and bot settings belong to Framer and are not configurable per site.'
  },
  {
    id: 'webflow', noteEs: "Webflow aloja el sitio web publicado en su propia infraestructura.", controlEs: "Webflow gestiona el CDN. El robots.txt es editable desde los ajustes del sitio web; las reglas de bots en la capa de red, no.", label: 'Webflow', managed: true,
    test: ({ html, headers }) => /assets(-global)?\.website-files\.com|webflow\.io/i.test(html) || /webflow/i.test(headers['x-served-by'] || ''),
    note: 'Webflow hosts the published site on its own infrastructure.',
    control: 'Webflow manages the CDN. robots.txt is editable in site settings; edge bot rules are not.'
  },
  {
    id: 'shopify', noteEs: "Shopify aloja la tienda en su propia infraestructura.", controlEs: "Shopify gestiona el CDN y la protección frente a bots. El robots.txt es editable mediante robots.txt.liquid; la capa de red, no.", label: 'Shopify', managed: true,
    test: ({ html, headers }) => /cdn\.shopify\.com|Shopify\.theme/i.test(html) || !!headers['x-shopid'],
    note: 'Shopify hosts the storefront on its own infrastructure.',
    control: 'Shopify manages the CDN and bot protection. robots.txt is editable via robots.txt.liquid; the edge layer is not.'
  },
  {
    id: 'wordpress', noteEs: "WordPress autoalojado: la cuenta de hosting y cualquier CDN por delante están bajo control del propietario.", controlEs: "Control total sobre robots.txt, el hosting y cualquier CDN o WAF por delante del sitio web.", label: 'WordPress', managed: false,
    test: ({ html }) => /wp-content\/|wp-includes\/|\/wp-json\//i.test(html),
    note: 'WordPress, self-hosted — the hosting account and any CDN in front of it are under the owner\'s control.',
    control: 'Full control over robots.txt, hosting, and any CDN or WAF the site sits behind.'
  }
];

function detectPlatform($, headers, html) {
  const h = {};
  if (headers) { try { headers.forEach((v, k) => { h[k.toLowerCase()] = v; }); } catch { /* ignore */ } }
  const ctx = { html: html || '', headers: h };
  for (const p of PLATFORMS) {
    let hit = false;
    try { hit = p.test(ctx); } catch { hit = false; }
    if (hit) return p;
  }
  return null;
}

// Reported as INFO: it is context for reading the rest of the report, never a pass or a failure,
// and it carries no score.
function checkPlatform(platform) {
  if (!platform) return null;
  return {
    id: 'hosting-platform',
    title: t('Plataforma de alojamiento', 'Hosting platform'),
    status: 'INFO',
    detail: t(
      `Creado y alojado en ${platform.label}. ${platform.noteEs || platform.note} ${platform.controlEs || platform.control}`,
      `Built and hosted on ${platform.label}. ${platform.note} ${platform.control}`
    ),
    howToFix: platform.managed
      ? t(
          `Lee el resto del informe con esto en mente: todo lo que ocurre en la capa de red o CDN lo define ${platform.label} y no puede cambiarse desde el sitio web. El trabajo en página —contenido, estructura, datos estructurados, enlazado interno— sí está por completo a su alcance, y es ahí donde debe ir el esfuerzo.`,
          `Read the rest of this report with that in mind: anything at the network or CDN layer is set by ${platform.label} and cannot be changed from the site itself. On-page work — content, structure, schema, internal linking — is entirely within reach and is where the effort should go.`
        )
      : undefined,
    raw: { platform: platform.id, managedHosting: platform.managed }
  };
}

// One hostname resolves and the other does not. Reported as a FAIL because it is a genuine
// availability and consolidation defect: visitors who type the bare domain get nothing, inbound
// links to that form are dead, and search and AI engines see two hostnames rather than one site.
function buildHostVariantCheck(fb) {
  return {
    id: 'host-variant',
    title: t('Resolución www / sin www', 'www / non-www resolution'),
    status: 'FAIL',
    detail: t(
      `${fb.requested} no resuelve (${fb.requestedError}), mientras que ${fb.resolved} sirve el sitio web con normalidad. El escaneo ha continuado contra ${fb.resolved}. Quien escriba o enlace la forma ${fb.requested} no llega absolutamente a nada.`,
      `${fb.requested} does not resolve (${fb.requestedError}), while ${fb.resolved} serves the site normally. The scan continued against ${fb.resolved}. Anyone typing or linking the ${fb.requested} form reaches nothing at all.`
    ),
    howToFix: t(
      `Crea un registro DNS para ${fb.requested} y redirígelo de forma permanente (301) a ${fb.resolved}. Las dos formas de un dominio deben resolver siempre, con una redirigiendo a la otra. De lo contrario, los enlaces entrantes y las direcciones tecleadas con la forma que falta fallan en silencio, y los buscadores y motores de IA ven dos nombres de host en lugar de un único sitio web.`,
      `Add a DNS record for ${fb.requested} and redirect it permanently (301) to ${fb.resolved}. Both forms of a domain should always resolve, with one redirecting to the other — otherwise inbound links and typed addresses using the missing form fail silently, and the two hostnames are not consolidated into a single site for search and AI engines.`
    ),
    raw: fb
  };
}

// ── Edge protection / CDN fingerprint ──
// Our user-agent test cannot settle whether AI crawlers are blocked at a CDN edge, because
// Cloudflare and similar services identify verified bots by source IP range, not by UA string.
// Spoofing GPTBot's UA from any other network sails straight through. Rather than let that gap
// sit silently behind a PASS, name it and hand over a concrete manual check.
const EDGE_PROVIDERS = [
  { id: 'cloudflare', label: 'Cloudflare', test: h => /cloudflare/i.test(h.server || '') || !!h['cf-ray'], where: 'Cloudflare → Security → Bots (check "Block AI Scrapers and Crawlers", Bot Fight Mode, and any AI Audit / pay-per-crawl setting)', whereEs: 'Cloudflare → Security → Bots (revisa «Block AI Scrapers and Crawlers», el Bot Fight Mode y cualquier ajuste de AI Audit o pago por rastreo)' },
  { id: 'sucuri', label: 'Sucuri', test: h => /sucuri/i.test(h.server || '') || !!h['x-sucuri-id'], where: 'Sucuri → Firewall → Access Control → Whitelist/Blacklist, and the "Block Bad Bots" setting', whereEs: 'Sucuri → Firewall → Access Control → listas de permitidos y bloqueados, y el ajuste «Block Bad Bots»' },
  { id: 'akamai', label: 'Akamai', test: h => /akamai/i.test(h.server || '') || !!h['x-akamai-transformed'], where: 'Akamai Bot Manager configuration' },
  { id: 'fastly', label: 'Fastly', test: h => /fastly/i.test(h.server || '') || !!h['x-served-by'] && /fastly/i.test(h['x-served-by'] || ''), where: 'Fastly service configuration' },
  { id: 'imperva', label: 'Imperva / Incapsula', test: h => !!h['x-iinfo'] || /incap/i.test(h['x-cdn'] || ''), where: 'Imperva Bot Protection settings' }
];

function checkEdgeProtection(headers, platform) {
  if (!headers) return null;
  const h = {};
  try { headers.forEach((v, k) => { h[k.toLowerCase()] = v; }); } catch { return null; }

  const found = EDGE_PROVIDERS.filter(p => { try { return p.test(h); } catch { return false; } });
  if (!found.length) {
    return {
      id: 'edge-protection',
      title: t('Protección frente a bots en la capa de red (CDN/WAF)', 'Edge bot protection (CDN/WAF)'),
      status: 'PASS',
      detail: t(
        'No se detecta ninguna huella de CDN ni de WAF en los encabezados de respuesta, así que es improbable que haya bloqueo de rastreadores de IA en la capa de red.',
        'No CDN or WAF fingerprint detected in the response headers, so no edge-level AI crawler blocking is likely to be in play.'
      ),
      raw: { providers: [] }
    };
  }

  const names = found.map(p => p.label).join(', ');
  const botManaged = found.some(p => p.id === 'cloudflare') && !!h['set-cookie'] && /__cf_bm/i.test(h['set-cookie']);

  return {
    id: 'edge-protection',
    title: t('Protección frente a bots en la capa de red (CDN/WAF)', 'Edge bot protection (CDN/WAF)'),
    status: 'INCONCLUSIVE',
    detail: t(
      `Este sitio web se sirve a través de ${names}${botManaged ? ', con la gestión de bots activa (esta petición ha recibido un token __cf_bm)' : ''}. Los servicios de red identifican a los rastreadores de IA por rango de IP de origen, no por la cadena de user-agent, así que la prueba de user-agents anterior no puede confirmar si GPTBot o ClaudeBot pasan realmente: una prueba de UA la supera en cualquier caso. Requiere verificación manual y se informa como no verificado en lugar de como correcto.`,
      `This site is served through ${names}${botManaged ? ', with bot management actively running (a __cf_bm token was issued on this request)' : ''}. Edge services identify AI crawlers by source IP range, not by user-agent string, so the user-agent test above cannot confirm whether GPTBot or ClaudeBot are actually allowed through — a UA test passes regardless. This requires manual verification and is reported as unverified rather than as a pass.`
    ),
    howToFix: (platform && platform.managed)
      ? t(
          `Esta capa de ${names} pertenece a ${platform.label}, la plataforma de alojamiento, no al propietario del sitio web, que no dispone de panel para ella ni puede permitir o desbloquear nada a este nivel. ${platform.controlEs || platform.control} Da la capa de red por fija y dedica el esfuerzo al trabajo en página, que sí está por completo bajo su control. Si el acceso de los rastreadores de IA en la capa de red resultara ser un problema real, las únicas vías son publicar en un dominio enrutado a través de su propio CDN o dejar ${platform.label}.`,
          `This ${names} layer belongs to ${platform.label}, the hosting platform — not to the site owner, who has no dashboard for it and cannot allowlist or unblock anything at this level. ${platform.control} Treat the edge layer as fixed and put the effort into on-page work, which is fully under your control. If AI crawler access at the edge turns out to be a genuine problem, the routes are to publish to a domain you route through your own CDN, or to move off ${platform.label}.`
        )
      : t(
          `Verifica el acceso de los rastreadores de IA directamente en ${found.map(p => p.whereEs || p.where).join(' / ')}. Estos ajustes bloquean a los rastreadores de IA en la capa de red con independencia de robots.txt y, en algunos proveedores, los dominios recientes los tienen activados por defecto sin que el propietario lo haya elegido, de modo que un sitio web intacto puede seguir siendo invisible. Empieza por los rastreadores de recuperación (OAI-SearchBot, ChatGPT-User, Claude-User, PerplexityBot): suelen depender de una casilla distinta a la de los de entrenamiento, y son los que determinan si el sitio web puede citarse en una respuesta. El resultado de robots.txt de este informe no se ve afectado por nada de esto y sigue siendo fiable: solo la capa de red no puede confirmarse en remoto.`,
          `Verify AI crawler access directly in ${found.map(p => p.where).join(' / ')}. These settings block AI crawlers at the network edge independently of robots.txt, and on some providers newer domains have them enabled by default without the owner ever choosing it — so an unchanged, untouched site can still be invisible. Check the retrieval crawlers first (OAI-SearchBot, ChatGPT-User, Claude-User, PerplexityBot): they are usually governed by a separate toggle from the training crawlers, and they are the ones that determine whether the site can be cited in an answer. The robots.txt result in this report is unaffected by any of this and remains reliable — it is only the edge layer that cannot be confirmed remotely.`
        ),
    raw: { providers: found.map(p => p.id), botManagementCookie: botManaged, server: h.server || null }
  };
}

// ── Sitemap-driven crawling ──
// Nav-based discovery finds the handful of pages a site links from its header and footer, which
// on a forty-page site means the score describes its front door rather than the site. The sitemap
// is the site's own declaration of what it contains, so it is the right source for a
// representative sample.
//
// Two safeguards. The page budget is capped, because a scan is a diagnostic and must not behave
// like a crawler — at two concurrent requests a twenty-page scan is already a minute of a client's
// server time. And the sample is spread evenly across the sitemap rather than taken from the top,
// since sitemaps are usually ordered by date or by section and the first twenty entries would
// otherwise all come from the same corner of the site.

const DEFAULT_MAX_PAGES = 20;
const MAX_SUBSITEMAPS = 5;

function extractLocs(xml) {
  return [...xml.matchAll(/<loc>\s*([^<\s]+)\s*<\/loc>/gi)].map(m => m[1]);
}

// Follows a sitemap index one level down, which is as deep as real sitemaps go in practice.
async function collectSitemapUrls(sitemapUrl, origin, limit, ua = USER_AGENTS.browser.ua) {
  const res = await fetchSafe(sitemapUrl, ua);
  if (!res.ok || res.status >= 400) return [];

  if (/<sitemapindex/i.test(res.text)) {
    const children = extractLocs(res.text).slice(0, MAX_SUBSITEMAPS);
    const pages = [];
    const fetched = await mapLimited(children, async u => fetchSafe(u, ua));
    fetched.forEach(r => { if (r.ok && r.status < 400) pages.push(...extractLocs(r.text)); });
    return dedupeSameOrigin(pages, origin, limit);
  }
  return dedupeSameOrigin(extractLocs(res.text), origin, limit);
}

function dedupeSameOrigin(urls, origin, limit) {
  const seen = new Set();
  const out = [];
  for (const raw of urls) {
    let u;
    try { u = new URL(raw, origin); } catch { continue; }
    if (!/^https?:$/.test(u.protocol)) continue;
    // Same registrable host only — sitemaps occasionally list other properties.
    if (u.hostname.replace(/^www\./, '') !== new URL(origin).hostname.replace(/^www\./, '')) continue;
    u.hash = '';
    const key = normalizeUrlForCompare(u.href);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(u.href);
  }
  return typeof limit === 'number' ? out.slice(0, limit) : out;
}

// Even spread rather than the first N, so a date-ordered sitemap does not yield twenty pages all
// from the same month.
function sampleEvenly(urls, n) {
  if (urls.length <= n) return urls;
  const step = urls.length / n;
  const picked = [];
  for (let i = 0; i < n; i++) picked.push(urls[Math.floor(i * step)]);
  return [...new Set(picked)];
}

// ── Key Page Discovery ──
// Before the per-page checks run, parse the homepage's nav/header/footer links for the handful
// of page types our own methodology treats as highest-impact for GEO (About and FAQ especially).
// Found pages are fetched and folded into the same per-page pipeline extraPages already uses —
// this is also what makes the Section 3 boilerplate/duplicate-content check actually useful,
// since it needs multiple real pages to compare and previously almost never got them.

const PAGE_DISCOVERY_PATTERNS = {
  about: { label: 'About', labelEs: 'Nosotros', patterns: ['quienes-somos', 'quiénes-somos', 'sobre-nosotros', 'about-us', 'nosotros', 'about'] },
  faq: { label: 'FAQ', labelEs: 'Preguntas frecuentes', patterns: ['preguntas-frecuentes', 'preguntas', 'faqs', 'faq'] },
  contact: { label: 'Contact', labelEs: 'Contacto', labelEs: 'contacto', patterns: ['contactanos', 'contáctanos', 'contact-us', 'contacto', 'contact'] },
  services: { label: 'Services', labelEs: 'Servicios', patterns: ['servicios', 'services'] },
  blog: { label: 'Blog', labelEs: 'Blog', patterns: ['articulos', 'artículos', 'insights', 'noticias', 'blog'] }
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
    const impactNoteEs = HIGH_IMPACT_DISCOVERY_CATEGORIES.has(c.id) ? ' Es uno de los dos tipos de página de mayor impacto para GEO según nuestra propia metodología.' : '';
    return {
      id: c.id,
      title: t(`Página de ${c.labelEs || c.label}`, `${c.label} page`),
      status: c.found ? 'PASS' : 'WARNING',
      found: c.found,
      url: c.url,
      detail: c.found
        ? t(
            `Encontrada en ${c.url}${alreadyIncluded ? ' (ya cubierta por una página añadida a mano).' : ', añadida automáticamente al escaneo.'}`,
            `Found at ${c.url}${alreadyIncluded ? ' (already covered by a manually-added page).' : ' — automatically added to the scan.'}`
          )
        : t(
            `No se encuentra ninguna página de ${c.labelEs || c.label} enlazada desde la navegación, la encabezado o el pie del sitio web.${impactNoteEs}`,
            `No ${c.label} page found linked from the site's nav, header, or footer.${impactNote}`
          ),
      howToFix: c.found ? undefined : t(
        `Añade una página de ${c.labelEs || c.label} claramente enlazada desde la navegación principal o el pie. La detección automática no la encuentra, lo que significa que los motores de IA probablemente tampoco.`,
        `Add a clearly-linked ${c.label} page from the main navigation or footer — automated discovery couldn't find one, which means AI engines likely can't either.`
      ),
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
    title: t('Coincidencia del schema FAQPage con el contenido visible', 'FAQPage schema vs. visible content match'),
    status,
    detail: status === 'PASS'
      ? t(
          `${matched} de ${pairs.length} pregunta(s) del schema FAQPage coinciden con texto visible en la página.`,
          `${matched}/${pairs.length} FAQPage schema question(s) match text visible on the page.`
        )
      : t(
          `Solo ${matched} de ${pairs.length} pregunta(s) del schema FAQPage han podido asociarse a contenido visible en la página.`,
          `Only ${matched}/${pairs.length} FAQPage schema question(s) could be matched to visible content on the page.`
        ),
    howToFix: status === 'PASS' ? undefined : t(
      'Asegúrate de que el schema FAQPage refleje preguntas y respuestas reales y visibles en la página. Un marcado que no coincide con lo que ve el visitante puede interpretarse como de baja calidad o manipulador.',
      'Make sure FAQPage schema mirrors real, visible Q&A content on the page — schema that doesn\'t match what a visitor actually sees can be flagged as low-quality or manipulative by AI engines.'
    ),
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
    title: t('Autoría y credenciales', 'Author/credential attribution'),
    status: found ? 'PASS' : 'WARNING',
    detail: found
      ? t(
          'Se encuentra atribución de autoría (firma, enlace rel="author" o schema Person vinculado a la autoría).',
          'Author attribution found (byline, rel="author" link, and/or Person schema tied to authorship).'
        )
      : t(
          'No se encuentra atribución de autoría: ni firma, ni enlace rel="author", ni schema Person vinculado a la autoría.',
          'No author attribution found — no byline, rel="author" link, or Person schema tied to authorship.'
        ),
    howToFix: found ? undefined : t(
      'Añade autoría con nombre a la página: una firma, una entrada de autor en los datos estructurados, o ambas. Los motores dan más peso a las fuentes identificadas y con credenciales que a un texto corporativo sin autor.',
      'Add named author attribution to the page — a byline, an author schema entry, or both. Named, credentialed sources are weighted more heavily by AI engines than unattributed corporate copy.'
    ),
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
    title: t('Especificidad de las primeras 250 palabras', 'First-250-words specificity'),
    status,
    detail: status === 'PASS'
      ? t(
          `Las primeras ~250 palabras contienen ${entities.properNounCount} expresión(es) con aspecto de nombre propio y ${entities.numberCount} cifra(s): el detalle concreto aparece pronto.`,
          `The first ~250 words contain ${entities.properNounCount} proper-noun-like phrase(s) and ${entities.numberCount} number(s) — specific detail appears early.`
        )
      : t(
          `Las primeras ~250 palabras resultan genéricas (${entities.properNounCount} nombres propios, ${entities.numberCount} cifras), aunque más abajo la página tenga contenido más concreto.`,
          `The first ~250 words read as generic (${entities.properNounCount} proper nouns, ${entities.numberCount} numbers), even if the page has more specific content further down.`
        ),
    howToFix: status === 'PASS' ? undefined : t(
      'Lleva los datos más concretos y específicos (nombres, cifras, credenciales) a las primeras 250-300 palabras. Los sistemas de extracción dan más peso al inicio del contenido que al texto enterrado más abajo.',
      'Move your most specific, concrete details (names, numbers, credentials) into the first 250-300 words. AI extraction tools weight the beginning of a page\'s content more heavily than text buried further down.'
    ),
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
    title: t('Datos de contacto legibles por máquina', 'Contact info machine-readability'),
    status: found ? 'PASS' : 'WARNING',
    detail: found
      ? t(
          `Se encuentran vías de contacto legibles por máquina: ${telLinks} enlace(s) tel:, ${mailtoLinks} enlace(s) mailto:${hasContactPointSchema ? ', y schema ContactPoint presente' : ''}.`,
          `Machine-readable contact method(s) found: ${telLinks} tel: link(s), ${mailtoLinks} mailto: link(s)${hasContactPointSchema ? ', ContactPoint schema present' : ''}.`
        )
      : t(
          'Los datos de contacto parecen estar solo como texto plano: no se encuentran enlaces tel: ni mailto:, ni schema ContactPoint.',
          'Contact info appears to be present as plain text only — no tel:/mailto: links or ContactPoint schema found.'
        ),
    howToFix: found ? undefined : t(
      'Envuelve los teléfonos en enlaces tel: y los correos en enlaces mailto:, y añade schema ContactPoint. Así los agentes de IA (y quien navegue desde el celular) pueden actuar sobre los datos de contacto, no solo leerlos.',
      'Wrap phone numbers in tel: links and emails in mailto: links, and add ContactPoint schema. This lets AI agents (and mobile users) actually act on the contact info, not just read it.'
    ),
    raw: { telLinks, mailtoLinks, hasContactPointSchema }
  };
}

// 5. JS-rendering dependency.
// Everything else in this file parses the raw HTML the server returned — exactly what a
// non-rendering crawler receives. If a site ships an empty shell and paints its content with
// JavaScript, that crawler sees nothing, and this tool would otherwise report the resulting
// emptiness as a dozen unrelated on-page failures (no h1, thin content, no schema) instead of
// naming the one root cause. Server-side rendering fixes it, which makes this an on-page,
// fixable finding rather than an infrastructure one.
const SPA_MOUNT_SELECTORS = ['#root', '#app', '#__next', '#__nuxt', '[data-reactroot]', '[data-server-rendered]', 'astro-island'];

function checkJsRendering($, mainText, html) {
  const words = mainText.split(/\s+/).filter(Boolean).length;
  const scriptCount = $('script[src]').length;
  const mountEl = SPA_MOUNT_SELECTORS.find(sel => { try { return $(sel).length > 0; } catch { return false; } });
  // A mount node that arrives already populated means the framework server-rendered it — the
  // presence of #root or #__next alone proves nothing, so measure what's actually inside it.
  const mountText = mountEl ? $(mountEl).text().replace(/\s+/g, ' ').trim().split(/\s+/).filter(Boolean).length : null;
  const hasNoscriptWarning = /enable\s+javascript|requires\s+javascript|javascript\s+(?:to|is)\s+(?:run|required)/i.test($('noscript').text() || '');

  const shellLike = words < 60 && scriptCount > 0 && html.length > 500;
  const emptyMount = mountEl && mountText !== null && mountText < 30;

  if (!shellLike && !emptyMount && !(hasNoscriptWarning && words < 150)) {
    return {
      id: 'js-rendering',
      title: t('Contenido visible sin JavaScript', 'Content visible without JavaScript'),
      status: 'PASS',
      detail: t(
        `El servidor devuelve ${words} palabras de contenido legible antes de que se ejecute ningún JavaScript, así que los rastreadores que no renderizan pueden leer esta página.`,
        `The server returns ${words} words of readable content before any JavaScript runs, so non-rendering crawlers can read this page.`
      ),
      raw: { serverRenderedWords: words, mountElement: mountEl || null, scriptCount }
    };
  }

  const evEs = []; const evEn = [];
  if (shellLike) { evEs.push(`solo ${words} palabras de texto en la respuesta del servidor junto a ${scriptCount} archivo(s) de script`); evEn.push(`only ${words} words of text in the server response alongside ${scriptCount} script file(s)`); }
  if (emptyMount) { evEs.push(`el punto de montaje ${mountEl} está vacío (${mountText} palabras)`); evEn.push(`the ${mountEl} mount point is empty (${mountText} words)`); }
  if (hasNoscriptWarning) { evEs.push('un bloque <noscript> que pide al visitante activar JavaScript'); evEn.push('a <noscript> block telling visitors to enable JavaScript'); }

  return {
    id: 'js-rendering',
    title: t('Contenido visible sin JavaScript', 'Content visible without JavaScript'),
    status: 'FAIL',
    detail: t(
      `Esta página parece renderizar su contenido en el cliente: ${evEs.join(', ')}. Los rastreadores que no ejecutan JavaScript reciben una página prácticamente en blanco. Toma el resto de resultados en página de esta URL como poco fiables: las revisiones que informan de encabezados ausentes, contenido escaso o falta de datos estructurados están viendo el armazón vacío, no la página real.`,
      `This page appears to render its content client-side — ${evEn.join(', ')}. Crawlers that do not execute JavaScript receive an effectively blank page. Treat the other on-page results for this page as unreliable: checks reporting missing headings, thin content or absent schema are most likely observing the empty shell rather than the real page.`
    ),
    howToFix: t(
      'Renderiza esta página en el servidor, o pregenera el HTML en la compilación, de modo que la respuesta contenga ya el contenido. La mayoría de rastreadores de IA no ejecutan JavaScript, lo que convierte esto en la corrección en página de mayor impacto disponible: cualquier otra señal GEO de la página es invisible hasta resolverlo.',
      'Server-side render this page, or pre-render it at build time, so the HTML response contains the content itself. Most AI crawlers do not execute JavaScript, which makes this the single highest-impact on-page fix available — every other GEO signal on the page is invisible until it is resolved.'
    ),
    raw: { serverRenderedWords: words, mountElement: mountEl || null, mountWords: mountText, scriptCount, hasNoscriptWarning }
  };
}

// ── Page type ──
// A contact page is meant to be short. Judging one on word count produced a FAIL on a 16-word
// /contacto/ page that was doing its job perfectly — advice that would have gone to a client as
// "add 300 words to your contact page", and the kind of visibly wrong finding that makes someone
// distrust the other thirty-two checks. Depth and scope expectations now depend on what kind of
// page is being looked at.
//
// Patterns are bilingual for the same reason the authority checks are: these are Spanish-language
// client sites, and an English-only matcher would classify every page as generic content.
const PAGE_TYPES = {
  contact: { label: 'Contact', labelEs: 'contacto', judgeDepth: false, patterns: /(^|\/)(contact|contacto|contactanos|cont[áa]ctanos|contact-us|get-in-touch)(\/|$|\.)/i },
  legal: { label: 'Legal / policy', labelEs: 'aviso legal o política', judgeDepth: false, patterns: /(^|\/)(privacy|privacidad|terms|terminos|t[ée]rminos|aviso-legal|legal|cookies|politica|pol[íi]tica|disclaimer)(\/|$|\.|-)/i },
  utility: { label: 'Utility', labelEs: 'utilidad', judgeDepth: false, patterns: /(^|\/)(thank-you|gracias|404|search|buscar|cart|carrito|checkout|login|acceder|sitemap)(\/|$|\.)/i },
  home: { label: 'Homepage', labelEs: 'portada', judgeDepth: true, patterns: null },
  content: { label: 'Content', labelEs: 'contenido', judgeDepth: true, patterns: null }
};

function detectPageType(pageUrl) {
  let path = '/';
  try { path = new URL(pageUrl).pathname; } catch { /* keep default */ }
  if (path === '/' || path === '') return { id: 'home', ...PAGE_TYPES.home };
  for (const [id, cfg] of Object.entries(PAGE_TYPES)) {
    if (cfg.patterns && cfg.patterns.test(path)) return { id, ...cfg };
  }
  return { id: 'content', ...PAGE_TYPES.content };
}

// ── Schema completeness ──
// Checking that Organization exists says nothing about whether it is usable. A block carrying
// only @type and a name gives an engine nothing to tie the business to, and it passed the
// presence check exactly as a complete one did. Required properties are the ones without which
// the type cannot function; recommended are those that materially help entity recognition.
const SCHEMA_REQUIREMENTS = {
  Organization: { required: ['name', 'url'], recommended: ['logo', 'sameAs', 'description', 'address'] },
  LocalBusiness: { required: ['name', 'address'], recommended: ['telephone', 'openingHours', 'geo', 'priceRange', 'sameAs'] },
  WebSite: { required: ['name', 'url'], recommended: ['publisher'] },
  Article: { required: ['headline'], recommended: ['author', 'datePublished', 'dateModified', 'image', 'publisher'] },
  BlogPosting: { required: ['headline'], recommended: ['author', 'datePublished', 'dateModified', 'image'] },
  Product: { required: ['name'], recommended: ['image', 'description', 'offers', 'brand', 'aggregateRating'] },
  Service: { required: ['name'], recommended: ['provider', 'areaServed', 'description', 'serviceType'] },
  FAQPage: { required: ['mainEntity'], recommended: [] },
  BreadcrumbList: { required: ['itemListElement'], recommended: [] },
  Person: { required: ['name'], recommended: ['jobTitle', 'sameAs', 'worksFor'] }
};

// Walks every JSON-LD node and returns the property keys actually present for each @type found.
function collectSchemaNodes($) {
  const found = {};
  const visit = node => {
    if (Array.isArray(node)) { node.forEach(visit); return; }
    if (!node || typeof node !== 'object') return;
    const types = node['@type'] ? (Array.isArray(node['@type']) ? node['@type'] : [node['@type']]) : [];
    types.forEach(t => {
      const key = String(t);
      const present = Object.keys(node).filter(k => {
        if (k.startsWith('@')) return false;
        const v = node[k];
        if (v == null) return false;
        if (typeof v === 'string') return v.trim().length > 0;
        if (Array.isArray(v)) return v.length > 0;
        return true;
      });
      found[key] = found[key] ? [...new Set([...found[key], ...present])] : present;
    });
    Object.values(node).forEach(v => { if (v && typeof v === 'object') visit(v); });
  };
  $('script[type="application/ld+json"]').each((_, el) => {
    try { visit(JSON.parse($(el).contents().text())); } catch { /* malformed block — the presence check already reports this */ }
  });
  return found;
}

function checkSchemaCompleteness($) {
  const nodes = collectSchemaNodes($);
  const known = Object.keys(nodes).filter(t => SCHEMA_REQUIREMENTS[t]);
  if (!known.length) return null; // no recognised types — the presence check covers that case

  const assessed = known.map(type => {
    const spec = SCHEMA_REQUIREMENTS[type];
    const present = nodes[type];
    return {
      type,
      missingRequired: spec.required.filter(p => !present.includes(p)),
      missingRecommended: spec.recommended.filter(p => !present.includes(p))
    };
  });

  const broken = assessed.filter(a => a.missingRequired.length);
  const thin = assessed.filter(a => !a.missingRequired.length && a.missingRecommended.length > Math.max(1, Math.floor((SCHEMA_REQUIREMENTS[a.type].recommended.length || 1) * 0.6)));

  if (broken.length) {
    return {
      id: 'schema-completeness',
      title: t('Integridad de los datos estructurados', 'Structured data completeness'),
      status: 'FAIL',
      detail: t(
        `Hay datos estructurados, pero incompletos: ${broken.map(b => `a ${b.type} le falta ${b.missingRequired.join(', ')}`).join('; ')}. Un tipo al que le faltan sus propiedades obligatorias no puede interpretarse, así que no aporta nada pese a estar en la página.`,
        `Structured data is present but incomplete: ${broken.map(b => `${b.type} is missing ${b.missingRequired.join(', ')}`).join('; ')}. A type missing its required properties cannot be interpreted, so it delivers nothing despite being on the page.`
      ),
      howToFix: t(
        `Añade las propiedades obligatorias que faltan: ${broken.map(b => `${b.type} necesita ${b.missingRequired.join(', ')}`).join('; ')}. Valida el resultado con la Prueba de resultados enriquecidos de Google o con el validador de schema.org antes de darlo por terminado.`,
        `Add the missing required properties: ${broken.map(b => `${b.type} needs ${b.missingRequired.join(', ')}`).join('; ')}. Validate the result with Google's Rich Results Test or schema.org's validator before considering it done.`
      ),
      raw: { assessed }
    };
  }
  if (thin.length) {
    return {
      id: 'schema-completeness',
      title: t('Integridad de los datos estructurados', 'Structured data completeness'),
      status: 'WARNING',
      detail: t(
        `Los datos estructurados son válidos pero incompletos: ${thin.map(x => `${x.type} omite ${x.missingRecommended.join(', ')}`).join('; ')}. Son precisamente las propiedades que conectan el marcado con una entidad reconocible del mundo real.`,
        `Structured data is valid but sparse: ${thin.map(x => `${x.type} omits ${x.missingRecommended.join(', ')}`).join('; ')}. These are the properties that connect the markup to a recognisable real-world entity.`
      ),
      howToFix: t(
        `Completa las propiedades que faltan donde apliquen: ${thin.map(x => `${x.type} → ${x.missingRecommended.join(', ')}`).join('; ')}. sameAs es la de mayor valor: vincula la entidad con perfiles en los que los motores ya confían.`,
        `Fill in the missing properties where they apply: ${thin.map(x => `${x.type} → ${x.missingRecommended.join(', ')}`).join('; ')}. sameAs is the highest-value of these — it links the entity to profiles engines already trust.`
      ),
      raw: { assessed }
    };
  }
  return {
    id: 'schema-completeness',
    title: t('Integridad de los datos estructurados', 'Structured data completeness'),
    status: 'PASS',
    detail: t(
      `${known.length} tipo(s) de datos estructurados comprobados (${known.join(', ')}): todas las propiedades obligatorias están presentes y el marcado es razonablemente completo.`,
      `${known.length} structured data type(s) checked (${known.join(', ')}) — all required properties present and reasonably complete.`
    ),
    raw: { assessed }
  };
}

// ── Freshness ──
// Engines weight recency, and a page carrying no date at all cannot be assessed for it — which
// is itself a disadvantage against a competitor whose page is visibly current.
function checkFreshness($, mainText) {
  const dates = [];
  const pushDate = v => {
    if (typeof v !== 'string') return;
    const d = new Date(v);
    if (!isNaN(d.getTime()) && d.getFullYear() > 1990 && d.getTime() <= Date.now() + 86400000) dates.push({ value: v, ts: d.getTime() });
  };

  $('script[type="application/ld+json"]').each((_, el) => {
    try {
      const visit = n => {
        if (Array.isArray(n)) { n.forEach(visit); return; }
        if (!n || typeof n !== 'object') return;
        ['dateModified', 'datePublished', 'uploadDate'].forEach(k => pushDate(n[k]));
        Object.values(n).forEach(v => { if (v && typeof v === 'object') visit(v); });
      };
      visit(JSON.parse($(el).contents().text()));
    } catch { /* ignore */ }
  });

  $('time[datetime]').each((_, el) => pushDate($(el).attr('datetime')));
  const metaDate = $('meta[property="article:modified_time"], meta[property="article:published_time"]').attr('content');
  if (metaDate) pushDate(metaDate);

  const hasVisibleYear = /\b20[12]\d\b/.test(mainText.slice(0, 4000));

  if (!dates.length) {
    return {
      id: 'content-freshness',
      title: t('Señales de actualidad', 'Freshness signals'),
      status: 'WARNING',
      detail: t(
        `No se encuentra ninguna fecha legible por máquina: ni dateModified ni datePublished en los datos estructurados, ni elemento <time>, ni metadatos de fecha de artículo.${hasVisibleYear ? ' En el texto visible aparece un año, pero no en un formato que una máquina pueda interpretar como fecha.' : ''} No se puede establecer lo reciente que es la página, lo que la deja por detrás de un competidor cuya página sí se muestra actual.`,
        `No machine-readable date found — no dateModified or datePublished in structured data, no <time> element, no article date metadata.${hasVisibleYear ? ' A year appears in the visible text, but not in a form a machine can read as a date.' : ''} The page's recency cannot be established, which puts it behind a competitor whose page is visibly current.`
      ),
      howToFix: t(
        'Añade dateModified (y datePublished donde corresponda) a los datos estructurados de la página, y marca las fechas visibles con un elemento <time datetime="…">. Mantén dateModified realmente exacto: una fecha que nunca cambia es peor que ninguna, y una que cambia sin que cambie el contenido, todavía peor.',
        'Add dateModified (and datePublished where it applies) to the page\'s structured data, and mark visible dates up with a <time datetime="…"> element. Keep dateModified genuinely accurate — a date that never changes is worse than none, and one that changes without the content changing is worse still.'
      ),
      raw: { datesFound: 0, hasVisibleYear }
    };
  }

  const newest = Math.max(...dates.map(d => d.ts));
  const ageDays = Math.round((Date.now() - newest) / 86400000);
  const status = ageDays <= 365 ? 'PASS' : 'WARNING';
  return {
    id: 'content-freshness',
    title: t('Señales de actualidad', 'Freshness signals'),
    status,
    detail: status === 'PASS'
      ? t(
          `La fecha legible por máquina más reciente tiene ${ageDays} día(s): la página declara su actualidad en un formato que los motores pueden leer.`,
          `Most recent machine-readable date is ${ageDays} day(s) old — the page declares its recency in a form engines can read.`
        )
      : t(
          `La fecha legible por máquina más reciente tiene ${ageDays} día(s), unos ${Math.round(ageDays / 365)} año(s). El marcado es correcto, pero el contenido en sí se lee como desactualizado.`,
          `The most recent machine-readable date is ${ageDays} day(s) old (roughly ${Math.round(ageDays / 365)} year(s)). The markup is correct, but the content itself reads as stale.`
        ),
    howToFix: status === 'PASS' ? undefined : t(
      'Revisa y actualiza el contenido de verdad, y después ajusta dateModified a la fecha real de la revisión. Cambiar la fecha sin tocar el contenido se detecta y resulta contraproducente.',
      'Review and genuinely update the content, then set dateModified to the real revision date. Refreshing the date without touching the content is detectable and counter-productive.'
    ),
    raw: { datesFound: dates.length, newestAgeDays: ageDays, newest: new Date(newest).toISOString().slice(0, 10) }
  };
}

// ── Content depth, page scope, and authority ──
//
// These four checks exist to answer the questions an analyst would otherwise work through by
// hand after reading the scan: is there enough substance here to be cited, does this page cover
// too much to rank for any of it, is there anything demonstrating the business is real and
// credible, and is the content shaped so an engine can lift an answer out of it.
//
// The older word-count check asked only "is this page empty", passing anything over 150 words.
// That is the wrong question for GEO: a 286-word page clears it comfortably while having far too
// little for any engine to draw on. These are calibrated against what retrieval actually needs.
//
// All patterns are bilingual. The sites this runs against are largely Spanish-language, and an
// English-only heuristic would report a well-credentialed Spanish site as having no authority
// signals at all — a false finding, and an embarrassing one to hand a client.

const DEPTH_THIN = 300;
const DEPTH_LIGHT = 600;
const DEPTH_ADEQUATE = 1200;

function checkContentDepth(wordCount, pageType) {
  // A contact or legal page is meant to be brief. Scoring it on length produced a FAIL on a
  // 16-word contact page that was doing its job, so these are reported as context instead.
  if (pageType && !pageType.judgeDepth) {
    return {
      id: 'content-depth',
      title: t('Profundidad del contenido para ser citado', 'Content depth for citation'),
      status: 'INFO',
      detail: t(
        `${wordCount} palabras. Es una página de ${(pageType.labelEs || pageType.label).toLowerCase()}, de la que no se espera contenido citable: queda fuera de la evaluación de profundidad en lugar de suspender por ser breve.`,
        `${wordCount} words. This is a ${pageType.label.toLowerCase()} page, which is not expected to carry citable depth — it is excluded from the depth assessment rather than failed for being short.`
      ),
      raw: { wordCount, pageType: pageType.id, judged: false }
    };
  }
  if (wordCount < DEPTH_THIN) {
    return {
      id: 'content-depth',
      title: t('Profundidad del contenido para ser citado', 'Content depth for citation'),
      status: 'FAIL',
      detail: t(
        `${wordCount} palabras de contenido principal. Por debajo de unas ${DEPTH_THIN} palabras no hay materia suficiente para que un motor generativo extraiga y cite un pasaje útil. La página puede rastrearse perfectamente y aun así no citarse nunca, sencillamente porque no hay nada que merezca la pena citar.`,
        `${wordCount} words of main content. Below roughly ${DEPTH_THIN} words there is not enough substance for a generative engine to extract and cite a useful passage — the page can be crawled perfectly and still never be quoted, because there is nothing in it worth quoting.`
      ),
      howToFix: t(
        `Amplía hasta al menos ${DEPTH_LIGHT}-${DEPTH_ADEQUATE} palabras de contenido de valor real: en qué consiste el servicio, a quién va dirigido, cómo se desarrolla, qué cuesta y qué resultado cabe esperar. La extensión por sí sola no sirve de nada; lo que se busca es material concreto del que un motor pueda sacar una respuesta.`,
        `Expand to at least ${DEPTH_LIGHT}-${DEPTH_ADEQUATE} words of genuinely substantive content: what the service actually involves, who it is for, how it works, what it costs, what the outcome looks like. Length alone is worthless — the target is specific, concrete material an engine can lift an answer from.`
      ),
      raw: { wordCount, band: 'thin' }
    };
  }
  if (wordCount < DEPTH_LIGHT) {
    return {
      id: 'content-depth',
      title: t('Profundidad del contenido para ser citado', 'Content depth for citation'),
      status: 'WARNING',
      detail: t(
        `${wordCount} palabras de contenido principal: suficiente para indexarse, pero escaso. Las páginas en este rango rara vez son la fuente que elige un motor cuando existe otra más completa sobre el mismo tema.`,
        `${wordCount} words of main content — enough to be indexed, but light. Pages in this range are rarely the source an engine chooses when a more thorough page exists on the same topic elsewhere.`
      ),
      howToFix: t(
        `Acércate a las ${DEPTH_ADEQUATE}+ palabras respondiendo a lo que realmente pregunta un comprador: proceso, plazos, precios, requisitos previos y comparativa con las alternativas.`,
        `Build toward ${DEPTH_ADEQUATE}+ words by answering the questions a buyer actually asks: process, timelines, pricing, prerequisites, comparisons with alternatives.`
      ),
      raw: { wordCount, band: 'light' }
    };
  }
  return {
    id: 'content-depth',
    title: t('Profundidad del contenido para ser citado', 'Content depth for citation'),
    status: 'PASS',
    detail: t(
      `${wordCount} palabras de contenido principal: profundidad ${wordCount >= DEPTH_ADEQUATE ? 'amplia' : 'suficiente'} para que un motor extraiga un pasaje citable.`,
      `${wordCount} words of main content — ${wordCount >= DEPTH_ADEQUATE ? 'substantial' : 'adequate'} depth for an engine to extract a citable passage.`
    ),
    raw: { wordCount, band: wordCount >= DEPTH_ADEQUATE ? 'substantial' : 'adequate' }
  };
}

// Splits the page at its H2 boundaries and measures the content under each, which is what makes
// "should this be several pages" answerable rather than a matter of taste.
function measureSections($) {
  const sections = [];
  $('h2').each((_, el) => {
    const heading = $(el).text().trim().replace(/\s+/g, ' ').slice(0, 90);
    let words = 0;
    let node = $(el).next();
    while (node.length && !/^h[12]$/i.test(node.get(0).tagName || '')) {
      words += node.text().replace(/\s+/g, ' ').trim().split(/\s+/).filter(Boolean).length;
      node = node.next();
    }
    if (heading) sections.push({ heading, words });
  });
  return sections;
}

function checkPageScope($, wordCount, pageType) {
  if (pageType && !pageType.judgeDepth) {
    return {
      id: 'page-scope',
      title: t('Alcance de la página: ¿debería dividirse?', 'Page scope — should this be split?'),
      status: 'INFO',
      detail: t(
        `No se evalúa: una página de ${(pageType.labelEs || pageType.label).toLowerCase()} tiene un único propósito por definición y nunca es candidata a dividirse.`,
        `Not assessed — a ${pageType.label.toLowerCase()} page is single-purpose by design and is never a candidate for splitting.`
      ),
      raw: { pageType: pageType.id, judged: false }
    };
  }
  const sections = measureSections($);
  const navLinks = $('nav a[href], header a[href]').toArray().map(a => $(a).attr('href') || '');
  const realNavLinks = navLinks.filter(h => h && !/^#/.test(h) && !/^(mailto:|tel:|javascript:)/i.test(h));
  const anchorNavLinks = navLinks.filter(h => /^#./.test(h));
  // Navigation built entirely from in-page anchors is the defining signature of a one-page site:
  // the "pages" a visitor is offered are scroll positions, so there is only ever one document for
  // an engine to retrieve no matter how many topics it covers.
  const anchorOnlyNav = anchorNavLinks.length >= 3 && realNavLinks.length === 0;
  const avgSectionWords = sections.length ? Math.round(sections.reduce((n, s) => n + s.words, 0) / sections.length) : 0;
  const raw = { sectionCount: sections.length, avgSectionWords, anchorOnlyNav, anchorNavLinks: anchorNavLinks.length, realNavLinks: realNavLinks.length, sections: sections.slice(0, 12) };
  const heads = sections.map(s => s.heading).slice(0, 5).join('; ');

  if (anchorOnlyNav && sections.length >= 3) {
    return {
      id: 'page-scope',
      title: t('Alcance de la página: ¿debería dividirse?', 'Page scope — should this be split?'),
      status: 'FAIL',
      detail: t(
        `Es un sitio web de una sola página que abarca ${sections.length} temas distintos (${heads}${sections.length > 5 ? '; …' : ''}), con una media de ${avgSectionWords} palabras cada uno. Todos los enlaces de navegación son anclas internas, así que solo existe un documento. Los motores generativos recuperan y citan a nivel de página: ningún tema de aquí puede devolverse ante una consulta sobre él, porque todos compiten dentro de una misma página escasa.`,
        `This is a single-page site covering ${sections.length} distinct topics (${heads}${sections.length > 5 ? '; …' : ''}), averaging ${avgSectionWords} words each. Every navigation link is an in-page anchor, so there is only one document in existence. Generative engines retrieve and cite at page level, which means no topic here can be returned for a query about it — they are all competing inside one thin page.`
      ),
      howToFix: t(
        `Divide el sitio web en páginas independientes, una por tema, cada una con su propia URL y su lugar en la navegación: ${heads}. Después dale a cada una ${DEPTH_LIGHT}+ palabras de contenido específico. Es el cambio estructural de mayor impacto disponible para este sitio web, y del que depende cualquier otra recomendación de contenido.`,
        `Split into separate pages, one per topic, each with its own URL and its own place in the navigation: ${heads}. Then give each ${DEPTH_LIGHT}+ words of specific content. This is the highest-impact structural change available to this site, and every other content recommendation depends on it.`
      ),
      raw
    };
  }
  if (sections.length >= 4 && avgSectionWords > 0 && avgSectionWords < 120) {
    return {
      id: 'page-scope',
      title: t('Alcance de la página: ¿debería dividirse?', 'Page scope — should this be split?'),
      status: 'WARNING',
      detail: t(
        `La página abarca ${sections.length} temas con una media de ${avgSectionWords} palabras cada uno. Cada apartado es demasiado breve para recuperarse por sí solo y, en conjunto, diluyen de qué trata la página.`,
        `The page covers ${sections.length} topics at an average of ${avgSectionWords} words each. Each section is too thin to be retrieved on its own, and together they dilute what the page is about.`
      ),
      howToFix: t(
        'Lleva a su propia página, con contenido de valor, los apartados que merezcan posicionar, y deja aquí solo un resumen con enlace. Una página que trata de una sola cosa es recuperable; una que trata de seis no trata de ninguna.',
        'Promote the sections that deserve to rank into their own pages with substantive content, and keep only a summary with a link on this page. A page that is about one thing is retrievable; a page about six things is about nothing.'
      ),
      raw
    };
  }
  return {
    id: 'page-scope',
    title: t('Alcance de la página: ¿debería dividirse?', 'Page scope — should this be split?'),
    status: 'PASS',
    detail: sections.length
      ? t(
          `${sections.length} sección(es) de contenido con una media de ${avgSectionWords} palabras. La página tiene un alcance coherente y no necesita dividirse.`,
          `${sections.length} content section(s) averaging ${avgSectionWords} words. The page has a coherent scope and does not need splitting.`
        )
      : t(
          'No se detecta una estructura multitema que justifique dividir esta página.',
          'No multi-topic structure detected that would warrant splitting this page.'
        ),
    raw
  };
}

// Authority is the half of GEO that on-page technical checks miss entirely. Engines favour
// sources that demonstrably belong to a real, identifiable organisation, and none of that is
// visible to a title-tag or schema check.
const AUTHORITY_PATTERNS = {
  namedPeople: /\b(?:founder|fundador[ao]?|ceo|director[ao]?|gerente|president[e|a]|our team|nuestro equipo|equipo directivo|written by|escrito por|autor)\b/i,
  clientEvidence: /\b(?:case stud(?:y|ies)|caso[s]? de [ée]xito|testimonial(?:s|es)?|testimonio[s]?|our clients|nuestros clientes|trusted by|clientes destacados|portfolio|portafolio)\b/i,
  credentials: /\b(?:certifi(?:ed|cation|cado|caci[óo]n)|accredit(?:ed|ation)|acreditad[ao]|award|premio|galard[óo]n|ISO\s?\d{4,5}|member of|miembro de|asociaci[óo]n|since\s+(?:19|20)\d{2}|desde\s+(?:19|20)\d{2}|\d{1,2}\+?\s*(?:years|a[ñn]os)\s+(?:of\s+)?(?:experience|experiencia|in business))\b/i,
  physicalPresence: /\b(?:\d{1,5}\s+[A-Z][a-z]+\s+(?:street|st\.|avenue|ave\.|road|rd\.|calle|avenida|av\.|blvd)|C\.?P\.?\s?\d{5}|co?l\.\s+[A-Z])/i
};

function checkAuthoritySignals($, mainText) {
  const present = {};
  present.namedPeople = AUTHORITY_PATTERNS.namedPeople.test(mainText) || $('[rel~="author"]').length > 0;
  present.clientEvidence = AUTHORITY_PATTERNS.clientEvidence.test(mainText);
  present.credentials = AUTHORITY_PATTERNS.credentials.test(mainText);
  present.physicalAddress = AUTHORITY_PATTERNS.physicalPresence.test(mainText) || $('[itemprop="address"], address').length > 0;
  present.directContact = $('a[href^="tel:"]').length > 0 || $('a[href^="mailto:"]').length > 0;

  // sameAs links are how an organisation is tied to the profiles an engine already trusts, and
  // are the single most direct on-page entity signal available.
  let hasSameAs = false;
  $('script[type="application/ld+json"]').each((_, el) => {
    try { if (/"sameAs"/i.test($(el).contents().text())) hasSameAs = true; } catch { /* ignore */ }
  });
  const socialLinks = $('a[href*="linkedin.com"], a[href*="facebook.com"], a[href*="instagram.com"], a[href*="x.com"], a[href*="twitter.com"], a[href*="youtube.com"]').length;
  present.externalProfiles = hasSameAs || socialLinks > 0;

  const LABELS = {
    namedPeople: { es: 'personas identificadas (fundadores, equipo o autores)', en: 'named people (founders, team, or authors)' },
    clientEvidence: { es: 'pruebas de clientes (casos de éxito, testimonios, clientes con nombre)', en: 'client evidence (case studies, testimonials, named clients)' },
    credentials: { es: 'credenciales (certificaciones, premios, asociaciones, años de actividad)', en: 'credentials (certifications, awards, memberships, years in business)' },
    physicalAddress: { es: 'una dirección física', en: 'a physical address' },
    directContact: { es: 'enlaces de contacto directo (tel: / mailto:)', en: 'direct contact links (tel: / mailto:)' },
    externalProfiles: { es: 'enlaces a perfiles externos (sameAs, LinkedIn, etc.)', en: 'links to external profiles (sameAs, LinkedIn, etc.)' }
  };
  const missingEs = []; const missingEn = [];
  Object.entries(LABELS).forEach(([k, l]) => { if (!present[k]) { missingEs.push(l.es); missingEn.push(l.en); } });
  const score = Object.values(present).filter(Boolean).length;
  const total = Object.keys(LABELS).length;
  const status = score >= 5 ? 'PASS' : score >= 3 ? 'WARNING' : 'FAIL';

  return {
    id: 'authority-signals',
    title: t('Señales de autoridad y credibilidad', 'Authority & credibility signals'),
    status,
    detail: status === 'PASS'
      ? t(
          `${score} de ${total} señales de autoridad presentes. La página demuestra que detrás hay una organización real e identificable.`,
          `${score} of ${total} authority signals present. The page demonstrates a real, identifiable organisation behind it.`
        )
      : t(
          `Solo ${score} de ${total} señales de autoridad. Faltan: ${missingEs.join('; ')}. Los motores generativos prefieren con claridad las fuentes que pertenecen visiblemente a una organización real y responsable; sin estas señales, el sitio web se lee como publicidad anónima por bien construido que esté.`,
          `Only ${score} of ${total} authority signals found. Missing: ${missingEn.join('; ')}. Generative engines strongly prefer sources that visibly belong to a real, accountable organisation — without these, the site reads as anonymous marketing copy regardless of how well it is built.`
        ),
    howToFix: status === 'PASS' ? undefined : t(
      `Añade lo que falta: ${missingEs.join('; ')}. Personas con nombre, cargo y credenciales, clientes identificados con resultados concretos, y certificaciones o años de actividad explícitos son las señales que con más fiabilidad separan una fuente citable de un texto genérico. Además aportan al contenido los datos específicos que ahora le faltan.`,
      `Add what is missing: ${missingEn.join('; ')}. Named people with roles and credentials, named clients with concrete outcomes, and explicit certifications or years in business are the signals that most reliably separate a citable source from generic copy — and they also give the content the specific facts it currently lacks.`
    ),
    raw: { present, missing: missingEn, score, total, socialLinks, hasSameAsSchema: hasSameAs }
  };
}

// Retrieval works by matching a question to a passage that answers it. Content written as
// question-and-answer, or structured into lists, tables and definitions, is markedly easier to
// lift an answer from than continuous prose.
function checkAnswerFormat($, mainText) {
  const headings = $('h2,h3,h4').toArray().map(el => $(el).text().trim()).filter(Boolean);
  const questionHeadings = headings.filter(h => /\?|^(?:how|what|why|when|where|which|who|can|do|does|is|are|should|c[óo]mo|qu[ée]|por qu[ée]|cu[áa]ndo|d[óo]nde|cu[áa]l|qui[ée]n|puede|debe)\b/i.test(h));
  const lists = $('ul li, ol li').length;
  const tables = $('table').length;
  const definitionLists = $('dl').length;
  const structures = lists + tables * 5 + definitionLists * 3;

  const sigEs = []; const sigEn = [];
  if (questionHeadings.length) { sigEs.push(`${questionHeadings.length} encabezado(s) en forma de pregunta`); sigEn.push(`${questionHeadings.length} question-form heading(s)`); }
  if (lists) { sigEs.push(`${lists} elemento(s) de lista`); sigEn.push(`${lists} list item(s)`); }
  if (tables) { sigEs.push(`${tables} tabla(s)`); sigEn.push(`${tables} table(s)`); }

  const good = questionHeadings.length >= 2 || structures >= 12;
  return {
    id: 'answer-format',
    title: t('Contenido con forma de respuesta', 'Answer-shaped content'),
    status: good ? 'PASS' : 'WARNING',
    detail: good
      ? t(`El contenido está estructurado para poder extraerse: ${sigEs.join(', ')}.`, `Content is structured for extraction: ${sigEn.join(', ')}.`)
      : t(
          `Apenas se encuentra estructura extraíble${sigEs.length ? ` (solo ${sigEs.join(', ')})` : ''}. La página es sobre todo prosa continua, de la que a un motor le cuesta más extraer una respuesta directa que de apartados de pregunta y respuesta, listas o tablas comparativas.`,
          `Little extractable structure found${sigEn.length ? ` (only ${sigEn.join(', ')})` : ''}. The page is largely continuous prose, which is harder for an engine to lift a direct answer from than question-and-answer sections, lists or comparison tables.`
        ),
    howToFix: good ? undefined : t(
      'Reescribe los apartados clave como preguntas que un cliente formularía de verdad, con la respuesta enunciada directamente en la primera frase de cada una. Añade tablas comparativas y listas de pasos donde encajen: los motores las favorecen de forma desproporcionada en sus respuestas, y además hacen la página más útil de leer.',
      'Rewrite key sections as questions a customer would actually ask, with the answer stated directly in the first sentence beneath each. Add comparison tables and step lists where they fit — these are disproportionately favoured in AI answers, and they make the page more useful to read as well.'
    ),
    raw: { questionHeadings: questionHeadings.slice(0, 8), questionHeadingCount: questionHeadings.length, listItems: lists, tables, definitionLists }
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
  checks.push({
    id: 'title',
    title: t('Etiqueta title', 'Title tag'),
    status: !title ? 'FAIL' : (title.length > 60 ? 'WARNING' : 'PASS'),
    detail: !title
      ? t('Falta la etiqueta <title>.', 'Missing <title> tag.')
      : t(
          `«${title}» — ${title.length} caracteres${title.length > 60 ? ' (por encima de la referencia de ~60; puede truncarse en los resultados).' : '.'}`,
          `"${title}" — ${title.length} characters${title.length > 60 ? ' (over the ~60 char guideline; may get truncated in results).' : '.'}`
        ),
    howToFix: !title
      ? t(
          'Añade una etiqueta <title> única y descriptiva a esta página. Es una de las señales en página más básicas e importantes, tanto para buscadores como para motores de IA.',
          'Add a unique, descriptive <title> tag to this page — it\'s one of the most basic and important on-page signals for both search and AI engines.'
        )
      : (title.length > 60 ? t(
          'Acorta el title por debajo de ~60 caracteres para que no se trunque en los resultados de búsqueda ni en las citas de IA.',
          'Shorten the title tag to under ~60 characters so it isn\'t truncated in search results and AI citations.'
        ) : undefined),
    raw: { title, length: title.length }
  });
  checks.push({
    id: 'meta-description',
    title: t('Meta description', 'Meta description'),
    status: !metaDescription ? 'FAIL' : (metaDescription.length > 160 ? 'WARNING' : 'PASS'),
    detail: !metaDescription
      ? t('Falta la meta description.', 'Missing meta description.')
      : t(
          `${metaDescription.length} caracteres${metaDescription.length > 160 ? ' (por encima de la referencia de ~160; puede truncarse).' : '.'}`,
          `${metaDescription.length} characters${metaDescription.length > 160 ? ' (over the ~160 char guideline; may get truncated.)' : '.'}`
        ),
    howToFix: !metaDescription
      ? t(
          'Añade una meta description única que resuma el contenido de la página y su propuesta de valor.',
          'Add a unique meta description summarizing the page\'s content and value proposition.'
        )
      : (metaDescription.length > 160 ? t(
          'Recorta la meta description por debajo de ~155-160 caracteres para que no se trunque en los resultados. Conserva la propuesta de valor y una llamada a la acción.',
          'Trim the meta description to under ~155-160 characters so it doesn\'t get truncated in search results. Keep the core value proposition and a call to action.'
        ) : undefined),
    raw: { metaDescription, length: metaDescription.length }
  });
  checks.push({
    id: 'schema',
    title: t('Datos estructurados (Schema.org / JSON-LD)', 'Schema.org / JSON-LD'),
    status: schemaTypes.length === 0 ? 'FAIL' : (missingCommonSchema.length > 4 ? 'WARNING' : 'PASS'),
    detail: schemaTypes.length === 0
      ? t('No se encuentran datos estructurados JSON-LD en esta página.', 'No JSON-LD structured data found on this page.')
      : t(
          `Presentes: ${schemaTypes.join(', ')}. Tipos habituales ausentes: ${missingCommonSchema.join(', ') || 'ninguno'}.`,
          `Found: ${schemaTypes.join(', ')}. Missing common types: ${missingCommonSchema.join(', ') || 'none'}.`
        ),
    howToFix: schemaTypes.length === 0
      ? t(
          'Añade datos estructurados JSON-LD (schema.org) acordes al contenido de la página: como mínimo Organization y WebSite en todo el sitio web, más FAQPage si hay preguntas frecuentes, y Service, Product o LocalBusiness donde corresponda. Es una de las señales de mayor impacto para ser citado por la IA.',
          'Add JSON-LD structured data (schema.org) appropriate to this page\'s content — at minimum Organization and WebSite site-wide, plus FAQPage if there\'s FAQ content, Service/Product/LocalBusiness where relevant. This is one of the highest-leverage signals for AI citation.'
        )
      : (missingCommonSchema.length > 4 ? t(
          `Valora añadir schema para: ${missingCommonSchema.join(', ')}, aquellos que realmente encajen con el contenido de esta página.`,
          `Consider adding schema for: ${missingCommonSchema.join(', ')} — whichever are actually relevant to this page's content.`
        ) : undefined),
    raw: { present: schemaTypes, missing: missingCommonSchema }
  });
  checks.push({
    id: 'headings',
    title: t('Estructura de encabezados', 'Heading structure'),
    status: headingInfo.h1Count === 1 && !headingInfo.skippedLevel ? 'PASS' : (headingInfo.h1Count === 0 ? 'FAIL' : 'WARNING'),
    detail: headingInfo.h1Count === 0
      ? t('No se encuentra ningún <h1> en la página.', 'No <h1> found on the page.')
      : headingInfo.h1Count > 1
        ? t(`Se encuentran ${headingInfo.h1Count} etiquetas <h1>; debería haber exactamente una.`, `${headingInfo.h1Count} <h1> tags found — should be exactly one.`)
        : headingInfo.skippedLevel
          ? t('Hay exactamente un <h1>, pero la jerarquía de encabezados se salta algún nivel (por ejemplo, de H1 directamente a H3 o H4).', 'Exactly one <h1>, but the heading hierarchy skips a level somewhere (e.g. H1 straight to H3/H4).')
          : t('Exactamente un <h1> y ningún nivel de encabezado omitido.', 'Exactly one <h1> and no skipped heading levels.'),
    howToFix: (headingInfo.h1Count === 1 && !headingInfo.skippedLevel) ? undefined : t(
      'Usa exactamente un <h1> por página, que represente el tema principal, y no te saltes niveles (H1 → H2 → H3). Controla el tamaño visual con CSS, no cambiando el nivel del encabezado.',
      'Use exactly one <h1> per page representing the main topic, and don\'t skip heading levels (H1 → H2 → H3) — use CSS instead of heading level to control visual size.'
    ),
    raw: headingInfo
  });
  checks.push({
    id: 'canonical',
    title: t('Etiqueta canonical', 'Canonical tag'),
    status: !canonical.present ? 'WARNING' : (canonical.crossDomain ? 'FAIL' : 'PASS'),
    detail: !canonical.present
      ? t('No hay etiqueta canonical.', 'No canonical tag present.')
      : canonical.crossDomain
        ? t(
            `La canonical apunta a otro dominio o host (${canonical.href}). Es un fallo habitual tras una migración, con las canonical apuntando todavía al entorno de pruebas.`,
            `Canonical points to a different domain/host (${canonical.href}) — a common bug after site migrations, leaving canonicals pointed at staging.`
          )
        : canonical.selfReferencing
          ? t('La etiqueta canonical está presente y apunta a la propia página.', 'Canonical tag is present and self-referencing.')
          : t(
              `Hay canonical y apunta a otra dirección del mismo dominio (${canonical.href}); confirma que es intencionado.`,
              `Canonical present and points elsewhere on the same domain (${canonical.href}) — confirm this is intentional.`
            ),
    howToFix: !canonical.present
      ? t(
          'Añade una etiqueta <link rel="canonical"> que apunte a la URL exacta de esta misma página. Evita la confusión por contenido duplicado.',
          'Add a self-referencing <link rel="canonical"> tag pointing to this exact page\'s URL — this prevents duplicate-content confusion.'
        )
      : (canonical.crossDomain ? t(
          'Corrige la canonical para que apunte a la URL de producción de esta página, no a otro dominio ni al entorno de pruebas. Es un resto habitual de las migraciones y puede impedir que la página en vivo se indexe.',
          'Update the canonical tag to point to this page\'s own production URL, not a staging/different domain — a common leftover from site migrations that can suppress the live page from being indexed.'
        ) : undefined),
    raw: canonical
  });
  const ogMissing = ['title', 'description', 'type'].filter(k => !og[k]);
  checks.push({
    id: 'open-graph',
    title: t('Etiquetas Open Graph', 'Open Graph tags'),
    status: ogMissing.length === 0 ? 'PASS' : (ogMissing.length === 3 ? 'FAIL' : 'WARNING'),
    detail: ogMissing.length === 0
      ? t('og:title, og:description y og:type están las tres presentes.', 'og:title, og:description and og:type all present.')
      : t(`Faltan: ${ogMissing.map(k => 'og:' + k).join(', ')}.`, `Missing: ${ogMissing.map(k => 'og:' + k).join(', ')}.`),
    howToFix: ogMissing.length === 0 ? undefined : t(
      `Añade las etiquetas Open Graph que faltan (${ogMissing.map(k => 'og:' + k).join(', ')}). Controlan cómo se muestra la página al compartirse o citarse, incluidas algunas herramientas de IA que recuperan metadatos de vista previa.`,
      `Add the missing Open Graph tags (${ogMissing.map(k => 'og:' + k).join(', ')}) — these control how the page appears when shared/cited, including by some AI tools that fetch preview metadata.`
    ),
    raw: og
  });
  checks.push({
    id: 'image-alt',
    title: t('Cobertura de texto alternativo en imágenes', 'Image alt text coverage'),
    status: images.total === 0 ? 'PASS' : (images.pct >= 80 ? 'PASS' : images.pct >= 40 ? 'WARNING' : 'FAIL'),
    detail: images.total === 0
      ? t('Esta página no tiene etiquetas <img>.', 'No <img> tags on this page.')
      : t(
          `${images.withAlt} de ${images.total} imágenes (${images.pct}%) tienen texto alternativo con contenido.`,
          `${images.withAlt}/${images.total} images (${images.pct}%) have non-empty alt text.`
        ),
    howToFix: (images.total === 0 || images.pct >= 80) ? undefined : t(
      'Añade texto alternativo descriptivo a las imágenes que no lo tienen. Ayuda tanto a las herramientas de accesibilidad como a los motores de IA a entender el contenido de la imagen, sobre todo en páginas de producto o servicio.',
      'Add descriptive alt text to images missing it — this helps both accessibility tools and AI engines understand image content, especially on product/service pages.'
    ),
    raw: images
  });
  // Added checks (page discovery add-on) — each returns null when not applicable to this page
  // (e.g. no FAQ schema present) rather than forcing an irrelevant row.
  [checkJsRendering($, mainText, html), checkSchemaCompleteness($), checkFaqSchemaMatch($, mainText), checkAuthorAttribution($, mainText), checkFirstWordsSpecificity(mainText), checkContactMachineReadability($, mainText)]
    .filter(Boolean)
    .forEach(c => checks.push(c));

  const mainCheck = checkMainLandmark($);
  const headingSeqCheck = checkHeadingHierarchySequential(headingInfo);
  const formCheck = checkFormLabels($);
  const a11yHealthCheck = computeAccessibilityTreeHealth(mainCheck, headingSeqCheck, formCheck, images);
  const agenticChecks = [mainCheck, headingSeqCheck, formCheck, a11yHealthCheck];

  // Counted once and shared, so every check and the reported wordCount are guaranteed to agree.
  const mainWordCount = mainText ? mainText.split(/\s+/).filter(Boolean).length : 0;

  const pageType = detectPageType(pageUrl);
  const depthChecks = [
    checkContentDepth(mainWordCount, pageType),
    checkPageScope($, mainWordCount, pageType),
    checkAuthoritySignals($, mainText),
    checkAnswerFormat($, mainText),
    checkFreshness($, mainText)
  ].filter(Boolean);

  return { url: pageUrl, title, metaDescription, schemaTypes, headingInfo, canonical, og, images, mainText, depthChecks, wordCount: mainWordCount, checks, agenticChecks };
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
    title: t('Presencia de la región <main>', 'Main landmark presence'),
    status: hasMain ? 'PASS' : 'FAIL',
    detail: hasMain
      ? t('Existe un elemento <main> (o role="main").', 'A <main> element (or role="main") is present.')
      : t('No se encuentra ningún elemento <main> ni región role="main".', 'No <main> element or role="main" landmark found.'),
    howToFix: hasMain ? undefined : t(
      'Envuelve el contenido principal de la página en una etiqueta <main>. Ayuda tanto a las tecnologías de apoyo como a los rastreadores de IA a distinguir el contenido central de la navegación, la barra lateral y el pie.',
      'Wrap the primary content of the page in a <main> tag. This helps both assistive technology and AI crawlers identify the core content versus navigation/sidebar/footer.'
    ),
    raw: { hasMain }
  };
}

function checkHeadingHierarchySequential(headingInfo) {
  const status = headingInfo.skippedLevel ? 'WARNING' : 'PASS';
  return {
    id: 'heading-hierarchy',
    title: t('Jerarquía de encabezados (orden secuencial)', 'Heading hierarchy (sequential order)'),
    status,
    detail: headingInfo.skippedLevel
      ? t(
          'Se omiten uno o más niveles de encabezado al descender el esquema (por ejemplo, de H1 directamente a H3, sin H2 intermedio).',
          'One or more heading levels are skipped when descending the outline (e.g. H1 straight to H3, with no H2 between).'
        )
      : t('Los niveles de encabezado descienden de forma secuencial, sin saltos.', 'Heading levels descend sequentially with no skips.'),
    howToFix: headingInfo.skippedLevel ? t(
      'Los encabezados deben descender de nivel en nivel (H1 → H2 → H3), aunque visualmente quieras un texto más pequeño. Usa CSS para el tamaño y reserva el nivel del encabezado para indicar la estructura a rastreadores y tecnologías de apoyo.',
      'Headings should descend one level at a time (H1 → H2 → H3), even if visually you want smaller text — use CSS for visual size, not heading level, to indicate structure to crawlers and assistive tech.'
    ) : undefined,
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
    title: t('Asociación de etiquetas en formularios', 'Form label association'),
    status,
    detail: total === 0
      ? t('Esta página no tiene campos de formulario.', 'No form fields on this page.')
      : unlabeled.length === 0
        ? t(`Los ${total} campo(s) del formulario tienen una etiqueta asociada.`, `All ${total} form field(s) have an associated label.`)
        : t(
            `${unlabeled.length} de ${total} campo(s) del formulario no tienen etiqueta: ${unlabeled.map(u => u.name || u.id || u.type || u.tag).join(', ')}.`,
            `${unlabeled.length}/${total} form field(s) missing a label: ${unlabeled.map(u => u.name || u.id || u.type || u.tag).join(', ')}.`
          ),
    howToFix: unlabeled.length === 0 ? undefined : t(
      'Añade una <label for="[id]"> que coincida con el id de cada campo, o un atributo aria-label directamente en el campo. Los campos sin etiqueta son invisibles para los lectores de pantalla y difíciles de interpretar para un agente de IA que intente rellenar el formulario.',
      'Add a <label for="[id]"> matching each form field\'s id, or an aria-label attribute directly on the field. Unlabeled form fields are invisible to screen readers and likely poorly understood by AI agents trying to interact with the page.'
    ),
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
    title: t('Salud del árbol de accesibilidad (estimación compuesta)', 'Accessibility Tree Health (composite estimate)'),
    status,
    detail: t(
      `Estimación compuesta: ${score}/100, a partir de la presencia de la región <main>, la jerarquía de encabezados, el etiquetado de formularios y la cobertura de texto alternativo. Se basa solo en señales estructurales del HTML estático; para la auditoría completa del árbol de accesibilidad de Chrome, contrasta con Google PageSpeed Insights.`,
      `Composite estimate: ${score}/100, based on main-landmark presence, heading hierarchy, form labeling, and image alt coverage. Based on structural signals from static HTML only — for Chrome's full accessibility tree audit, cross-check with Google PageSpeed Insights.`
    ),
    howToFix: status === 'PASS' ? undefined : t(
      'Resuelve las revisiones individuales anteriores (región <main>, jerarquía de encabezados, etiquetas de formulario y texto alternativo): esta puntuación compuesta sube a medida que mejoran.',
      'Address the individual checks above (main landmark, heading hierarchy, form labels, image alt text) — this composite score moves as those improve.'
    ),
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
    let detail = t(
      `${entities.properNounCount} expresiones con aspecto de nombre propio, ${entities.numberCount} cifras y ${entities.yearCount} referencias a años en ${p.wordCount} palabras de contenido principal.`,
      `${entities.properNounCount} proper-noun-like phrases, ${entities.numberCount} numbers, ${entities.yearCount} year references found in ${p.wordCount} words of main content.`
    );
    if (entities.properNounCount < 3 && entities.numberCount < 3) {
      status = 'WARNING';
      detail = t(
        `Se detectan muy pocos datos concretos y citables (${entities.properNounCount} nombres propios, ${entities.numberCount} cifras): el contenido se lee como genérico. Los motores prefieren contenido específico y citable frente al texto comercial de relleno.`,
        `Very few specific, citable facts detected (${entities.properNounCount} proper nouns, ${entities.numberCount} numbers) — content reads as generic. AI engines favor specific, citable content over boilerplate marketing copy.`
      );
    }
    return { url: p.url, entities, checks: [
      ...(p.depthChecks || []),
      { id: 'entities', title: t('Entidades nombradas y especificidad', 'Named entity / specificity signal'), status, detail, howToFix: status === 'PASS' ? undefined : t(
        'Añade datos más concretos —cifras reales, fechas, entidades con nombre (personas, lugares, nombres de producto)— en lugar de lenguaje comercial genérico. Los motores prefieren contenido específico y citable frente a afirmaciones vagas.',
        'Add more specific facts — real numbers, dates, named entities (people, places, product names) — rather than generic marketing language. AI engines favor citable, specific content over vague claims.'
      ), raw: entities },
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
    title: t('Contenido duplicado o de plantilla', 'Boilerplate / templated content'),
    // With fewer than two pages there is nothing to compare, so this cannot pass or fail. It
    // used to return PASS regardless, which handed a full-marks check to scans that analysed no
    // pages at all — inflating the total on exactly the runs that had measured the least.
    status: pages.length < 2 ? 'INCONCLUSIVE' : (boilerplatePairs.length ? 'WARNING' : 'PASS'),
    detail: boilerplatePairs.length
      ? t(
          `${boilerplatePairs.length} par(es) de páginas comparten contenido muy solapado (${boilerplatePairs.map(p => p.similarity + '%').join(', ')}), señal de páginas de plantilla con poco valor propio.`,
          `${boilerplatePairs.length} page pair(s) share heavily overlapping content (${boilerplatePairs.map(p => p.similarity + '%').join(', ')}) — a sign of templated, low-value pages (this is exactly the pattern found in directory-listing-style sites).`
        )
      : (pages.length > 1
          ? t('No se detecta solapamiento de contenido relevante entre las páginas analizadas.', 'No significant content overlap detected between the scanned pages.')
          : t(
              'Solo había una página con la que comparar: no se encontró sitemap ni páginas de Nosotros/FAQ/Contacto/Servicios/Blog enlazadas desde la navegación, ni se añadieron páginas a mano.',
              'Only one page was available to compare — no sitemap and no About/FAQ/Contact/Services/Blog page linked from the navigation, and no additional pages were provided manually.'
            )),
    howToFix: boilerplatePairs.length ? t(
      'Diferencia las páginas de plantilla con contenido propio y específico de cada una, sobre todo en páginas tipo listado o directorio, donde una plantilla compartida puede dejarlas casi idénticas.',
      'Differentiate templated pages with unique, page-specific content — especially for directory/listing-style pages where a shared template can make every page nearly identical.'
    ) : undefined,
    raw: { pairs: boilerplatePairs }
  };

  return { perPage, boilerplateCheck };
}

// ── Layer view ──
// Regroups every check the scan produced into the three layers defined in the registry, so the
// report is organised by the question each check answers and by who is able to act on it:
// access is hosting and DNS, readability is the developer, substance is the content team.
// The previous grouping mixed a missing <title> in with a thin About page, which left a reader
// no way to see which parts of the report were even theirs to act on.
//
// Scoring is deliberately flat: every check counts equally inside its layer, and the two scored
// layers count equally in the headline. Weighted models invite argument about the weights; a
// stated rule anyone can recompute from the same page does not.
function buildLayers(siteChecks, pages) {
  const instances = [];
  siteChecks.forEach(c => instances.push({ check: c, page: null }));
  pages.forEach(p => (p.checks || []).forEach(c => instances.push({ check: c, page: p.url })));

  return Object.values(LAYERS)
    .sort((a, b) => a.order - b.order)
    .map(layer => {
      const mine = instances.filter(({ check }) => (CHECKS[check.id] || {}).layer === layer.id);
      const scorable = mine.filter(({ check }) => SCORE_POINTS[check.status] !== undefined && (CHECKS[check.id] || {}).scored !== false);
      const score = scorable.length
        ? Math.round(scorable.reduce((sum, { check }) => sum + SCORE_POINTS[check.status], 0) / scorable.length)
        : null;

      const counts = { PASS: 0, WARNING: 0, FAIL: 0, INCONCLUSIVE: 0, INFO: 0 };
      mine.forEach(({ check }) => { if (counts[check.status] !== undefined) counts[check.status]++; });

      return {
        id: layer.id,
        title: layer.title,
        question: layer.question,
        summary: layer.summary,
        owner: layer.owner,
        scored: layer.scored,
        scoringNote: layer.scoringNote,
        score,
        counts,
        checksRun: mine.length,
        checks: mine.map(({ check, page }) => ({
          id: check.id,
          title: check.title,
          status: check.status,
          detail: check.detail,
          howToFix: check.howToFix,
          page,
          measures: (CHECKS[check.id] || {}).measures,
          rule: (CHECKS[check.id] || {}).rule,
          why: (CHECKS[check.id] || {}).why,
          raw: check.raw
        }))
      };
    });
}

// Any check the scan emitted that the registry does not describe. Surfaced rather than swallowed:
// an undocumented check is one the published methodology does not cover, which is precisely the
// drift the registry exists to prevent.
function findUnregisteredChecks(siteChecks, pages) {
  const ids = new Set();
  siteChecks.forEach(c => ids.add(c.id));
  pages.forEach(p => (p.checks || []).forEach(c => ids.add(c.id)));
  return Array.from(ids).filter(id => !CHECKS[id]);
}

// ── Scoring ──

const SCORE_POINTS = { PASS: 100, WARNING: 55, FAIL: 0 };

// INCONCLUSIVE checks are dropped from the denominator entirely — they are neither credited nor
// penalised. Scoring "we could not measure this" as zero was what let a network failure on our
// side publish itself as a verdict about the client's site.
function scoreChecks(checks) {
  const scorable = (checks || []).filter(c => c && SCORE_POINTS[c.status] !== undefined);
  if (!scorable.length) return null;
  return Math.round(scorable.reduce((sum, c) => sum + SCORE_POINTS[c.status], 0) / scorable.length);
}

function averagePageScores(pages) {
  const scores = pages.map(p => scoreChecks(p.checks)).filter(s => s !== null);
  return scores.length ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : null;
}

// The headline number is now on-page readiness only — the things a client's web team can
// actually change on the site, which is what this tool exists to produce. Crawlability is
// reported alongside it as blockers rather than folded in: it is largely hosting and WAF
// territory, it is the least reliable thing to measure remotely, and every false result this
// tool has produced originated there. Letting it carry 45% of the score and clamp the total
// meant infrastructure noise moved a number that is supposed to track on-page work.
const ONPAGE_WEIGHTS = { onPage: 0.40, agenticBrowsing: 0.20, contentSpecificity: 0.40 };

function computeScoreFromLayers(layers, section1Checks, pagesAnalyzed) {
  const scoredLayers = layers.filter(l => l.scored && l.score !== null);
  const overall = scoredLayers.length
    ? Math.round(scoredLayers.reduce((sum, l) => sum + l.score, 0) / scoredLayers.length)
    : null;
  const blockers = section1Checks.filter(c => c.status === 'FAIL');
  const unverified = section1Checks.filter(c => c.status === 'INCONCLUSIVE');
  const byId = id => (layers.find(l => l.id === id) || {}).score ?? null;
  return {
    overall,
    scored: overall !== null,
    pagesAnalyzed,
    sections: {
      onPage: byId('readability'),
      agenticBrowsing: byId('readability'),
      contentSpecificity: byId('substance'),
      crawlability: byId('access')
    },
    layers: layers.map(l => ({ id: l.id, title: l.title, score: l.score, scored: l.scored, counts: l.counts })),
    blockers: { count: blockers.length, items: blockers.map(c => ({ id: c.id, title: c.title })) },
    unverified: { count: unverified.length, items: unverified.map(c => ({ id: c.id, title: c.title })) },
    rubricVersion: 4
  };
}

function computeScoreLegacy(section1Checks, section2Pages, section4Pages, section3, pagesAnalyzed) {
  const crawlability = scoreChecks(section1Checks);
  const onPage = averagePageScores(section2Pages);
  const agenticBrowsing = averagePageScores(section4Pages);
  const contentSpecificity = pagesAnalyzed > 0
    ? scoreChecks([...section3.perPage.flatMap(p => p.checks), section3.boilerplateCheck])
    : null;

  // Weights are renormalised across whatever could actually be measured, so a missing section
  // widens the error bar instead of dragging the score toward zero. If nothing was measurable,
  // the score is null — the report says so rather than inventing a number.
  const parts = [['onPage', onPage], ['agenticBrowsing', agenticBrowsing], ['contentSpecificity', contentSpecificity]]
    .filter(([, v]) => v !== null);
  const weightSum = parts.reduce((s, [k]) => s + ONPAGE_WEIGHTS[k], 0);
  const overall = weightSum > 0
    ? Math.round(parts.reduce((s, [k, v]) => s + v * ONPAGE_WEIGHTS[k], 0) / weightSum)
    : null;

  const blockers = section1Checks.filter(c => c.status === 'FAIL');
  const unverified = section1Checks.filter(c => c.status === 'INCONCLUSIVE');

  return {
    overall,
    scored: overall !== null,
    pagesAnalyzed,
    sections: { onPage, agenticBrowsing, contentSpecificity, crawlability },
    blockers: { count: blockers.length, items: blockers.map(c => ({ id: c.id, title: c.title })) },
    unverified: { count: unverified.length, items: unverified.map(c => ({ id: c.id, title: c.title })) },
    // Recorded so a re-audit can tell a genuine change from a rubric change. Bump on any edit
    // to SCORE_POINTS, ONPAGE_WEIGHTS, or which checks feed which section.
    rubricVersion: 3
  };
}

// Unverified items are separated from real findings and sorted last. They are not defects and
// must not be handed to a client as work to do — they are things the scan could not establish,
// each carrying a manual check instead. Mixing them in with confirmed problems is how a scanner
// limitation ends up on someone's remediation backlog.
// Findings carry the layer they belong to, read from the registry, so a check is described the
// same way wherever it appears in the report.
function layerTitle(checkId) {
  const entry = CHECKS[checkId];
  return entry && LAYERS[entry.layer] ? LAYERS[entry.layer].title : 'Other';
}

function buildPrioritizedFindings(section1Checks, pageDiscovery, section2Pages, section4Pages, section3) {
  const findings = [];
  const actionable = c => c.status === 'FAIL' || c.status === 'WARNING';

  section1Checks.filter(actionable).forEach(c => findings.push({ priority: 'blocker', section: layerTitle(c.id), title: c.title, detail: c.detail, howToFix: c.howToFix, status: c.status }));
  section2Pages.forEach(p => p.checks.filter(actionable).forEach(c => findings.push({ priority: 'on-page', section: layerTitle(c.id), page: p.url, title: c.title, detail: c.detail, howToFix: c.howToFix, status: c.status })));
  section4Pages.forEach(p => p.checks.filter(actionable).forEach(c => findings.push({ priority: 'agentic', section: layerTitle(c.id), page: p.url, title: c.title, detail: c.detail, howToFix: c.howToFix, status: c.status })));
  section3.perPage.forEach(p => p.checks.filter(actionable).forEach(c => findings.push({ priority: 'content', section: layerTitle(c.id), page: p.url, title: c.title, detail: c.detail, howToFix: c.howToFix, status: c.status })));
  if (actionable(section3.boilerplateCheck)) findings.push({ priority: 'content', section: layerTitle(section3.boilerplateCheck.id), title: section3.boilerplateCheck.title, detail: section3.boilerplateCheck.detail, howToFix: section3.boilerplateCheck.howToFix, status: section3.boilerplateCheck.status });
  pageDiscovery.categories.filter(actionable).forEach(c => findings.push({ priority: 'discovery', section: 'Key Page Discovery', title: c.title, detail: c.detail, howToFix: c.howToFix, status: c.status }));

  const unverified = [
    ...section1Checks.filter(c => c.status === 'INCONCLUSIVE').map(c => ({ priority: 'unverified', section: layerTitle(c.id), title: c.title, detail: c.detail, howToFix: c.howToFix, status: c.status })),
    ...pageDiscovery.categories.filter(c => c.status === 'INCONCLUSIVE').map(c => ({ priority: 'unverified', section: 'Needs manual verification', title: c.title, detail: c.detail, howToFix: c.howToFix, status: c.status }))
  ];

  const order = { blocker: 0, 'on-page': 1, agentic: 2, content: 3, discovery: 4, unverified: 5 };
  return [...findings, ...unverified].sort((a, b) => order[a.priority] - order[b.priority]);
}

// ── Entry point ──
// Runs the full scan pipeline and returns the result object, or throws on a genuinely invalid
// request (bad URL). Kept independent of any HTTP/Response wrapping so it can be driven by a
// background function (see run-scan-background.js) instead of a synchronous request/response
// cycle — this scan can legitimately take longer than a regular function's execution ceiling on
// a slow site, and a slow site is exactly the case this tool needs to diagnose, not crash on.

// Toggles the www prefix on a URL's hostname, leaving everything else intact.
function toggleWwwHost(href) {
  const u = new URL(href);
  u.hostname = u.hostname.startsWith('www.') ? u.hostname.slice(4) : 'www.' + u.hostname;
  return u;
}

export async function runScan({ url, extraPages, maxPages }) {
  let parsed = normalizeUrl(url);

  // ── Host resolution ──
  // A domain that answers on www but not on the bare apex (or the reverse) is extremely common,
  // and left unhandled it presents as a total scan failure for a site that is perfectly healthy —
  // whichever form the operator happened to type decides whether the scan works at all.
  //
  // Worse, failing there buries a genuine finding. If the apex does not resolve, every person who
  // types the bare domain reaches nothing, every link written to that form is dead, and the two
  // hostnames are not consolidated for search or AI engines. So: try the other form, scan
  // whichever one answers, and report the one that did not as a finding in its own right.
  let timingFetch = await fetchSafe(parsed.href, USER_AGENTS.browser.ua);
  let hostFallback = null;
  let contentUa = USER_AGENTS.browser.ua;
  let contentIdentity = USER_AGENTS.browser.label;
  let identityFallback = null;
  if (!timingFetch.ok && (timingFetch.errorKind === 'dns' || timingFetch.errorKind === 'refused')) {
    const alt = toggleWwwHost(parsed.href);
    const altFetch = await fetchSafe(alt.href, contentUa);
    if (altFetch.ok) {
      hostFallback = {
        requested: parsed.hostname,
        resolved: alt.hostname,
        requestedError: timingFetch.error,
        requestedErrorKind: timingFetch.errorKind
      };
      parsed = alt;
      timingFetch = altFetch;
    }
  }

  const origin = parsed.origin;
  const homepageUrl = parsed.href;

  const cleanExtraPages = Array.isArray(extraPages)
    ? extraPages.filter(Boolean).slice(0, 5).map(p => { try { return new URL(p, origin).href; } catch { return null; } }).filter(Boolean)
    : [];

  // ── Request pacing ──
  // Every fetch below flows through mapLimited at MAX_CONCURRENT_FETCHES. The previous version
  // issued eight requests as a single Promise.all burst, which on modest hosting is enough to
  // make the origin fail outright: measured against a real client site, seven concurrent
  // requests all timed out while the identical requests issued two-at-a-time each returned in
  // ~2s. The scan was manufacturing the outage it then reported. Phases run in sequence so the
  // ceiling holds across the whole pipeline, not just within one call.

  // Phase 1 — one isolated request. Times the homepage with nothing else contending, and its
  // response doubles as the crawl-test baseline and the HTML source for every on-page check, so
  // the homepage is fetched exactly once.
  // If the server will not answer a browser, ask as something it will. A 403 to a browser while
  // every crawler gets 200 is a real configuration — reporting such a site as unreadable says
  // nothing true about it, and is exactly the case that made this scanner look broken.
  // Kept before any fallback: this is how the server treats a browser, which is what the crawl
  // test compares every other identity against.
  const browserBaseline = timingFetch;

  if (!isOk2xx(timingFetch)) {
    for (const key of ['googlebot', 'gptbot', 'claudebot', 'oaisearchbot', 'perplexitybot', 'bare']) {
      const alt = await fetchSafe(parsed.href, USER_AGENTS[key].ua);
      if (!isOk2xx(alt)) continue;
      identityFallback = {
        refusedAs: USER_AGENTS.browser.label,
        refusedStatus: timingFetch.status,
        readAs: USER_AGENTS[key].label
      };
      contentUa = USER_AGENTS[key].ua;
      contentIdentity = USER_AGENTS[key].label;
      timingFetch = alt;
      break;
    }
  }

  const homepageFetch = timingFetch;

  // A second isolated timing sample, taken only when the first succeeded. checkResponseTime uses
  // the faster of the two so a single blip can't move the score between re-audits. Its body is
  // discarded — the first response remains the sole HTML source for every on-page check.
  const timingSamples = [timingFetch];
  if (timingFetch.ok) {
    await sleep(INTER_WAVE_DELAY_MS);
    timingSamples.push(await fetchSafe(homepageUrl, contentUa));
  }

  // Phase 2 — the remaining four user-agents (paced internally by checkMultiUA).
  const multiUA = await checkMultiUA(homepageUrl, browserBaseline);

  // Phase 3 — robots.txt first, on its own, because its Sitemap: declarations tell the sitemap
  // check where to look. Guessing paths before reading the declaration is exactly how a site with
  // a perfectly good sitemap at a non-default location gets reported as having none.
  const robotsResult = await checkRobots(origin, contentUa);
  const declaredSitemaps = (robotsResult.raw && robotsResult.raw.sitemapsDeclared) || [];

  // Phase 4 — sitemap (using those declarations) and llms.txt.
  const [sitemapResult, llmsResult] = await mapLimited(
    [() => checkSitemap(origin, declaredSitemaps, contentUa), () => checkLlmsTxt(origin, contentUa)],
    fn => fn()
  );

  // Phase 5 — any manually supplied extra pages.
  const extraPageFetches = await mapLimited(cleanExtraPages, async u => ({ url: u, ...(await fetchSafe(u, contentUa)) }));

  const section1Checks = [];
  let $home = null;

  if (homepageFetch.ok) {
    $home = cheerio.load(homepageFetch.text);
    const platform = detectPlatform($home, homepageFetch.headers, homepageFetch.text);
    const platformCheck = checkPlatform(platform);
    const edgeCheck = checkEdgeProtection(homepageFetch.headers, platform);
    section1Checks.push(
      multiUA.check,
      robotsResult,
      checkXRobotsTag(homepageFetch.headers),
      checkNoindexMeta($home),
      sitemapResult,
      checkResponseTime(timingFetch, timingSamples)
    );
    if (hostFallback) section1Checks.push(buildHostVariantCheck(hostFallback));
    if (platformCheck) section1Checks.push(platformCheck);
    if (edgeCheck) section1Checks.push(edgeCheck);
    if (llmsResult) section1Checks.push(llmsResult);
  } else {
    // The homepage never responded. This is reported as a scanner-reachability result, not as a
    // verdict about the site: a refused connection is most often edge bot protection rejecting
    // our cloud egress IP, and the site is typically serving real visitors normally throughout.
    // Checks that genuinely cannot be evaluated without HTML are omitted rather than guessed.
    if (hostFallback) section1Checks.push(buildHostVariantCheck(hostFallback));
    section1Checks.push(
      buildUnreachableCheck(multiUA.errorKinds || [homepageFetch.errorKind], multiUA.sampleError || homepageFetch.error),
      multiUA.check,
      robotsResult,
      sitemapResult,
      checkResponseTime(timingFetch, timingSamples)
    );
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
    discoveredFetches = await mapLimited(toFetch, async c => ({ url: c.url, ...(await fetchSafe(c.url, contentUa)) }));
    pageDiscovery = { title: 'Key Page Discovery', skipped: false, categories: buildPageDiscoveryReport(categories, alreadyCovered) };
  } else {
    // Homepage was unreachable — there's no nav/header/footer to parse, so discovery can't run.
    // Reported as unverified, not as missing pages: the pages may well exist. Previously these
    // came back as WARNINGs, which put "add an About page" on the client's to-do list for a site
    // whose navigation the scanner had simply never managed to load.
    pageDiscovery = {
      title: 'Key Page Discovery',
      skipped: true,
      categories: Object.entries(PAGE_DISCOVERY_PATTERNS).map(([id, cfg]) => ({
        id, title: t(`Página de ${cfg.labelEs || cfg.label}`, `${cfg.label} page`), status: 'INCONCLUSIVE', found: null, url: null,
        detail: t(
          `No se ha podido comprobar: la portada no ha cargado, así que nunca se analizaron sus enlaces de navegación. Esto no significa que falte la página de ${cfg.labelEs || cfg.label}.`,
          `Could not check — the homepage could not be loaded, so its navigation links were never parsed. This does not mean the ${cfg.label} page is missing.`
        ),
        howToFix: t('Repite el escaneo cuando el sitio web sea accesible desde el escáner.', 'Re-run once the site is reachable from the scanner.'), raw: {}
      }))
    };
  }

  // Sitemap sweep — runs after nav discovery so the pages our methodology treats as highest
  // impact (About, FAQ) are always included, then fills whatever budget remains from the
  // sitemap for a representative sample of the rest of the site.
  const pageBudget = Math.max(1, Math.min(Number(maxPages) || DEFAULT_MAX_PAGES, 50));
  let sitemapFetches = [];
  let sitemapSweep = { attempted: false, listed: 0, sampled: 0 };
  const sitemapSource = sitemapResult.raw && sitemapResult.raw.url;
  if ($home && sitemapSource && sitemapResult.status !== 'INCONCLUSIVE') {
    const covered = new Set([homepageUrl, ...cleanExtraPages, ...discoveredFetches.map(d => d.url)].map(normalizeUrlForCompare));
    const listed = await collectSitemapUrls(sitemapSource, origin, undefined, contentUa);
    const candidates = listed.filter(u => !covered.has(normalizeUrlForCompare(u)));
    const slots = Math.max(0, pageBudget - covered.size);
    const chosen = sampleEvenly(candidates, slots);
    sitemapSweep = { attempted: true, listed: listed.length, sampled: chosen.length };
    if (chosen.length) sitemapFetches = await mapLimited(chosen, async u => ({ url: u, ...(await fetchSafe(u, contentUa)) }));
  }

  // Section 2 + 3 + 4 source pages: homepage (if it loaded) + any extra pages that loaded +
  // any auto-discovered pages that loaded.
  const pageFetches = [
    { url: homepageUrl, html: homepageFetch.text, ok: homepageFetch.ok, status: homepageFetch.status },
    ...extraPageFetches.map(p => ({ url: p.url, html: p.text, ok: p.ok, status: p.status })),
    ...discoveredFetches.map(p => ({ url: p.url, html: p.text, ok: p.ok, status: p.status })),
    ...sitemapFetches.map(p => ({ url: p.url, html: p.text, ok: p.ok, status: p.status }))
  ];

  // A 429 or 404 body is not this site's content. Analysing one produces a page with no title,
  // no meta description, no structured data and a handful of words — every one of which then gets
  // reported as a fault of the site rather than of the scan.
  const isReadable = p => p.ok && p.html && p.status >= 200 && p.status < 300;
  const validPages = pageFetches.filter(isReadable);
  const skippedPages = pageFetches.filter(p => !isReadable(p)).map(p => ({ url: p.url, status: p.status }));

  const analyzedPages = validPages.map(p => analyzePage(p.url, p.html));
  const section3 = analyzeContentSpecificity(analyzedPages);

  const section2Pages = analyzedPages.map(p => ({ url: p.url, title: p.title, metaDescription: p.metaDescription, schemaTypes: p.schemaTypes, headingInfo: p.headingInfo, canonical: p.canonical, og: p.og, images: p.images, wordCount: p.wordCount, checks: p.checks }));
  const section4Pages = analyzedPages.map(p => ({ url: p.url, checks: p.agenticChecks }));

  // Every check the scan produced, regrouped by the question it answers rather than by the
  // internal section it happened to be computed in. This is the shape the report is built from.
  const s3ByUrl = new Map(section3.perPage.map(p => [p.url, p.checks]));
  const mergedPages = analyzedPages.map(p => ({
    url: p.url,
    checks: [...p.checks, ...p.agenticChecks, ...(s3ByUrl.get(p.url) || [])]
  }));
  const siteLevelChecks = [...section1Checks, section3.boilerplateCheck];

  const layers = buildLayers(siteLevelChecks, mergedPages);
  const unregisteredChecks = findUnregisteredChecks(siteLevelChecks, mergedPages);
  const score = computeScoreFromLayers(layers, section1Checks, analyzedPages.length);
  const prioritizedFindings = buildPrioritizedFindings(section1Checks, pageDiscovery, section2Pages, section4Pages, section3);

  return {
    scannedAt: new Date().toISOString(),
    input: { url: homepageUrl, extraPages: cleanExtraPages },
    // Top-level scan state, so the UI never has to infer "did this work?" from a low number.
    // reachable:false means the scanner could not load the site — there is no score to show and
    // nothing in the report should be read as a judgement about the site's quality.
    reachable: isOk2xx(homepageFetch),
    scanQuality: {
      pagesAnalyzed: analyzedPages.length,
      pagesAttempted: pageFetches.length,
      unverifiedChecks: section1Checks.filter(c => c.status === 'INCONCLUSIVE').length,
      unregisteredChecks,
      pageBudget,
      fetchedAs: contentIdentity,
      identityFallback,
      sitemapSweep,
      timeoutMs: FETCH_TIMEOUT_MS,
      maxConcurrency: MAX_CONCURRENT_FETCHES
    },
    skippedPages,
    score,
    // Layer view — the organising structure for the report.
    layers,
    section1: { title: 'Crawlability Layer', checks: section1Checks },
    pageDiscovery,
    section2: { title: 'On-Page GEO Signals', pages: section2Pages },
    section4: { title: 'Agentic Browsing / AI Agent Accessibility', pages: section4Pages },
    section3: { title: 'Content Specificity Signals', perPage: section3.perPage.map(p => ({ url: p.url, checks: p.checks })), boilerplate: section3.boilerplateCheck },
    prioritizedFindings
  };
}


/**
 * Analyse HTML that was captured by hand, for a site no server can fetch.
 *
 * Some sites refuse every request from a datacentre by IP range — Cloudflare bot management is
 * the usual case — so no user-agent fallback reaches them. A person can still open the page in
 * their own browser, and the on-page analysis needs nothing else: analyzePage() does no fetching.
 * Layers 2 and 3 run exactly as they do on a fetched page, which is every check that counts
 * toward the score.
 *
 * What this cannot do is Layer 1. Whether robots.txt admits GPTBot, whether the host rate-limits,
 * whether a CDN refuses crawlers by IP — none of that is in the HTML, and none of it is guessed
 * at here. It is reported as unverified, which is what that layer already does for such sites.
 * A score from this path is therefore an on-page score, and the report says so.
 */
export function runScanFromHtml({ url, pages }) {
  const supplied = (pages || [])
    .map(p => ({ url: (p && p.url) || url, html: p && p.html }))
    .filter(p => p.html && String(p.html).trim().length > 0);
  if (!supplied.length) throw new Error('No se recibió HTML que analizar.');

  const homepageUrl = supplied[0].url || url;
  const analyzedPages = supplied.map(p => analyzePage(p.url, p.html));
  const section3 = analyzeContentSpecificity(analyzedPages);

  const section2Pages = analyzedPages.map(p => ({ url: p.url, title: p.title, metaDescription: p.metaDescription, schemaTypes: p.schemaTypes, headingInfo: p.headingInfo, canonical: p.canonical, og: p.og, images: p.images, wordCount: p.wordCount, checks: p.checks }));
  const section4Pages = analyzedPages.map(p => ({ url: p.url, checks: p.agenticChecks }));

  const s3ByUrl = new Map(section3.perPage.map(p => [p.url, p.checks]));
  const mergedPages = analyzedPages.map(p => ({
    url: p.url,
    checks: [...p.checks, ...p.agenticChecks, ...(s3ByUrl.get(p.url) || [])]
  }));

  // Nothing about crawlability can be established from a saved page, so Layer 1 carries no checks
  // rather than inventing passes. It is not scored in any case.
  const section1Checks = [];
  const siteLevelChecks = [...section1Checks, section3.boilerplateCheck];

  // The navigation was never followed, so a missing About page cannot be distinguished from one
  // that simply was not pasted in. Reported as unverified, never as missing.
  const pageDiscovery = {
    title: 'Key Page Discovery',
    skipped: true,
    categories: Object.entries(PAGE_DISCOVERY_PATTERNS).map(([id, cfg]) => ({
      id, title: t(`Página de ${cfg.labelEs || cfg.label}`, `${cfg.label} page`), status: 'INCONCLUSIVE', found: null, url: null,
      detail: t(
        `No se ha podido comprobar: el análisis se hizo sobre HTML pegado a mano, así que no se siguieron los enlaces de navegación. Esto no significa que falte la página de ${cfg.labelEs || cfg.label}.`,
        `Could not check — this analysis ran on hand-supplied HTML, so navigation links were never followed. This does not mean the ${cfg.label} page is missing.`
      ),
      howToFix: undefined
    }))
  };

  const layers = buildLayers(siteLevelChecks, mergedPages);
  const unregisteredChecks = findUnregisteredChecks(siteLevelChecks, mergedPages);
  const score = computeScoreFromLayers(layers, section1Checks, analyzedPages.length);
  const prioritizedFindings = buildPrioritizedFindings(section1Checks, pageDiscovery, section2Pages, section4Pages, section3);

  return {
    scannedAt: new Date().toISOString(),
    input: { url: homepageUrl, extraPages: supplied.slice(1).map(p => p.url) },
    reachable: true,
    scanQuality: {
      // The one field that tells every reader this was not a live fetch.
      source: 'supplied-html',
      pagesAnalyzed: analyzedPages.length,
      pagesAttempted: analyzedPages.length,
      unverifiedChecks: pageDiscovery.categories.length,
      unregisteredChecks,
      pageBudget: analyzedPages.length,
      fetchedAs: null,
      identityFallback: null,
      sitemapSweep: { attempted: false, listed: 0, sampled: 0 },
      timeoutMs: null,
      maxConcurrency: null
    },
    skippedPages: [],
    score,
    layers,
    section1: { title: 'Crawlability Layer', checks: section1Checks },
    pageDiscovery,
    section2: { title: 'On-Page GEO Signals', pages: section2Pages },
    section4: { title: 'Agentic Browsing / AI Agent Accessibility', pages: section4Pages },
    section3: { title: 'Content Specificity Signals', perPage: section3.perPage.map(p => ({ url: p.url, checks: p.checks })), boilerplate: section3.boilerplateCheck },
    prioritizedFindings
  };
}
