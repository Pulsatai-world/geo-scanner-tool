import { t } from './i18n.js';

// ── The check registry ──
//
// Single source of truth for what this scanner tests, how each verdict is decided, and why the
// factor matters for generative-engine citation.
//
// Both the scanner and the published methodology checklist read from this file. That is the whole
// point: a checklist maintained by hand is accurate the day it is written and wrong a month later,
// and the gap between what a tool claims to check and what it actually checks is exactly where
// credibility is lost with a client.
//
// Every entry states an explicit rule. GEO is a machine reading a machine, so a verdict should be
// reproducible by anyone holding the same page — "the content should be substantial" is an
// opinion, "under 300 words fails" is a measurement. Where a factor genuinely cannot be settled
// remotely it is marked unverifiable rather than guessed at.

export const LAYERS = {
  access: {
    id: 'access',
    order: 1,
    title: t('Capa 1 — Acceso', 'Layer 1 — Access'),
    question: t('¿Pueden los sistemas de IA acceder al sitio web?', 'Can AI systems reach this site at all?'),
    summary: t(
      'Si los rastreadores y los bots de recuperación pueden descargar el sitio web web, y si algo los bloquea, los redirige o les limita la frecuencia. Si esto falla, nada de lo que viene después importa.',
      'Whether crawlers and retrieval bots can fetch the site, and whether anything blocks, redirects or rate-limits them. Nothing downstream matters if this fails.'
    ),
    owner: t(
      'Hosting, DNS y CDN: normalmente el proveedor de alojamiento o la plataforma, no el equipo web.',
      'Hosting, DNS and CDN — usually the host or platform, not the web team.'
    ),
    scored: false,
    scoringNote: t(
      'Se informa como bloqueos, no se integra en la puntuación. Queda en gran medida fuera del control del propietario, es lo menos fiable de medir en remoto, y dejar que mueva la cifra significaría que el ruido de infraestructura se hace pasar por avance de contenido.',
      'Reported as blockers rather than folded into the score. It is largely outside the site owner\'s control, it is the least reliable thing to measure remotely, and letting it move the score would mean infrastructure noise masquerading as content progress.'
    )
  },
  readability: {
    id: 'readability',
    order: 2,
    title: t('Capa 2 — Legibilidad por máquina', 'Layer 2 — Machine readability'),
    question: t('¿Puede una máquina interpretar la página y entender su estructura?', 'Can a machine parse the page and understand its structure?'),
    summary: t(
      'Si el contenido existe en el HTML sin necesidad de JavaScript, y si los títulos, los metadatos, los datos estructurados, los encabezados y las regiones lo describen en un formato que una máquina pueda interpretar.',
      'Whether the content exists in the HTML without JavaScript, and whether titles, metadata, structured data, headings and landmarks describe it in a form a machine can interpret.'
    ),
    owner: t('Desarrollo o el propio CMS.', 'Developer or CMS.'),
    scored: true
  },
  substance: {
    id: 'substance',
    order: 3,
    title: t('Capa 3 — Contenido y autoridad', 'Layer 3 — Substance & authority'),
    question: t('¿Hay aquí algo que merezca ser citado, y alguna razón para confiar en ello?', 'Is there anything here worth citing, and any reason to trust it?'),
    summary: t(
      'Si la página tiene contenido suficientemente concreto y bien delimitado como para ser citada, y si demuestra que detrás hay una organización real y responsable. Una página puede superar todas las revisiones técnicas y aun así no citarse nunca, sencillamente porque no hay nada que citar.',
      'Whether the page carries enough specific, well-scoped content to be quoted, and whether it demonstrates a real, accountable organisation behind it. A page can pass every technical check and still never be cited because there is nothing in it to quote.'
    ),
    owner: t('Contenido y marketing.', 'Content and marketing.'),
    scored: true
  }
};

// scored: false marks a check that reports context or an unverifiable condition and is excluded
// from the arithmetic entirely — never credited, never penalised.
export const CHECKS = {
  // ── Layer 1: Access ────────────────────────────────────────────────────────
  'site-reachability': {
    layer: 'access', scored: false,
    title: 'Site reachability from the scanner',
    measures: 'Whether any request to the origin completes, and the transport-level reason when none do.',
    rule: 'Reported as UNVERIFIED whenever every user-agent fails at the connection layer. Never a failure of the site: a refused connection is most often edge protection rejecting the scanner\'s network, and the site typically serves real visitors normally throughout.',
    why: 'Distinguishes "we could not measure this" from "this site is broken". Scoring an unreachable site would publish our network conditions as a verdict about the client.'
  },
  'host-variant': {
    layer: 'access', scored: true,
    title: 'www / non-www resolution',
    measures: 'Whether both the apex domain and the www hostname resolve and serve the site.',
    rule: 'FAIL when one form resolves and the other does not. The scan continues against whichever answers.',
    why: 'Anyone typing or linking the missing form reaches nothing, and engines see two hostnames rather than one consolidated site.'
  },
  'multi-ua': {
    layer: 'access', scored: true,
    title: 'Multi-user-agent crawl test',
    measures: 'The homepage fetched with seven user-agents: a browser, GPTBot, ClaudeBot, Googlebot, OAI-SearchBot, PerplexityBot and a plain default.',
    rule: 'FAIL only when the server returns an explicit refusal (401, 402, 403, 405, 451) to a bot while the browser request succeeds. Rate limiting (429) and dropped connections WARN instead — they are transient, and scanning can cause them.',
    why: 'Catches user-agent-based bot blocking at the host. Requires a deliberate refusal status: a timeout is evidence of an unreliable connection, not of a policy.'
  },
  'robots-txt': {
    layer: 'access', scored: true,
    title: 'robots.txt AI crawler rules',
    measures: '18 crawler tokens evaluated against robots.txt, split into live retrieval, model training and search indexing.',
    rule: 'FAIL if any retrieval or search crawler is blocked (OAI-SearchBot, ChatGPT-User, Claude-User, Claude-SearchBot, PerplexityBot, Perplexity-User, Google-Extended, Googlebot, Bingbot, *). WARNING if only training crawlers are blocked (GPTBot, ClaudeBot, CCBot, Applebot-Extended and similar).',
    why: 'Blocking retrieval means the site cannot be cited in answers at all. Blocking training is a legitimate licensing choice with a slower cost, so it is named rather than treated as a defect. Google-Extended is singled out because the one-click AI toggle in Yoast and RankMath sets it, removing sites from Gemini without their owners knowing.'
  },
  'x-robots-tag': {
    layer: 'access', scored: true,
    title: 'X-Robots-Tag header',
    measures: 'The X-Robots-Tag HTTP response header.',
    rule: 'FAIL if it contains noindex or none. WARNING if present without those directives.',
    why: 'A server-level indexing block set in .htaccess, nginx config or a plugin — invisible in the page source, and easily missed by hand.'
  },
  'noindex-meta': {
    layer: 'access', scored: true,
    title: 'Meta robots noindex tag',
    measures: 'meta name="robots" and meta name="googlebot" in the document head.',
    rule: 'FAIL if either contains noindex.',
    why: 'Commonly left on after a staging launch, or by the WordPress "discourage search engines" setting.'
  },
  'sitemap': {
    layer: 'access', scored: true,
    title: 'XML sitemap',
    measures: 'Sitemap declarations in robots.txt, then five common paths: /sitemap.xml, /sitemap_index.xml, /wp-sitemap.xml, /sitemap-index.xml, /sitemap1.xml.',
    rule: 'PASS on a valid sitemap with 3 or more URLs. WARNING if none is found, or fewer than 3 URLs are listed. FAIL if a sitemap exists but is empty or malformed.',
    why: 'Speeds discovery for every crawler. Checking declarations first avoids reporting a correctly configured site as having no sitemap.'
  },
  'response-time': {
    layer: 'access', scored: true,
    title: 'Response time',
    measures: 'The fastest of two isolated homepage requests, each issued with nothing else contending for the origin.',
    rule: 'WARNING above 2500ms. Never a FAIL — a timing sample should not be able to gate anything. UNVERIFIED if no request completed.',
    why: 'Slow origins get abandoned by crawlers. Two isolated samples rather than one keeps the figure stable enough to compare across re-audits.'
  },
  'edge-protection': {
    layer: 'access', scored: false,
    title: 'Edge bot protection (CDN/WAF)',
    measures: 'CDN and WAF fingerprints in response headers — Cloudflare, Sucuri, Akamai, Fastly, Imperva.',
    rule: 'Always UNVERIFIED when a provider is detected. Edge services identify verified bots by source IP range, not user-agent string, so user-agent testing cannot settle whether AI crawlers are permitted — it passes regardless.',
    why: 'The scanner\'s clearest blind spot, reported as such rather than hidden behind a pass. Carries the exact manual check, and names the hosting platform when the CDN belongs to the platform rather than the client.'
  },
  'hosting-platform': {
    layer: 'access', scored: false,
    title: 'Hosting platform',
    measures: 'Platform fingerprints in the page and headers — Lovable, Wix, Squarespace, Framer, Webflow, Shopify, self-hosted WordPress.',
    rule: 'Informational. Never a pass or a failure.',
    why: 'Decides who can fix what. On a managed platform the CDN belongs to the host, so advice to change bot settings sends the client looking for a dashboard they do not have.'
  },
  'llms-txt': {
    layer: 'access', scored: false,
    title: 'llms.txt',
    measures: 'Presence of /llms.txt.',
    rule: 'Presence only. Its absence is never counted against a site.',
    why: 'An emerging convention that no major engine has committed to honouring. Reported as an early-mover signal, not a requirement.'
  },

  // ── Layer 2: Machine readability ───────────────────────────────────────────
  'js-rendering': {
    layer: 'readability', scored: true,
    title: 'Content visible without JavaScript',
    measures: 'Readable words in the server response, script count, and whether a framework mount point arrived empty.',
    rule: 'FAIL if the server returns under 60 words alongside scripts, or a mount point (#root, #__next, #app) contains under 30 words.',
    why: 'Most AI crawlers do not execute JavaScript. If this fails, every other on-page result for the page is unreliable — the checks are reading an empty shell, not the real page.'
  },
  'title': {
    layer: 'readability', scored: true,
    title: 'Title tag',
    measures: 'Presence and length of the title element.',
    rule: 'FAIL if missing. WARNING above 60 characters.',
    why: 'The strongest single statement of what a page is about, used by both search and AI surfaces.'
  },
  'meta-description': {
    layer: 'readability', scored: true,
    title: 'Meta description',
    measures: 'Presence and length of the meta description.',
    rule: 'FAIL if missing. WARNING above 160 characters.',
    why: 'Frequently lifted verbatim as the summary shown alongside a citation.'
  },
  'schema': {
    layer: 'readability', scored: true,
    title: 'Schema.org / JSON-LD',
    measures: 'JSON-LD blocks parsed for @type, compared against eight common types.',
    rule: 'FAIL if no structured data is present. WARNING if more than four common types are absent.',
    why: 'The most direct way to state machine-readable facts about an entity. Among the highest-leverage signals available for citation.'
  },
  'headings': {
    layer: 'readability', scored: true,
    title: 'Heading structure',
    measures: 'Count of h1 elements and whether heading levels are skipped.',
    rule: 'PASS with exactly one h1 and no skipped levels. FAIL with no h1. WARNING otherwise.',
    why: 'Headings are how a machine segments a page into passages it can retrieve individually.'
  },
  'heading-hierarchy': {
    layer: 'readability', scored: true,
    title: 'Sequential heading hierarchy',
    measures: 'Whether heading levels descend without gaps.',
    rule: 'WARNING when a level is skipped (h1 straight to h3).',
    why: 'A broken hierarchy produces a misleading document outline, blurring where one topic ends and the next begins.'
  },
  'canonical': {
    layer: 'readability', scored: true,
    title: 'Canonical tag',
    measures: 'link rel="canonical" and whether it is self-referencing or cross-domain.',
    rule: 'FAIL if it points to another domain. WARNING if absent.',
    why: 'A canonical left pointing at staging after a migration can suppress the live page entirely.'
  },
  'open-graph': {
    layer: 'readability', scored: true,
    title: 'Open Graph tags',
    measures: 'og:title, og:description and og:type.',
    rule: 'FAIL if all three are missing. WARNING if some are.',
    why: 'Controls how the page is represented when shared or previewed, including by tools that fetch preview metadata.'
  },
  'image-alt': {
    layer: 'readability', scored: true,
    title: 'Image alt text coverage',
    measures: 'Proportion of img elements carrying non-empty alt text.',
    rule: 'PASS at 80% or above. WARNING from 40%. FAIL below 40%.',
    why: 'Alt text is the only description of an image a non-visual system receives.'
  },
  'main-landmark': {
    layer: 'readability', scored: true,
    title: 'Main landmark presence',
    measures: 'A main element or role="main".',
    rule: 'FAIL if absent.',
    why: 'Tells an agent which part of the document is the content, as distinct from navigation and chrome.'
  },
  'form-labels': {
    layer: 'readability', scored: true,
    title: 'Form input labels',
    measures: 'Whether form inputs have associated labels or accessible names.',
    rule: 'WARNING when inputs lack them.',
    why: 'An AI agent completing a form on a user\'s behalf can only identify a field by its accessible name.'
  },
  'a11y-tree-health': {
    layer: 'readability', scored: true,
    title: 'Accessibility tree health',
    measures: 'Composite of the landmark, heading hierarchy, form label and image alt results.',
    rule: 'Derived from its component checks.',
    why: 'The accessibility tree is broadly what an agentic browser navigates by, so its health predicts how well an agent can operate the page.'
  },
  'contact-machine-readable': {
    layer: 'readability', scored: true,
    title: 'Contact info machine-readability',
    measures: 'tel: and mailto: links, and ContactPoint schema. Only applied when the page shows contact details at all.',
    rule: 'WARNING when contact details appear as plain text only.',
    why: 'Lets an agent act on the details rather than merely read them.'
  },
  'schema-completeness': {
    layer: 'readability', scored: true,
    title: 'Structured data completeness',
    measures: 'Every property actually present on each recognised schema.org type, checked against that type’s required and recommended properties.',
    rule: 'FAIL when a type is missing a required property (Organization without name or url, LocalBusiness without an address). WARNING when most recommended properties are absent. Only recognised types are assessed.',
    why: 'Presence alone proves nothing. A block carrying only @type and a name gives an engine no way to tie the markup to a real entity, yet it passes a presence check exactly as a complete one does.'
  },
  'faq-schema-match': {
    layer: 'readability', scored: true,
    title: 'FAQ schema vs visible content',
    measures: 'FAQPage schema questions matched against text visible on the page. Only applied where FAQ schema exists.',
    rule: 'PASS when 70% or more of schema questions appear in the visible content.',
    why: 'Structured data that does not reflect the page can be treated as manipulative.'
  },

  // ── Layer 3: Substance & authority ─────────────────────────────────────────
  'content-depth': {
    layer: 'substance', scored: true,
    title: 'Content depth for citation',
    measures: 'Words of main content, with navigation, header and footer removed.',
    rule: 'FAIL under 300 words. WARNING under 600. PASS at 600 or above; 1200 or above is recorded as substantial.',
    why: 'Below roughly 300 words there is not enough for an engine to extract a useful passage. A page can be crawled perfectly and never be quoted because there is nothing in it worth quoting.'
  },
  'page-scope': {
    layer: 'substance', scored: true,
    title: 'Page scope — should this be split?',
    measures: 'Content split at h2 boundaries and measured per section, plus whether navigation is built entirely from in-page anchors.',
    rule: 'FAIL when navigation is anchor-only across 3 or more topics — a single-page site. WARNING at 4 or more sections averaging under 120 words.',
    why: 'Engines retrieve and cite at page level. Topics sharing one document cannot be returned for queries about them individually, however good the writing.'
  },
  'authority-signals': {
    layer: 'substance', scored: true,
    title: 'Authority & credibility signals',
    measures: 'Six signals, detected bilingually (English and Spanish): named people, client evidence, credentials, physical address, direct contact links, external profile links including sameAs.',
    rule: 'PASS at 5 of 6 or more. WARNING at 3 or 4. FAIL at 2 or fewer.',
    why: 'Engines favour sources visibly belonging to a real, accountable organisation. Without these a site reads as anonymous marketing copy however well it is built.'
  },
  'answer-format': {
    layer: 'substance', scored: true,
    title: 'Answer-shaped content',
    measures: 'Question-form headings (English and Spanish), list items, tables and definition lists.',
    rule: 'PASS with 2 or more question-form headings, or a structure score of 12 or more (lists count 1, tables 5, definition lists 3).',
    why: 'Retrieval matches a question to a passage that answers it. Q&A sections, lists and comparison tables are markedly easier to lift an answer from than continuous prose.'
  },
  'entities': {
    layer: 'substance', scored: true,
    title: 'Named entity / specificity signal',
    measures: 'Proper-noun phrases, numbers and year references in the main content.',
    rule: 'WARNING when fewer than 3 proper nouns and fewer than 3 numbers are present.',
    why: 'Specific, checkable facts are what gets quoted. Generic marketing language offers nothing to cite.'
  },
  'first-250-specificity': {
    layer: 'substance', scored: true,
    title: 'First-250-words specificity',
    measures: 'The same entity heuristic applied to the opening 250 words only.',
    rule: 'PASS with 3 or more proper nouns, or 3 or more numbers, in the opening.',
    why: 'Extraction weights the beginning of a page more heavily than material further down.'
  },
  'author-attribution': {
    layer: 'substance', scored: true,
    title: 'Author / credential attribution',
    measures: 'Bylines, rel="author" links, and Person schema tied to authorship.',
    rule: 'WARNING when none is found.',
    why: 'Named, credentialed sources are weighted more heavily than unattributed corporate copy.'
  },
  'content-freshness': {
    layer: 'substance', scored: true,
    title: 'Freshness signals',
    measures: 'dateModified, datePublished and uploadDate in structured data, <time datetime> elements, and article date metadata.',
    rule: 'WARNING when no machine-readable date exists at all, or when the most recent is over a year old. PASS within a year.',
    why: 'Engines weight recency. A page carrying no readable date cannot be assessed for it, which is itself a disadvantage against a competitor whose page is visibly current.'
  },
  'boilerplate': {
    layer: 'substance', scored: true,
    title: 'Boilerplate / templated content',
    measures: 'Pairwise five-word shingle similarity between analysed pages.',
    rule: 'WARNING above 60% similarity between any pair. UNVERIFIED with fewer than two pages, since there is nothing to compare.',
    why: 'Near-identical pages compete with each other and signal low-value templating.'
  }
};

// Groups the registry by layer, in display order.
export function checksByLayer() {
  return Object.values(LAYERS)
    .sort((a, b) => a.order - b.order)
    .map(layer => ({
      ...layer,
      checks: Object.entries(CHECKS)
        .filter(([, c]) => c.layer === layer.id)
        .map(([id, c]) => ({ id, ...c }))
    }));
}

export function layerOf(checkId) {
  return CHECKS[checkId] ? CHECKS[checkId].layer : null;
}
