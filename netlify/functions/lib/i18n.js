// ── Bilingual output ──
//
// Spanish is the default and is written natively, not translated from the English. The two
// versions of a string say the same thing to their own reader rather than tracking each other
// word for word — a literal translation of an English SEO sentence reads as foreign to a Spanish
// client, and these reports go in front of clients.
//
// Every user-facing string passes through t(es, en), which returns both. Renderers resolve with
// pick(), so the engine computes a scan once and either language can be shown from the same
// result — a report can be produced in both without rescanning, and switching language in the UI
// never triggers new requests to a client's server.
//
// pick() passes plain strings through unchanged, so a string that has not been converted yet
// still renders rather than showing "[object Object]".

export const LOCALES = ['es', 'en'];
export const DEFAULT_LOCALE = 'es';

export function t(es, en) {
  return { es, en };
}

export function pick(value, lang = DEFAULT_LOCALE) {
  if (value == null) return value;
  if (typeof value === 'string') return value;
  if (typeof value === 'object' && (typeof value.es === 'string' || typeof value.en === 'string')) {
    return value[lang] ?? value[DEFAULT_LOCALE] ?? value.en ?? '';
  }
  return value;
}

// Resolves every bilingual field in a scan result for one language, leaving everything else
// untouched. Used by the renderers rather than by the engine, so the stored result keeps both
// languages and can be re-rendered either way later.
const BILINGUAL_FIELDS = new Set(['detail', 'howToFix', 'title', 'question', 'summary', 'owner', 'scoringNote', 'measures', 'rule', 'why', 'section']);

export function localize(node, lang = DEFAULT_LOCALE) {
  if (Array.isArray(node)) return node.map(n => localize(n, lang));
  if (node && typeof node === 'object') {
    // A bilingual leaf resolves to its string rather than being walked into.
    if (typeof node.es === 'string' || typeof node.en === 'string') return pick(node, lang);
    const out = {};
    for (const [k, v] of Object.entries(node)) {
      out[k] = BILINGUAL_FIELDS.has(k) ? pick(v, lang) : localize(v, lang);
    }
    return out;
  }
  return node;
}

// Shared UI chrome, kept beside the check text so both live in one place.
export const UI = {
  scoreTitle: t('Calificación técnica GEO', 'GEO Technical Readiness Score'),
  scoreOf: t('/ 100', '/ 100'),
  strong: t('Buen nivel técnico GEO', 'Strong on-page GEO readiness'),
  emerging: t('Nivel técnico GEO en desarrollo', 'Emerging on-page GEO readiness'),
  low: t('Nivel técnico GEO bajo', 'Low on-page GEO readiness'),
  notScored: t('no puntúa', 'not in score'),
  countsToward: t('cuenta para la calificación', 'counts toward score'),
  whoFixes: t('Quién puede resolverlo', 'Who fixes this'),
  findingsTitle: t('Hallazgos priorizados', 'Prioritized findings'),
  findingsCaption: t(
    'Todo lo que requiere acción, de mayor a menor gravedad. Más abajo aparece agrupado por capa, junto con quién puede resolver cada punto.',
    'Everything needing action, most severe first. Grouped by layer below, alongside who is able to fix each one.'
  ),
  howToFix: t('Cómo resolverlo', 'How to fix'),
  needsVerification: t('Requiere verificación manual', 'Needs manual verification'),
  needsVerificationNote: t(
    'El escáner no ha podido determinar estos puntos. Son cuestiones abiertas que debemos revisar a mano, no problemas confirmados en el sitio web.',
    'The scanner could not establish these. They are open questions for us to check, not problems confirmed on the site.'
  ),
  notClientFindings: t('no son hallazgos para el cliente', 'not client-facing findings'),
  noIssues: t('Sin problemas: todas las revisiones evaluables han pasado.', 'No issues found — every check that could be evaluated passed.'),
  unreachableTitle: t('Escaneo incompleto', 'Scan incomplete'),
  unreachableHead: t('Sin calificación: el escáner no ha podido acceder al sitio web', 'No score — site not reachable from the scanner'),
  unreachableNote: t(
    'El escáner no ha podido cargar el sitio web, así que no hay nada que calificar. Esto <b>no</b> es un hallazgo sobre el sitio web, que puede estar atendiendo visitas con normalidad. Consulta «Requiere verificación manual» más abajo.',
    'The scanner could not load this site, so there is nothing to score. This is <b>not</b> a finding about the site, which may be serving visitors normally. See "Needs manual verification" below for what was determined.'
  ),
  scoreNote: t(
    'Media de las dos capas que califican, sobre {n} página(s). Dentro de cada capa todas las revisiones pesan igual. El Acceso se informa aparte porque depende del hosting y del CDN: incluirlo dejaría que el ruido de infraestructura moviera una cifra que debe reflejar el trabajo realizado.',
    'Mean of the two scored layers, across {n} page(s). Every check counts equally within its layer. Access is reported separately because it is hosting and CDN territory, and folding it in would let infrastructure noise move a number meant to track the work.'
  ),
  blockersTag: t('{n} bloqueo(s) de rastreo — se listan aparte, no puntúan', '{n} crawlability blocker(s) — listed separately, not scored'),
  unverifiedTag: t('{n} revisión(es) requieren verificación manual', '{n} check(s) need manual verification'),
  toImprove: t('{n} por mejorar', '{n} to improve'),
  passing: t('{n} cumplen', '{n} passing'),
  failing: t('{n} no cumplen', '{n} failing'),
  unverifiedChip: t('{n} sin verificar', '{n} unverified'),
  infoChip: t('{n} informativas', '{n} info'),
  check: t('Revisión', 'Check'),
  status: t('Estado', 'Status'),
  detail: t('Detalle', 'Detail'),
  details: t('Detalles', 'Details'),
  STATUS: {
    PASS: t('CUMPLE', 'PASS'),
    WARNING: t('ATENCIÓN', 'WARNING'),
    FAIL: t('NO CUMPLE', 'FAIL'),
    INCONCLUSIVE: t('SIN VERIFICAR', 'UNVERIFIED'),
    INFO: t('INFO', 'INFO')
  }
};

export function fill(str, vars = {}) {
  return String(str).replace(/\{(\w+)\}/g, (_, k) => (vars[k] ?? `{${k}}`));
}
