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
      'Si los rastreadores y los bots de recuperación pueden descargar el sitio web, y si algo los bloquea, los redirige o les limita la frecuencia. Si esto falla, nada de lo que viene después importa.',
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
    title: t('Accesibilidad del sitio web desde el escáner', 'Site reachability from the scanner'),
    measures: t('Si alguna petición al servidor llega a completarse, y el motivo técnico cuando ninguna lo logra.', 'Whether any request to the origin completes, and the transport-level reason when none do.'),
    rule: t('Se marca como SIN VERIFICAR cuando todos los user-agents fallan a nivel de conexión. Nunca es una falla del sitio web: una conexión rechazada casi siempre es la protección de red bloqueando la IP del escáner, mientras el sitio web atiende visitas con toda normalidad.', 'Reported as UNVERIFIED whenever every user-agent fails at the connection layer. Never a failure of the site: a refused connection is most often edge protection rejecting the scanner\'s network, and the site typically serves real visitors normally throughout.'),
    why: t('Distingue «no lo pudimos medir» de «el sitio web está roto». Calificar un sitio web inaccesible convertiría un problema de nuestra red en un veredicto sobre el cliente.', 'Distinguishes "we could not measure this" from "this site is broken". Scoring an unreachable site would publish our network conditions as a verdict about the client.')
  },
  'host-variant': {
    layer: 'access', scored: true,
    title: t('Resolución con y sin www', 'www / non-www resolution'),
    measures: t('Si tanto el dominio sin www como el que lo lleva resuelven y sirven el sitio web.', 'Whether both the apex domain and the www hostname resolve and serve the site.'),
    rule: t('NO CUMPLE cuando una forma resuelve y la otra no. El análisis continúa con la que sí responde.', 'FAIL when one form resolves and the other does not. The scan continues against whichever answers.'),
    why: t('Quien escriba o enlace la forma que falta no llega a ningún lado, y los motores ven dos nombres de dominio en lugar de un solo sitio web consolidado.', 'Anyone typing or linking the missing form reaches nothing, and engines see two hostnames rather than one consolidated site.')
  },
  'multi-ua': {
    layer: 'access', scored: true,
    title: t('Prueba de rastreo con varios user-agents', 'Multi-user-agent crawl test'),
    measures: t('La portada solicitada con siete user-agents: un navegador, GPTBot, ClaudeBot, Googlebot, OAI-SearchBot, PerplexityBot y uno genérico.', 'The homepage fetched with seven user-agents: a browser, GPTBot, ClaudeBot, Googlebot, OAI-SearchBot, PerplexityBot and a plain default.'),
    rule: t('NO CUMPLE únicamente cuando el servidor responde con un rechazo explícito (401, 402, 403, 405, 451) a un bot mientras la petición del navegador sí funciona. El límite de peticiones (429) y las conexiones cortadas dan ATENCIÓN: son pasajeros, y el propio análisis puede provocarlos.', 'FAIL only when the server returns an explicit refusal (401, 402, 403, 405, 451) to a bot while the browser request succeeds. Rate limiting (429) and dropped connections WARN instead — they are transient, and scanning can cause them.'),
    why: t('Detecta bloqueos por user-agent en el hosting. Exige un rechazo deliberado: un tiempo de espera agotado indica una conexión inestable, no una política.', 'Catches user-agent-based bot blocking at the host. Requires a deliberate refusal status: a timeout is evidence of an unreliable connection, not of a policy.')
  },
  'robots-txt': {
    layer: 'access', scored: true,
    title: t('Reglas de robots.txt para rastreadores de IA', 'robots.txt AI crawler rules'),
    measures: t('18 identificadores de rastreadores evaluados contra robots.txt, separados en recuperación en vivo, entrenamiento de modelos e indexación de búsqueda.', '18 crawler tokens evaluated against robots.txt, split into live retrieval, model training and search indexing.'),
    rule: t('NO CUMPLE si se bloquea cualquier rastreador de recuperación o de búsqueda (OAI-SearchBot, ChatGPT-User, Claude-User, Claude-SearchBot, PerplexityBot, Perplexity-User, Google-Extended, Googlebot, Bingbot, *). ATENCIÓN si solo se bloquean los de entrenamiento (GPTBot, ClaudeBot, CCBot, Applebot-Extended y similares).', 'FAIL if any retrieval or search crawler is blocked (OAI-SearchBot, ChatGPT-User, Claude-User, Claude-SearchBot, PerplexityBot, Perplexity-User, Google-Extended, Googlebot, Bingbot, *). WARNING if only training crawlers are blocked (GPTBot, ClaudeBot, CCBot, Applebot-Extended and similar).'),
    why: t('Bloquear la recuperación significa que el sitio web no puede citarse en ninguna respuesta. Bloquear el entrenamiento es una decisión legítima de licencia con un costo más lento, así que se señala en lugar de tratarse como falla. Google-Extended se destaca aparte porque la casilla de «bloquear IA» de Yoast y RankMath lo activa, dejando sitios web fuera de Gemini sin que sus dueños lo sepan.', 'Blocking retrieval means the site cannot be cited in answers at all. Blocking training is a legitimate licensing choice with a slower cost, so it is named rather than treated as a defect. Google-Extended is singled out because the one-click AI toggle in Yoast and RankMath sets it, removing sites from Gemini without their owners knowing.')
  },
  'x-robots-tag': {
    layer: 'access', scored: true,
    title: t('Encabezado X-Robots-Tag', 'X-Robots-Tag header'),
    measures: t('El encabezado de respuesta HTTP X-Robots-Tag.', 'The X-Robots-Tag HTTP response header.'),
    rule: t('NO CUMPLE si contiene noindex o none. ATENCIÓN si está presente sin esas directivas.', 'FAIL if it contains noindex or none. WARNING if present without those directives.'),
    why: t('Un bloqueo de indexación a nivel de servidor, puesto en .htaccess, en la configuración de nginx o por un plugin. No se ve en el código de la página y es fácil pasarlo por alto revisando a mano.', 'A server-level indexing block set in .htaccess, nginx config or a plugin — invisible in the page source, and easily missed by hand.')
  },
  'noindex-meta': {
    layer: 'access', scored: true,
    title: t('Meta etiqueta robots noindex', 'Meta robots noindex tag'),
    measures: t('Las etiquetas meta name="robots" y meta name="googlebot" dentro del head del documento.', 'meta name="robots" and meta name="googlebot" in the document head.'),
    rule: t('NO CUMPLE si cualquiera de las dos contiene noindex.', 'FAIL if either contains noindex.'),
    why: t('Suele quedarse encendido después de lanzar desde un entorno de pruebas, o por la casilla de WordPress que pide a los buscadores no indexar el sitio web.', 'Commonly left on after a staging launch, or by the WordPress "discourage search engines" setting.')
  },
  'sitemap': {
    layer: 'access', scored: true,
    title: t('Sitemap XML', 'XML sitemap'),
    measures: t('Las declaraciones Sitemap de robots.txt y después cinco rutas habituales: /sitemap.xml, /sitemap_index.xml, /wp-sitemap.xml, /sitemap-index.xml y /sitemap1.xml.', 'Sitemap declarations in robots.txt, then five common paths: /sitemap.xml, /sitemap_index.xml, /wp-sitemap.xml, /sitemap-index.xml, /sitemap1.xml.'),
    rule: t('CUMPLE con un sitemap válido de 3 URLs o más. ATENCIÓN si no se encuentra ninguno, o si lista menos de 3 URLs. NO CUMPLE si existe pero está vacío o mal formado.', 'PASS on a valid sitemap with 3 or more URLs. WARNING if none is found, or fewer than 3 URLs are listed. FAIL if a sitemap exists but is empty or malformed.'),
    why: t('Acelera el descubrimiento para todos los rastreadores. Revisar primero lo declarado evita reportar como «sin sitemap» a un sitio web que lo tiene bien configurado en otra ruta.', 'Speeds discovery for every crawler. Checking declarations first avoids reporting a correctly configured site as having no sitemap.')
  },
  'response-time': {
    layer: 'access', scored: true,
    title: t('Tiempo de respuesta', 'Response time'),
    measures: t('La más rápida de dos peticiones aisladas a la portada, cada una lanzada sin nada más compitiendo por el servidor.', 'The fastest of two isolated homepage requests, each issued with nothing else contending for the origin.'),
    rule: t('ATENCIÓN por encima de 2500 ms. Nunca NO CUMPLE: una muestra de tiempo no debería poder condicionar nada. SIN VERIFICAR si ninguna petición llegó a completarse.', 'WARNING above 2500ms. Never a FAIL — a timing sample should not be able to gate anything. UNVERIFIED if no request completed.'),
    why: t('Los rastreadores abandonan los servidores lentos. Tomar dos muestras aisladas en vez de una mantiene la cifra lo bastante estable para compararla entre auditorías.', 'Slow origins get abandoned by crawlers. Two isolated samples rather than one keeps the figure stable enough to compare across re-audits.')
  },
  'edge-protection': {
    layer: 'access', scored: false,
    title: t('Protección frente a bots en la capa de red (CDN/WAF)', 'Edge bot protection (CDN/WAF)'),
    measures: t('Huellas de CDN y WAF en los encabezados de respuesta: Cloudflare, Sucuri, Akamai, Fastly, Imperva.', 'CDN and WAF fingerprints in response headers — Cloudflare, Sucuri, Akamai, Fastly, Imperva.'),
    rule: t('Siempre SIN VERIFICAR cuando se detecta un proveedor. Estos servicios identifican a los bots verificados por rango de IP, no por la cadena de user-agent, así que probar user-agents no puede resolver si los rastreadores de IA tienen paso: la prueba la supera en cualquier caso.', 'Always UNVERIFIED when a provider is detected. Edge services identify verified bots by source IP range, not user-agent string, so user-agent testing cannot settle whether AI crawlers are permitted — it passes regardless.'),
    why: t('Es el punto ciego más claro del escáner, y se informa como tal en lugar de esconderlo tras un CUMPLE. Incluye la revisión manual exacta, y nombra la plataforma de alojamiento cuando el CDN es de ella y no del cliente.', 'The scanner\'s clearest blind spot, reported as such rather than hidden behind a pass. Carries the exact manual check, and names the hosting platform when the CDN belongs to the platform rather than the client.')
  },
  'hosting-platform': {
    layer: 'access', scored: false,
    title: t('Plataforma de alojamiento', 'Hosting platform'),
    measures: t('Huellas de la plataforma en la página y en los encabezados: Lovable, Wix, Squarespace, Framer, Webflow, Shopify y WordPress autoalojado.', 'Platform fingerprints in the page and headers — Lovable, Wix, Squarespace, Framer, Webflow, Shopify, self-hosted WordPress.'),
    rule: t('Informativo. Nunca cuenta como cumplir ni como fallar.', 'Informational. Never a pass or a failure.'),
    why: t('Define quién puede resolver qué. En una plataforma administrada el CDN es de la plataforma, así que recomendar cambiar ajustes de bots manda al cliente a buscar un panel que nunca va a tener.', 'Decides who can fix what. On a managed platform the CDN belongs to the host, so advice to change bot settings sends the client looking for a dashboard they do not have.')
  },
  'llms-txt': {
    layer: 'access', scored: false,
    title: t('llms.txt (estándar emergente)', 'llms.txt'),
    measures: t('La presencia del archivo /llms.txt.', 'Presence of /llms.txt.'),
    rule: t('Solo se informa si existe. Su ausencia jamás cuenta en contra del sitio web.', 'Presence only. Its absence is never counted against a site.'),
    why: t('Es una convención emergente que ningún motor importante se ha comprometido a respetar todavía. Se reporta como señal de adopción temprana, no como requisito.', 'An emerging convention that no major engine has committed to honouring. Reported as an early-mover signal, not a requirement.')
  },

  // ── Layer 2: Machine readability ───────────────────────────────────────────
  'js-rendering': {
    layer: 'readability', scored: true,
    title: t('Contenido visible sin JavaScript', 'Content visible without JavaScript'),
    measures: t('Palabras legibles en la respuesta del servidor, cantidad de scripts, y si el punto de montaje del framework llegó vacío.', 'Readable words in the server response, script count, and whether a framework mount point arrived empty.'),
    rule: t('NO CUMPLE si el servidor devuelve menos de 60 palabras junto con scripts, o si un punto de montaje (#root, #__next, #app) contiene menos de 30 palabras.', 'FAIL if the server returns under 60 words alongside scripts, or a mount point (#root, #__next, #app) contains under 30 words.'),
    why: t('La mayoría de los rastreadores de IA no ejecutan JavaScript. Si esto falla, el resto de resultados de la página no son confiables: las revisiones estarían leyendo un cascarón vacío, no la página real.', 'Most AI crawlers do not execute JavaScript. If this fails, every other on-page result for the page is unreliable — the checks are reading an empty shell, not the real page.')
  },
  'title': {
    layer: 'readability', scored: true,
    title: t('Etiqueta title', 'Title tag'),
    measures: t('La presencia y la longitud del elemento title.', 'Presence and length of the title element.'),
    rule: t('NO CUMPLE si falta. ATENCIÓN por encima de 60 caracteres.', 'FAIL if missing. WARNING above 60 characters.'),
    why: t('Es la declaración más contundente de qué trata una página, y la usan tanto los buscadores como los motores de IA.', 'The strongest single statement of what a page is about, used by both search and AI surfaces.')
  },
  'meta-description': {
    layer: 'readability', scored: true,
    title: t('Meta description', 'Meta description'),
    measures: t('La presencia y la longitud de la meta description.', 'Presence and length of the meta description.'),
    rule: t('NO CUMPLE si falta. ATENCIÓN por encima de 160 caracteres.', 'FAIL if missing. WARNING above 160 characters.'),
    why: t('Con frecuencia se toma tal cual como el resumen que acompaña a una cita.', 'Frequently lifted verbatim as the summary shown alongside a citation.')
  },
  'schema': {
    layer: 'readability', scored: true,
    title: t('Datos estructurados (Schema.org / JSON-LD)', 'Schema.org / JSON-LD'),
    measures: t('Los bloques JSON-LD, leyendo su @type y comparándolo contra ocho tipos habituales.', 'JSON-LD blocks parsed for @type, compared against eight common types.'),
    rule: t('NO CUMPLE si no hay ningún dato estructurado. ATENCIÓN si faltan más de cuatro de los tipos habituales.', 'FAIL if no structured data is present. WARNING if more than four common types are absent.'),
    why: t('Es la forma más directa de declarar hechos legibles por máquina sobre una entidad, y de las señales de mayor peso para conseguir citas.', 'The most direct way to state machine-readable facts about an entity. Among the highest-leverage signals available for citation.')
  },
  'headings': {
    layer: 'readability', scored: true,
    title: t('Estructura de encabezados', 'Heading structure'),
    measures: t('Cuántos elementos h1 hay y si se salta algún nivel de encabezado.', 'Count of h1 elements and whether heading levels are skipped.'),
    rule: t('CUMPLE con exactamente un h1 y sin saltos de nivel. NO CUMPLE sin h1. ATENCIÓN en cualquier otro caso.', 'PASS with exactly one h1 and no skipped levels. FAIL with no h1. WARNING otherwise.'),
    why: t('Los encabezados son la forma en que una máquina divide la página en pasajes que puede recuperar por separado.', 'Headings are how a machine segments a page into passages it can retrieve individually.')
  },
  'heading-hierarchy': {
    layer: 'readability', scored: true,
    title: t('Jerarquía de encabezados (orden secuencial)', 'Sequential heading hierarchy'),
    measures: t('Si los niveles de encabezado descienden sin huecos.', 'Whether heading levels descend without gaps.'),
    rule: t('ATENCIÓN cuando se salta un nivel, por ejemplo de h1 directo a h3.', 'WARNING when a level is skipped (h1 straight to h3).'),
    why: t('Una jerarquía rota produce un índice engañoso del documento y difumina dónde termina un tema y empieza el siguiente.', 'A broken hierarchy produces a misleading document outline, blurring where one topic ends and the next begins.')
  },
  'canonical': {
    layer: 'readability', scored: true,
    title: t('Etiqueta canonical', 'Canonical tag'),
    measures: t('La etiqueta link rel="canonical" y si apunta a sí misma o a otro dominio.', 'link rel="canonical" and whether it is self-referencing or cross-domain.'),
    rule: t('NO CUMPLE si apunta a otro dominio. ATENCIÓN si no existe.', 'FAIL if it points to another domain. WARNING if absent.'),
    why: t('Un canonical que quedó apuntando al entorno de pruebas después de una migración puede desaparecer por completo la página real.', 'A canonical left pointing at staging after a migration can suppress the live page entirely.')
  },
  'open-graph': {
    layer: 'readability', scored: true,
    title: t('Etiquetas Open Graph', 'Open Graph tags'),
    measures: t('Las etiquetas og:title, og:description y og:type.', 'og:title, og:description and og:type.'),
    rule: t('NO CUMPLE si faltan las tres. ATENCIÓN si falta alguna.', 'FAIL if all three are missing. WARNING if some are.'),
    why: t('Controlan cómo se representa la página al compartirla o al generar una vista previa, incluidas las herramientas que leen esos metadatos.', 'Controls how the page is represented when shared or previewed, including by tools that fetch preview metadata.')
  },
  'image-alt': {
    layer: 'readability', scored: true,
    title: t('Cobertura de texto alternativo en imágenes', 'Image alt text coverage'),
    measures: t('Qué proporción de los elementos img llevan texto alternativo con contenido.', 'Proportion of img elements carrying non-empty alt text.'),
    rule: t('CUMPLE del 80% para arriba. ATENCIÓN desde el 40%. NO CUMPLE por debajo del 40%.', 'PASS at 80% or above. WARNING from 40%. FAIL below 40%.'),
    why: t('El texto alternativo es la única descripción de una imagen que recibe un sistema que no la ve.', 'Alt text is the only description of an image a non-visual system receives.')
  },
  'main-landmark': {
    layer: 'readability', scored: true,
    title: t('Presencia de la región <main>', 'Main landmark presence'),
    measures: t('La existencia de un elemento main o de role="main".', 'A main element or role="main".'),
    rule: t('NO CUMPLE si no está.', 'FAIL if absent.'),
    why: t('Le indica a un agente qué parte del documento es el contenido, a diferencia de la navegación y los elementos de plantilla.', 'Tells an agent which part of the document is the content, as distinct from navigation and chrome.')
  },
  'form-labels': {
    layer: 'readability', scored: true,
    title: t('Asociación de etiquetas en formularios', 'Form input labels'),
    measures: t('Si los campos de formulario tienen etiqueta asociada o nombre accesible.', 'Whether form inputs have associated labels or accessible names.'),
    rule: t('ATENCIÓN cuando los campos no lo tienen.', 'WARNING when inputs lack them.'),
    why: t('Un agente de IA que llene un formulario por encargo del usuario solo puede identificar un campo por su nombre accesible.', 'An AI agent completing a form on a user\'s behalf can only identify a field by its accessible name.')
  },
  'a11y-tree-health': {
    layer: 'readability', scored: true,
    title: t('Salud del árbol de accesibilidad (estimación compuesta)', 'Accessibility tree health'),
    measures: t('Un compuesto de los resultados de región principal, jerarquía de encabezados, etiquetas de formulario y texto alternativo.', 'Composite of the landmark, heading hierarchy, form label and image alt results.'),
    rule: t('Se deriva de las revisiones que lo componen.', 'Derived from its component checks.'),
    why: t('El árbol de accesibilidad es, a grandes rasgos, aquello por lo que navega un agente, así que su salud anticipa qué tan bien podrá operar la página.', 'The accessibility tree is broadly what an agentic browser navigates by, so its health predicts how well an agent can operate the page.')
  },
  'contact-machine-readable': {
    layer: 'readability', scored: true,
    title: t('Datos de contacto legibles por máquina', 'Contact info machine-readability'),
    measures: t('Los enlaces tel: y mailto:, y el schema ContactPoint. Solo se aplica cuando la página muestra datos de contacto.', 'tel: and mailto: links, and ContactPoint schema. Only applied when the page shows contact details at all.'),
    rule: t('ATENCIÓN cuando los datos de contacto aparecen únicamente como texto plano.', 'WARNING when contact details appear as plain text only.'),
    why: t('Permite que un agente actúe sobre los datos en lugar de solo leerlos.', 'Lets an agent act on the details rather than merely read them.')
  },
  'schema-completeness': {
    layer: 'readability', scored: true,
    title: t('Integridad de los datos estructurados', 'Structured data completeness'),
    measures: t('Todas las propiedades realmente presentes en cada tipo de schema.org reconocido, contrastadas con las obligatorias y las recomendadas de ese tipo.', 'Every property actually present on each recognised schema.org type, checked against that type’s required and recommended properties.'),
    rule: t('NO CUMPLE cuando a un tipo le falta una propiedad obligatoria (Organization sin name o url, LocalBusiness sin dirección). ATENCIÓN cuando falta la mayoría de las recomendadas. Solo se evalúan los tipos reconocidos.', 'FAIL when a type is missing a required property (Organization without name or url, LocalBusiness without an address). WARNING when most recommended properties are absent. Only recognised types are assessed.'),
    why: t('Que exista no prueba nada. Un bloque con solo @type y un nombre no le da al motor forma de vincular el marcado con una entidad real, y aun así supera una revisión de mera presencia igual que uno completo.', 'Presence alone proves nothing. A block carrying only @type and a name gives an engine no way to tie the markup to a real entity, yet it passes a presence check exactly as a complete one does.')
  },
  'faq-schema-match': {
    layer: 'readability', scored: true,
    title: t('Coincidencia del schema FAQ con el contenido visible', 'FAQ schema vs visible content'),
    measures: t('Las preguntas del schema FAQPage contrastadas con el texto visible en la página. Solo se aplica donde existe ese schema.', 'FAQPage schema questions matched against text visible on the page. Only applied where FAQ schema exists.'),
    rule: t('CUMPLE cuando el 70% o más de las preguntas del schema aparecen en el contenido visible.', 'PASS when 70% or more of schema questions appear in the visible content.'),
    why: t('Los datos estructurados que no reflejan lo que hay en la página pueden interpretarse como manipulación.', 'Structured data that does not reflect the page can be treated as manipulative.')
  },

  // ── Layer 3: Substance & authority ─────────────────────────────────────────
  'content-depth': {
    layer: 'substance', scored: true,
    title: t('Profundidad del contenido para ser citado', 'Content depth for citation'),
    measures: t('Las palabras de contenido principal, quitando navegación, encabezado y pie de página.', 'Words of main content, with navigation, header and footer removed.'),
    rule: t('NO CUMPLE por debajo de 300 palabras. ATENCIÓN por debajo de 600. CUMPLE de 600 en adelante; a partir de 1200 se registra como amplio.', 'FAIL under 300 words. WARNING under 600. PASS at 600 or above; 1200 or above is recorded as substantial.'),
    why: t('Por debajo de unas 300 palabras no hay material suficiente para que un motor extraiga un pasaje útil. Una página puede rastrearse a la perfección y no citarse nunca, sencillamente porque no hay nada que valga la pena citar.', 'Below roughly 300 words there is not enough for an engine to extract a useful passage. A page can be crawled perfectly and never be quoted because there is nothing in it worth quoting.')
  },
  'page-scope': {
    layer: 'substance', scored: true,
    title: t('Alcance de la página: ¿debería dividirse?', 'Page scope — should this be split?'),
    measures: t('El contenido dividido en los encabezados h2 y medido por apartado, más si la navegación está hecha únicamente de anclas internas.', 'Content split at h2 boundaries and measured per section, plus whether navigation is built entirely from in-page anchors.'),
    rule: t('NO CUMPLE cuando la navegación es solo de anclas y abarca 3 temas o más, es decir, un sitio web de una sola página. ATENCIÓN con 4 apartados o más que promedien menos de 120 palabras.', 'FAIL when navigation is anchor-only across 3 or more topics — a single-page site. WARNING at 4 or more sections averaging under 120 words.'),
    why: t('Los motores recuperan y citan a nivel de página. Los temas que comparten un mismo documento no pueden devolverse ante consultas sobre cada uno por separado, por bien escritos que estén.', 'Engines retrieve and cite at page level. Topics sharing one document cannot be returned for queries about them individually, however good the writing.')
  },
  'authority-signals': {
    layer: 'substance', scored: true,
    title: t('Señales de autoridad y credibilidad', 'Authority & credibility signals'),
    measures: t('Seis señales, detectadas en español y en inglés: personas identificadas, pruebas de clientes, credenciales, dirección física, enlaces de contacto directo y enlaces a perfiles externos, incluido sameAs.', 'Six signals, detected bilingually (English and Spanish): named people, client evidence, credentials, physical address, direct contact links, external profile links including sameAs.'),
    rule: t('CUMPLE con 5 de 6 o más. ATENCIÓN con 3 o 4. NO CUMPLE con 2 o menos.', 'PASS at 5 of 6 or more. WARNING at 3 or 4. FAIL at 2 or fewer.'),
    why: t('Los motores prefieren las fuentes que visiblemente pertenecen a una organización real y responsable. Sin estas señales, el sitio web se lee como publicidad anónima por bien construido que esté.', 'Engines favour sources visibly belonging to a real, accountable organisation. Without these a site reads as anonymous marketing copy however well it is built.')
  },
  'answer-format': {
    layer: 'substance', scored: true,
    title: t('Contenido con forma de respuesta', 'Answer-shaped content'),
    measures: t('Encabezados en forma de pregunta (en español y en inglés), elementos de lista, tablas y listas de definición.', 'Question-form headings (English and Spanish), list items, tables and definition lists.'),
    rule: t('CUMPLE con 2 o más encabezados en forma de pregunta, o con una puntuación de estructura de 12 o más: cada elemento de lista suma 1, cada tabla 5 y cada lista de definición 3.', 'PASS with 2 or more question-form headings, or a structure score of 12 or more (lists count 1, tables 5, definition lists 3).'),
    why: t('La recuperación empareja una pregunta con el pasaje que la responde. Los apartados de pregunta y respuesta, las listas y las tablas comparativas son mucho más fáciles de aprovechar que la prosa continua.', 'Retrieval matches a question to a passage that answers it. Q&A sections, lists and comparison tables are markedly easier to lift an answer from than continuous prose.')
  },
  'entities': {
    layer: 'substance', scored: true,
    title: t('Entidades nombradas y especificidad', 'Named entity / specificity signal'),
    measures: t('Las expresiones con aspecto de nombre propio, las cifras y las referencias a años dentro del contenido principal.', 'Proper-noun phrases, numbers and year references in the main content.'),
    rule: t('ATENCIÓN cuando hay menos de 3 nombres propios y menos de 3 cifras.', 'WARNING when fewer than 3 proper nouns and fewer than 3 numbers are present.'),
    why: t('Lo que se cita son los datos concretos y verificables. El lenguaje comercial genérico no ofrece nada que citar.', 'Specific, checkable facts are what gets quoted. Generic marketing language offers nothing to cite.')
  },
  'first-250-specificity': {
    layer: 'substance', scored: true,
    title: t('Especificidad de las primeras 250 palabras', 'First-250-words specificity'),
    measures: t('El mismo criterio de entidades aplicado únicamente a las primeras 250 palabras.', 'The same entity heuristic applied to the opening 250 words only.'),
    rule: t('CUMPLE con 3 o más nombres propios, o 3 o más cifras, en la apertura.', 'PASS with 3 or more proper nouns, or 3 or more numbers, in the opening.'),
    why: t('La extracción da más peso al inicio de la página que al material enterrado más abajo.', 'Extraction weights the beginning of a page more heavily than material further down.')
  },
  'author-attribution': {
    layer: 'substance', scored: true,
    title: t('Autoría y credenciales', 'Author / credential attribution'),
    measures: t('Las firmas, los enlaces rel="author" y el schema Person vinculado a la autoría.', 'Bylines, rel="author" links, and Person schema tied to authorship.'),
    rule: t('ATENCIÓN cuando no se encuentra ninguno.', 'WARNING when none is found.'),
    why: t('Las fuentes con nombre y credenciales pesan más que el texto corporativo sin autor.', 'Named, credentialed sources are weighted more heavily than unattributed corporate copy.')
  },
  'content-freshness': {
    layer: 'substance', scored: true,
    title: t('Señales de actualidad', 'Freshness signals'),
    measures: t('Las propiedades dateModified, datePublished y uploadDate de los datos estructurados, los elementos <time datetime> y los metadatos de fecha de artículo.', 'dateModified, datePublished and uploadDate in structured data, <time datetime> elements, and article date metadata.'),
    rule: t('ATENCIÓN cuando no existe ninguna fecha legible por máquina, o cuando la más reciente tiene más de un año. CUMPLE dentro del año.', 'WARNING when no machine-readable date exists at all, or when the most recent is over a year old. PASS within a year.'),
    why: t('Los motores dan peso a lo reciente. Una página sin fecha legible no puede evaluarse en ese aspecto, lo cual ya es una desventaja frente a un competidor cuya página sí se ve actual.', 'Engines weight recency. A page carrying no readable date cannot be assessed for it, which is itself a disadvantage against a competitor whose page is visibly current.')
  },
  'boilerplate': {
    layer: 'substance', scored: true,
    title: t('Contenido duplicado o de plantilla', 'Boilerplate / templated content'),
    measures: t('La similitud por pares entre las páginas analizadas, comparando secuencias de cinco palabras.', 'Pairwise five-word shingle similarity between analysed pages.'),
    rule: t('ATENCIÓN por encima del 60% de similitud entre cualquier par. SIN VERIFICAR con menos de dos páginas, porque no hay con qué comparar.', 'WARNING above 60% similarity between any pair. UNVERIFIED with fewer than two pages, since there is nothing to compare.'),
    why: t('Las páginas casi idénticas compiten entre sí y delatan un uso de plantilla con poco valor propio.', 'Near-identical pages compete with each other and signal low-value templating.')
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
