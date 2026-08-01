# GEO On-Page Scanner — Build Prompt for Claude Code

## Context for Claude Code
This tool is for Akore Labs, a GEO (Generative Engine Optimization) consultancy. It fills a gap in our existing workflow: **Hieronymus** (our other tool, already built and deployed) tests whether AI engines actually cite a brand by running search prompts against Claude/ChatGPT/Gemini. This new tool answers a different, earlier question: **is the site even structurally capable of being crawled and cited in the first place?**

This maps to "Layer 1 — The Technical Gate" in our internal methodology: before reading any citation-rate scores, we need to know if the site is crawlable at all. Every client audit so far (3 real cases) found this layer broken in some way, and it was always the #1 blocking issue. Right now we check this manually and inconsistently. This tool should make it automatic, repeatable, and thorough — including checks a human might not think to run (like testing with multiple user-agents to catch server-level bot-blocking, which we hit ourselves on our own site and couldn't diagnose quickly by hand).

## Architecture — this must live alongside Hieronymus as a matching web dashboard
This is **not a CLI tool** — it's a web-based dashboard, deployed to Netlify, styled to visually match Hieronymus (dark theme, background `#0c0c0e`, violet accent `#7c6bff`, green accent `#00d48a`, 'Space Mono' + 'Syne' fonts, same card/badge/progress-bar visual language). A person should be able to open this tool right next to Hieronymus and immediately recognize it as part of the same internal toolset.

**Important technical constraint to design around:** a browser cannot directly fetch another domain's robots.txt, HTTP headers, or raw HTML due to CORS restrictions — this is a hard browser limitation, not a bug to work around client-side. Follow the same pattern Hieronymus already uses: a **Netlify serverless function** (Node.js, in `/netlify/functions/`) does the actual outbound HTTP requests server-side (no CORS restriction applies server-to-server), and the frontend calls that function and renders the results. This keeps the core scanning function completely free of any AI/API dependency — it's just a serverless proxy doing HTTP requests, the same architectural role Hieronymus's backend plays for its own fetching needs.

## Does this need to connect to Claude/an LLM to function?
**No — the core scanning functionality works with zero AI API involvement.** Everything in Sections 1-4 below is deterministic: parsing HTML, checking headers, validating XML, done via the Netlify function described above. No Claude API key required, no per-scan cost, no rate limit dependency.

**Section 5 (narrative summary) is optional and separate** — same UX pattern as Hieronymus's own "Claude API Key" input field: if the user provides one, use it to turn raw findings into a plain-language "hallazgo principal" summary in our client-report style. If the field is left blank, skip Section 5 entirely — the dashboard still shows a complete, fully-scored report either way.

## Tech stack
- Frontend: single HTML file (or minimal set), vanilla JS + CSS matching Hieronymus's existing style — reuse its font imports, color variables, card/badge/progress-bar CSS classes directly where possible for visual consistency
- Backend: Netlify Functions (Node.js) — use `node-fetch` or native fetch, `cheerio` for HTML/DOM parsing (the Node equivalent of BeautifulSoup), a robots.txt parser (e.g. `robots-parser` npm package)
- Optional: Anthropic SDK call from the Netlify function, only invoked if a Claude API key was submitted in that request (same pattern as Hieronymus's own API key field)

## What to build

### Input
A dashboard page with a single input field: **"Website URL to scan"**, plus a **"Run Scan"** button — mirroring Hieronymus's existing input-then-run pattern. Optionally, a collapsible "Advanced" section for specifying up to 5 additional key pages to check beyond the homepage (same optional/collapsible pattern Hieronymus uses for Google Sheets config).

### Section 1 — Crawlability Layer (the most important section — this is Layer 1 of our methodology)

1. **Fetch and parse robots.txt properly** (via the Netlify function). Don't just check if it loads — parse the actual `Disallow`/`Allow` rules per user-agent and report clearly which paths are blocked and for which bots.
2. **Test with multiple distinct user-agent strings**, each as a separate server-side request — at minimum: a generic browser UA, `GPTBot`, `ClaudeBot`/`anthropic-ai`, `Googlebot`, and a plain default UA. Report whether the response differs (status code, content, or an outright block) between them. This is the check that would have caught our own site's issue faster than the hour we spent manually hunting through cPanel.
3. **Check for `X-Robots-Tag` HTTP response headers** — this is a separate blocking mechanism from robots.txt and from WordPress's own "discourage search engines" setting, and it's easy to miss without checking headers directly.
4. **Check for a `noindex` meta tag** in the HTML `<head>` as a third, distinct mechanism.
5. **Fetch and validate sitemap.xml** — confirm it exists, is valid XML, and contains a reasonable number of URLs (flag if it's empty or clearly stale).
6. **Report response time / basic performance signal** — slow-loading pages are a secondary but real factor.

Output for this section: a clear PASS/FAIL/WARNING per check, rendered as status pills (reuse Hieronymus's `badge-cited`/`badge-not` style green/red pill CSS), plus a plain description of what's blocking what, if anything.

### Section 2 — On-Page GEO Signals

For the homepage and up to 5 additional user-specified key pages:

1. **Title tag**: presence, character length (flag if >60 or missing)
2. **Meta description**: presence, character length (flag if >160 or missing)
3. **Schema.org JSON-LD**: extract and list every schema type found (e.g., Organization, LocalBusiness, Service, FAQPage, Product, Article). Report which types are present and which common/expected types are absent, since our client reports score this explicitly.
4. **Heading structure**: confirm exactly one `<h1>` per page, and report the overall heading hierarchy (flag skipped levels, e.g., H1 straight to H4).
5. **Canonical tag**: present and self-referencing correctly (not pointing to a different domain/staging URL — this is a real bug we've hit with migrated sites).
6. **Open Graph tags**: og:title, og:description, og:type presence.
7. **Image alt text coverage**: percentage of `<img>` tags with non-empty alt attributes.

### Section 3 — Content Specificity Signals (best-effort, lower precision than Sections 1-2)

This is the harder, more judgment-based category, tied to our core thesis that AI engines favor specific, citable content over generic corporate language.

1. **Named entity presence**: rough detection of proper nouns, numbers, and dates in the page's main content (a simple heuristic is fine — e.g., regex for capitalized multi-word sequences, digit sequences, year patterns — this doesn't need to be a full NLP pipeline).
2. **Boilerplate detection**: flag if large blocks of text are identical across multiple pages of the site (a sign of templated, low-value content — this is exactly what we found wrong with Jeeves Solutions' directory listings).
3. **Word count** of main content area per page (very short pages are a weak signal, not a hard fail).

### Section 4 — Dashboard Output

1. **Score each of Sections 1-3** using the same weighted category model as our client audits (Section 1 findings should heavily gate the overall score — if crawlability fails, the total score should reflect that as critical, not just average it in evenly with everything else). Render this the same way Hieronymus renders its overall score circle + category breakdown bars.
2. **Results table**, same visual pattern as Hieronymus's results table — one row per check, with a status pill and an expandable "view details" toggle for the raw data (matching Hieronymus's collapsible response-text pattern).
3. **Export buttons**: "Export JSON" and "Export PDF" (reuse Hieronymus's existing button styling). PDF should ideally reuse our client-report visual style (violet/emerald accent, clean corporate look) if feasible in scope for v1 — a plain readable PDF is an acceptable fallback.
4. **Prioritized findings list** — critical issues first (crawlability), then on-page gaps, then content specificity notes — mirroring how we structure the "Plan de Acción por Fases" in our client deliverables.

### Section 5 — Optional Claude-Powered Narrative

Add a **"Claude API Key"** password-type input field, identical in placement/style to Hieronymus's own API key field ("Never stored. Used only for this session."). If filled in:
- Pass the structured findings from Sections 1-4 to Claude via the Netlify function
- Generate a short, plain-language "hallazgo principal" summary in the same style as our existing client reports — one clear sentence stating the core problem, written for a non-technical business owner
- Display this at the top of the results, above the score circle

If the field is left blank, skip this entirely — no error, no missing functionality, just a complete report without the narrative summary line.

## What NOT to build (scope boundaries)
- Do not build a full citation-testing feature (that's Hieronymus's job, not this tool's)
- Do not require any API keys for the core functionality to run
- Do not attempt full competitive analysis or content rewriting — this tool diagnoses, it doesn't fix
- Do not duplicate Hieronymus's Google Sheets logging unless explicitly asked — keep this tool's output self-contained (JSON/PDF export) for v1

## Success criteria
Running this tool against a site should have caught, automatically and quickly, every Layer 1 issue we've found by hand so far across our real audits: a crawl-blocked site (Fiacsa, PML, Jeeves — all three), a missing `<title>` tag (the Akore Labs mockup), and ideally would have caught our own fiacsa.mx robots/bot-blocking confusion faster than the manual troubleshooting session it actually took. Deployed to Netlify, sitting visually and functionally alongside Hieronymus as a companion tool in the same internal toolset.

