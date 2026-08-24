// ── Competitor benchmarking ──
// A score on its own invites the question "compared to what". Run against named competitors it
// becomes a position, which is both more honest and more useful: 61/100 means little until it
// sits beside a competitor on 78.
//
// Competitor scans use a smaller page budget than the client's. The point is a fair comparison of
// the same measures, not an audit of someone else's site, and scanning three competitors at full
// depth would triple an already minute-long run for no added insight.

const COMPETITOR_PAGE_BUDGET = 8;

export async function benchmark(runScan, subjectResult, competitorUrls, budget = COMPETITOR_PAGE_BUDGET) {
  const rivals = [];
  for (const url of competitorUrls) {
    try {
      const r = await runScan({ url, maxPages: budget });
      rivals.push({
        url,
        reachable: r.reachable,
        overall: r.score.overall,
        pagesAnalyzed: r.scanQuality.pagesAnalyzed,
        layers: (r.layers || []).map(l => ({ id: l.id, title: l.title, score: l.score, scored: l.scored }))
      });
    } catch (err) {
      // A competitor that cannot be scanned is reported as such rather than dropped — a silent
      // omission would leave the comparison looking complete when it is not.
      rivals.push({ url, reachable: false, overall: null, error: err.message, layers: [] });
    }
  }

  const subject = {
    url: subjectResult.input.url,
    overall: subjectResult.score.overall,
    pagesAnalyzed: subjectResult.scanQuality.pagesAnalyzed,
    layers: (subjectResult.layers || []).map(l => ({ id: l.id, title: l.title, score: l.score, scored: l.scored }))
  };

  const scored = [subject, ...rivals].filter(e => typeof e.overall === 'number');
  const ranked = [...scored].sort((a, b) => b.overall - a.overall);
  const position = ranked.findIndex(e => e.url === subject.url) + 1;

  // Per-layer position, which is where the actionable story usually is: a site can trail overall
  // while leading on access and losing badly on substance.
  const layerStanding = subject.layers.filter(l => l.scored).map(l => {
    const all = [subject, ...rivals]
      .map(e => ({ url: e.url, score: (e.layers.find(x => x.id === l.id) || {}).score }))
      .filter(e => typeof e.score === 'number')
      .sort((a, b) => b.score - a.score);
    return {
      id: l.id,
      title: l.title,
      score: l.score,
      rank: all.findIndex(e => e.url === subject.url) + 1,
      of: all.length,
      best: all[0] ? { url: all[0].url, score: all[0].score } : null
    };
  });

  return {
    subject,
    competitors: rivals,
    position: position || null,
    of: scored.length,
    unreachable: rivals.filter(r => !r.reachable).map(r => r.url),
    layerStanding,
    competitorPageBudget: budget
  };
}
