// ── Scan history and deltas ──
// Every scan was standalone, which made the monitoring half of the service impossible: without a
// stored baseline there is nothing to compare a re-audit against, and "it improved" is an
// assertion rather than a measurement.
//
// Snapshots are trimmed rather than stored whole. A full payload carries raw HTML excerpts and
// runs to megabytes; what a comparison needs is the score, the layer breakdown and the verdict
// for each check. The rubric version is stored with every snapshot because a scoring change would
// otherwise read as client progress — a delta across different rubric versions is not a delta at
// all, and is reported as incomparable rather than quietly shown.

import { mkdirSync, readdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const HISTORY_DIR = 'history';

function hostSlug(url) {
  try { return new URL(url).hostname.replace(/^www\./, '').replace(/[^a-z0-9.-]/gi, '-'); }
  catch { return 'unknown'; }
}

export function snapshot(result) {
  const checks = {};
  const record = (c, page) => { checks[page ? `${page}::${c.id}` : c.id] = c.status; };
  (result.layers || []).forEach(l => l.checks.forEach(c => record(c, c.page)));

  return {
    url: result.input.url,
    scannedAt: result.scannedAt,
    rubricVersion: result.score.rubricVersion,
    reachable: result.reachable,
    overall: result.score.overall,
    layers: (result.layers || []).map(l => ({ id: l.id, title: l.title, score: l.score, scored: l.scored, counts: l.counts })),
    pagesAnalyzed: result.scanQuality.pagesAnalyzed,
    blockers: result.score.blockers.count,
    unverified: result.score.unverified.count,
    checks
  };
}

export function saveSnapshot(result, baseDir = '.') {
  const dir = join(baseDir, HISTORY_DIR, hostSlug(result.input.url));
  mkdirSync(dir, { recursive: true });
  const name = `${result.scannedAt.replace(/[:.]/g, '-')}.json`;
  const path = join(dir, name);
  writeFileSync(path, JSON.stringify(snapshot(result), null, 2));
  return path;
}

export function previousSnapshot(url, baseDir = '.') {
  const dir = join(baseDir, HISTORY_DIR, hostSlug(url));
  if (!existsSync(dir)) return null;
  const files = readdirSync(dir).filter(f => f.endsWith('.json')).sort();
  // The current scan is saved before comparison, so the newest file is this run; the one before
  // it is the baseline.
  if (files.length < 2) return null;
  try { return JSON.parse(readFileSync(join(dir, files[files.length - 2]), 'utf8')); }
  catch { return null; }
}

const RANK = { FAIL: 0, WARNING: 1, INCONCLUSIVE: 2, INFO: 2, PASS: 3 };

export function diff(current, previous) {
  if (!previous) return null;
  if (previous.rubricVersion !== current.rubricVersion) {
    return {
      comparable: false,
      reason: `The previous scan used scoring rubric v${previous.rubricVersion}; this one uses v${current.rubricVersion}. The two numbers were produced by different rules, so the difference between them says nothing about the site and is not reported as a change.`,
      previousDate: previous.scannedAt
    };
  }

  const improved = [];
  const regressed = [];
  const added = [];
  const removed = [];

  Object.entries(current.checks).forEach(([k, status]) => {
    const before = previous.checks[k];
    if (before === undefined) { added.push({ key: k, status }); return; }
    if (before === status) return;
    const entry = { key: k, from: before, to: status };
    (RANK[status] > RANK[before] ? improved : regressed).push(entry);
  });
  Object.keys(previous.checks).forEach(k => { if (current.checks[k] === undefined) removed.push({ key: k, status: previous.checks[k] }); });

  return {
    comparable: true,
    previousDate: previous.scannedAt,
    overall: { from: previous.overall, to: current.overall, delta: (current.overall ?? 0) - (previous.overall ?? 0) },
    layers: current.layers.map(l => {
      const before = (previous.layers || []).find(p => p.id === l.id);
      return { id: l.id, title: l.title, from: before ? before.score : null, to: l.score, delta: before && before.score !== null && l.score !== null ? l.score - before.score : null };
    }),
    pagesAnalyzed: { from: previous.pagesAnalyzed, to: current.pagesAnalyzed },
    improved, regressed, added, removed
  };
}
