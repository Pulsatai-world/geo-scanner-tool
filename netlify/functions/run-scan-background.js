import { getStore } from '@netlify/blobs';
import { runScan } from './lib/scan-engine.js';

// Background Function (note the -background.js suffix — that's what tells Netlify to run this
// async, up to 15 minutes, instead of under a regular synchronous function's ~10s ceiling). The
// caller gets an immediate response on invocation and has no way to read this function's return
// value, so progress/results are written to Blobs keyed by the client-generated jobId, and the
// client learns the outcome by polling scan-status.js instead.
const STORE_NAME = 'geo-scan-jobs';

export default async (request) => {
  if (request.method !== 'POST') return;

  let body;
  try {
    body = await request.json();
  } catch {
    return;
  }

  const jobId = body?.jobId;
  if (!jobId) return;

  const store = getStore(STORE_NAME);
  const startedAt = new Date().toISOString();
  await store.setJSON(jobId, { status: 'running', startedAt });

  try {
    const result = await runScan({ url: body.url, extraPages: body.extraPages });
    await store.setJSON(jobId, { status: 'done', result, startedAt, finishedAt: new Date().toISOString() });
  } catch (err) {
    await store.setJSON(jobId, { status: 'error', message: err.message || 'Unexpected error running scan', startedAt, finishedAt: new Date().toISOString() });
  }
};
