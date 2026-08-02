import { getStore } from '@netlify/blobs';

// Regular (synchronous) function that fronts the background scan. It exists specifically to
// close a race: a client that triggers run-scan-background.js directly and immediately starts
// polling scan-status.js can start polling before the background function has even begun
// executing — Background Functions are dispatched asynchronously and can have real queueing /
// cold-start delay before their code runs at all, which showed up in practice as a premature
// "Could not start the scan" error even though the scan would have completed fine given a
// moment longer. This function writes the initial "running" job record ITSELF, synchronously,
// so by the time it responds, the client is guaranteed a valid status to poll for — no waiting,
// no race, no arbitrary grace-retry timeout to tune.
const STORE_NAME = 'geo-scan-jobs';

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

  if (!body?.url || !String(body.url).trim()) {
    return new Response(JSON.stringify({ error: 'Enter a URL to scan.' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
  }

  const jobId = crypto.randomUUID();
  const store = getStore(STORE_NAME);
  await store.setJSON(jobId, { status: 'running', startedAt: new Date().toISOString() });

  // Await the trigger call itself (not its completion — background functions ack almost
  // immediately on invocation, well before the scan finishes). This has to be awaited rather
  // than fired-and-forgotten: once this handler returns its response, the serverless runtime can
  // freeze the execution context, and an in-flight fetch that hasn't been awaited can get cut off
  // before it actually reaches the network.
  const backgroundUrl = new URL('/.netlify/functions/run-scan-background', request.url);
  try {
    await fetch(backgroundUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jobId, url: body.url, extraPages: body.extraPages })
    });
  } catch (err) {
    // The trigger itself failed to even dispatch (rare) — surface it through the job record
    // rather than leaving the client polling a "running" status forever.
    await store.setJSON(jobId, { status: 'error', message: 'Could not start the background scan: ' + err.message, startedAt: new Date().toISOString(), finishedAt: new Date().toISOString() });
  }

  return new Response(JSON.stringify({ jobId }), { status: 200, headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' } });
};
