import { getStore } from '@netlify/blobs';

const STORE_NAME = 'geo-scan-jobs';

export default async (request) => {
  if (request.method !== 'GET') {
    return new Response('Method Not Allowed', { status: 405 });
  }

  const url = new URL(request.url);
  const jobId = url.searchParams.get('jobId');
  if (!jobId) {
    return new Response(JSON.stringify({ error: 'Missing jobId' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
  }

  const store = getStore(STORE_NAME);
  const record = await store.get(jobId, { type: 'json' });

  // Not an error — the background function may not have written its first "running" status yet.
  // The frontend treats this as "keep polling" rather than "something went wrong."
  if (!record) {
    return new Response(JSON.stringify({ status: 'not_found' }), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'no-store' }
    });
  }

  return new Response(JSON.stringify(record), {
    status: 200,
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'no-store' }
  });
};
