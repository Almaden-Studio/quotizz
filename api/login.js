export const config = { runtime: 'edge' };

const COOKIE_NAME = 'quotizz_auth';
const SESSION_HOURS = 24 * 7; // 7 days

function bytesToB64url(bytes) {
  let bin = '';
  bytes.forEach((b) => (bin += String.fromCharCode(b)));
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function sign(payloadB64, secret) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payloadB64));
  return bytesToB64url(new Uint8Array(sig));
}

export default async function handler(request) {
  if (request.method !== 'POST') {
    return new Response('Method not allowed', { status: 405 });
  }

  const { password } = await request.json().catch(() => ({}));
  const correctPassword = process.env.SITE_PASSWORD;
  const secret = process.env.COOKIE_SECRET;

  if (!correctPassword || !secret) {
    return new Response(
      JSON.stringify({ ok: false, error: 'Server not configured' }),
      { status: 500, headers: { 'Content-Type': 'application/json' } }
    );
  }

  if (!password || password !== correctPassword) {
    return new Response(
      JSON.stringify({ ok: false, error: 'Incorrect password' }),
      { status: 401, headers: { 'Content-Type': 'application/json' } }
    );
  }

  const exp = Date.now() + SESSION_HOURS * 60 * 60 * 1000;
  const payloadB64 = bytesToB64url(new TextEncoder().encode(JSON.stringify({ exp })));
  const sig = await sign(payloadB64, secret);
  const token = `${payloadB64}.${sig}`;

  const cookie = `${COOKIE_NAME}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${
    SESSION_HOURS * 3600
  }`;

  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Set-Cookie': cookie,
    },
  });
}
