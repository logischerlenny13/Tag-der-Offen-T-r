const PHOTO_TTL_MS = 5 * 60 * 1000; // Exakt 5 Minuten
const MAX_ACTIVE_PHOTOS = 30;       // Maximal 30 Fotos (älteste werden ersetzt)
const MAX_FILE_SIZE_BYTES = 24 * 1024 * 1024;
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
  });

const toHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
const fromHex = (hex) => {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
};
const safeEqual = (a, b) => {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
};
const sha256 = async (str) => new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str)));

async function pbkdf2(pin, saltHex) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(pin), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: fromHex(saltHex), iterations: 100000, hash: 'SHA-256' },
    key,
    256
  );
  return toHex(new Uint8Array(bits));
}

function detectMime(b) {
  if (b.length < 12) return null;
  if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return 'image/jpeg';
  if (b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47 && b[4] === 0x0d && b[5] === 0x0a && b[6] === 0x1a && b[7] === 0x0a) return 'image/png';
  if (b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46 && b[8] === 0x57 && b[9] === 0x45 && b[10] === 0x42 && b[11] === 0x50) return 'image/webp';
  return null;
}

function fileNameFor(mime, ts) {
  const ext = mime === 'image/png' ? 'png' : mime === 'image/webp' ? 'webp' : 'jpg';
  const d = new Date(ts);
  const pad = (n) => String(n).padStart(2, '0');
  return `tag-der-offenen-tuer-${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}.${ext}`;
}

function getToken(req) {
  const h = req.headers.get('Authorization') || '';
  return h.startsWith('Bearer ') ? h.slice(7).trim() || null : null;
}

async function isValidSession(env, token) {
  if (!token) return false;
  const row = await env.DB.prepare('SELECT token, expires_at FROM sessions WHERE token = ?').bind(token).first();
  if (!row) return false;
  if (row.expires_at <= Date.now()) {
    await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
    return false;
  }
  return true;
}

async function createSession(env) {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  const token = toHex(bytes);
  const now = Date.now();
  await env.DB.prepare('DELETE FROM sessions WHERE expires_at <= ?').bind(now).run();
  await env.DB.prepare('INSERT INTO sessions (token, created_at, expires_at) VALUES (?, ?, ?)').bind(token, now, now + SESSION_TTL_MS).run();
  return { token, expiresInMs: SESSION_TTL_MS };
}

async function getPinStatus(env) {
  if (env.UPLOAD_PIN && env.UPLOAD_PIN.trim()) return { configured: true, envManaged: true, storedHash: null };
  const row = await env.DB.prepare('SELECT value FROM app_config WHERE key = ?').bind('pin_hash').first();
  return { configured: Boolean(row && row.value), envManaged: false, storedHash: row ? row.value : null };
}

async function verifyPin(env, candidate) {
  if (env.UPLOAD_PIN && env.UPLOAD_PIN.trim()) {
    return safeEqual(await sha256(candidate), await sha256(env.UPLOAD_PIN.trim()));
  }
  const st = await getPinStatus(env);
  if (!st.storedHash) return false;
  const [salt, hash] = st.storedHash.split(':');
  return safeEqual(fromHex(await pbkdf2(candidate, salt)), fromHex(hash));
}

async function purgeExpired(env, now) {
  const expired = await env.DB.prepare('SELECT id, r2_key FROM photos WHERE expires_at <= ?').bind(now).all();
  if (expired.results.length === 0) return;
  await Promise.all(expired.results.map((r) => env.PHOTOS_KV.delete(r.r2_key)));
  await env.DB.prepare('DELETE FROM photos WHERE expires_at <= ?').bind(now).run();
}

async function enforceMax30(env) {
  const overflow = await env.DB.prepare('SELECT id, r2_key FROM photos ORDER BY created_at DESC LIMIT -1 OFFSET ?').bind(MAX_ACTIVE_PHOTOS).all();
  if (overflow.results.length === 0) return;
  await Promise.all(overflow.results.map((r) => env.PHOTOS_KV.delete(r.r2_key)));
  for (const row of overflow.results) {
    await env.DB.prepare('DELETE FROM photos WHERE id = ?').bind(row.id).run();
  }
}

export async function onRequest({ request, env }) {
  if (!env.DB || !env.PHOTOS_KV) {
    return json({ error: 'Bitte DB (D1) und PHOTOS_KV (KV-Namespace) in Cloudflare Pages -> Einstellungen -> Bindungen verknüpfen.' }, 500);
  }
  const url = new URL(request.url);
  const sub = url.pathname.replace(/^\/api\/?/, '');
  const method = request.method.toUpperCase();
  const now = Date.now();

  if (sub === 'auth/status' && method === 'GET') {
    const st = await getPinStatus(env);
    return json({ configured: st.configured, envManaged: st.envManaged, authenticated: await isValidSession(env, getToken(request)) });
  }

  if (sub === 'auth/setup' && method === 'POST') {
    const st = await getPinStatus(env);
    if (st.envManaged || st.configured) return json({ error: 'Team-PIN ist bereits eingerichtet.' }, 403);
    const body = await request.json().catch(() => ({}));
    const pin = typeof body.pin === 'string' ? body.pin.trim() : '';
    if (pin.length < 4 || pin.length > 32) return json({ error: 'PIN muss 4–32 Zeichen haben.' }, 400);
    const salt = new Uint8Array(16); crypto.getRandomValues(salt);
    const saltHex = toHex(salt);
    await env.DB.prepare('INSERT INTO app_config (key, value) VALUES (?, ?)').bind('pin_hash', saltHex + ':' + (await pbkdf2(pin, saltHex))).run();
    return json({ ...(await createSession(env)), configured: true }, 201);
  }

  if (sub === 'auth/login' && method === 'POST') {
    const body = await request.json().catch(() => ({}));
    const pin = typeof body.pin === 'string' ? body.pin.trim() : '';
    if (!pin || !(await verifyPin(env, pin))) return json({ error: 'Team-PIN ist falsch.' }, 401);
    return json(await createSession(env));
  }

  if (sub === 'auth/logout' && method === 'POST') {
    const tok = getToken(request);
    if (tok) await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(tok).run();
    return json({ ok: true });
  }

  if (sub === 'photos' && method === 'GET') {
    await purgeExpired(env, now);
    const rows = await env.DB.prepare('SELECT * FROM photos WHERE expires_at > ? ORDER BY created_at DESC LIMIT ?').bind(now, MAX_ACTIVE_PHOTOS).all();
    return json({
      serverNow: now,
      ttlMs: PHOTO_TTL_MS,
      maxPhotos: MAX_ACTIVE_PHOTOS,
      photos: rows.results.map((r) => ({
        id: r.id, fileName: r.file_name, mimeType: r.mime_type, sizeBytes: r.size_bytes,
        width: r.width, height: r.height, createdAt: r.created_at, expiresAt: r.expires_at,
        remainingMs: Math.max(0, r.expires_at - now),
      })),
    });
  }

  if (sub === 'photos' && method === 'POST') {
    if (!(await isValidSession(env, getToken(request)))) return json({ error: 'Bitte mit Team-PIN anmelden.' }, 401);
    await purgeExpired(env, now);
    const fd = await request.formData().catch(() => null);
    const file = fd && fd.get('photo');
    if (!file || typeof file === 'string') return json({ error: 'Bitte eine Bilddatei auswählen.' }, 400);
    if (file.size === 0 || file.size > MAX_FILE_SIZE_BYTES) return json({ error: 'Maximal 15 MB pro Foto.' }, 413);

    const arrayBuffer = await file.arrayBuffer();
    const bytes = new Uint8Array(arrayBuffer);
    const mime = detectMime(bytes);
    if (!mime) return json({ error: 'Nur JPEG, PNG oder WebP erlaubt.' }, 400);

    const id = crypto.randomUUID();
    const createdAt = Date.now();
    const expiresAt = createdAt + PHOTO_TTL_MS;
    const fileName = fileNameFor(mime, createdAt);
    const kvKey = 'live:' + id;

    await env.PHOTOS_KV.put(kvKey, arrayBuffer, { expirationTtl: 300 });
    await env.DB.prepare(
      'INSERT INTO photos (id, r2_key, file_name, mime_type, size_bytes, width, height, created_at, expires_at) VALUES (?, ?, ?, ?, ?, NULL, NULL, ?, ?)'
    ).bind(id, kvKey, fileName, mime, bytes.length, createdAt, expiresAt).run();
    await enforceMax30(env);

    return json({ serverNow: createdAt, photo: { id, fileName, mimeType: mime, sizeBytes: bytes.length, width: null, height: null, createdAt, expiresAt, remainingMs: PHOTO_TTL_MS } }, 201);
  }

  const fileMatch = sub.match(/^photos\/([a-zA-Z0-9-]+)\/file$/);
  if (fileMatch && method === 'GET') {
    const row = await env.DB.prepare('SELECT * FROM photos WHERE id = ?').bind(fileMatch[1]).first();
    if (!row) return json({ error: 'Foto wurde bereits gelöscht.' }, 404);
    if (row.expires_at <= now) {
      await env.PHOTOS_KV.delete(row.r2_key);
      await env.DB.prepare('DELETE FROM photos WHERE id = ?').bind(row.id).run();
      return json({ error: 'Foto ist abgelaufen.' }, 404);
    }
    const stream = await env.PHOTOS_KV.get(row.r2_key, { type: 'stream' });
    if (!stream) return json({ error: 'Datei nicht mehr vorhanden.' }, 404);
    const disp = url.searchParams.get('download') === '1' ? 'attachment' : 'inline';
    return new Response(stream, {
      headers: {
        'Content-Type': row.mime_type,
        'Content-Length': String(row.size_bytes),
        'Content-Disposition': `${disp}; filename="${row.file_name}"`,
        'Cache-Control': 'no-store, no-cache, must-revalidate, private',
        'X-Content-Type-Options': 'nosniff',
      },
    });
  }

  const delMatch = sub.match(/^photos\/([a-zA-Z0-9-]+)$/);
  if (delMatch && method === 'DELETE') {
    if (!(await isValidSession(env, getToken(request)))) return json({ error: 'Bitte mit Team-PIN anmelden.' }, 401);
    const row = await env.DB.prepare('SELECT id, r2_key FROM photos WHERE id = ?').bind(delMatch[1]).first();
    if (!row) return json({ error: 'Nicht gefunden.' }, 404);
    await env.PHOTOS_KV.delete(row.r2_key);
    await env.DB.prepare('DELETE FROM photos WHERE id = ?').bind(row.id).run();
    return json({ ok: true });
  }

  return json({ error: 'Nicht gefunden.' }, 404);
}
