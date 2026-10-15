import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { test } from 'node:test';
import { createClient } from '@supabase/supabase-js';
import {
  COOKIE_NAME, cleanLabel, createDeviceGate, createSupabaseDeviceStore, deviceCookie, gateEnforced, hashDevice, newDeviceId,
  readDeviceId, requestCode,
} from '../src/device-approval.mjs';
import { createDeviceApi } from '../src/device-api.mjs';
import { createNotesApi } from '../src/notes-api.mjs';
import { createRestoreApi, contentSha256 } from '../src/restore-api.mjs';

const root = resolve(import.meta.dirname, '..');
const A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const NOTE = 'b0000000-0000-4000-8000-000000000001';

const res = () => {
  const r = { headers: {}, statusCode: 200, body: undefined };
  r.setHeader = (k, v) => { r.headers[k] = v; };
  r.status = (c) => { r.statusCode = c; return r; };
  r.json = (v) => { r.body = v; return r; };
  return r;
};
const req = (method, { token = 'tokA', cookie, body, id } = {}) => ({
  method, body, query: id ? { id } : {},
  headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), ...(cookie ? { cookie } : {}) },
});
const verify = async (authorization) => (authorization === 'Bearer tokA' ? { kind: 'student', userId: A }
  : authorization === 'Bearer tokB' ? { kind: 'student', userId: B } : null);
const quiet = async (work) => {
  const [w, e] = [console.warn, console.error];
  console.warn = () => {}; console.error = () => {};
  try { return await work(); } finally { console.warn = w; console.error = e; }
};

// 메모리 속 가짜 기기 표. status는 코드가 정할 수 없고 시험만 바꿀 수 있습니다(운영자 역할).
function memoryStore({ fail = {} } = {}) {
  const rows = [];
  const boom = (name) => { if (fail[name]) { const e = new Error('x'); e.code = 'UNAVAILABLE'; throw e; } };
  return {
    rows,
    operatorSets(status) { for (const row of rows) row.status = status; },
    async find(userId, hash) { boom('find'); const r = rows.find((x) => x.userId === userId && x.hash === hash); return r ? { id: r.id, status: r.status } : null; },
    async countPending(userId) { boom('count'); return rows.filter((x) => x.userId === userId && x.status === 'pending').length; },
    async createPending({ userId, hash, label }) {
      boom('create');
      const row = { id: `${String(rows.length + 1).padStart(8, '0')}-0000-4000-8000-000000000000`, userId, hash, label, status: 'pending' };
      rows.push(row);
      return { id: row.id, status: 'pending' };
    },
  };
}
const cookieOf = (response) => String(response.headers['Set-Cookie']).split(';')[0];

test('cookie helpers: only a well-formed 43-character id is read, and the cookie is HttpOnly, Secure, Strict', () => {
  const id = newDeviceId();
  assert.match(id, /^[A-Za-z0-9_-]{43}$/u);
  assert.notEqual(id, newDeviceId());
  assert.equal(readDeviceId({ headers: { cookie: `a=1; ${COOKIE_NAME}=${id}; b=2` } }), id);
  for (const bad of [undefined, '', `${COOKIE_NAME}=short`, `${COOKIE_NAME}=${id}x`, `other=${id}`, `${COOKIE_NAME}=${id.replace(/./u, '!')}`]) {
    assert.equal(readDeviceId({ headers: { cookie: bad } }), null, String(bad));
  }
  assert.equal(readDeviceId({}), null);
  const cookie = deviceCookie(id);
  for (const part of ['__Host-device=', 'Path=/', 'Secure', 'HttpOnly', 'SameSite=Strict', 'Max-Age=']) assert.ok(cookie.includes(part), part);
  assert.equal(cookie.includes('Domain'), false);
  assert.match(hashDevice(id), /^[0-9a-f]{64}$/u);
  assert.notEqual(hashDevice(id), id);
  assert.equal(requestCode('6f051b56-4bd6-4de0-ae67-3fe3d7e1c92c'), '6f051b56');
  assert.equal(cleanLabel('  내 \u0000노트북<b>  '), '내 노트북 b');
  assert.equal(cleanLabel('x'.repeat(100)).length, 40);
  for (const v of [undefined, 5, '', '   ', null]) assert.equal(cleanLabel(v), null);
});

test('GET /api/device needs a login, reports none before any request and never creates a row', async () => {
  const store = memoryStore();
  const api = createDeviceApi({ verify, getStore: () => store });
  assert.equal((await (async () => { const r = res(); await api.handle(req('GET', { token: null }), r); return r; })()).statusCode, 401);
  const r = res();
  await api.handle(req('GET'), r);
  assert.equal(r.statusCode, 200);
  assert.equal(r.body.state, 'none');
  assert.equal(store.rows.length, 0);
  for (const method of ['PUT', 'DELETE', 'PATCH']) {
    const m = res(); await api.handle(req(method), m);
    assert.equal(m.statusCode, 405);
  }
});

test('requesting approval creates one pending row, sets an HttpOnly cookie, and grants nothing', async () => {
  const store = memoryStore();
  const api = createDeviceApi({ verify, getStore: () => store });
  const r = res();
  await api.handle(req('POST', { body: { label: '내 노트북' } }), r);
  assert.equal(r.statusCode, 201);
  assert.equal(r.body.state, 'pending');
  assert.match(r.body.requestCode, /^[0-9a-f]{8}$/u);
  assert.equal(store.rows.length, 1);
  assert.equal(store.rows[0].status, 'pending');
  assert.equal(store.rows[0].label, '내 노트북');
  const cookie = cookieOf(r);
  assert.ok(String(r.headers['Set-Cookie']).includes('HttpOnly'));
  // 저장된 값은 해시이고 쿠키 원문이 아닙니다.
  const idValue = cookie.split('=')[1];
  assert.equal(store.rows[0].hash, hashDevice(idValue));
  assert.notEqual(store.rows[0].hash, idValue);
  assert.equal(JSON.stringify(r.body).includes(idValue), false, '응답 본문에 기기 식별자를 싣지 않습니다');

  // 같은 기기가 다시 눌러도 줄이 늘지 않고 새 쿠키도 주지 않습니다.
  const again = res();
  await api.handle(req('POST', { cookie }), again);
  assert.equal(again.statusCode, 200);
  assert.equal(again.body.state, 'pending');
  assert.equal(again.headers['Set-Cookie'], undefined);
  assert.equal(store.rows.length, 1);
});

test('the request body cannot approve: status, approved, userId and deviceId are never read', async () => {
  const store = memoryStore();
  const api = createDeviceApi({ verify, getStore: () => store });
  const r = res();
  await api.handle(req('POST', { body: { status: 'approved', approved: true, userId: B, deviceId: 'x'.repeat(43), label: 'a' } }), r);
  assert.equal(r.body.state, 'pending');
  assert.equal(store.rows[0].status, 'pending');
  assert.equal(store.rows[0].userId, A);
  assert.notEqual(store.rows[0].hash, hashDevice('x'.repeat(43)));
});

test('the operator, and only the operator, changes the state; the same cookie of another user stays separate', async () => {
  const store = memoryStore();
  const api = createDeviceApi({ verify, getStore: () => store });
  const first = res();
  await api.handle(req('POST'), first);
  const cookie = cookieOf(first);
  store.operatorSets('approved');
  const status = res(); await api.handle(req('GET', { cookie }), status);
  assert.equal(status.body.state, 'approved');
  assert.equal(status.body.requestCode, undefined, '승인된 뒤에는 요청 번호를 알리지 않습니다');
  // 다른 사람이 같은 브라우저로 로그인하면 그 사람은 승인된 것이 아닙니다.
  const other = res(); await api.handle(req('GET', { token: 'tokB', cookie }), other);
  assert.equal(other.body.state, 'none');
  // 회수되면 다시 요청해도 새 줄을 만들지 않고 revoked로 남습니다.
  store.operatorSets('revoked');
  const revoked = res(); await api.handle(req('POST', { cookie }), revoked);
  assert.equal(revoked.body.state, 'revoked');
  assert.equal(store.rows.length, 1);
});

test('too many pending requests are refused and store failures never grant anything', async () => {
  const store = memoryStore();
  const api = createDeviceApi({ verify, getStore: () => store });
  for (let i = 0; i < 5; i += 1) { const r = res(); await api.handle(req('POST'), r); assert.equal(r.statusCode, 201); }
  const sixth = res(); await api.handle(req('POST'), sixth);
  assert.equal(sixth.statusCode, 429);
  assert.equal(store.rows.length, 5);

  await quiet(async () => {
    const broken = createDeviceApi({ verify, getStore: () => memoryStore({ fail: { find: true } }) });
    const r = res(); await broken.handle(req('GET', { cookie: `${COOKIE_NAME}=${newDeviceId()}` }), r);
    assert.equal(r.statusCode, 502);
    assert.equal(r.body.state, undefined);
    const unconfigured = createDeviceApi({ verify, getStore: () => { throw new Error('not_configured'); } });
    const u = res(); await unconfigured.handle(req('GET'), u);
    assert.equal(u.statusCode, 500);
  });
});

test('the gate opens only for an approved device and fails closed on every other state or error', async () => {
  const store = memoryStore();
  const gate = createDeviceGate({ getStore: () => store, enforced: () => true });
  const id = newDeviceId();
  const cookie = `${COOKIE_NAME}=${id}`;
  const identity = { userId: A };
  assert.deepEqual(await gate(req('GET'), identity), { allowed: false, state: 'none' });
  assert.deepEqual(await gate(req('GET', { cookie }), identity), { allowed: false, state: 'none' });
  store.rows.push({ id: '11111111-0000-4000-8000-000000000000', userId: A, hash: hashDevice(id), status: 'pending' });
  assert.equal((await gate(req('GET', { cookie }), identity)).allowed, false);
  for (const status of ['revoked', 'APPROVED', 'approved ', '', 'ok', null]) {
    store.rows[0].status = status;
    assert.equal((await gate(req('GET', { cookie }), identity)).allowed, false, String(status));
  }
  store.rows[0].status = 'approved';
  assert.deepEqual(await gate(req('GET', { cookie }), identity), { allowed: true, state: 'approved' });
  assert.equal((await gate(req('GET', { cookie }), { userId: B })).allowed, false, '다른 사용자는 같은 쿠키로도 열 수 없습니다');
  const failing = createDeviceGate({ getStore: () => memoryStore({ fail: { find: true } }), enforced: () => true });
  await assert.rejects(failing(req('GET', { cookie }), identity));
});

test('only DEVICE_GATE=off disables the check', () => {
  assert.equal(gateEnforced({}), true);
  for (const value of ['on', 'OFF', 'false', '0', '', 'no', ' off']) assert.equal(gateEnforced({ DEVICE_GATE: value }), true, value);
  assert.equal(gateEnforced({ DEVICE_GATE: 'off' }), false);
});

function notesWithGate(store) {
  const notes = { async list() { return []; }, async ownerOf() { return null; } };
  return createNotesApi({ verify, getStore: () => notes, gate: createDeviceGate({ getStore: () => store, enforced: () => true }) });
}

test('the notes API stays closed with 403 until the device is approved, then behaves as before', async () => {
  const store = memoryStore();
  const api = notesWithGate(store);
  const call = async (request) => { const r = res(); await api.collection(request, r); return r; };
  await quiet(async () => {
    const none = await call(req('GET'));
    assert.equal(none.statusCode, 403);
    assert.equal(none.body.error, 'DEVICE_NOT_APPROVED');
    assert.equal(none.body.deviceState, 'none');
    assert.equal(Array.isArray(none.body), false);
    assert.deepEqual(Object.keys(none.body).sort(), ['deviceState', 'error', 'message']);
    // 로그인 없는 요청은 기기 상태와 상관없이 401입니다.
    assert.equal((await call(req('GET', { token: null }))).statusCode, 401);
    // 요청만 한 상태(pending)에서도 닫혀 있습니다.
    const deviceApi = createDeviceApi({ verify, getStore: () => store });
    const asked = res(); await deviceApi.handle(req('POST'), asked);
    const cookie = cookieOf(asked);
    const pending = await call(req('GET', { cookie }));
    assert.equal(pending.statusCode, 403);
    assert.equal(pending.body.deviceState, 'pending');
    // 쓰기 요청도 같습니다.
    const write = res(); await api.collection(req('POST', { cookie, body: { title: 't', body: 'b' } }), write);
    assert.equal(write.statusCode, 403);
    // 운영자가 승인하면 열립니다.
    store.operatorSets('approved');
    const open = await call(req('GET', { cookie }));
    assert.equal(open.statusCode, 200);
    assert.deepEqual(open.body, []);
    // 승인은 그 사람 것입니다. 같은 쿠키라도 다른 사용자는 닫혀 있습니다.
    assert.equal((await call(req('GET', { token: 'tokB', cookie }))).statusCode, 403);
    // 기기 확인이 고장 나면 열지 않습니다.
    const broken = notesWithGate(memoryStore({ fail: { find: true } }));
    const down = res(); await broken.collection(req('GET', { cookie }), down);
    assert.equal(down.statusCode, 503);
    assert.equal(down.body.error, 'DEVICE_CHECK_UNAVAILABLE');
  });
});

test('the single-note and restore routes use the same gate', async () => {
  const store = memoryStore();
  const gate = createDeviceGate({ getStore: () => store, enforced: () => true });
  const notes = createNotesApi({ verify, getStore: () => ({ async ownerOf() { return null; } }), gate });
  const restore = createRestoreApi({ verify, getStore: () => { throw new Error('must not be reached'); }, gate });
  await quiet(async () => {
    const item = res(); await notes.item(req('GET', { id: NOTE }), item);
    assert.equal(item.statusCode, 403);
    const back = res(); await restore.restoreOne(req('POST', { id: NOTE }), back);
    assert.equal(back.statusCode, 403);
    assert.equal(back.body.error, 'DEVICE_NOT_APPROVED');
  });
});

test('production instances are wired with the gate', async () => {
  for (const file of ['src/notes-api.mjs', 'src/restore-api.mjs']) {
    const source = await readFile(resolve(root, file), 'utf8');
    assert.match(source, /gate: defaultGate/u, file);
  }
  const apiFile = await readFile(resolve(root, 'api/device/index.js'), 'utf8');
  assert.match(apiFile, /deviceApi\.handle\(request, response\)/u);
});

test('Supabase adapter never sends a status, and sends only user_id, device_hash and label', async () => {
  const seen = [];
  const client = createClient('https://fake-project.supabase.co', 'fake-key', {
    global: { fetch: async (url, init) => {
      seen.push({ url: String(url), method: init?.method ?? 'GET', body: init?.body ? String(init.body) : null });
      const created = (init?.method ?? 'GET') === 'POST';
      return new Response(JSON.stringify(created ? { id: '6f051b56-4bd6-4de0-ae67-3fe3d7e1c92c' } : null), {
        status: created ? 201 : 200, headers: { 'content-type': 'application/json' } });
    } },
    auth: { persistSession: false, autoRefreshToken: false },
  });
  const store = createSupabaseDeviceStore(client);
  await store.find(A, 'a'.repeat(64));
  const row = await store.createPending({ userId: A, hash: 'a'.repeat(64), label: '내 노트북' });
  assert.equal(row.status, 'pending');
  const insert = seen.find((x) => x.method === 'POST');
  assert.deepEqual(JSON.parse(insert.body), { user_id: A, device_hash: 'a'.repeat(64), label: '내 노트북' });
  assert.equal(seen.some((x) => x.method === 'PATCH' || x.method === 'DELETE' || x.method === 'PUT'), false);
  assert.ok(seen[0].url.includes('user_id=eq.') && seen[0].url.includes('device_hash=eq.'));
});

test('the device SQL keeps status out of the server key and stores no memo text', async () => {
  const sql = await readFile(resolve(root, 'sql/11-device-approvals.sql'), 'utf8');
  for (const needle of ['enable row level security', "default 'pending'", "device_hash ~ '^[0-9a-f]{64}$'",
    'revoke all on table public.device_approvals from public, anon, authenticated',
    'revoke all on table public.device_approvals from service_role',
    'grant select on table public.device_approvals to service_role',
    'grant insert (user_id, device_hash, label) on table public.device_approvals to service_role']) {
    assert.ok(sql.includes(needle), needle);
  }
  assert.equal(/grant[^;]*\b(update|delete|all)\b[^;]*service_role/iu.test(sql), false);
  assert.equal(/@|sb_secret|eyJ/iu.test(sql), false);
  void contentSha256;
});

// ---- 화면·설치 설정 정적 점검 ----------------------------------------------------
import { readFile as readFileStatic } from 'node:fs/promises';
import { existsSync } from 'node:fs';
const rootDir = new URL('..', import.meta.url).pathname;

test('page keeps no device key or token in browser storage and asks the server for the device state', async () => {
  const page = await readFileStatic(`${rootDir}public/index.html`, 'utf8');
  assert.equal(/localStorage|sessionStorage|indexedDB|document\.cookie/u.test(page), false);
  assert.match(page, /persistSession:\s*false/u);
  assert.match(page, /'\/api\/device'/u);
  assert.match(page, /rel="manifest"/u);
  assert.match(page, /serviceWorker/u);
  // 메모 영역은 서버가 approved라고 답한 뒤에만 열립니다.
  assert.match(page, /info\?\.state === 'approved'/u);
});

test('manifest names the app, points at real icons, and the worker never touches api routes', async () => {
  const manifest = JSON.parse(await readFileStatic(`${rootDir}public/manifest.webmanifest`, 'utf8'));
  assert.ok(manifest.name && manifest.short_name);
  assert.equal(manifest.display, 'standalone');
  for (const icon of manifest.icons) assert.ok(existsSync(`${rootDir}public${icon.src}`), icon.src);
  const worker = await readFileStatic(`${rootDir}public/sw.js`, 'utf8');
  assert.match(worker, /\/api/u);
  assert.match(worker, /navigate/u);
  const offline = await readFileStatic(`${rootDir}public/offline.html`, 'utf8');
  assert.match(offline, /오프라인|연결/u);
});
