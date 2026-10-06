import assert from 'node:assert/strict';
import { access, readFile, readdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { test } from 'node:test';
import { createClient } from '@supabase/supabase-js';
import { createNotesApi, createSupabaseStore } from '../src/notes-api.mjs';
import { createLoginVerifier } from '../src/verify-login.mjs';
import config from '../aleph.config.json' with { type: 'json' };

const root = resolve(import.meta.dirname, '..');
// 시험용 가짜 값입니다. 실제 키나 주소가 아닙니다.
const FAKE_URL = 'https://fake-project.supabase.co';
const FAKE_KEY = 'fake-secret-key-for-tests-only';
const A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const OTHER_ID = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';

function fakeResponse() {
  const res = { headers: {}, statusCode: 200, body: undefined };
  res.setHeader = (name, value) => { res.headers[name] = value; };
  res.status = (code) => { res.statusCode = code; return res; };
  res.json = (value) => { res.body = value; return res; };
  return res;
}
const req = (method, { token, body, id, headers } = {}) => ({
  method, body, query: id ? { id } : {},
  headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), ...headers },
});

// 토큰 검사는 가짜로 대신합니다. 실제 검사는 틀의 src/verify-login.mjs가 합니다.
const verify = async (authorization) => {
  if (authorization === 'Bearer tokA') return { kind: 'student', userId: A };
  if (authorization === 'Bearer tokB') return { kind: 'student', userId: B };
  return null;
};

function memoryStore() {
  const rows = new Map();
  const view = ({ id, title, content }) => ({ id, title, body: content });
  return {
    rows,
    async list(userId) {
      return [...rows.values()].filter((r) => r.ownerId === userId || r.ownerId === null).map(view);
    },
    async get(id) { return rows.has(id) ? view(rows.get(id)) : null; },
    async create({ id, ownerId, title, content }) {
      if (rows.has(id)) { const e = new Error('dup'); e.code = 'CONFLICT'; throw e; }
      rows.set(id, { id, ownerId, title, content });
      return id;
    },
    async update(id, { title, content }) {
      if (!rows.has(id)) return null;
      rows.set(id, { ...rows.get(id), title, content });
      return view(rows.get(id));
    },
    async remove(id) { return rows.delete(id); },
  };
}

function setup() {
  const store = memoryStore();
  store.rows.set(OTHER_ID, { id: OTHER_ID, ownerId: null, title: '시작 틀 메모', content: '주인 없는 가상 메모' });
  return { store, api: createNotesApi({ verify, getStore: () => store }) };
}

async function call(handlerFn, request) {
  const res = fakeResponse();
  await handlerFn(request, res);
  return res;
}

test('requests without a valid login are rejected with a JSON error and no data', async () => {
  const { store, api } = setup();
  let verifyCalls = 0;
  const counting = createNotesApi({ verify: async (a) => { verifyCalls += 1; return verify(a); }, getStore: () => store });

  for (const [fn, request] of [
    [counting.collection, req('GET')],
    [counting.collection, req('POST', { body: { title: 't', body: 'b' } })],
    [counting.item, req('GET', { id: OTHER_ID })],
    [counting.item, req('PUT', { id: OTHER_ID, body: { title: 't', body: 'b' } })],
    [counting.item, req('DELETE', { id: OTHER_ID })],
  ]) {
    const res = await call(fn, request);
    assert.equal(res.statusCode, 401);
    assert.equal(res.body.error, 'UNAUTHORIZED');
    assert.equal(typeof res.body.message, 'string');
    assert.equal(res.headers['WWW-Authenticate'], 'Bearer');
    assert.equal(JSON.stringify(res.body).includes('시작 틀 메모'), false);
  }
  assert.equal(verifyCalls, 0, '토큰이 없으면 검사기를 부르지 않고 바로 거부합니다.');

  const bad = await call(api.collection, req('GET', { token: 'forged' }));
  assert.equal(bad.statusCode, 401);
  assert.equal(bad.body.error, 'UNAUTHORIZED');
  assert.equal(store.rows.size, 1, '거부된 요청은 아무것도 바꾸지 못합니다.');
});

test('a verifier that cannot start gives a generic 500 without secrets', async () => {
  const { store } = setup();
  const broken = createNotesApi({ verify: async () => { throw new Error(`boom ${FAKE_KEY}`); }, getStore: () => store });
  const logged = [];
  const saved = console.error;
  console.error = (...args) => logged.push(args.map(String).join(' '));
  try {
    const res = await call(broken.collection, req('GET', { token: 'tokA' }));
    assert.equal(res.statusCode, 500);
    assert.equal(res.body.error, 'NOT_CONFIGURED');
    assert.equal(JSON.stringify([res.body, logged]).includes(FAKE_KEY), false);
  } finally { console.error = saved; }
});

test('POST stores the verified user id as owner and ignores client-sent identity', async () => {
  const { store, api } = setup();
  const res = await call(api.collection, req('POST', {
    token: 'tokA',
    headers: { 'x-user-id': B, 'x-role': 'admin' },
    body: { title: '  첫 메모 ', body: '내용', owner_id: B, userId: B, role: 'admin' },
  }));
  assert.equal(res.statusCode, 201);
  assert.deepEqual(Object.keys(res.body), ['id']);
  assert.match(res.body.id, /^[0-9a-f-]{36}$/u);
  const saved = store.rows.get(res.body.id);
  assert.equal(saved.ownerId, A);
  assert.equal(saved.title, '첫 메모');

  const given = await call(api.collection, req('POST', { token: 'tokB', body: { id: OTHER_ID.replace(/^c/u, 'd'), title: 't', body: '' } }));
  assert.equal(given.statusCode, 201);
  assert.equal(given.body.id, OTHER_ID.replace(/^c/u, 'd'));
  assert.equal(store.rows.get(given.body.id).ownerId, B);

  const dup = await call(api.collection, req('POST', { token: 'tokB', body: { id: given.body.id, title: 't', body: '' } }));
  assert.equal(dup.statusCode, 409);

  for (const body of [undefined, 'x', { title: '', body: 'b' }, { title: 't' }, { title: 't', body: 3 },
    { title: 'x'.repeat(201), body: 'b' }, { title: 't', body: 'b', id: 'not-a-uuid' }]) {
    const invalid = await call(api.collection, req('POST', { token: 'tokA', body }));
    assert.equal(invalid.statusCode, 400);
    assert.equal(invalid.body.error, 'INVALID_REQUEST');
  }
});

test('list, read, update and delete work for a logged-in user', async () => {
  const { api } = setup();
  const created = await call(api.collection, req('POST', { token: 'tokA', body: { title: '메모', body: '내용' } }));
  const { id } = created.body;

  const list = await call(api.collection, req('GET', { token: 'tokA' }));
  assert.equal(list.statusCode, 200);
  assert.ok(Array.isArray(list.body));
  assert.ok(list.body.some((n) => n.id === id && n.title === '메모' && n.body === '내용'));
  for (const note of list.body) assert.deepEqual(Object.keys(note).sort(), ['body', 'id', 'title']);

  const bList = await call(api.collection, req('GET', { token: 'tokB' }));
  assert.equal(bList.body.some((n) => n.id === id), false, '목록은 로그인한 본인의 메모만 보여 줍니다.');

  const one = await call(api.item, req('GET', { token: 'tokA', id }));
  assert.deepEqual(one.body, { id, title: '메모', body: '내용' });

  const put = await call(api.item, req('PUT', { token: 'tokA', id, body: { title: '고침', body: '새 내용' } }));
  assert.equal(put.statusCode, 200);
  assert.deepEqual(put.body, { id, title: '고침', body: '새 내용' });
  const badPut = await call(api.item, req('PUT', { token: 'tokA', id, body: { title: '' } }));
  assert.equal(badPut.statusCode, 400);

  const del = await call(api.item, req('DELETE', { token: 'tokA', id }));
  assert.equal(del.statusCode, 200);
  const gone = await call(api.item, req('GET', { token: 'tokA', id }));
  assert.equal(gone.statusCode, 404);
  assert.equal(gone.body.error, 'NOT_FOUND');
  assert.equal((await call(api.item, req('DELETE', { token: 'tokA', id }))).statusCode, 404);
  assert.equal((await call(api.item, req('GET', { token: 'tokA', id: 'not-a-uuid' }))).statusCode, 404);
});

test('known weakness: another logged-in user can still change a memo by id (fixed in step 4)', async () => {
  const { api } = setup();
  const { body: { id } } = await call(api.collection, req('POST', { token: 'tokA', body: { title: 'A의 메모', body: '비공개여야 함' } }));
  const read = await call(api.item, req('GET', { token: 'tokB', id }));
  assert.equal(read.statusCode, 200, '4단계 전에는 소유자를 검사하지 않습니다.');
  const edit = await call(api.item, req('PUT', { token: 'tokB', id, body: { title: 'B가 고침', body: 'x' } }));
  assert.equal(edit.statusCode, 200);
});

test('other HTTP methods are rejected', async () => {
  const { api } = setup();
  const c = await call(api.collection, req('DELETE', { token: 'tokA' }));
  assert.equal(c.statusCode, 405);
  assert.equal(c.headers.Allow, 'GET, POST');
  const i = await call(api.item, req('POST', { token: 'tokA', id: OTHER_ID }));
  assert.equal(i.statusCode, 405);
  assert.equal(i.headers.Allow, 'GET, PUT, DELETE');
});

async function withFetch(fake, run) {
  const original = globalThis.fetch;
  const savedError = console.error;
  const logged = [];
  globalThis.fetch = fake;
  console.error = (...args) => logged.push(args.map(String).join(' '));
  try { return await run(logged); } finally {
    globalThis.fetch = original;
    console.error = savedError;
  }
}
const jsonResponse = (value, status = 200) => new Response(JSON.stringify(value), {
  status, headers: { 'content-type': 'application/json' },
});
const storeFor = () => createSupabaseStore(createClient(FAKE_URL, FAKE_KEY, {
  auth: { persistSession: false, autoRefreshToken: false },
}));

test('the Supabase store reads study_notes with the server key and maps content to body', async () => {
  let seen;
  await withFetch(async (input, init) => {
    seen = { url: decodeURIComponent(String(input?.url ?? input)), key: new Headers(init?.headers ?? input?.headers).get('apikey') };
    return jsonResponse([{ id: A, title: 'T', content: 'C', owner_id: B }]);
  }, async (logged) => {
    const notes = await storeFor().list(A);
    assert.deepEqual(notes, [{ id: A, title: 'T', body: 'C' }]);
    assert.ok(seen.url.startsWith(`${FAKE_URL}/rest/v1/study_notes`));
    assert.ok(seen.url.includes(`owner_id.eq.${A}`) && seen.url.includes('owner_id.is.null'));
    assert.equal(seen.key, FAKE_KEY);
    assert.equal(logged.length, 0);
  });
});

test('store errors become codes only and never carry the key, address or upstream message', async () => {
  await withFetch(async () => jsonResponse({ code: '42501', message: `denied ${FAKE_KEY} ${FAKE_URL}` }, 403), async () => {
    await assert.rejects(() => storeFor().list(A), (error) => {
      assert.equal(error.code, 'UNAVAILABLE');
      assert.equal(JSON.stringify([error.message, error.code, error.upstreamCode]).includes(FAKE_KEY), false);
      assert.equal(error.message.includes(FAKE_URL), false);
      return true;
    });
  });
  await withFetch(async () => jsonResponse({ code: '23505', message: 'duplicate' }, 409), async () => {
    await assert.rejects(() => storeFor().create({ id: A, ownerId: A, title: 't', content: 'c' }),
      (error) => error.code === 'CONFLICT');
  });
});

test('the API turns a store failure into a generic 502 without secrets', async () => {
  const failing = createNotesApi({ verify, getStore: () => ({ list: async () => {
    const e = new Error('store_failed'); e.code = 'UNAVAILABLE'; e.upstreamCode = '42501'; throw e;
  } }) });
  const logged = [];
  const saved = console.error;
  console.error = (...args) => logged.push(args.map(String).join(' '));
  try {
    const res = await call(failing.collection, req('GET', { token: 'tokA' }));
    assert.equal(res.statusCode, 502);
    assert.equal(res.body.error, 'UNAVAILABLE');
    assert.deepEqual(logged, ['notes_store_failed 42501']);
  } finally { console.error = saved; }
});

test('aleph.config.json is ready for step 3 and the login helper accepts it', async () => {
  assert.equal(config.step, 3);
  assert.deepEqual(Object.keys(config.identityProvider).sort(), ['audience', 'issuer', 'jwksUrl']);
  assert.equal(config.identityProvider.jwksUrl, `${config.identityProvider.issuer}/.well-known/jwks.json`);
  assert.ok(config.identityProvider.issuer.endsWith('.supabase.co/auth/v1'));
  assert.deepEqual([...config.allowedRoutes].sort(), ['/api/notes', '/api/notes/:id']);
  // 도우미가 설정을 받아들이는지만 봅니다(가짜 서버 키, 네트워크 요청 없음).
  const verifyLogin = createLoginVerifier({ config, supabaseSecretKey: FAKE_KEY });
  assert.equal(await verifyLogin(undefined), null);
  assert.equal(await verifyLogin('Bearer not.a.jwt'), null);
});

test('route files exist and the old public notes function is gone', async () => {
  await access(resolve(root, 'api', 'notes', 'index.js'));
  await access(resolve(root, 'api', 'notes', '[id].js'));
  await assert.rejects(() => access(resolve(root, 'api', 'notes.js')));
});

test('browser files hold no memos or key names, use the official SDK and call the API', async () => {
  const publicData = JSON.parse(await readFile(resolve(root, 'public', 'data.json'), 'utf8'));
  const sourceData = JSON.parse(await readFile(resolve(root, 'data.json'), 'utf8'));
  assert.deepEqual(publicData.notes, []);
  assert.deepEqual(sourceData.notes, []);

  const files = (await readdir(resolve(root, 'public'), { recursive: true })).filter((f) => /\.(html|json|js|mjs|css)$/u.test(f));
  for (const file of files) {
    const text = await readFile(resolve(root, 'public', file), 'utf8');
    assert.equal(/SUPABASE_SECRET_KEY|sb_secret_|service_role/u.test(text), false, `${file}에 비밀 키 이름이 있습니다.`);
  }
  const page = await readFile(resolve(root, 'public', 'index.html'), 'utf8');
  const pkg = JSON.parse(await readFile(resolve(root, 'package.json'), 'utf8'));
  assert.ok(page.includes(`@supabase/supabase-js@${pkg.dependencies['@supabase/supabase-js']}/+esm`),
    '화면은 package.json과 같은 버전의 공식 SDK를 씁니다.');
  assert.match(page, /signInWithPassword/u);
  assert.match(page, /signOut\(/u);
  assert.match(page, /'\/api\/notes'/u);
  assert.match(page, /Authorization/u);
  assert.equal(page.includes("fetch('/data.json'"), false);
});
