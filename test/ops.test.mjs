// 12단계: 탈환 작전실 서버 요약, 실측 표 도구, 화면 정적 점검
import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { createOpsApi, createSupabaseOpsStore, NOT_RUN, SUMMARY_SCHEMA } from '../src/ops-api.mjs';
import { buildCases, renderMarkdown, runMatrix } from '../scripts/verify-matrix.mjs';

const A = '11111111-1111-4111-8111-111111111111';
const B = '22222222-2222-4222-8222-222222222222';
const root = new URL('..', import.meta.url).pathname;

const verify = async (header) => (header === 'Bearer tokA' ? { userId: A } : header === 'Bearer tokB' ? { userId: B } : null);
const makeRes = () => {
  const res = { statusCode: 200, headers: {}, body: null,
    setHeader(k, v) { this.headers[k] = v; }, status(c) { this.statusCode = c; return this; }, json(b) { this.body = b; return this; }, end(b) { this.body = b; return this; } };
  return res;
};
const call = async (api, { method = 'GET', token = 'tokA', headers = {} } = {}) => {
  const res = makeRes();
  await api.handle({ method, headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), ...headers }, query: {} }, res);
  return res;
};
const rawBody = (res) => (typeof res.body === 'string' ? JSON.parse(res.body) : res.body);

const fakeStore = (over = {}) => ({
  devices: async (u) => (u === A ? [{ status: 'approved' }, { status: 'pending' }, { status: 'revoked' }, { status: 'approved' }] : []),
  backups: async (u) => (u === A ? [{ backed_up_at: '2026-10-01T00:00:00Z' }, { backed_up_at: '2026-10-05T00:00:00Z' }] : []),
  audit: async (u) => (u === A ? [{ action: 'restore_note', result: 'restored', at: '2026-10-06T00:00:00Z' }, { action: 'restore_note', result: 'denied_owner', at: '2026-10-07T00:00:00Z' }] : []),
  ...over,
});
const practice = async () => ({ decider: { status: 'practice', ruleIds: ['device_registered'], total: 4, passed: 4 }, detect: { status: 'practice', rules: ['burst_read'], total: 6, passed: 6 } });
const allow = async () => ({ allowed: true, state: 'approved' });
const deny = async () => ({ allowed: false, state: 'pending' });

test('ops summary needs a login and an approved device, and fails closed', async () => {
  const api = createOpsApi({ verify, getStore: () => fakeStore(), gate: allow, practice });
  assert.equal((await call(api, { token: null })).statusCode, 401);
  assert.equal((await call(api, { token: 'bad' })).statusCode, 401);
  assert.equal((await call(createOpsApi({ verify, getStore: () => fakeStore(), gate: deny, practice }))).statusCode, 403);
  const broken = createOpsApi({ verify, getStore: () => fakeStore(), gate: async () => { throw new Error('x'); }, practice });
  assert.equal((await call(broken)).statusCode, 503);
  assert.equal((await call(api, { method: 'POST' })).statusCode, 405);
});

test('ops summary counts what the store returns, per signed-in user, and marks what was not run', async () => {
  const api = createOpsApi({ verify, getStore: () => fakeStore(), gate: allow, practice, now: () => new Date('2026-10-15T00:00:00Z') });
  const res = await call(api, { headers: { 'x-vercel-id': 'icn1::abc-123' } });
  assert.equal(res.statusCode, 200);
  const body = rawBody(res);
  assert.equal(body.schema, SUMMARY_SCHEMA);
  assert.equal(body.requestId, 'icn1::abc-123');
  assert.equal(body.generatedAt, '2026-10-15T00:00:00.000Z');
  assert.deepEqual(body.sections.revoke.devices, { pending: 1, approved: 2, revoked: 1 });
  assert.equal(body.sections.revoke.status, 'confirmed');
  assert.equal(body.sections.restore.backups.count, 2);
  assert.equal(body.sections.restore.backups.latestAt, '2026-10-05T00:00:00.000Z');
  assert.deepEqual(body.sections.restore.audit.byResult, { restored: 1, denied_owner: 1 });
  assert.equal(body.sections.decider.status, 'practice');
  assert.deepEqual(body.notRun.map((n) => n.id), NOT_RUN.map((n) => n.id));
  assert.ok(body.notRun.some((n) => n.id === 'attack_41'));
  // 다른 사용자는 자기 기록만 봅니다(A의 줄이 섞이지 않음).
  const other = rawBody(await call(api, { token: 'tokB' }));
  assert.equal(other.sections.restore.backups.count, 0);
  assert.deepEqual(other.sections.revoke.devices, { pending: 0, approved: 0, revoked: 0 });
});

test('ops summary never carries note bodies, titles, emails or tokens, and a store failure gives no numbers', async () => {
  const api = createOpsApi({ verify, getStore: () => fakeStore(), gate: allow, practice });
  const text = JSON.stringify(rawBody(await call(api)));
  assert.equal(/title|content|body|email|token|Bearer|owner_id|content_sha256/iu.test(text.replace(/"restore_note"/gu, '')), false);
  const failing = createOpsApi({ verify, getStore: () => fakeStore({ audit: async () => { throw new Error('boom'); } }), gate: allow, practice });
  const res = await call(failing);
  assert.equal(res.statusCode, 502);
  assert.equal(rawBody(res).error, 'UNAVAILABLE');
  assert.equal('sections' in rawBody(res), false);
});

test('ops store reads only counting columns', async () => {
  const seen = [];
  const chain = (table) => { const q = { select(cols) { seen.push([table, cols]); return q; }, eq() { return q; }, order() { return q; }, limit() { return q; }, then(res) { res({ data: [], error: null }); } }; return q; };
  const store = createSupabaseOpsStore({ from: chain });
  await store.devices(A); await store.backups(A); await store.audit(A);
  assert.deepEqual(seen, [['device_approvals', 'status'], ['study_notes_backup', 'backed_up_at'], ['study_notes_audit', 'action, result, at']]);
});

// ---- 실측 표 ---------------------------------------------------------------
function fakeNetwork({ approved = true } = {}) {
  const calls = [];
  const json = (status, body, headers = {}) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', 'x-vercel-id': `icn1::req-${calls.length}`, ...headers } });
  const impl = async (url, init = {}) => {
    const u = new URL(String(url));
    const headers = init.headers ?? {};
    calls.push({ method: init.method ?? 'GET', url: String(url), headers });
    if (u.pathname === '/aleph.json') return json(200, { database: { url: 'https://db.example.test', publishableKey: 'pub-key' }, originalApiUrl: 'https://db.example.test/rest/v1/study_notes' });
    if (u.pathname === '/auth/v1/token') return json(200, { access_token: JSON.parse(init.body).email.startsWith('a') ? 'tokA' : 'tokB' });
    if (u.hostname === 'db.example.test' && u.pathname.startsWith('/rest/')) return json(401, { message: 'no' });
    const auth = headers.Authorization; const cookie = headers.Cookie;
    if (u.pathname === '/') return new Response('<html></html>', { status: 200, headers: { 'content-type': 'text/html' } });
    if (u.pathname === '/data.json') return json(200, { notes: [] });
    if (u.pathname === '/manifest.webmanifest') return json(200, { name: 'BYTE BACK 자료실' });
    if (u.pathname === '/api/no-such-route') return json(404, { error: 'NOT_FOUND' });
    if (u.pathname === '/api/device') {
      if (!auth) return json(401, { error: 'UNAUTHORIZED' });
      if ((init.method ?? 'GET') === 'POST') return json(200, { state: 'pending' }, { 'set-cookie': `__Host-device=${'x'.repeat(43)}; Path=/; Secure; HttpOnly` });
      return json(200, { state: cookie && approved ? 'approved' : cookie ? 'pending' : 'none' });
    }
    if (!auth) return json(401, { error: 'UNAUTHORIZED' });
    if (!cookie || !approved) return json(403, { error: 'DEVICE_NOT_APPROVED', deviceState: 'none' });
    if (u.pathname === '/api/notes') return json(200, auth.endsWith('tokA') ? [{ id: 'note-a-1', title: 'SECRET TITLE', body: 'SECRET BODY' }] : []);
    if (u.pathname.startsWith('/api/notes/')) return json(404, { error: 'NOT_FOUND' });
    if (u.pathname.startsWith('/api/restore/')) return json(404, { error: 'NOT_FOUND' });
    if (u.pathname === '/api/ops/summary') return json(200, { schema: 'aleph.ops.summary.v1' });
    return json(500, { error: 'x' });
  };
  return { impl, calls };
}
const stamp = () => new Date('2026-10-15T01:00:00Z');

test('matrix without logins runs only anonymous rows and leaves the rest not_run', async () => {
  const net = fakeNetwork();
  const result = await runMatrix({ base: 'https://app.example.test', env: {}, fetchImpl: net.impl, now: stamp });
  const byId = Object.fromEntries(result.rows.map((r) => [r.id, r]));
  for (const id of ['s1-home', 's2-data-json', 's3-notes-anon', 's4-note-anon', 's5-original-direct', 's10-restore-anon', 's10-unmatched', 's11-manifest', 's11-device-anon', 's12-ops-anon']) {
    assert.equal(byId[id].verdict, 'match', id);
    assert.match(byId[id].requestId, /^icn1::req-\d+$|^없음$/u);
    assert.equal(byId[id].checkedAt, '2026-10-15T01:00:00.000Z');
  }
  for (const id of ['s3-notes-A', 's11-device-A', 's4-s8-cross-read', 's12-ops-A']) {
    assert.equal(byId[id].verdict, 'not_run', id);
    assert.equal(byId[id].actual, null);
  }
  assert.equal(result.summary.mismatch, 0);
  assert.equal(result.attack41.executed, 0);
  assert.equal(result.attack41.verdict, 'not_run');
  assert.equal(byId['attack-41'].verdict, 'not_run');
});

test('matrix with logins records both allowed and denied requests, and never passes unrun rows', async () => {
  const net = fakeNetwork();
  const env = { ALEPH_A_EMAIL: 'a@example.test', ALEPH_A_PASSWORD: 'pw-a', ALEPH_B_EMAIL: 'b@example.test', ALEPH_B_PASSWORD: 'pw-b' };
  const result = await runMatrix({ base: 'https://app.example.test', env, fetchImpl: net.impl, now: stamp });
  const byId = Object.fromEntries(result.rows.map((r) => [r.id, r]));
  assert.equal(byId['s11-notes-A-no-device'].verdict, 'match');   // 금지: 기기 쿠키 없이는 403
  assert.equal(byId['s3-notes-A'].verdict, 'match');              // 정상: 승인된 기기에서는 200
  assert.equal(byId['s4-s8-cross-read'].verdict, 'match');        // 금지: B가 A의 메모를 읽으면 404
  assert.equal(byId['s12-ops-A'].verdict, 'match');
  assert.equal(result.rows.filter((r) => r.kind === '정상' && r.verdict === 'match').length >= 4, true);
  assert.equal(result.rows.filter((r) => r.kind === '금지' && r.verdict === 'match').length >= 8, true);
  for (const id of ['s6-decider', 's7-step-up', 's9-detect', 'attack-41']) assert.equal(byId[id].verdict, 'not_run', id);
  // 표·파일에 로그인 값, 토큰, 메모 본문이 들어가지 않습니다.
  const text = JSON.stringify(result) + renderMarkdown(result);
  assert.equal(/pw-a|pw-b|tokA|tokB|pub-key|SECRET|a@example|b@example/u.test(text), false);
});

test('matrix marks a wrong answer as mismatch and a device that is not approved as not_run', async () => {
  const unapproved = fakeNetwork({ approved: false });
  const env = { ALEPH_A_EMAIL: 'a@example.test', ALEPH_A_PASSWORD: 'pw-a' };
  const r1 = await runMatrix({ base: 'https://app.example.test', env, fetchImpl: unapproved.impl, now: stamp });
  const ids = Object.fromEntries(r1.rows.map((r) => [r.id, r]));
  assert.equal(ids['s3-notes-A'].verdict, 'not_run');
  assert.match(ids['s3-notes-A'].note, /승인/u);
  assert.equal(ids['s11-device-A'].verdict, 'match');

  const base = fakeNetwork();
  const leaky = async (url, init) => (new URL(String(url)).pathname === '/api/notes' && !init?.headers?.Authorization
    ? new Response(JSON.stringify([{ id: 'x' }]), { status: 200, headers: { 'content-type': 'application/json' } })
    : base.impl(url, init));
  const r2 = await runMatrix({ base: 'https://app.example.test', env: {}, fetchImpl: leaky, now: stamp });
  const leak = r2.rows.find((r) => r.id === 's3-notes-anon');
  assert.equal(leak.verdict, 'mismatch');
  assert.equal(r2.summary.mismatch, 1);
});

test('matrix reports a connection failure as not_run, not as a pass', async () => {
  const result = await runMatrix({ base: 'https://app.example.test', env: {}, fetchImpl: async () => { throw new TypeError('fetch failed'); }, now: stamp });
  assert.equal(result.summary.match, 0);
  assert.equal(result.rows.every((r) => r.verdict === 'not_run'), true);
});

test('matrix case list covers every step the server can show and states the table columns', () => {
  const cases = buildCases({ origin: 'https://x.example.test', originalApiUrl: null, publishableKey: null });
  const steps = new Set(cases.map((c) => c.step));
  for (const step of [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]) assert.ok(steps.has(step), `단계 ${step}`);
  assert.ok(cases.some((c) => c.kind === '정상') && cases.some((c) => c.kind === '금지'));
  const md = renderMarkdown({ base: 'https://x', createdAt: 't', summary: { total: 0, match: 0, mismatch: 0, notRun: 0 }, attack41: { total: 41, executed: 0 }, rows: [] });
  assert.match(md, /\| 단계 \| 구분 \| 요청 \| 기대 결과 \| 실제 API 결과 \| 판정 \| 요청 ID \| 확인 시각 \|/u);
  assert.match(md, /41종 총공세: 실행 0\/41/u);
});

// ---- 화면과 연결 -------------------------------------------------------------
test('page shows the summary as received, loads it only after the server approves the device, and uses no innerHTML', async () => {
  const page = await readFile(`${root}public/index.html`, 'utf8');
  assert.equal(/innerHTML|outerHTML|insertAdjacentHTML|localStorage|sessionStorage|indexedDB/u.test(page), false);
  const approvedBranch = page.indexOf("if (info?.state === 'approved') {");
  const firstOps = page.indexOf('await loadOps()');
  assert.ok(approvedBranch > 0 && firstOps > approvedBranch, '작전실은 서버가 approved라고 답한 뒤에만 부릅니다.');
  assert.equal(page.slice(0, approvedBranch).includes('await loadOps()'), false);
  assert.match(page, /\/api\/ops\/summary/u);
  assert.match(page, /가상 요청 연습 · 실제 판정 아님/u);
  assert.match(page, /미실행/u);
});

test('production route file, step number and package scripts are wired for step 12', async () => {
  const route = await readFile(`${root}api/ops/summary.js`, 'utf8');
  assert.match(route, /opsApi\.handle/u);
  const ops = await readFile(`${root}src/ops-api.mjs`, 'utf8');
  assert.match(ops, /gate: defaultGate/u);
  const pkg = JSON.parse(await readFile(`${root}package.json`, 'utf8'));
  assert.ok(pkg.scripts['verify:matrix'] && pkg.scripts['test:ops']);
  const sql = await readFile(`${root}sql/12-ops-check.sql`, 'utf8');
  assert.equal(/\b(insert|update|delete|drop|alter|grant|truncate)\b/iu.test(sql.replace(/--.*$/gmu, '')), false);
});
