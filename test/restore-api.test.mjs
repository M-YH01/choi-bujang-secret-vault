import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { access, readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { test } from 'node:test';
import { createClient } from '@supabase/supabase-js';
import { contentSha256, createRestoreApi, createSupabaseRestoreStore } from '../src/restore-api.mjs';
import config from '../aleph.config.json' with { type: 'json' };

const root = resolve(import.meta.dirname, '..');
const A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const NOTE_B = 'b0000000-0000-4000-8000-000000000001';
const NOTE_A = 'a0000000-0000-4000-8000-000000000001';
const MISSING = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';

function fakeResponse() {
  const res = { headers: {}, statusCode: 200, body: undefined };
  res.setHeader = (name, value) => { res.headers[name] = value; };
  res.status = (code) => { res.statusCode = code; return res; };
  res.json = (value) => { res.body = value; return res; };
  return res;
}
const req = (method, { token, id, body, headers } = {}) => ({
  method, body, query: id ? { id } : {},
  headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), ...headers },
});
const verify = async (authorization) => {
  if (authorization === 'Bearer tokA') return { kind: 'student', userId: A };
  if (authorization === 'Bearer tokB') return { kind: 'student', userId: B };
  return null;
};

// 메모리 속 가짜 저장소: 표 세 개(현재 메모, 사본, 감사 기록)와 실패 주입.
function memory({ fail = {} } = {}) {
  const state = { notes: new Map(), backup: new Map(), audit: [] };
  const boom = (name) => { if (fail[name]) { const e = new Error('store_failed'); e.code = 'UNAVAILABLE'; throw e; } };
  const store = {
    async getBackup(id) { boom('getBackup'); const r = state.backup.get(id); return r ? { ...r } : null; },
    async getCurrent(id) { boom('getCurrent'); const r = state.notes.get(id); return r ? { ...r } : null; },
    async insertOne(row) { boom('write'); state.notes.set(row.id, { ...row }); },
    async updateOne(row) {
      boom('write');
      const r = state.notes.get(row.id);
      if (!r || r.ownerId !== row.ownerId) { const e = new Error('store_failed'); e.code = 'UNAVAILABLE'; throw e; }
      state.notes.set(row.id, fail.corruptWrite ? { ...r, title: 'x', content: 'y' } : { ...r, title: row.title, content: row.content });
    },
    async audit(entry) { boom(`audit_${entry.result}`); state.audit.push({ ...entry }); },
  };
  return { state, store };
}
function seed(options) {
  const m = memory(options);
  const original = { title: 'B의 시험 메모 제목', content: 'B의 시험 메모 내용입니다.' };
  m.state.backup.set(NOTE_B, { id: NOTE_B, ownerId: B, ...original, contentSha256: contentSha256(original.title, original.content) });
  m.state.notes.set(NOTE_B, { id: NOTE_B, ownerId: B, title: '침해로 바뀐 제목', content: '침해로 바뀐 내용' });
  const a = { title: 'A의 메모', content: 'A만 볼 수 있음' };
  m.state.backup.set(NOTE_A, { id: NOTE_A, ownerId: A, ...a, contentSha256: contentSha256(a.title, a.content) });
  m.state.notes.set(NOTE_A, { id: NOTE_A, ownerId: A, title: 'A가 지금 쓰는 제목', content: 'A의 최신 내용' });
  return { ...m, original, api: createRestoreApi({ verify, getStore: () => m.store }) };
}
async function call(api, request) { const res = fakeResponse(); await api.restoreOne(request, res); return res; }
async function quiet(run) {
  const keep = { warn: console.warn, error: console.error };
  const lines = [];
  console.warn = (...a) => lines.push(a.map(String).join(' '));
  console.error = (...a) => lines.push(a.map(String).join(' '));
  try { return await run(lines); } finally { console.warn = keep.warn; console.error = keep.error; }
}

test('the content hash is sha256 of title, a zero byte and content', () => {
  const expected = (title, content) => createHash('sha256').update(Buffer.from([...Buffer.from(title), 0, ...Buffer.from(content)])).digest('hex');
  for (const [t, c] of [['a', 'b'], ['', ''], ['한글 제목', '내용\n줄바꿈'], ['😀', '😀']]) assert.equal(contentSha256(t, c), expected(t, c));
  assert.notEqual(contentSha256('a', 'b'), contentSha256('b', 'a'));
  assert.notEqual(contentSha256('a\nb', 'c'), contentSha256('a', 'b\nc'));
  assert.notEqual(contentSha256('ab', ''), contentSha256('a', 'b'));
  assert.match(contentSha256('x', 'y'), /^[0-9a-f]{64}$/u);
});

test('requests without a valid login, wrong methods and bad ids are rejected before any store access', async () => {
  const { api, state } = seed({ fail: { getBackup: true, getCurrent: true, write: true } });
  assert.equal((await call(api, req('POST', { id: NOTE_B }))).statusCode, 401);
  assert.equal((await call(api, req('POST', { token: 'bad', id: NOTE_B }))).statusCode, 401);
  for (const method of ['GET', 'PUT', 'DELETE', 'PATCH']) {
    const res = await call(api, req(method, { token: 'tokB', id: NOTE_B }));
    assert.equal(res.statusCode, 405);
    assert.equal(res.headers.Allow, 'POST');
  }
  for (const id of [undefined, 'not-a-uuid', '../x', NOTE_B.toUpperCase().slice(0, 35)]) {
    assert.equal((await call(api, req('POST', { token: 'tokB', id }))).statusCode, 404, String(id));
  }
  assert.equal(state.audit.length, 0);
});

test('B restores only the chosen note from the backup and nothing else changes', async () => {
  const { api, state, original } = seed();
  const aBefore = structuredClone(state.notes.get(NOTE_A));
  const res = await call(api, req('POST', { token: 'tokB', id: NOTE_B }));
  assert.equal(res.statusCode, 200);
  assert.deepEqual(res.body, { id: NOTE_B, restored: true, contentSha256: contentSha256(original.title, original.content) });
  const restored = state.notes.get(NOTE_B);
  assert.deepEqual([restored.id, restored.ownerId, restored.title, restored.content], [NOTE_B, B, original.title, original.content]);
  assert.equal(contentSha256(restored.title, restored.content), state.backup.get(NOTE_B).contentSha256);
  assert.deepEqual(state.notes.get(NOTE_A), aBefore, '다른 메모는 그대로');
  assert.equal(state.notes.size, 2);
  // 감사 기록: 시작 → 결과, 추가만 합니다.
  assert.deepEqual(state.audit.map((e) => [e.actor, e.action, e.noteId, e.result]),
    [[B, 'restore_note', NOTE_B, 'started'], [B, 'restore_note', NOTE_B, 'restored']]);
  assert.ok(state.audit.every((e) => e.digest === res.body.contentSha256));
  assert.equal(JSON.stringify(res.body).includes('시험 메모'), false, '본문은 응답에 싣지 않습니다');
});

test('a note that was deleted is put back, and one that already matches is left alone', async () => {
  const { api, state } = seed();
  state.notes.delete(NOTE_B);
  const res = await call(api, req('POST', { token: 'tokB', id: NOTE_B }));
  assert.equal(res.body.restored, true);
  assert.equal(state.notes.get(NOTE_B).ownerId, B);
  const auditCount = state.audit.length;
  const again = await call(api, req('POST', { token: 'tokB', id: NOTE_B }));
  assert.deepEqual(again.body, { id: NOTE_B, restored: false, reason: 'already_matches', contentSha256: res.body.contentSha256 });
  assert.equal(state.audit.length, auditCount, '바꾸지 않았으면 기록도 늘리지 않습니다');
});

test('dryRun shows what would change without writing or auditing', async () => {
  const { api, state } = seed();
  const before = structuredClone([...state.notes]);
  const res = await call(api, req('POST', { token: 'tokB', id: NOTE_B, body: { dryRun: true } }));
  assert.deepEqual(Object.keys(res.body).sort(), ['contentSha256', 'dryRun', 'id', 'replacesExisting', 'wouldRestore']);
  assert.equal(res.body.dryRun, true);
  assert.equal(res.body.replacesExisting, true);
  assert.deepEqual([...state.notes], before);
  assert.equal(state.audit.length, 0);
  const asString = await call(api, req('POST', { token: 'tokB', id: NOTE_B, body: JSON.stringify({ dryRun: true }) }));
  assert.equal(asString.body.dryRun, true);
  // dryRun이 아닌 값은 실제 복원입니다.
  const real = await call(api, req('POST', { token: 'tokB', id: NOTE_B, body: { dryRun: 'true' } }));
  assert.equal(real.body.restored, true);
});

test('another user cannot restore a note from someone else’s backup, and a missing backup looks the same', async () => {
  const { api, state } = seed();
  const before = structuredClone([...state.notes]);
  await quiet(async (lines) => {
    const wrong = await call(api, req('POST', { token: 'tokA', id: NOTE_B, body: { owner_id: A, userId: A, role: 'instructor' },
      headers: { 'x-user-id': A, 'x-role': 'instructor' } }));
    const missing = await call(api, req('POST', { token: 'tokA', id: MISSING }));
    assert.equal(wrong.statusCode, 404);
    assert.deepEqual(wrong.body, missing.body);
    assert.deepEqual(lines, ['restore_denied not_owner', 'restore_denied no_backup']);
  });
  assert.deepEqual([...state.notes], before);
  assert.equal(state.audit.length, 0);
});

test('a backup whose hash no longer matches is refused and recorded', async () => {
  const { api, state } = seed();
  state.backup.set(NOTE_B, { ...state.backup.get(NOTE_B), content: '사본이 몰래 바뀜' });
  const noteBefore = structuredClone(state.notes.get(NOTE_B));
  await quiet(async (lines) => {
    const res = await call(api, req('POST', { token: 'tokB', id: NOTE_B }));
    assert.equal(res.statusCode, 422);
    assert.equal(res.body.error, 'BACKUP_INVALID');
    assert.deepEqual(lines, ['restore_denied backup_hash_mismatch']);
  });
  assert.deepEqual(state.notes.get(NOTE_B), noteBefore);
  assert.deepEqual(state.audit.map((e) => e.result), ['rejected_backup_hash']);
  // 해시 칸이 비었거나 모양이 다른 사본도 거부합니다.
  for (const bad of [null, '', 5, 'abc']) {
    state.backup.set(NOTE_B, { ...state.backup.get(NOTE_B), contentSha256: bad });
    assert.equal((await call(api, req('POST', { token: 'tokB', id: NOTE_B }))).statusCode, 422);
  }
  // dryRun도 같은 검사를 거치지만 기록은 남기지 않습니다.
  const count = state.audit.length;
  assert.equal((await call(api, req('POST', { token: 'tokB', id: NOTE_B, body: { dryRun: true } }))).statusCode, 422);
  assert.equal(state.audit.length, count);
});

test('a row that now belongs to someone else is never overwritten', async () => {
  const { api, state } = seed();
  state.notes.set(NOTE_B, { ...state.notes.get(NOTE_B), ownerId: A });
  const before = structuredClone(state.notes.get(NOTE_B));
  await quiet(async () => {
    const res = await call(api, req('POST', { token: 'tokB', id: NOTE_B }));
    assert.equal(res.statusCode, 409);
  });
  assert.deepEqual(state.notes.get(NOTE_B), before);
  state.notes.set(NOTE_B, { ...before, ownerId: null });
  await quiet(async () => { assert.equal((await call(api, req('POST', { token: 'tokB', id: NOTE_B }))).statusCode, 409); });
});

test('store failures never leave a half-done restore without a record and never leak details', async () => {
  // 시작 기록을 못 남기면 아무것도 바꾸지 않습니다.
  let m = seed({ fail: { audit_started: true } });
  let before = structuredClone(m.state.notes.get(NOTE_B));
  await quiet(async () => { assert.equal((await call(m.api, req('POST', { token: 'tokB', id: NOTE_B }))).statusCode, 502); });
  assert.deepEqual(m.state.notes.get(NOTE_B), before);
  // 쓰기에 실패하면 실패 기록을 남깁니다.
  m = seed({ fail: { write: true } });
  before = structuredClone(m.state.notes.get(NOTE_B));
  await quiet(async () => {
    const res = await call(m.api, req('POST', { token: 'tokB', id: NOTE_B }));
    assert.equal(res.statusCode, 502);
    assert.equal(JSON.stringify(res.body).includes('store_failed'), false);
  });
  assert.deepEqual(m.state.notes.get(NOTE_B), before);
  assert.deepEqual(m.state.audit.map((e) => e.result), ['started', 'failed']);
  // 쓴 뒤 다시 읽은 해시가 다르면 실패로 기록합니다.
  m = seed({ fail: { corruptWrite: true } });
  await quiet(async () => { assert.equal((await call(m.api, req('POST', { token: 'tokB', id: NOTE_B }))).statusCode, 502); });
  assert.deepEqual(m.state.audit.map((e) => e.result), ['started', 'failed']);
  // 읽기 실패
  m = seed({ fail: { getBackup: true } });
  await quiet(async () => { assert.equal((await call(m.api, req('POST', { token: 'tokB', id: NOTE_B }))).statusCode, 502); });
  // 서버 설정이 없을 때
  const unconfigured = createRestoreApi({ verify, getStore: () => { throw new Error('not_configured'); } });
  await quiet(async () => { assert.equal((await call(unconfigured, req('POST', { token: 'tokB', id: NOTE_B }))).statusCode, 500); });
});

test('logs hold only short codes: no ids, tokens, titles or contents', async () => {
  const m = seed({ fail: { write: true } });
  await quiet(async (lines) => {
    await call(m.api, req('POST', { token: 'tokB', id: NOTE_B }));
    await call(m.api, req('POST', { token: 'tokA', id: NOTE_B }));
    assert.ok(lines.length >= 2);
    for (const line of lines) assert.equal(/[0-9a-f]{8}-|tok[AB]|시험 메모|침해/u.test(line), false, line);
  });
});

// ---- Supabase 저장소 어댑터 ----------------------------------------------------
async function withFetch(fake, run) {
  const original = globalThis.fetch;
  globalThis.fetch = fake;
  try { return await run(); } finally { globalThis.fetch = original; }
}
const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } });
const storeFor = () => createSupabaseRestoreStore(createClient('https://fake-project.supabase.co', 'fake-secret-key-for-tests-only',
  { auth: { persistSession: false, autoRefreshToken: false } }));

test('the Supabase adapter touches only the chosen row, in the three tables', async () => {
  const seen = [];
  await withFetch(async (input, init) => {
    seen.push({ method: init?.method ?? input?.method ?? 'GET', url: decodeURIComponent(String(input?.url ?? input)), body: init?.body });
    if (String(input?.url ?? input).includes('study_notes_backup')) return json([{ id: NOTE_B, owner_id: B, title: 't', content: 'c', content_sha256: 'h' }]);
    return json([{ id: NOTE_B, owner_id: B, title: 't', content: 'c' }]);
  }, async () => {
    const store = storeFor();
    assert.deepEqual(await store.getBackup(NOTE_B), { id: NOTE_B, ownerId: B, title: 't', content: 'c', contentSha256: 'h' });
    assert.deepEqual(await store.getCurrent(NOTE_B), { id: NOTE_B, ownerId: B, title: 't', content: 'c' });
    await store.updateOne({ id: NOTE_B, ownerId: B, title: 'x', content: 'y' });
    await store.insertOne({ id: NOTE_B, ownerId: B, title: 'x', content: 'y' });
    await store.audit({ actor: B, action: 'restore_note', noteId: NOTE_B, digest: 'h', result: 'restored' });
  });
  const [backup, current, update, insert, audit] = seen;
  assert.ok(backup.url.includes('/study_notes_backup') && backup.url.includes(`id=eq.${NOTE_B}`));
  assert.ok(current.url.includes('/study_notes?') && current.url.includes(`id=eq.${NOTE_B}`));
  assert.equal(update.method, 'PATCH');
  assert.ok(update.url.includes(`id=eq.${NOTE_B}`) && update.url.includes(`owner_id=eq.${B}`), '고칠 때 id와 owner_id가 모두 조건입니다');
  assert.deepEqual(JSON.parse(update.body), { title: 'x', content: 'y' });
  assert.equal(insert.method, 'POST');
  assert.deepEqual(JSON.parse(insert.body), { id: NOTE_B, owner_id: B, title: 'x', content: 'y' });
  assert.ok(audit.url.includes('/study_notes_audit'));
  assert.deepEqual(JSON.parse(audit.body), { actor: B, action: 'restore_note', note_id: NOTE_B, content_sha256: 'h', result: 'restored' });
  assert.equal(seen.some((s) => s.method === 'DELETE'), false, '삭제 요청은 없습니다');
});

test('the adapter turns upstream errors into codes only and refuses to claim a write that changed no row', async () => {
  await withFetch(async () => json({ code: '42501', message: 'denied fake-secret-key-for-tests-only' }, 403), async () => {
    await assert.rejects(() => storeFor().getBackup(NOTE_B), (e) => {
      assert.equal(JSON.stringify([e.message, e.code, e.upstreamCode]).includes('fake-secret'), false);
      return e.message === 'store_failed';
    });
  });
  await withFetch(async () => json([]), async () => {
    await assert.rejects(() => storeFor().updateOne({ id: NOTE_B, ownerId: B, title: 'x', content: 'y' }), /store_failed/u);
  });
});

test('the backup SQL, route file and config describe the same feature', async () => {
  const sql = await readFile(resolve(root, 'sql/10-backup-tables.sql'), 'utf8');
  for (const needle of ['study_notes_backup', 'study_notes_audit', 'enable row level security',
    'revoke all on table public.study_notes_backup from public, anon, authenticated',
    'revoke all on table public.study_notes_audit from public, anon, authenticated',
    'revoke update, delete, truncate on table public.study_notes_audit from service_role',
    "convert_to(n.title, 'UTF8') || '\\x00'::bytea || convert_to(n.content, 'UTF8')", 'on conflict (id) do nothing']) {
    assert.ok(sql.includes(needle), needle);
  }
  assert.equal(/@|sb_secret|eyJ|insert into public\.study_notes_backup[^;]*values/iu.test(sql), false, 'SQL에 이메일·키·메모 문장을 넣지 않습니다');
  await access(resolve(root, 'api/restore/notes/[id].js'));
  assert.equal(config.restoreRoute, 'POST /api/restore/notes/:id');
  assert.equal(config.allowedRoutes.includes(config.restoreRoute), false);
  const route = await readFile(resolve(root, 'api/restore/notes/[id].js'), 'utf8');
  assert.ok(route.includes('restoreApi.restoreOne'));
});
