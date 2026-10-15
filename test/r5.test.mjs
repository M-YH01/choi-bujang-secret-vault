import assert from 'node:assert/strict';
import { test } from 'node:test';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';

// 아래 대부분의 시험은 요청을 실제로 보내는 모드(학생이 자기 PC에서 켜는 모드)를 확인합니다.
// 기본값(요청 기록이 없는 점검을 not_run으로 둠)은 파일 맨 끝 시험이 확인합니다.
process.env.ALEPH_ATTACK_CHECK_SEND = '1';

const config = {
  step: 1,
  judgeIssuer: 'https://aleph-judge-production.up.railway.app/defense/judge',
  sampleMarker: 'SAMPLE_NOTE_1',
  publicAppUrl: 'https://student-defense.vercel.app',
};
const env = {
  VERCEL_GIT_PROVIDER: 'github',
  VERCEL_GIT_REPO_OWNER: 'Student-A',
  VERCEL_GIT_REPO_SLUG: 'aleph-defense',
  VERCEL_GIT_COMMIT_SHA: 'a'.repeat(40),
  VERCEL_URL: 'student-defense-123.vercel.app',
  // 시험용 가짜 값입니다. 실제 주소나 키가 아닙니다.
  SUPABASE_URL: 'https://abcdefghijklmnopqrst.supabase.co',
  SUPABASE_PUBLISHABLE_KEY: `sb_publishable_${'t'.repeat(24)}`,
};

test('build identity uses Vercel Git and deployment metadata', () => {
  assert.deepEqual(deploymentIdentity(env, config), {
    schema: 'aleph.defense.deployment.v1',
    step: 1,
    repoUrl: 'https://github.com/student-a/aleph-defense',
    commit: 'a'.repeat(40),
    publicAppUrl: 'https://student-defense-123.vercel.app',
    judgeIssuer: config.judgeIssuer,
    sampleMarker: config.sampleMarker,
    database: {
      schema: 'aleph.defense.database.v1',
      url: 'https://abcdefghijklmnopqrst.supabase.co',
      publishableKey: env.SUPABASE_PUBLISHABLE_KEY,
      table: 'study_notes',
    },
  });
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_PROVIDER: undefined }, config));
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_COMMIT_SHA: 'short' }, config));
});

test('database entry accepts only a Supabase origin and a publishable key', () => {
  // 끝의 슬래시는 주소만 남기고, 경로가 붙은 주소는 거부합니다.
  assert.equal(deploymentIdentity({ ...env, SUPABASE_URL: `${env.SUPABASE_URL}/` }, config).database.url,
    'https://abcdefghijklmnopqrst.supabase.co');
  assert.throws(() => deploymentIdentity({ ...env, SUPABASE_URL: `${env.SUPABASE_URL}/rest/v1` }, config));
  assert.throws(() => deploymentIdentity({ ...env, SUPABASE_URL: 'http://abcdefghijklmnopqrst.supabase.co' }, config));
  assert.throws(() => deploymentIdentity({ ...env, SUPABASE_URL: 'https://example.com' }, config));
  assert.throws(() => deploymentIdentity({ ...env, SUPABASE_URL: undefined }, config));
  // 키가 없거나 공개 키 형식이 아니면 거부합니다. secret 키 모양은 절대 통과하면 안 됩니다.
  assert.throws(() => deploymentIdentity({ ...env, SUPABASE_PUBLISHABLE_KEY: undefined }, config));
  assert.throws(() => deploymentIdentity({ ...env, SUPABASE_PUBLISHABLE_KEY: `sb_${'secret'}_${'t'.repeat(24)}` }, config));
  assert.throws(() => deploymentIdentity({ ...env, SUPABASE_PUBLISHABLE_KEY: 'short' }, config));
  // 오류 메시지에는 키 값이 들어가지 않습니다.
  try {
    deploymentIdentity({ ...env, SUPABASE_PUBLISHABLE_KEY: `sb_${'secret'}_${'t'.repeat(24)}` }, config);
  } catch (error) {
    assert.equal(error.message.includes('t'.repeat(24)), false);
  }
});

test('first attack check reads public data.json without credentials', async () => {
  const originalFetch = globalThis.fetch;
  let requestUrl;
  let options;
  try {
    globalThis.fetch = async (url, init) => {
      requestUrl = String(url);
      options = init;
      return new Response(JSON.stringify({ sampleMarker: 'SAMPLE_NOTE_1', notes: [{ title: '가상' }] }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    };
    const [result] = await runAttackChecks(config);
    assert.equal(requestUrl, 'https://student-defense.vercel.app/data.json');
    assert.equal(options.redirect, 'error');
    assert.match(result.observed, /확인 표시가 보임/u);
    globalThis.fetch = async () => new Response('<html>not the data</html>', { status: 200 });
    const [failed] = await runAttackChecks(config);
    assert.match(failed.observed, /보이지 않음/u);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

const config3 = {
  ...config,
  step: 3,
  identityProvider: {
    issuer: 'https://abcdefghijklmnopqrst.supabase.co/auth/v1',
    audience: 'authenticated',
    jwksUrl: 'https://abcdefghijklmnopqrst.supabase.co/auth/v1/.well-known/jwks.json',
  },
  allowedRoutes: ['/api/notes', '/api/notes/:id'],
};

test('step 3 identity adds the login issuer and routes, tied to the same Supabase project', () => {
  const identity = deploymentIdentity(env, config3);
  assert.equal(identity.step, 3);
  assert.deepEqual(identity.identityProvider, config3.identityProvider);
  assert.deepEqual(identity.allowedRoutes, config3.allowedRoutes);
  assert.equal(identity.database.table, 'study_notes');
  assert.equal('sampleMarker' in identity, false);
  assert.throws(() => deploymentIdentity(env, { ...config3, identityProvider: null }));
  assert.throws(() => deploymentIdentity(env, { ...config3, allowedRoutes: [] }));
  assert.throws(() => deploymentIdentity(env, { ...config3, allowedRoutes: ['api/notes'] }));
  assert.throws(() => deploymentIdentity(env, { ...config3, step: 13 }));
  assert.equal(deploymentIdentity(env, { ...config3, step: 4 }).step, 4);
  assert.equal('originalApiUrl' in deploymentIdentity(env, { ...config3, step: 4 }), false);
  // 발급자가 다른 프로젝트를 가리키면 거부합니다.
  assert.throws(() => deploymentIdentity(env, { ...config3, identityProvider: {
    ...config3.identityProvider,
    issuer: 'https://zzzzzzzzzzzzzzzzzzzz.supabase.co/auth/v1',
    jwksUrl: 'https://zzzzzzzzzzzzzzzzzzzz.supabase.co/auth/v1/.well-known/jwks.json',
  } }));
});

test('step 3 attack check records anonymous results without reading note bodies', async () => {
  const originalFetch = globalThis.fetch;
  const urls = [];
  try {
    globalThis.fetch = async (url) => {
      urls.push(String(url));
      if (String(url).endsWith('/data.json')) {
        return new Response(JSON.stringify({ notes: [] }), { status: 200, headers: { 'content-type': 'application/json' } });
      }
      return new Response(JSON.stringify({ error: 'UNAUTHORIZED', message: '로그인이 필요합니다.' }),
        { status: 401, headers: { 'content-type': 'application/json' } });
    };
    const results = await runAttackChecks(config3);
    assert.deepEqual(urls, ['https://student-defense.vercel.app/data.json', 'https://student-defense.vercel.app/api/notes']);
    assert.deepEqual(results.map((r) => r.attackId), ['anonymous_note_read', 'anonymous_note_list']);
    assert.match(results[0].observed, /보이지 않음/u);
    assert.match(results[1].observed, /JSON 오류로 거부됨 \(HTTP 401\)/u);
    for (const r of results) assert.deepEqual(Object.keys(r).sort(), ['attackId', 'expected', 'observed']);

    globalThis.fetch = async () => new Response('<html>not json</html>', { status: 200, headers: { 'content-type': 'text/html' } });
    const [, open] = await runAttackChecks(config3);
    assert.match(open.observed, /거부되지 않음 \(HTTP 200\)/u);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('step 4 attack check adds the anonymous single-note request and leaves A/B checks unrun', async () => {
  const originalFetch = globalThis.fetch;
  const urls = [];
  try {
    globalThis.fetch = async (url) => {
      urls.push(String(url));
      if (String(url).endsWith('/data.json')) return new Response(JSON.stringify({ notes: [] }), { status: 200, headers: { 'content-type': 'application/json' } });
      return new Response(JSON.stringify({ error: 'UNAUTHORIZED' }), { status: 401, headers: { 'content-type': 'application/json' } });
    };
    const results = await runAttackChecks({ ...config3, step: 4 });
    assert.deepEqual(results.map((r) => r.attackId), ['anonymous_note_read', 'anonymous_note_list', 'anonymous_note_item']);
    assert.match(urls[2], /\/api\/notes\/00000000-0000-4000-8000-000000000000$/u);
    assert.match(results[2].observed, /JSON 오류로 거부됨 \(HTTP 401\)/u);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

const config5 = { ...config3, step: 5, originalApiUrl: 'https://abcdefghijklmnopqrst.supabase.co/rest/v1/study_notes' };

test('step 5 identity publishes the original API address only for the same project and table', () => {
  const identity = deploymentIdentity(env, config5);
  assert.equal(identity.step, 5);
  assert.equal(identity.originalApiUrl, config5.originalApiUrl);
  assert.deepEqual(identity.allowedRoutes, config5.allowedRoutes);
  for (const bad of [null, '', 'http://abcdefghijklmnopqrst.supabase.co/rest/v1/study_notes',
    'https://abcdefghijklmnopqrst.supabase.co/rest/v1/study_notes?select=*',
    'https://abcdefghijklmnopqrst.supabase.co/rest/v1/other_table',
    'https://zzzzzzzzzzzzzzzzzzzz.supabase.co/rest/v1/study_notes']) {
    assert.throws(() => deploymentIdentity(env, { ...config5, originalApiUrl: bad }));
  }
});

test('step 5 attack check calls the original address with the public key and records only status', async () => {
  const originalFetch = globalThis.fetch;
  const PUBLIC_KEY = `sb_publishable_${'k'.repeat(24)}`;
  let direct;
  const run = async (directResponse) => {
    globalThis.fetch = async (url, init) => {
      const text = String(url);
      if (text.endsWith('/data.json')) return new Response(JSON.stringify({ notes: [] }), { status: 200, headers: { 'content-type': 'application/json' } });
      if (text.endsWith('/aleph.json')) return new Response(JSON.stringify({ database: { publishableKey: PUBLIC_KEY } }), { status: 200, headers: { 'content-type': 'application/json' } });
      if (text.startsWith(config5.originalApiUrl)) { direct = { url: text, key: new Headers(init.headers).get('apikey') }; return directResponse(); }
      return new Response(JSON.stringify({ error: 'UNAUTHORIZED' }), { status: 401, headers: { 'content-type': 'application/json' } });
    };
    const results = await runAttackChecks(config5);
    return results.at(-1);
  };
  try {
    const denied = await run(() => new Response(JSON.stringify({ code: '42501', message: '비밀 메모 본문' }), { status: 401, headers: { 'content-type': 'application/json' } }));
    assert.equal(denied.attackId, 'direct_original_read');
    assert.match(denied.observed, /거부됨 \(HTTP 401\)/u);
    assert.equal(direct.key, PUBLIC_KEY);
    assert.ok(direct.url.startsWith(config5.originalApiUrl));
    const empty = await run(() => new Response('[]', { status: 200, headers: { 'content-type': 'application/json' } }));
    assert.match(empty.observed, /메모가 0건/u);
    const leaked = await run(() => new Response(JSON.stringify([{ id: 'x', title: '비밀 메모 본문' }]), { status: 200, headers: { 'content-type': 'application/json' } }));
    assert.match(leaked.observed, /메모가 읽힘/u);
    for (const r of [denied, empty, leaked]) {
      assert.deepEqual(Object.keys(r).sort(), ['attackId', 'expected', 'observed']);
      assert.equal(JSON.stringify(r).includes(PUBLIC_KEY) || JSON.stringify(r).includes('비밀 메모'), false);
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('step 6 identity keeps the step 5 fields', () => {
  const identity = deploymentIdentity(env, { ...config5, step: 6 });
  assert.equal(identity.step, 6);
  assert.equal(identity.originalApiUrl, config5.originalApiUrl);
});

test('step 8 allowed routes carry the method and must match the decider allow list shape', () => {
  const config8 = { ...config5, step: 8, allowedRoutes: ['GET /api/notes/:id', 'PUT /api/notes/:id', 'DELETE /api/notes/:id'] };
  const identity = deploymentIdentity(env, config8);
  assert.equal(identity.step, 8);
  assert.deepEqual(identity.allowedRoutes, config8.allowedRoutes);
  assert.equal(identity.originalApiUrl, config5.originalApiUrl);
  // 8단계부터는 메서드 없는 경로, 알 수 없는 메서드, 소문자 메서드를 받지 않습니다.
  for (const bad of [['/api/notes/:id'], ['FETCH /api/notes/:id'], ['get /api/notes/:id'], ['GET api/notes/:id'], ['GET  /api/notes/:id'], []]) {
    assert.throws(() => deploymentIdentity(env, { ...config8, allowedRoutes: bad }), undefined, JSON.stringify(bad));
  }
  // 3~7단계의 경로만 적는 형식은 그대로 받습니다.
  assert.deepEqual(deploymentIdentity(env, { ...config5, step: 7 }).allowedRoutes, config5.allowedRoutes);
});

test('step 10 attack check sends no write request: the restore check is recorded as not run, and every sent request is GET', async () => {
  const originalFetch = globalThis.fetch;
  const calls = [];
  try {
    globalThis.fetch = async (url, init = {}) => {
      calls.push({ url: String(url), method: init.method ?? 'GET', headers: init.headers ?? {} });
      if (String(url).endsWith('/data.json')) return new Response(JSON.stringify({ notes: [] }), { status: 200, headers: { 'content-type': 'application/json' } });
      if (String(url).includes('/rest/v1/')) return new Response('[]', { status: 401, headers: { 'content-type': 'application/json' } });
      return new Response(JSON.stringify({ error: 'UNAUTHORIZED' }), { status: 401, headers: { 'content-type': 'application/json' } });
    };
    const results = await runAttackChecks({ ...config5, step: 10 });
    const restore = results.find((r) => r.attackId === 'anonymous_restore');
    assert.ok(restore.observed.startsWith('not_run · 미실행'));
    assert.equal(/HTTP \d{3}/u.test(restore.observed), false);
    assert.equal(calls.some((c) => c.url.includes('/api/restore/')), false);
    assert.deepEqual([...new Set(calls.map((c) => c.method))], ['GET']);
    assert.equal(JSON.stringify(calls.map((c) => c.headers)).toLowerCase().includes('authorization'), false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('step 10 identity publishes the restore route and rejects a missing or malformed one', () => {
  const config10 = { ...config5, step: 10, allowedRoutes: ['GET /api/notes/:id'], restoreRoute: '/api/restore/notes/:id' };
  const identity = deploymentIdentity(env, config10);
  assert.equal(identity.restoreRoute, '/api/restore/notes/:id');
  assert.equal(deploymentIdentity(env, { ...config10, restoreRoute: 'POST /api/restore/notes/:id' }).restoreRoute, 'POST /api/restore/notes/:id');
  assert.equal(identity.step, 10);
  assert.equal('restoreRoute' in deploymentIdentity(env, { ...config10, step: 9 }), false);
  assert.throws(() => deploymentIdentity(env, { ...config10, restoreRoute: undefined }));
  for (const bad of ['api/restore/notes/:id', 'PUT-ish /x', '', 'https://example.com/api/restore', '/a b']) {
    assert.throws(() => deploymentIdentity(env, { ...config10, restoreRoute: bad }), bad);
  }
});

test('step 11 attack check adds an anonymous GET to the device status route and sends no token', async () => {
  const originalFetch = globalThis.fetch;
  const calls = [];
  try {
    globalThis.fetch = async (url, init = {}) => {
      calls.push({ url: String(url), method: init.method ?? 'GET', headers: init.headers ?? {} });
      if (String(url).endsWith('/data.json')) return new Response(JSON.stringify({ notes: [] }), { status: 200, headers: { 'content-type': 'application/json' } });
      if (String(url).includes('/rest/v1/')) return new Response('[]', { status: 401, headers: { 'content-type': 'application/json' } });
      return new Response(JSON.stringify({ error: 'UNAUTHORIZED' }), { status: 401, headers: { 'content-type': 'application/json' } });
    };
    const results = await runAttackChecks({ ...config5, step: 11 });
    const device = results.find((r) => r.attackId === 'anonymous_device_status');
    assert.match(device.observed, /JSON 오류로 거부됨 \(HTTP 401\)/u);
    const call = calls.find((c) => c.url.endsWith('/api/device'));
    assert.equal(call.method, 'GET');
    assert.equal(JSON.stringify(call.headers).toLowerCase().includes('authorization'), false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('step 12 attack check sends one anonymous request and marks everything it did not send as not run', async () => {
  const originalFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, init = {}) => {
    calls.push({ url: String(url), method: init.method ?? 'GET', headers: init.headers ?? {} });
    if (String(url).endsWith('/data.json')) return new Response(JSON.stringify({ notes: [] }), { status: 200, headers: { 'content-type': 'application/json' } });
    if (String(url).includes('/rest/v1/')) return new Response('[]', { status: 401, headers: { 'content-type': 'application/json' } });
    return new Response(JSON.stringify({ error: 'UNAUTHORIZED' }), { status: 401, headers: { 'content-type': 'application/json' } });
  };
  try {
    const results = await runAttackChecks({ ...config5, step: 12 });
    const ops = results.find((r) => r.attackId === 'anonymous_ops_summary');
    assert.match(ops.observed, /JSON 오류로 거부됨 \(HTTP 401\)/u);
    assert.equal(JSON.stringify(calls.find((c) => c.url.endsWith('/api/ops/summary')).headers).toLowerCase().includes('authorization'), false);
    for (const id of ['cross_user_note_read', 'verification_matrix', 'attack_41']) {
      const row = results.find((r) => r.attackId === id);
      assert.ok(row.observed.startsWith('not_run · 미실행'), id);
      assert.equal(/HTTP|\d+줄/u.test(row.observed), false, `${id}에 보내지 않은 요청의 상태나 수치를 적으면 안 됩니다.`);
    }
    // 요청을 보낸 줄에는 실제 HTTP 상태가 있어야 합니다.
    for (const row of results.filter((r) => !r.observed.startsWith('not_run · 미실행') && r.attackId !== 'direct_original_read')) {
      assert.match(row.observed, /HTTP \d{3}|메모 ?가 없|없음/u, row.attackId);
    }
    assert.ok(results.length <= 20);
    assert.equal(new Set(results.map((r) => r.attackId)).size, results.length);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('with no network the attack checks do not stop the bundle: every unsent request is recorded as not run, never as a pass', async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => { throw new TypeError('fetch failed'); };
  try {
    for (const step of [1, 5, 10, 12]) {
      const results = await runAttackChecks({ ...config5, step });
      assert.ok(results.length >= 1 && results.length <= 20);
      assert.equal(new Set(results.map((r) => r.attackId)).size, results.length);
      for (const row of results) {
        assert.deepEqual(Object.keys(row).sort(), ['attackId', 'expected', 'observed']);
        assert.ok(row.observed.startsWith('not_run · 미실행'), `${step}단계 ${row.attackId}`);
        assert.ok(row.observed.length <= 300 && row.expected.length <= 300);
      }
    }
    // 설정 오류는 숨기지 않고 그대로 알립니다.
    await assert.rejects(runAttackChecks({ ...config5, step: 5, originalApiUrl: 'not a url' }), /originalApiUrl/u);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('the direct original read puts its query in the URL text and sends the public key only in a header', async () => {
  const originalFetch = globalThis.fetch;
  const seen = [];
  globalThis.fetch = async (url, init = {}) => {
    seen.push({ url: String(url), headers: init.headers ?? {} });
    if (String(url).endsWith('/aleph.json')) return new Response(JSON.stringify({ database: { publishableKey: 'pub-key-for-test' } }), { status: 200, headers: { 'content-type': 'application/json' } });
    return new Response('[]', { status: 401, headers: { 'content-type': 'application/json' } });
  };
  try {
    const results = await runAttackChecks({ ...config5, step: 5 });
    const call = seen.find((c) => c.url.includes('/rest/v1/'));
    assert.ok(call.url.endsWith('?select=id&limit=1'), call.url);
    assert.equal(call.url.includes('pub-key-for-test'), false);
    assert.equal(call.headers.apikey, 'pub-key-for-test');
    assert.match(results.find((r) => r.attackId === 'direct_original_read').observed, /거부됨 \(HTTP 401\)/u);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('a response that cannot be read is recorded as not_run and never stops the bundle or counts as a result', async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => ({ status: 200 });   // headers·json이 없는 응답 모양
  try {
    const results = await runAttackChecks({ ...config5, step: 12 });
    for (const row of results) assert.ok(row.observed.startsWith('not_run · 미실행'), row.attackId);
    assert.ok(results.length <= 20);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('by default the six request-based checks send nothing and are recorded as not_run, with no HTTP status invented', async () => {
  const originalFetch = globalThis.fetch;
  const saved = process.env.ALEPH_ATTACK_CHECK_SEND;
  delete process.env.ALEPH_ATTACK_CHECK_SEND;
  let sent = 0;
  globalThis.fetch = async () => { sent += 1; return new Response('{}', { status: 200 }); };
  try {
    for (const step of [1, 5, 12]) {
      const results = await runAttackChecks({ ...config5, step });
      assert.ok(results.length >= 1 && results.length <= 20);
      assert.equal(new Set(results.map((r) => r.attackId)).size, results.length);
      for (const row of results) {
        assert.deepEqual(Object.keys(row).sort(), ['attackId', 'expected', 'observed']);
        assert.ok(row.observed.startsWith('not_run · 미실행'), `${step}단계 ${row.attackId}`);
        assert.equal(/HTTP \d{3}/u.test(row.observed), false, row.attackId);
      }
    }
    assert.equal(sent, 0, '기본 모드에서는 요청을 보내지 않습니다.');
    const twelve = await runAttackChecks({ ...config5, step: 12 });
    for (const id of ['anonymous_note_read', 'anonymous_note_list', 'anonymous_note_item', 'direct_original_read', 'anonymous_device_status', 'anonymous_ops_summary']) {
      assert.ok(twelve.some((r) => r.attackId === id), id);
    }
  } finally {
    globalThis.fetch = originalFetch;
    if (saved === undefined) delete process.env.ALEPH_ATTACK_CHECK_SEND; else process.env.ALEPH_ATTACK_CHECK_SEND = saved;
  }
});
