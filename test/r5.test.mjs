import assert from 'node:assert/strict';
import { test } from 'node:test';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';

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
