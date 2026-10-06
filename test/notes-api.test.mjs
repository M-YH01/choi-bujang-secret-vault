import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { test } from 'node:test';
import handler from '../api/notes.js';

const root = resolve(import.meta.dirname, '..');
// 시험용 가짜 값입니다. 실제 키가 아닙니다.
const FAKE_URL = 'https://fake-project.supabase.co';
const FAKE_KEY = 'fake-secret-key-for-tests-only';

function fakeResponse() {
  const res = { headers: {}, statusCode: 200, body: undefined };
  res.setHeader = (name, value) => { res.headers[name] = value; };
  res.status = (code) => { res.statusCode = code; return res; };
  res.json = (value) => { res.body = value; return res; };
  return res;
}

async function withEnv(values, run) {
  const saved = { url: process.env.SUPABASE_URL, key: process.env.SUPABASE_SECRET_KEY };
  const set = (name, value) => {
    if (value === undefined) delete process.env[name]; else process.env[name] = value;
  };
  set('SUPABASE_URL', values.url);
  set('SUPABASE_SECRET_KEY', values.key);
  try { return await run(); } finally {
    set('SUPABASE_URL', saved.url);
    set('SUPABASE_SECRET_KEY', saved.key);
  }
}

async function withFetch(fake, run) {
  const original = globalThis.fetch;
  const savedError = console.error;
  const logged = [];
  globalThis.fetch = fake;
  console.error = (...args) => { logged.push(args.map(String).join(' ')); };
  try { return await run(logged); } finally {
    globalThis.fetch = original;
    console.error = savedError;
  }
}

test('missing environment variables give a generic error and no key', async () => {
  await withEnv({}, async () => {
    const res = fakeResponse();
    await withFetch(async () => { throw new Error('no network expected'); }, async (logged) => {
      await handler({ method: 'GET' }, res);
      assert.equal(res.statusCode, 500);
      assert.deepEqual(res.body, { error: 'NOTES_NOT_CONFIGURED' });
      assert.equal(logged.some((line) => line.includes(FAKE_KEY)), false);
    });
  });
});

test('reads study_notes with the server key and returns only title and content', async () => {
  await withEnv({ url: FAKE_URL, key: FAKE_KEY }, async () => {
    let requested;
    const rows = [
      { title: 'A', content: 'a', owner_id: 'should-not-leak' },
      { title: 'B', content: 'b', owner_id: null },
    ];
    await withFetch(async (input, init) => {
      requested = { url: String(input?.url ?? input), headers: new Headers(init?.headers ?? input?.headers) };
      return new Response(JSON.stringify(rows), {
        status: 200, headers: { 'content-type': 'application/json' },
      });
    }, async (logged) => {
      const res = fakeResponse();
      await handler({ method: 'GET' }, res);
      assert.equal(res.statusCode, 200);
      assert.deepEqual(res.body, { notes: [{ title: 'A', content: 'a' }, { title: 'B', content: 'b' }] });
      assert.equal(res.headers['Cache-Control'], 'no-store');
      assert.ok(requested.url.startsWith(`${FAKE_URL}/rest/v1/study_notes`));
      assert.equal(requested.headers.get('apikey'), FAKE_KEY);
      assert.equal(JSON.stringify(res.body).includes(FAKE_KEY), false);
      assert.equal(JSON.stringify(res.headers).includes(FAKE_KEY), false);
      assert.equal(logged.length, 0);
    });
  });
});

test('upstream errors never expose the key, URL or upstream message', async () => {
  await withEnv({ url: FAKE_URL, key: FAKE_KEY }, async () => {
    await withFetch(async () => new Response(
      JSON.stringify({ code: '42501', message: `denied for ${FAKE_KEY} at ${FAKE_URL}` }),
      { status: 403, headers: { 'content-type': 'application/json' } },
    ), async (logged) => {
      const res = fakeResponse();
      await handler({ method: 'GET' }, res);
      assert.equal(res.statusCode, 502);
      assert.deepEqual(res.body, { error: 'NOTES_UNAVAILABLE' });
      const everything = JSON.stringify([res.body, res.headers, logged]);
      assert.equal(everything.includes(FAKE_KEY), false);
      assert.equal(everything.includes(FAKE_URL), false);
    });
  });
});

test('other HTTP methods are rejected', async () => {
  const res = fakeResponse();
  await handler({ method: 'POST' }, res);
  assert.equal(res.statusCode, 405);
  assert.equal(res.headers.Allow, 'GET, HEAD');
});

test('browser files hold no memos, no key names and read notes from the API', async () => {
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
  assert.match(page, /fetch\('\/api\/notes'/u);
  assert.equal(page.includes("fetch('/data.json'"), false);
});
