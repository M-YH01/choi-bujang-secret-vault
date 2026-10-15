import assert from 'node:assert/strict';
import { test } from 'node:test';
import { detect } from '../src/detect.mjs';
import { checkDetection } from '../scripts/detect-test.mjs';

const START = Date.UTC(2026, 9, 1, 0, 0, 0);
const SUBJECT = 'learner_fixture';
// method를 undefined로 넘겨도 'GET'으로 바뀌지 않도록, 키가 있는지로 구분합니다.
const event = (offsetSeconds, options = {}) => ({
  at: new Date(START + offsetSeconds * 1000).toISOString(),
  method: 'method' in options ? options.method : 'GET',
  identity: { sub: options.sub ?? SUBJECT },
});
// 같은 간격으로 count건. 첫 사건과 마지막 사건의 시각 차 = (count - 1) × interval.
const reads = (count, intervalSeconds, options) => Array.from({ length: count }, (_, i) => event(i * intervalSeconds, options));
const BURST = { action: 'propose_revocation', reasonCode: 'burst_read', subject: SUBJECT };
const OBSERVE = { action: 'observe' };

test('the local practice command passes all six cases', async () => {
  const results = await checkDetection(detect);
  assert.equal(results.length, 6);
  assert.deepEqual(results.filter((r) => !r.passed), []);
});

test('only more than 120 reads in a ten minute window propose revocation', () => {
  assert.deepEqual(detect(reads(0, 1)), OBSERVE);
  assert.deepEqual(detect(reads(30, 2)), OBSERVE);
  assert.deepEqual(detect(reads(120, 1)), OBSERVE, '정확히 120건은 의심이 아닙니다');
  assert.deepEqual(detect(reads(121, 1)), BURST);
  assert.deepEqual(detect(reads(200, 1)), BURST);
  assert.deepEqual(detect(reads(5000, 0.1)), BURST);
});

test('the window is ten minutes: exactly ten minutes apart still counts, one second more does not', () => {
  // 121건이 정확히 600초 안(마지막-첫 = 600초): 같은 구간
  assert.deepEqual(detect(reads(121, 5)), BURST);
  // 첫 사건만 1초 일찍 → 마지막-첫 = 601초라서 한 구간에 120건뿐
  const spread = reads(121, 5).map((e, i) => (i === 0 ? event(-1) : e));
  assert.deepEqual(detect(spread), OBSERVE);
  // 느린 조회: 어느 10분 구간에도 120건이 안 됨
  assert.deepEqual(detect(reads(200, 7)), OBSERVE);
  assert.deepEqual(detect(reads(1000, 30)), OBSERVE);
});

test('a burst is found in any ten minute window, not just the first one', () => {
  const quiet = reads(50, 60);                           // 50분 동안 천천히
  const burst = reads(121, 1).map((e, i) => event(4000 + i));   // 그 뒤 121건이 몰림
  assert.deepEqual(detect([...quiet, ...burst]), BURST);
  const justBelow = reads(120, 1).map((e, i) => event(4000 + i));
  assert.deepEqual(detect([...quiet, ...justBelow]), OBSERVE);
  // 두 번으로 나뉜 100건 + 100건(11분 간격)은 합치지 않습니다.
  assert.deepEqual(detect([...reads(100, 1), ...reads(100, 1).map((e, i) => event(700 + i))]), OBSERVE);
});

test('events of different users are never added together', () => {
  const mixed = [...reads(100, 1), ...reads(100, 1, { sub: 'other_fixture' })];
  assert.deepEqual(detect(mixed), OBSERVE);
  // 한 명이 넘으면 그 사람만 지목합니다.
  const one = [...reads(121, 1), ...reads(50, 1, { sub: 'other_fixture' })];
  assert.deepEqual(detect(one), BURST);
  const other = [...reads(50, 1), ...reads(121, 1, { sub: 'other_fixture' })];
  assert.deepEqual(detect(other), { ...BURST, subject: 'other_fixture' });
  // 둘 다 넘으면 먼저 한도를 넘은 사용자 한 명입니다.
  const both = [...reads(121, 1, { sub: 'late_fixture' }).map((e, i) => event(300 + i, { sub: 'late_fixture' })),
    ...reads(121, 1, { sub: 'early_fixture' })];
  assert.deepEqual(detect(both), { ...BURST, subject: 'early_fixture' });
});

test('only GET events are counted and unsorted input gives the same result', () => {
  const posts = reads(300, 1, { method: 'POST' });
  assert.deepEqual(detect(posts), OBSERVE);
  for (const method of ['get', 'Get', 'HEAD', 'PUT', 'DELETE', '', undefined, null, 5]) {
    assert.deepEqual(detect(reads(200, 1, { method })), OBSERVE, String(method));
  }
  assert.deepEqual(detect([...reads(100, 1), ...reads(100, 1, { method: 'POST' })]), OBSERVE);
  const shuffled = reads(121, 1).reverse();
  assert.deepEqual(detect(shuffled), BURST);
  const interleaved = reads(121, 1).sort((a, b) => (a.at.charCodeAt(18) % 3) - (b.at.charCodeAt(18) % 3));
  assert.deepEqual(detect(interleaved), BURST);
});

test('malformed events are skipped, never filled in with made-up values', () => {
  const good = reads(120, 1);
  const bad = [null, undefined, 5, 'GET', [], {}, { at: 'nope', method: 'GET', identity: { sub: SUBJECT } },
    { at: START, method: 'GET', identity: { sub: SUBJECT } }, { at: null, method: 'GET', identity: { sub: SUBJECT } },
    { at: event(1).at, method: 'GET' }, { at: event(1).at, method: 'GET', identity: null },
    { at: event(1).at, method: 'GET', identity: {} }, { at: event(1).at, method: 'GET', identity: { sub: '' } },
    { at: event(1).at, method: 'GET', identity: { sub: 7 } }, { at: event(1).at, method: 'GET', identity: { sub: 'x'.repeat(129) } },
    { at: event(1).at, method: 'GET', sub: SUBJECT }];
  // 120건 + 모양이 틀린 사건 아무리 많아도 121번째로 세지 않습니다.
  assert.deepEqual(detect([...good, ...bad, ...bad, ...bad]), OBSERVE);
  assert.deepEqual(detect([...bad, ...reads(121, 1)]), BURST);
  assert.throws(() => detect(null), TypeError);
  assert.throws(() => detect(undefined), TypeError);
  assert.throws(() => detect('events'), /invalid_detection_events/u);
  assert.throws(() => detect({ length: 3 }), TypeError);
});

test('only at, method and identity.sub are read from an event', () => {
  const touched = new Set();
  const spy = (offset) => new Proxy({ ...event(offset), network: 'x', deviceId: 'd', geo: 'kr', token: 't', body: '메모 내용' }, {
    get(target, name) { touched.add(String(name)); return target[name]; },
  });
  const events = Array.from({ length: 130 }, (_, i) => spy(i));
  detect(events);
  assert.deepEqual([...touched].sort(), ['at', 'identity', 'method']);
  // 사건에 붙은 다른 값이 결과에 영향을 주지 않습니다.
  const decorated = reads(121, 1).map((e) => ({ ...e, network: 'usual', deviceId: 'd1', geo: 'kr', body: '메모 내용', role: 'admin' }));
  assert.deepEqual(detect(decorated), BURST);
  const decorated120 = reads(120, 1).map((e) => ({ ...e, network: 'unusual', deviceId: 'd1' }));
  assert.deepEqual(detect(decorated120), OBSERVE);
});

test('the result has exactly the contract keys, copies nothing else and leaves the input unchanged', () => {
  const events = reads(121, 1).map((e) => ({ ...e, body: '메모 내용', token: 'secret-token', deviceId: 'dev' }));
  const frozen = structuredClone(events);
  const result = detect(events);
  assert.deepEqual(Object.keys(result), ['action', 'reasonCode', 'subject']);
  assert.deepEqual(events, frozen, '입력 사건을 바꾸지 않습니다');
  assert.equal(JSON.stringify(result).includes('메모 내용') || JSON.stringify(result).includes('secret-token') || JSON.stringify(result).includes('dev'), false);
  assert.deepEqual(Object.keys(detect(reads(10, 1))), ['action']);
});

test('special subject names are handled as plain text', () => {
  for (const sub of ['__proto__', 'constructor', 'toString', 'a b', '한글 사용자', 'x'.repeat(128)]) {
    assert.deepEqual(detect(reads(121, 1, { sub })), { ...BURST, subject: sub }, sub);
    assert.deepEqual(detect(reads(120, 1, { sub })), OBSERVE, sub);
  }
});

test('the detector only proposes: it does not call the network or change files', async () => {
  const original = globalThis.fetch;
  let called = false;
  globalThis.fetch = async () => { called = true; throw new Error('no network'); };
  try {
    detect(reads(500, 1));
    assert.equal(called, false);
  } finally {
    globalThis.fetch = original;
  }
});
