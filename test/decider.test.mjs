import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomUUID } from 'node:crypto';
import { decide, RULE_IDS } from '../src/decider.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';
import { checkDecider } from '../scripts/decider-test.mjs';

// docs/DECIDER_REQUEST.md의 요청 이름 18개입니다.
const CONTRACT_NAMES = ['schema', 'requestId', 'classId', 'projectId', 'subjectId', 'deviceId', 'service',
  'method', 'path', 'route', 'queryLength', 'querySha256', 'at', 'policyRevision', 'deviceRegistered',
  'stepUp', 'recentEvents', 'signals'];
const RESPONSE_KEYS = 'decision,reasonCode,requestId,ruleIds,schema';

test('RULE_IDS lists only the implemented rule', () => {
  assert.deepEqual([...RULE_IDS], ['device_registered']);
});

test('a registered device is allowed and an unregistered one is denied with device_not_registered', async () => {
  const { normal } = fixtureRequests();
  const allowed = await decide(normal);
  assert.equal(allowed.decision, 'allow');
  assert.equal(allowed.reasonCode, 'approved');
  assert.equal(allowed.requestId, normal.requestId);

  const denied = await decide({ ...normal, requestId: randomUUID(), deviceRegistered: false });
  assert.equal(denied.decision, 'deny');
  assert.equal(denied.reasonCode, 'device_not_registered');
  assert.deepEqual(denied.ruleIds, ['device_registered']);
});

test('a missing or oddly shaped deviceRegistered is denied', async () => {
  const { normal } = fixtureRequests();
  const { deviceRegistered, ...withoutFlag } = normal;
  for (const value of [undefined, null, 'true', 1, 0, {}, [], 'yes']) {
    const response = await decide({ ...normal, deviceRegistered: value });
    assert.equal(response.decision, 'deny', String(value));
    assert.equal(response.reasonCode, 'device_not_registered');
  }
  assert.equal(deviceRegistered, true);
  assert.equal((await decide(withoutFlag)).decision, 'deny');
});

test('every response has exactly the five contract keys and only known rule ids', async () => {
  const { normal, suspicious } = fixtureRequests();
  for (const request of [normal, suspicious, { ...normal, deviceRegistered: false }, { ...normal, deviceRegistered: undefined }]) {
    const response = await decide(request);
    assert.equal(Object.keys(response).sort().join(','), RESPONSE_KEYS);
    assert.equal(response.schema, 'aleph.decision.v1');
    assert.equal(response.requestId, request.requestId);
    assert.match(response.reasonCode, /^[a-z][a-z0-9_]{0,63}$/u);
    assert.ok(response.ruleIds.length > 0 && response.ruleIds.every((id) => RULE_IDS.includes(id)));
  }
});

test('the decider reads only contract names and never role, identity, device or geo', async () => {
  const { normal } = fixtureRequests();
  const read = new Set();
  const spy = new Proxy(normal, { get(target, name) { read.add(String(name)); return target[name]; } });
  await decide(spy);
  await decide(new Proxy({ ...normal, deviceRegistered: false }, { get(target, name) { read.add(String(name)); return target[name]; } }));
  for (const name of read) assert.ok(CONTRACT_NAMES.includes(name), `계약에 없는 이름을 읽었습니다: ${name}`);
  for (const forbidden of ['role', 'identity', 'device', 'geo', 'userId', 'token']) assert.equal(read.has(forbidden), false);
  assert.deepEqual([...read].sort(), ['deviceRegistered', 'requestId']);
});

test('the local practice command passes both checks', async () => {
  const results = await checkDecider({ decide, ruleIds: RULE_IDS });
  assert.deepEqual(results.map((r) => [r.name, r.passed]),
    [['등록 기기의 정상 요청', true], ['미등록 기기의 가상 요청', true]]);
});
