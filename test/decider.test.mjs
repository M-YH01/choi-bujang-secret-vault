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

test('RULE_IDS lists only the implemented rules', () => {
  assert.deepEqual([...RULE_IDS], ['device_registered', 'step_up_required']);
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
  // 7단계: 계약의 이름 중 requestId, deviceRegistered, signals, recentEvents, stepUp만 읽습니다.
  for (const name of read) assert.ok(['requestId', 'deviceRegistered', 'signals', 'recentEvents', 'stepUp'].includes(name), name);
});

test('the local practice command passes all four checks', async () => {
  const results = await checkDecider({ decide, ruleIds: RULE_IDS });
  assert.deepEqual(results.map((r) => [r.name, r.passed]), [
    ['등록 기기의 정상 요청', true], ['미등록 기기의 가상 요청', true],
    ['복합 이상 접속', true], ['다시 확인한 복합 이상 접속', true]]);
});

// ---- 7단계 ----------------------------------------------------------------
const withSignals = (request, signals) => ({ ...request, requestId: randomUUID(), signals: { ...request.signals, ...signals } });

test('the composite anomaly asks for another check and the normal request is allowed', async () => {
  const { normal, suspicious } = fixtureRequests();
  const normalResponse = await decide(normal);
  assert.equal(normalResponse.decision, 'allow');
  const unusual = await decide(suspicious);
  assert.equal(unusual.decision, 'step_up');
  assert.equal(unusual.reasonCode, 'step_up_required');
  assert.deepEqual(unusual.ruleIds, ['step_up_required']);
  assert.notEqual(normalResponse.decision, unusual.decision);
});

test('a verified recent re-check lets the anomalous request through, other shapes do not', async () => {
  const { suspicious } = fixtureRequests();
  const verified = (stepUp) => decide({ ...suspicious, requestId: randomUUID(), stepUp });
  assert.equal((await verified({ verified: true, authAgeSeconds: 60 })).decision, 'allow');
  assert.equal((await verified({ verified: true, authAgeSeconds: 0 })).decision, 'allow');
  for (const stepUp of [{ verified: false, authAgeSeconds: null }, { verified: true, authAgeSeconds: 901 },
    { verified: true, authAgeSeconds: -1 }, { verified: true, authAgeSeconds: null }, { verified: 'true', authAgeSeconds: 60 },
    { verified: true, authAgeSeconds: '60' }, undefined, null, 'yes']) {
    assert.equal((await verified(stepUp)).decision, 'step_up', JSON.stringify(stepUp));
  }
});

test('one or two signs alone never trigger a re-check, and region alone is never used', async () => {
  const { suspicious } = fixtureRequests();
  const decideWith = (request) => decide({ ...request, requestId: randomUUID() });
  // 지역만 이상: 정상
  const regionOnly = { ...suspicious, signals: { source: 'judge_fixture', region: 'foreign', network: 'usual', hour: 14 }, recentEvents: [] };
  assert.equal((await decideWith(regionOnly)).decision, 'allow');
  // 한 가지 또는 두 가지만 이상
  const hourOnly = { ...regionOnly, signals: { ...regionOnly.signals, hour: 3 } };
  const networkOnly = { ...regionOnly, signals: { ...regionOnly.signals, network: 'unusual' } };
  const burstOnly = { ...regionOnly, recentEvents: suspicious.recentEvents };
  const hourNetwork = { ...hourOnly, signals: { ...hourOnly.signals, network: 'unusual' } };
  const hourBurst = { ...hourOnly, recentEvents: suspicious.recentEvents };
  const networkBurst = { ...networkOnly, recentEvents: suspicious.recentEvents };
  for (const request of [hourOnly, networkOnly, burstOnly, hourNetwork, hourBurst, networkBurst]) {
    assert.equal((await decideWith(request)).decision, 'allow');
  }
  // 지역 값을 바꿔도 결과가 같습니다.
  const a = await decideWith(withSignals(suspicious, { region: 'local' }));
  const b = await decideWith(withSignals(suspicious, { region: 'foreign' }));
  assert.equal(a.decision, b.decision);
});

test('signals that are not from the judge fixture, or are malformed, are not promoted to evidence', async () => {
  const { suspicious } = fixtureRequests();
  const decideWith = (request) => decide({ ...request, requestId: randomUUID() });
  // 실제 경로의 source는 none입니다. 같은 값이라도 출처가 다르면 이상으로 세지 않습니다.
  for (const source of ['none', 'client', 'header', 'x-forwarded', '', undefined, null, 1]) {
    assert.equal((await decideWith(withSignals(suspicious, { source }))).decision, 'allow', String(source));
  }
  // 모양이 틀린 값은 정상값으로 채우지 않고 근거에서 뺍니다(그래서 이상으로 세지 않음).
  for (const signals of [{ hour: 25 }, { hour: -1 }, { hour: 3.5 }, { hour: '3' }, { hour: null }, { network: 5 }, { network: undefined }]) {
    assert.equal((await decideWith(withSignals(suspicious, signals))).decision, 'allow', JSON.stringify(signals));
  }
  for (const signals of [null, 'judge_fixture', [], 7]) {
    assert.equal((await decideWith({ ...suspicious, signals })).decision, 'allow');
  }
  // 규칙이 읽지 않는 이름(role, geo, device, 헤더)을 덧붙여도 결과가 바뀌지 않습니다.
  const { normal } = fixtureRequests();
  const forged = { ...normal, role: 'admin', identity: { id: 'x' }, device: { approval: true }, geo: 'local',
    headers: { 'x-forwarded-for': '1.1.1.1', 'x-device-registered': 'true' } };
  assert.equal((await decide(forged)).decision, 'allow');
  const forgedUnregistered = { ...forged, deviceRegistered: false };
  assert.equal((await decide(forgedUnregistered)).decision, 'deny');
});

test('burst events are counted only when well formed, recent and large enough', async () => {
  const { suspicious } = fixtureRequests();
  const decideEvents = (recentEvents) => decide({ ...suspicious, requestId: randomUUID(), recentEvents });
  assert.equal((await decideEvents([{ kind: 'risk_signal', ageSeconds: 60, count: 10 }])).decision, 'step_up');
  assert.equal((await decideEvents([{ kind: 'risk_signal', ageSeconds: 60, count: 6 }, { kind: 'risk_signal', ageSeconds: 100, count: 4 }])).decision, 'step_up');
  for (const events of [[], [{ kind: 'risk_signal', ageSeconds: 60, count: 9 }], [{ kind: 'risk_signal', ageSeconds: 301, count: 50 }],
    [{ kind: 'other', ageSeconds: 60, count: 50 }], [{ kind: 'risk_signal', ageSeconds: 60, count: '50' }],
    [{ kind: 'risk_signal', ageSeconds: -1, count: 50 }], [null, 5, 'x'], 'many', null, undefined, {}]) {
    assert.equal((await decideEvents(events)).decision, 'allow', JSON.stringify(events));
  }
});

test('an unregistered device is denied even when everything else looks normal or anomalous', async () => {
  const { normal, suspicious } = fixtureRequests();
  for (const request of [normal, suspicious]) {
    const response = await decide({ ...request, requestId: randomUUID(), deviceRegistered: false, stepUp: { verified: true, authAgeSeconds: 1 } });
    assert.equal(response.decision, 'deny');
    assert.equal(response.reasonCode, 'device_not_registered');
  }
});
