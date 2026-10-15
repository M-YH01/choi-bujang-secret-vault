// 보너스 xdr-05: 권한 가로채기 모듈 시험(가상 경보 연습이며 심판 판정이 아닙니다)
import assert from 'node:assert/strict';
import test from 'node:test';
import { cp, mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ALERT_AT, BLOCK_AT, PATTERNS, decide } from '../xdr/privilege/decide.mjs';
import { pickRow, readAlerts, redact } from '../xdr/privilege/read-alerts.mjs';
import { buildDenyRules, isDenied, isProtectedAddress, respond } from '../xdr/privilege/respond.mjs';
import { runXdr } from '../scripts/xdr-run.mjs';

const root = new URL('..', import.meta.url).pathname;
const fixturePath = join(root, 'xdr', 'fixtures', 'privilege.json');
const fixture = JSON.parse(await readFile(fixturePath, 'utf8'));
const patternsFile = JSON.parse(await readFile(join(root, 'xdr', 'privilege', 'patterns.json'), 'utf8'));
const num = (n) => Number(n.slice(3));
const expectedAction = (alert) => (num(alert.id) <= 9 ? 'block' : num(alert.id) <= 17 ? 'alert' : 'record');

test('every pattern has a name, a technique, conditions and a one-line evidence, and nothing is listed without evidence', () => {
  assert.ok(patternsFile.patterns.length >= 2);
  const names = new Set();
  for (const p of patternsFile.patterns) {
    assert.match(p.name, /^[a-z][a-z0-9_]+$/u);
    assert.match(p.technique, /^T(1068|1078)$/u);
    assert.ok(p.when && Object.keys(p.when).length > 0);
    assert.ok(typeof p.evidence === 'string' && p.evidence.length > 10 && !p.evidence.includes('\n'));
    assert.ok(/T1068|T1078/u.test(p.evidence), `${p.name}: 근거에 ATT&CK 번호가 있어야 합니다`);
    names.add(p.name);
  }
  assert.equal(names.size, patternsFile.patterns.length);
});

test('decide.mjs repeats the patterns file exactly, imports nothing and touches no files, network or process', async () => {
  assert.deepEqual(PATTERNS, patternsFile.patterns);
  const source = await readFile(join(root, 'xdr', 'privilege', 'decide.mjs'), 'utf8');
  const code = source.replace(/\/\/.*$/gmu, '');
  assert.equal(/\bimport\b|\brequire\s*\(|\bprocess\b|\bfetch\b|\bXMLHttpRequest\b|\bfs\b|readFile|writeFile|Date\.now|Math\.random|globalThis/u.test(code), false);
});

test('decide splits the practice alerts into block, alert and record, and never blocks a normal event', () => {
  const counts = { block: 0, alert: 0, record: 0 };
  for (const alert of fixture.alerts) {
    const out = decide(alert);
    assert.equal(out.action, expectedAction(alert), `${alert.id}: ${JSON.stringify(out)}`);
    assert.ok(out.confidence >= 0 && out.confidence <= 1);
    assert.equal(typeof out.reason, 'string');
    assert.equal(out.reason.includes('\n'), false);
    assert.deepEqual(Object.keys(out).sort(), ['action', 'confidence', 'reason']);
    counts[out.action] += 1;
    if (num(alert.id) >= 18) assert.notEqual(out.action, 'block', `정상 이벤트 ${alert.id}를 막았습니다`);
  }
  assert.deepEqual(counts, { block: 9, alert: 8, record: 9 });
  // 임계값과 행동이 맞물립니다.
  for (const alert of fixture.alerts) {
    const { action, confidence } = decide(alert);
    assert.equal(action, confidence >= BLOCK_AT ? 'block' : confidence >= ALERT_AT ? 'alert' : 'record');
  }
});

test('decide handles boundaries and odd input without throwing', () => {
  const mk = (level, description, mitre = ['T1078'], data = {}) => ({ id: 'x', rule: { level, description, mitre }, data: { srcip: '203.0.113.9', srcuser: 'u', ...data } });
  assert.equal(decide(mk(12, 'u 이 원격 주소에서 관리자 그룹에 추가됐습니다.')).action, 'block');
  assert.equal(decide(mk(12, '방금 관리자가 된 u 이 관리자 명령을 실행했습니다.', ['T1068'])).action, 'block');
  assert.equal(decide(mk(12, 'u 이 관리자 그룹에 추가됐습니다.')).action, 'alert'); // 신호가 하나면 막지 않습니다
  assert.equal(decide(mk(12, '수업 시간 밖에 처음 보는 주소에서 접속했습니다.')).action, 'alert'); // 시각·주소만으로는 막지 않습니다
  assert.equal(decide(mk(7, 'u 가 과제 그룹에 추가됐습니다. 관리자 그룹은 아닙니다.')).action, 'alert');
  assert.equal(decide(mk(7, '관리자 명령이 실패 1건으로 끝났습니다.', ['T1068'])).action, 'alert'); // 실패는 신호로 세지 않습니다
  assert.equal(decide(mk(5, '평소 주소에서 관리자 명령이 한 번 실행됐습니다.', ['T1068'])).action, 'alert'); // 평소 주소는 확신도를 깎습니다
  assert.equal(decide(mk(3, 'u 이 관리자 그룹에 추가됐습니다.')).action, 'record'); // 수준 3 이하는 평소 사건
  assert.equal(decide(mk(12, 'u 이 원격 주소에서 관리자 그룹에 추가됐습니다.', [])).action, 'record'); // 권한 기술 표시가 없으면 막지 않습니다
  for (const odd of [null, undefined, 5, 'x', [], {}, { rule: null }, { rule: { level: 'high' }, data: 'abc' }, { rule: { level: 12, mitre: ['T1078'], description: 7 } }]) {
    const out = decide(odd);
    assert.ok(['block', 'alert', 'record'].includes(out.action));
    assert.ok(out.confidence >= 0 && out.confidence <= 1);
    assert.notEqual(out.action, 'block');
  }
});

test('read-alerts returns as many rows as there are alerts, keeps only the five fields, masks secret-looking values and leaves the file alone', async () => {
  const before = createHash('sha256').update(await readFile(fixturePath)).digest('hex');
  const { total, rows } = await readAlerts(fixturePath);
  assert.equal(total, fixture.alerts.length);
  assert.equal(rows.length, total);
  for (const row of rows) assert.deepEqual(Object.keys(row), ['at', 'srcip', 'srcuser', 'level', 'description']);
  const dirty = pickRow({ timestamp: 't', data: { srcip: '203.0.113.1', srcuser: 'password=hunter2' }, rule: { level: 5, description: 'token: abc123 Bearer abcdefghijklmnop sb_secret_ABCDEF eyJhbGciOiJI.eyJzdWIiOiIx.sig 0123456789abcdef0123456789abcdef' } });
  const text = JSON.stringify(dirty);
  for (const secret of ['hunter2', 'abc123', 'abcdefghijklmnop', 'sb_secret_ABCDEF', 'eyJhbGciOiJI', '0123456789abcdef0123456789abcdef']) assert.equal(text.includes(secret), false, secret);
  assert.equal(redact(42), '');
  assert.equal(createHash('sha256').update(await readFile(fixturePath)).digest('hex'), before);
  const source = await readFile(join(root, 'xdr', 'privilege', 'decide.mjs'), 'utf8');
  assert.equal(source.includes('read-alerts'), false);
});

test('respond adds deny rules only for block candidates, with expiry and alert id, and normal traffic passes', async () => {
  const decisions = fixture.alerts.map((alert) => ({ alertId: alert.id, ...decide(alert) }));
  const now = new Date('2026-10-15T00:00:00Z');
  const { rules, skipped } = buildDenyRules({ alerts: fixture.alerts, decisions, now });
  const blockAddresses = new Set(fixture.alerts.filter((a) => expectedAction(a) === 'block').map((a) => a.data.srcip));
  assert.deepEqual(new Set(rules.map((r) => r.address)), blockAddresses);
  assert.equal(skipped.length, 0);
  for (const rule of rules) {
    assert.equal(rule.effect, 'deny');
    assert.match(rule.alertId, /^pv-\d+$/u);
    assert.ok(Date.parse(rule.expiresAt) > Date.parse(rule.createdAt));
  }
  // 정상(record)·애매(alert) 경보의 주소는 규칙에 없고 통과합니다.
  for (const alert of fixture.alerts.filter((a) => expectedAction(a) !== 'block')) {
    assert.equal(isDenied(alert.data.srcip, rules, now), null, alert.id);
  }
  for (const address of blockAddresses) assert.ok(isDenied(address, rules, now), address);
  // 만료되면 더는 막지 않습니다.
  assert.equal(isDenied('203.0.113.10', rules, new Date(now.getTime() + 2 * 60 * 60 * 1000)), null);
});

test('respond never blocks a protected address or an address that also shows normal use', () => {
  assert.equal(isProtectedAddress('127.0.0.1'), true);
  assert.equal(isProtectedAddress('192.168.0.5'), true);
  assert.equal(isProtectedAddress('10.1.2.3'), true);
  assert.equal(isProtectedAddress('::1'), true);
  assert.equal(isProtectedAddress('not an ip'), true);
  assert.equal(isProtectedAddress('203.0.113.10'), false);
  const alerts = [
    { id: 'a', data: { srcip: '192.168.0.9' } }, { id: 'b', data: { srcip: '203.0.113.77' } }, { id: 'c', data: { srcip: '203.0.113.77' } },
    { id: 'd', data: { srcip: '' } }, { id: 'e', data: { srcip: '203.0.113.88' } },
  ];
  const decisions = [
    { alertId: 'a', action: 'block', confidence: 0.9, reason: 'p' }, { alertId: 'b', action: 'block', confidence: 0.9, reason: 'p' },
    { alertId: 'c', action: 'record', confidence: 0, reason: 'n' }, { alertId: 'd', action: 'block', confidence: 0.9, reason: 'p' },
    { alertId: 'e', action: 'alert', confidence: 0.6, reason: 'p' },
  ];
  const { rules, skipped } = buildDenyRules({ alerts, decisions });
  assert.deepEqual(rules, []);
  assert.deepEqual(skipped.map((s) => s.reason).sort(), ['invalid_address', 'protected_address', 'shared_with_normal_use']);
});

test('respond writes the rule file and one log line per alert or block, and leaves decider.mjs and the fixture alone', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'xdr-pv-'));
  try {
    await mkdir(join(dir, 'xdr', 'fixtures'), { recursive: true });
    await cp(fixturePath, join(dir, 'xdr', 'fixtures', 'privilege.json'));
    const result = await respond({ root: dir, now: new Date('2026-10-15T00:00:00Z') });
    assert.equal(result.logged, 17);
    const log = (await readFile(join(dir, 'xdr', 'alerts.log'), 'utf8')).trim().split('\n');
    assert.equal(log.length, 17);
    assert.equal(log.filter((l) => l.includes(' block ')).length, 9);
    assert.equal(log.filter((l) => l.includes(' alert ')).length, 8);
    assert.equal(/password=|token[:=]|Bearer |sb_secret_|eyJ[A-Za-z0-9_-]{10,}/u.test(log.join("\n")), false);
    const file = JSON.parse(await readFile(join(dir, 'xdr', 'deny-rules.json'), 'utf8'));
    assert.equal(file.schema, 'aleph.deny-rules.v1');
    assert.equal(file.rules.length, 8);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
  const decider = await readFile(join(root, 'src', 'decider.mjs'), 'utf8');
  assert.equal(/xdr|brute|deny-rules/u.test(decider), false, '판정기 코드는 이번 보너스에서 바뀌지 않습니다.');
});

test('the provided runner gets the same result: counts, no normal event blocked, bad shapes recorded', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'xdr-run-'));
  try {
    await mkdir(join(dir, 'xdr', 'fixtures'), { recursive: true });
    await mkdir(join(dir, 'xdr', 'privilege'), { recursive: true });
    await cp(fixturePath, join(dir, 'xdr', 'fixtures', 'privilege.json'));
    await cp(join(root, 'xdr', 'privilege', 'decide.mjs'), join(dir, 'xdr', 'privilege', 'decide.mjs'));
    const errors = [];
    const result = await runXdr({ root: dir, moduleKey: 'privilege', writeError: (line) => errors.push(line) });
    assert.deepEqual(result.counts, { block: 9, alert: 8, record: 9 });
    assert.deepEqual(errors, []);
    for (const d of result.decisions.filter((x) => num(x.alertId) >= 18)) assert.notEqual(d.action, 'block');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
