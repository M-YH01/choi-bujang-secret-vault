// 보너스 xdr-06: 자료 빼돌리기 모듈 시험(가상 경보 연습이며 심판 판정이 아닙니다)
import assert from 'node:assert/strict';
import test from 'node:test';
import { cp, mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ALERT_AT, BLOCK_AT, PATTERNS, decide } from '../xdr/exfiltration/decide.mjs';
import { pickRow, readAlerts, redact } from '../xdr/exfiltration/read-alerts.mjs';
import { buildDenyRules, isDenied, isProtectedAddress, respond } from '../xdr/exfiltration/respond.mjs';
import { runXdr } from '../scripts/xdr-run.mjs';

const root = new URL('..', import.meta.url).pathname;
const fixturePath = join(root, 'xdr', 'fixtures', 'exfiltration.json');
const fixture = JSON.parse(await readFile(fixturePath, 'utf8'));
const patternsFile = JSON.parse(await readFile(join(root, 'xdr', 'exfiltration', 'patterns.json'), 'utf8'));
const num = (n) => Number(n.slice(3));
const expectedAction = (alert) => (num(alert.id) <= 10 ? 'block' : num(alert.id) <= 20 ? 'alert' : 'record');

test('every pattern has a name, a technique, conditions and a one-line evidence, and nothing is listed without evidence', () => {
  assert.ok(patternsFile.patterns.length >= 2);
  const names = new Set();
  for (const p of patternsFile.patterns) {
    assert.match(p.name, /^[a-z][a-z0-9_]+$/u);
    assert.match(p.technique, /^T10(41|48)$/u);
    assert.ok(p.when && Object.keys(p.when).length > 0);
    assert.ok(typeof p.evidence === 'string' && p.evidence.length > 10 && !p.evidence.includes('\n'));
    assert.ok(/T1041|T1048/u.test(p.evidence), `${p.name}: 근거에 ATT&CK 번호가 있어야 합니다`);
    names.add(p.name);
  }
  assert.equal(names.size, patternsFile.patterns.length);
});

test('decide.mjs repeats the patterns file exactly, imports nothing and touches no files, network or process', async () => {
  assert.deepEqual(PATTERNS, patternsFile.patterns);
  const source = await readFile(join(root, 'xdr', 'exfiltration', 'decide.mjs'), 'utf8');
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
    if (num(alert.id) >= 21) assert.notEqual(out.action, 'block', `정상 이벤트 ${alert.id}를 막았습니다`);
  }
  assert.deepEqual(counts, { block: 10, alert: 10, record: 10 });
  // 임계값과 행동이 맞물립니다.
  for (const alert of fixture.alerts) {
    const { action, confidence } = decide(alert);
    assert.equal(action, confidence >= BLOCK_AT ? 'block' : confidence >= ALERT_AT ? 'alert' : 'record');
  }
});

test('decide handles boundaries and odd input without throwing', () => {
  const mk = (level, description, data = {}, mitre = ['T1048']) => ({ id: 'x', rule: { level, description, mitre }, data: { srcip: '192.0.2.9', srcuser: 'u', dstip: '203.0.113.9', ...data } });
  assert.equal(decide(mk(12, '10분 안에 자료 200건이 처음 보는 목적지로 나갔습니다.', { bytes: '240000000', files: '200' })).action, 'block');
  assert.equal(decide(mk(12, '수업 시간 밖에 압축 파일이 처음 보는 주소로 나갔습니다.', { bytes: '180000000', files: '1' })).action, 'block');
  assert.equal(decide(mk(12, '큰 파일이 나갔습니다.', { bytes: '60000000' })).action, 'alert'); // 크기 하나만으로는 막지 않습니다
  assert.equal(decide(mk(12, '처음 보는 목적지로 나갔습니다.', { bytes: '1000' })).action, 'alert'); // 작은 전송은 목적지가 낯설어도 막지 않습니다
  assert.equal(decide(mk(5, '전송이 실패 1건으로 끝났습니다. 목적지는 처음 봅니다.', { bytes: '0' })).action, 'alert'); // 실패는 신호로 세지 않습니다
  assert.equal(decide(mk(7, '평소 목적지인데 파일 수가 한 번 늘었습니다.', { files: '12' })).action, 'alert');
  assert.equal(decide(mk(3, '수업 자료 주소로 작은 동기화가 끝났습니다.', { bytes: '20000', files: '3' })).action, 'record'); // 수준 3 이하는 평소 사건
  assert.equal(decide(mk(12, '10분 안에 자료 200건이 처음 보는 목적지로 나갔습니다.', { bytes: '240000000', files: '200' }, [])).action, 'record'); // 유출 기술 표시가 없으면 막지 않습니다
  for (const odd of [null, undefined, 5, 'x', [], {}, { rule: null }, { rule: { level: 'high' }, data: 'abc' }, { rule: { level: 12, mitre: ['T1048'], description: 7 }, data: { bytes: 'abc' } }]) {
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
  const source = await readFile(join(root, 'xdr', 'exfiltration', 'decide.mjs'), 'utf8');
  assert.equal(source.includes('read-alerts'), false);
});

test('respond adds deny rules only for block candidates, with expiry and alert id, and normal traffic passes', async () => {
  const decisions = fixture.alerts.map((alert) => ({ alertId: alert.id, ...decide(alert) }));
  const now = new Date('2026-10-15T00:00:00Z');
  const { rules, skipped } = buildDenyRules({ alerts: fixture.alerts, decisions, now });
  const blockAddresses = new Set(fixture.alerts.filter((a) => expectedAction(a) === 'block').map((a) => a.data.dstip));
  assert.deepEqual(new Set(rules.map((r) => r.address)), blockAddresses);
  assert.equal(skipped.length, 0);
  for (const rule of rules) {
    assert.equal(rule.effect, 'deny');
    assert.match(rule.alertId, /^ex-\d+$/u);
    assert.ok(Date.parse(rule.expiresAt) > Date.parse(rule.createdAt));
  }
  // 정상(record)·애매(alert) 경보의 주소는 규칙에 없고 통과합니다.
  for (const alert of fixture.alerts.filter((a) => expectedAction(a) !== 'block')) {
    assert.equal(isDenied(alert.data.dstip, rules, now), null, alert.id);
  }
  for (const address of blockAddresses) assert.ok(isDenied(address, rules, now), address);
  // 만료되면 더는 막지 않습니다.
  assert.equal(isDenied(rules[0].address, rules, new Date(now.getTime() + 2 * 60 * 60 * 1000)), null);
});

test('respond never blocks a protected address or an address that also shows normal use', () => {
  assert.equal(isProtectedAddress('127.0.0.1'), true);
  assert.equal(isProtectedAddress('192.168.0.5'), true);
  assert.equal(isProtectedAddress('10.1.2.3'), true);
  assert.equal(isProtectedAddress('::1'), true);
  assert.equal(isProtectedAddress('not an ip'), true);
  assert.equal(isProtectedAddress('203.0.113.10'), false);
  const alerts = [
    { id: 'a', data: { dstip: '192.168.0.9' } }, { id: 'b', data: { dstip: '203.0.113.77' } }, { id: 'c', data: { dstip: '203.0.113.77' } },
    { id: 'd', data: { dstip: '' } }, { id: 'e', data: { dstip: '203.0.113.88' } },
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
  const dir = await mkdtemp(join(tmpdir(), 'xdr-ex-'));
  try {
    await mkdir(join(dir, 'xdr', 'fixtures'), { recursive: true });
    await cp(fixturePath, join(dir, 'xdr', 'fixtures', 'exfiltration.json'));
    const result = await respond({ root: dir, now: new Date('2026-10-15T00:00:00Z') });
    assert.equal(result.logged, 20);
    const log = (await readFile(join(dir, 'xdr', 'alerts.log'), 'utf8')).trim().split('\n');
    assert.equal(log.length, 20);
    assert.equal(log.filter((l) => l.includes(' block ')).length, 10);
    assert.equal(log.filter((l) => l.includes(' alert ')).length, 10);
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
    await mkdir(join(dir, 'xdr', 'exfiltration'), { recursive: true });
    await cp(fixturePath, join(dir, 'xdr', 'fixtures', 'exfiltration.json'));
    await cp(join(root, 'xdr', 'exfiltration', 'decide.mjs'), join(dir, 'xdr', 'exfiltration', 'decide.mjs'));
    const errors = [];
    const result = await runXdr({ root: dir, moduleKey: 'exfiltration', writeError: (line) => errors.push(line) });
    assert.deepEqual(result.counts, { block: 10, alert: 10, record: 10 });
    assert.deepEqual(errors, []);
    for (const d of result.decisions.filter((x) => num(x.alertId) >= 21)) assert.notEqual(d.action, 'block');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
