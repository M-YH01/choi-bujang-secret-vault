// 보너스 xdr-02 제작 4: decide 결과 가운데 "차단 후보"만 거부 규칙으로 만들고, 알림은 xdr/alerts.log에 한 줄씩 쌓습니다.
//
//   npm run xdr:respond
//
// - decide.mjs는 판단만 합니다. 파일 쓰기와 거부 규칙 만들기는 이 파일만 합니다.
// - 거부 규칙에는 만료 시각과 근거 경보 번호가 붙습니다(xdr/deny-rules.json, schema aleph.deny-rules.v1).
// - 정상 사용자를 막는 규칙은 만들지 않습니다: 정상 사건(record)과 같은 주소, 루프백·사설·링크 로컬 주소,
//   주소 모양이 아닌 값은 차단 후보여도 규칙에서 뺍니다(뺀 이유는 알림 로그에 남습니다).
// - 이 파일은 내 ZTNA 판정기(src/decider.mjs)를 고치지 않습니다. 판정기 요청 계약(docs/DECIDER_REQUEST.md)에는
//   출발 주소 항목이 없어서, 규칙 파일을 판정기가 실제로 읽는 연결은 만들지 못했습니다(isDenied는 연결용 조회 함수입니다).
import { appendFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from './decide.mjs';

export const RULE_ID = 'web_injection_block';
export const DENY_SCHEMA = 'aleph.deny-rules.v1';
export const TTL_MS = 60 * 60 * 1000; // 차단 규칙은 1시간 뒤 만료됩니다.

const here = dirname(fileURLToPath(import.meta.url));
const ROOT = join(here, '..', '..');

// 자동으로 막지 않는 주소: 루프백, 사설망, 링크 로컬, 미지정. (내 PC·집 공유기를 스스로 막는 일을 피합니다.)
export function isProtectedAddress(address) {
  const version = isIP(address);
  if (version === 4) {
    const [a, b] = address.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
  }
  if (version === 6) {
    const lower = address.toLowerCase();
    return lower === '::' || lower === '::1' || lower.startsWith('fe80:') || lower.startsWith('fc') || lower.startsWith('fd');
  }
  return true;
}

const addressOf = (alert) => (typeof alert?.data?.srcip === 'string' ? alert.data.srcip.trim() : '');

export function buildDenyRules({ alerts, decisions, now = new Date(), ttlMs = TTL_MS }) {
  const byId = new Map(alerts.map((alert) => [alert?.id, alert]));
  const normalAddresses = new Set(
    decisions.filter((d) => d.action === 'record').map((d) => addressOf(byId.get(d.alertId))).filter(Boolean),
  );
  const rules = new Map();
  const skipped = [];
  for (const decision of decisions) {
    if (decision.action !== 'block') continue;
    const address = addressOf(byId.get(decision.alertId));
    if (!isIP(address)) { skipped.push({ alertId: decision.alertId, reason: 'invalid_address' }); continue; }
    if (isProtectedAddress(address)) { skipped.push({ alertId: decision.alertId, reason: 'protected_address' }); continue; }
    if (normalAddresses.has(address)) { skipped.push({ alertId: decision.alertId, reason: 'shared_with_normal_use' }); continue; }
    const rule = {
      ruleId: RULE_ID, effect: 'deny', address, alertId: decision.alertId, confidence: decision.confidence,
      reason: String(decision.reason).split(' (')[0],
      createdAt: now.toISOString(), expiresAt: new Date(now.getTime() + ttlMs).toISOString(),
    };
    const existing = rules.get(address);
    if (!existing || rule.confidence > existing.confidence) rules.set(address, rule);
  }
  return { rules: [...rules.values()], skipped };
}

// 판정기 쪽에서 쓸 조회 함수: 만료되지 않은 거부 규칙이 이 주소에 있으면 그 규칙을, 없으면 null을 돌려줍니다.
export function isDenied(address, rules, now = new Date()) {
  const time = now.getTime();
  return rules.find((rule) => rule?.effect === 'deny' && rule.address === address && Date.parse(rule.expiresAt) > time) ?? null;
}

// 같은 주소의 차단 후보가 여럿이면 규칙은 한 줄(가장 확신도 높은 경보)만 만들고, 나머지는 어느 경보와 합쳐졌는지 적습니다.
function denyNote(decision, byId, rules) {
  const rule = rules.find((r) => r.address === addressOf(byId.get(decision.alertId)));
  return !rule || rule.alertId === decision.alertId ? 'denyRule=added' : `denyRule=same_address_as:${rule.alertId}`;
}

const clean = (value) => String(value ?? '').replace(/[\u0000-\u001f\u007f]/gu, ' ').slice(0, 120);

export async function respond({ root = ROOT, now = new Date(), ttlMs = TTL_MS } = {}) {
  const fixture = JSON.parse(await readFile(join(root, 'xdr', 'fixtures', 'web-injection.json'), 'utf8'));
  const alerts = fixture.alerts;
  const decisions = alerts.map((alert) => ({ alertId: alert?.id, ...decide(alert) }));
  const { rules, skipped } = buildDenyRules({ alerts, decisions, now, ttlMs });

  // 이미 있는 규칙 가운데 만료되지 않은 것은 남기고, 같은 주소는 새 규칙으로 바꿉니다.
  const rulesPath = join(root, 'xdr', 'deny-rules.json');
  let kept = [];
  try {
    const old = JSON.parse(await readFile(rulesPath, 'utf8'));
    if (old?.schema === DENY_SCHEMA && Array.isArray(old.rules)) {
      kept = old.rules.filter((rule) => Date.parse(rule?.expiresAt) > now.getTime() && !rules.some((r) => r.address === rule.address));
    }
  } catch { /* 처음 실행이면 파일이 없습니다. */ }
  const all = [...kept, ...rules];
  await mkdir(join(root, 'xdr'), { recursive: true });
  await writeFile(rulesPath, `${JSON.stringify({ schema: DENY_SCHEMA, rules: all }, null, 2)}\n`, 'utf8');

  const byId = new Map(alerts.map((alert) => [alert?.id, alert]));
  const lines = [];
  for (const d of decisions) {
    if (d.action === 'record') continue;
    const skip = skipped.find((s) => s.alertId === d.alertId);
    lines.push([now.toISOString(), d.action, clean(d.alertId), `address=${clean(addressOf(byId.get(d.alertId)))}`, `confidence=${d.confidence}`,
      `pattern=${clean(String(d.reason).split(' (')[0])}`, skip ? `denyRule=skipped:${skip.reason}` : d.action === 'block' ? denyNote(d, byId, rules) : 'denyRule=none'].join(' '));
  }
  if (lines.length) await appendFile(join(root, 'xdr', 'alerts.log'), `${lines.join('\n')}\n`, 'utf8');
  return { decisions, rules, skipped, logged: lines.length };
}

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  try {
    const { decisions, rules, skipped, logged } = await respond();
    const count = (action) => decisions.filter((d) => d.action === action).length;
    process.stdout.write(`block ${count('block')} · alert ${count('alert')} · record ${count('record')}\n`);
    process.stdout.write(`거부 규칙 ${rules.length}개 추가(만료 ${TTL_MS / 60000}분), 규칙에서 뺀 차단 후보 ${skipped.length}개, 알림 로그 ${logged}줄\n`);
  } catch (error) {
    process.stderr.write(`respond 첫 오류: ${error.message}\n`);
    process.exitCode = 1;
  }
}
