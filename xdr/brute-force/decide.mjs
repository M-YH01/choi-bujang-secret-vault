// 보너스 xdr-01: 무차별 로그인 공격 판단 모듈.
// 이 파일은 다른 파일이나 패키지를 불러오지 않고, 파일을 읽거나 쓰지 않으며, 바깥에 묻지 않고 혼자 계산합니다.
// 판단 결과만 돌려줍니다. 파일 쓰기·판정기 연결은 respond.mjs가 따로 합니다.

// xdr/brute-force/patterns.json 의 패턴을 그대로 옮겨 적은 상수입니다(시험이 두 곳이 같은지 비교합니다).
export const PATTERNS = [
  {
    name: 'burst_failures_same_source',
    technique: 'T1110.001',
    when: { minFailures: 15 },
    evidence: 'T1110.001 Password Guessing: 한 주소·한 계정에서 짧은 시간에 로그인 실패가 연속으로 쌓이는 비밀번호 추측 형태입니다.',
  },
  {
    name: 'password_spray_many_accounts',
    technique: 'T1110.003',
    when: { minAccounts: 8 },
    evidence: 'T1110.003 Password Spraying: 같은 주소가 여러 계정에 같은 비밀번호를 대입하는 형태입니다.',
  },
  {
    name: 'slow_failures_below_burst',
    technique: 'T1110.001',
    when: { minFailures: 3, maxFailures: 14, needsT1110Tag: true },
    evidence: 'T1110.001 Password Guessing과 같은 기술이지만 실패 수가 기준 미만이라, 막지 않고 알림으로만 남기는 낮은 확신도 구간입니다.',
  },
];

export const BLOCK_AT = 0.85;  // 이 값 이상이면 block
export const ALERT_AT = 0.5;   // 이 값 이상이면 alert, 아래는 record
const NORMAL_CAP = 0.4;        // 정상으로 보이는 사건(수준 3 이하, T1110 표시 없음)은 아무리 높아도 record

const byName = (name) => PATTERNS.find((pattern) => pattern.name === name);
const round2 = (value) => Math.round(Math.min(1, Math.max(0, value)) * 100) / 100;

function numberOf(value) {
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (typeof value === 'string' && /^\d{1,7}$/u.test(value.trim())) return Number(value.trim());
  return null;
}

// 로그인 실패 건수: data.count가 있으면 그 값, 없으면 설명의 "실패 N건"에서 읽습니다.
function failuresOf(data, description) {
  const counted = numberOf(data?.count);
  if (counted !== null) return counted;
  const match = /실패[^0-9]{0,12}(\d{1,6})\s*건/u.exec(description);
  return match ? Number(match[1]) : 0;
}

// 시도한 계정 수: data.accounts(쉼표로 나눈 목록) 또는 설명의 "계정 N개".
function accountsOf(data, description) {
  if (typeof data?.accounts === 'string' && data.accounts.trim()) {
    return new Set(data.accounts.split(',').map((name) => name.trim()).filter(Boolean)).size;
  }
  const match = /계정\s*(\d{1,4})\s*개/u.exec(description);
  return match ? Number(match[1]) : 0;
}

function evaluate(alert) {
  const description = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  const level = numberOf(alert?.rule?.level) ?? 0;
  const tagged = Array.isArray(alert?.rule?.mitre) && alert.rule.mitre.some((id) => typeof id === 'string' && id.startsWith('T1110'));
  const failures = failuresOf(alert?.data, description);
  const accounts = accountsOf(alert?.data, description);
  const succeededAfter = /성공(했|하였)/u.test(description) && !/성공은 없/u.test(description);
  const sameSecret = description.includes('같은 비밀번호');

  const matches = [];
  const burst = byName('burst_failures_same_source');
  if (failures >= burst.when.minFailures) {
    matches.push({ pattern: burst, score: 0.75 + (level >= 10 ? 0.1 : 0) + (failures >= 40 ? 0.05 : 0) + (tagged ? 0.05 : 0), note: `같은 주소 로그인 실패 ${failures}건` });
  }
  const spray = byName('password_spray_many_accounts');
  if (accounts >= spray.when.minAccounts) {
    matches.push({ pattern: spray, score: 0.75 + (level >= 10 ? 0.1 : 0) + (tagged ? 0.05 : 0) + (sameSecret ? 0.05 : 0), note: `계정 ${accounts}개에 같은 주소가 시도` });
  }
  const slow = byName('slow_failures_below_burst');
  if (failures >= slow.when.minFailures && failures <= slow.when.maxFailures && (!slow.when.needsT1110Tag || tagged)) {
    matches.push({ pattern: slow, score: 0.5 + (level >= 7 ? 0.05 : 0) + (failures >= 8 ? 0.05 : 0) + (succeededAfter ? 0 : 0.05), note: `로그인 실패 ${failures}건(기준 미만)` });
  }

  const normalLooking = level <= 3 && !tagged;
  if (!matches.length) return { score: 0, best: null, normalLooking };
  matches.sort((a, b) => b.score - a.score);
  return { score: matches[0].score, best: matches[0], normalLooking };
}

export function decide(alert) {
  if (alert === null || typeof alert !== 'object' || Array.isArray(alert)) {
    return { action: 'record', confidence: 0, reason: 'no_pattern: 경보 형식이 아니라 기록만 합니다' };
  }
  const { score, best, normalLooking } = evaluate(alert);
  let confidence = round2(score);
  if (normalLooking && confidence > NORMAL_CAP) confidence = NORMAL_CAP;
  const action = confidence >= BLOCK_AT ? 'block' : confidence >= ALERT_AT ? 'alert' : 'record';
  const reason = best
    ? `${best.pattern.name} (${best.pattern.technique}): ${best.note}`
    : 'no_pattern: 일치하는 패턴이 없어 기록만 합니다';
  return { action, confidence, reason };
}
