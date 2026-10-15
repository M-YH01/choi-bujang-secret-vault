// 보너스 xdr-02: 웹 주입 공격 판단 모듈.
// 이 파일은 다른 파일이나 패키지를 불러오지 않고, 파일을 읽거나 쓰지 않으며, 바깥에 묻지 않고 혼자 계산합니다.
// 판단 결과만 돌려줍니다. 파일 쓰기·판정기 연결은 respond.mjs가 따로 합니다.

// xdr/web-injection/patterns.json 의 패턴을 그대로 옮겨 적은 상수입니다(시험이 두 곳이 같은지 비교합니다).
export const PATTERNS = [
  {
    name: 'sql_injection_repeated',
    technique: 'T1190',
    when: { signal: 'sql', minRepeats: 8 },
    evidence: 'T1190: 요청 인자에 SQL 구문을 이어 붙여 공개 앱의 데이터베이스 조회를 바꾸려는 SQL 주입이, 같은 주소에서 반복되는 형태입니다.',
  },
  {
    name: 'script_injection_repeated',
    technique: 'T1190',
    when: { signal: 'script', minRepeats: 8 },
    evidence: 'T1190: 요청 인자에 스크립트 태그를 넣어 공개 앱이 그대로 되돌려 보내게 하려는 스크립트 삽입이, 같은 주소에서 반복되는 형태입니다.',
  },
  {
    name: 'path_traversal_repeated',
    technique: 'T1190',
    when: { signal: 'path', minRepeats: 8 },
    evidence: 'T1190: 경로 인자에 ../ 를 여러 단계 이어 붙여 공개 앱이 허용하지 않은 위치를 열어 보려는 경로 거슬러 올라가기가 반복되는 형태입니다.',
  },
  {
    name: 'command_separator_repeated',
    technique: 'T1190',
    when: { signal: 'command', minRepeats: 8 },
    evidence: 'T1190: 요청 인자에 명령 구분자를 끼워 공개 앱이 다른 명령까지 실행하게 하려는 시도가, 연속 요청에서 반복되는 형태입니다.',
  },
  {
    name: 'single_marker_below_repeat',
    technique: 'T1190',
    when: { minRepeats: 1, maxRepeats: 7, needsT1190Tag: true },
    evidence: 'T1190 표시가 붙었지만 반복이 기준 미만이라, 정상 입력(수업 단어·따옴표)과 구별되지 않아 막지 않고 알림으로만 남기는 낮은 확신도 구간입니다.',
  },
];

export const BLOCK_AT = 0.85;  // 이 값 이상이면 block
export const ALERT_AT = 0.5;   // 이 값 이상이면 alert, 아래는 record
const NORMAL_CAP = 0.4;        // 정상으로 보이는 사건(수준 3 이하, T1190 표시 없음)은 아무리 높아도 record

const byName = (name) => PATTERNS.find((p) => p.name === name);

function numberOf(value) {
  const n = typeof value === 'number' ? value : Number.parseInt(String(value ?? ''), 10);
  return Number.isFinite(n) && n >= 0 ? n : 0;
}

// 반복 횟수: data.count 를 먼저 보고, 없으면 설명의 "N번" 표기를 봅니다.
function repeatsOf(alert) {
  const fromData = numberOf(alert?.data?.count);
  if (fromData > 0) return fromData;
  const match = /(\d{1,6})\s*번/u.exec(String(alert?.rule?.description ?? ''));
  return match ? Number(match[1]) : 0;
}

// 설명에 나온 주입 신호 종류. 하나의 경보에 여러 종류가 섞일 수 있습니다.
function signalsOf(alert) {
  const text = String(alert?.rule?.description ?? '');
  const found = [];
  if (/SQL|데이터베이스 조회/iu.test(text)) found.push('sql');
  if (/스크립트\s*(삽입|표식|태그)/u.test(text)) found.push('script');
  if (/경로|거슬러/u.test(text)) found.push('path');
  if (/명령 구분자/u.test(text)) found.push('command');
  return found;
}

const hasT1190 = (alert) => Array.isArray(alert?.rule?.mitre) && alert.rule.mitre.includes('T1190');
const levelOf = (alert) => numberOf(alert?.rule?.level);
const round = (x) => Math.round(Math.min(1, Math.max(0, x)) * 100) / 100;

function evaluate(alert) {
  const level = levelOf(alert);
  const repeats = repeatsOf(alert);
  const signals = signalsOf(alert);
  const tagged = hasT1190(alert);

  // 정상으로 보이는 사건: 수준이 낮고 T1190 표시가 없습니다. 어떤 패턴도 붙이지 않습니다.
  if (!tagged && level <= 3) return { pattern: null, confidence: Math.min(NORMAL_CAP, 0.1) };

  // 반복이 기준 이상이고 신호 종류가 읽히면 반복 패턴(차단 구간 후보).
  const kind = ['sql', 'script', 'path', 'command'].find((s) => signals.includes(s));
  if (tagged && kind) {
    const pattern = PATTERNS.find((p) => p.when.signal === kind);
    if (repeats >= pattern.when.minRepeats) {
      let c = 0.75;
      if (level >= 10) c += 0.1;
      if (repeats >= 12) c += 0.05;
      if (signals.length >= 2) c += 0.05; // 종류가 섞여 있으면 더 뚜렷합니다.
      return { pattern, confidence: round(c) };
    }
  }

  // 표시는 있으나 반복이 기준 미만: 알림 구간.
  const single = byName('single_marker_below_repeat');
  if (tagged && repeats >= single.when.minRepeats) {
    let c = 0.5;
    if (level >= 7) c += 0.05;
    if (repeats >= 2) c += 0.05;
    return { pattern: single, confidence: round(Math.min(c, BLOCK_AT - 0.1)) };
  }

  // 그 밖: 패턴 없음 → 기록만.
  return { pattern: null, confidence: round(Math.min(NORMAL_CAP, 0.1 + level / 100)) };
}

export function decide(alert) {
  if (!alert || typeof alert !== 'object' || Array.isArray(alert)) {
    return { action: 'record', confidence: 0, reason: 'no_pattern: 경보 형식이 아니라 기록만 합니다' };
  }
  const { pattern, confidence } = evaluate(alert);
  const action = confidence >= BLOCK_AT ? 'block' : confidence >= ALERT_AT ? 'alert' : 'record';
  const reason = pattern
    ? `${pattern.name} (${pattern.technique}): ${action === 'block' ? '반복이 뚜렷해 차단 후보입니다' : '표시는 있으나 뚜렷하지 않아 알립니다'}`
    : 'no_pattern: 일치하는 패턴이 없어 기록만 합니다';
  return { action, confidence, reason };
}
