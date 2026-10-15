// 보너스 xdr-04: 몰래 심어진 프로그램(서비스·예약 작업·시작 항목) 판단 모듈.
// 이 파일은 다른 파일이나 패키지를 불러오지 않고, 파일을 읽거나 쓰지 않으며, 바깥에 묻지 않고 혼자 계산합니다.
// 판단 결과만 돌려줍니다. 파일 쓰기·판정기 연결은 respond.mjs가 따로 합니다.

// xdr/persistence/patterns.json 의 패턴을 그대로 옮겨 적은 상수입니다(시험이 두 곳이 같은지 비교합니다).
export const PATTERNS = [
  {
    name: 'unsigned_service_registered',
    technique: 'T1543',
    when: { signal: '서명 없는 서비스 등록·변경' },
    evidence: 'T1543: 공격자는 다시 켜도 남도록 서비스를 새로 만들거나 실행 파일을 바꿔 두는데, 서명이 없는 새 서비스 등록·변경은 그 대표 형태입니다.',
  },
  {
    name: 'unknown_scheduled_task',
    technique: 'T1053',
    when: { signal: '처음 보는 예약 작업, 임의 문자열 이름, 수업 시간 밖 실행' },
    evidence: 'T1053: 공격자는 예약 작업으로 프로그램을 정해진 때마다 다시 실행시켜 남아 있으므로, 평소 목록에 없는 낯선 예약 작업은 지속 형태의 신호입니다.',
  },
  {
    name: 'startup_folder_added',
    technique: 'T1547.001',
    when: { signal: '시작 폴더에 평소 목록에 없는 프로그램 추가' },
    evidence: 'T1547.001: 시작 폴더에 넣은 프로그램은 로그인할 때마다 자동 실행되므로, 평소 목록에 없는 시작 폴더 추가는 지속 형태입니다.',
  },
  {
    name: 'temp_folder_executable_persisted',
    technique: 'T1543',
    when: { signal: '서비스·예약 작업·시작 항목이 임시 폴더의 실행 파일을 가리킴' },
    evidence: 'T1543/T1053: 임시 폴더는 일반 사용자도 쓸 수 있는 자리라, 서비스·예약 작업이 그곳의 실행 파일을 가리키면 심어 둔 프로그램일 가능성이 큽니다.',
  },
  {
    name: 'multiple_mechanisms_or_remote_registration',
    technique: 'T1543',
    when: { signal: '서비스와 예약 작업·시작 항목을 함께 사용, 원격 주소의 연속 서비스 등록' },
    evidence: 'T1543/T1053: 한 파일을 여러 방식(서비스·예약·시작)으로 동시에 걸어 두거나 원격에서 서비스를 연속 등록하는 것은, 한 방식이 지워져도 남으려는 지속 형태입니다.',
  },
  {
    name: 'unconfirmed_item_below_threshold',
    technique: 'T1543',
    when: { needsTag: true, minLevel: 4, maxPoints: 1 },
    evidence: 'T1543/T1053 표시는 있으나 서명 없음·임시 폴더·원격 등록 같은 뚜렷한 지속 신호가 부족해, 정상 수업 작업과 구별되지 않으므로 막지 않고 알림으로만 남깁니다.',
  },
];

export const BLOCK_AT = 0.85;  // 이 값 이상이면 block
export const ALERT_AT = 0.5;   // 이 값 이상이면 alert, 아래는 record
const NORMAL_CAP = 0.4;        // 평소 사건(수준 3 이하 또는 표시 없음)은 아무리 높아도 record
const POINT = 0.1;             // 뚜렷한 지속 신호 1점마다 확신도 +0.1 (4점이면 0.9)

const byName = (name) => PATTERNS.find((p) => p.name === name);
const round = (x) => Math.round(Math.min(1, Math.max(0, x)) * 100) / 100;

function numberOf(value) {
  const n = typeof value === 'number' ? value : Number.parseInt(String(value ?? ''), 10);
  return Number.isFinite(n) && n >= 0 ? n : 0;
}

const TAGS = ['T1543', 'T1053', 'T1547'];
const hasTag = (alert, tag) => Array.isArray(alert?.rule?.mitre) && alert.rule.mitre.some((t) => String(t).startsWith(tag));

// 설명을 문장으로 나눠, "없습니다/않았습니다/모릅니다/그대로입니다" 같은 부정 문장은 신호로 세지 않습니다.
// 단, "서명 없는"·"평소 목록에 없는"의 '없다'는 부정이 아니라 신호 자체이므로 먼저 떼어 둡니다.
function positiveSentences(description) {
  return String(description ?? '')
    .split(/(?<=[.!?。])\s*/u)
    .map((s) => s.trim())
    .filter(Boolean)
    .filter((s) => {
      const stripped = s.replace(/서명(?:이|은)?\s*없|평소 목록에\s*없/gu, '');
      return !/없습니다|않았습니다|않습니다|모릅니다|아닙니다|그대로입니다|확인되지/u.test(stripped);
    });
}

function signalsOf(alert) {
  const text = positiveSentences(alert?.rule?.description).join(' ');
  const path = typeof alert?.data?.path === 'string' ? alert.data.path : '';
  const count = numberOf(alert?.data?.count);
  const s = {};
  s.unsigned = /서명(?:이|은)?\s*없/u.test(text);
  s.newTask = /처음 보는/u.test(text);
  s.randomName = /임의 문자열/u.test(text);
  s.offHours = /수업 시간 밖/u.test(text);
  s.unknownItem = /평소 목록에\s*없/u.test(text);
  s.startup = /시작 폴더에[^.]*추가|시작 프로그램/u.test(text) || /\\Startup\\/iu.test(path);
  s.temp = /\\Temp\\/iu.test(path) || /임시 폴더/u.test(text);
  s.changedBinary = /실행 파일이 바뀌/u.test(text);
  s.persist = /다시 켜도 남도록/u.test(text);
  s.remote = /원격 주소/u.test(text) || count >= 3;
  s.both = hasTag(alert, 'T1543') && hasTag(alert, 'T1053');
  return s;
}

// 신호마다 점수. 서명 없음이 가장 무겁습니다.
const WEIGHTS = { unsigned: 3, unknownItem: 2, temp: 2, startup: 2, remote: 2, persist: 2, changedBinary: 2, newTask: 2, randomName: 2, offHours: 1, both: 1 };

function evaluate(alert) {
  const level = numberOf(alert?.rule?.level);
  const tagged = TAGS.some((tag) => hasTag(alert, tag));
  // 평소 사건: 수준이 낮거나(3 이하) 지속 기술 표시가 없습니다. 패턴을 붙이지 않습니다.
  if (!tagged || level <= 3) return { pattern: null, confidence: round(Math.min(NORMAL_CAP, 0.1 + level / 100)) };

  const s = signalsOf(alert);
  const points = Object.entries(WEIGHTS).reduce((sum, [key, weight]) => sum + (s[key] ? weight : 0), 0);
  const confidence = round(Math.min(0.98, 0.5 + POINT * points));

  let name = 'unconfirmed_item_below_threshold';
  if (points >= 2) {
    if (s.unsigned) name = 'unsigned_service_registered';
    else if (s.newTask || s.randomName || s.offHours) name = 'unknown_scheduled_task';
    else if (s.startup && !s.temp) name = 'startup_folder_added';
    else if (s.both) name = 'multiple_mechanisms_or_remote_registration';
    else if (s.temp) name = 'temp_folder_executable_persisted';
    else name = 'multiple_mechanisms_or_remote_registration';
  }
  return { pattern: byName(name), confidence };
}

export function decide(alert) {
  if (!alert || typeof alert !== 'object' || Array.isArray(alert)) {
    return { action: 'record', confidence: 0, reason: 'no_pattern: 경보 형식이 아니라 기록만 합니다' };
  }
  const { pattern, confidence } = evaluate(alert);
  const action = confidence >= BLOCK_AT ? 'block' : confidence >= ALERT_AT ? 'alert' : 'record';
  const reason = pattern
    ? `${pattern.name} (${pattern.technique}): ${action === 'block' ? '지속 신호가 여러 개 겹쳐 격리 후보입니다' : '지속 신호가 뚜렷하지 않아 알립니다'}`
    : 'no_pattern: 평소 사건이라 기록만 합니다';
  return { action, confidence, reason };
}
