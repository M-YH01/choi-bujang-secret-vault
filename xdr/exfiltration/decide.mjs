// 보너스 xdr-06: 자료 빼돌리기(외부 전송) 판단 모듈.
// 이 파일은 다른 파일이나 패키지를 불러오지 않고, 파일을 읽거나 쓰지 않으며, 바깥에 묻지 않고 혼자 계산합니다.
// 판단 결과만 돌려줍니다. 파일 쓰기·판정기 연결은 respond.mjs가 따로 합니다.

// xdr/exfiltration/patterns.json 의 패턴을 그대로 옮겨 적은 상수입니다(시험이 두 곳이 같은지 비교합니다).
export const PATTERNS = [
  {
    name: 'large_transfer_to_new_destination',
    technique: 'T1048',
    when: { minBytes: 50000000, signal: '처음 보는 목적지·목적지 여러 곳·평소 쓰지 않던 포트' },
    evidence: 'T1048: 공격자는 평소 쓰지 않는 목적지나 통로로 자료를 내보내므로, 처음 보는 목적지로 가는 대용량 전송은 다른 프로토콜 유출의 대표 형태입니다.',
  },
  {
    name: 'offhours_archive_transfer',
    technique: 'T1048',
    when: { signal: '수업 시간 밖·업무 시간 밖의 압축 파일 또는 대용량 전송' },
    evidence: 'T1048: 유출 전에 자료를 압축으로 묶어 사람이 적은 시간에 내보내는 일이 많아, 업무 시간 밖의 압축 파일 반출은 유출 준비·실행의 신호입니다.',
  },
  {
    name: 'repeated_large_transfer_same_destination',
    technique: 'T1041',
    when: { minRepeats: 8, orSignal: '명령 통로 + 대용량' },
    evidence: 'T1041: 공격자는 이미 열어 둔 명령 통로로 자료를 나눠 계속 보내므로, 같은 목적지로 대용량 전송이 반복되는 것은 명령 통로 유출 형태입니다.',
  },
  {
    name: 'bulk_file_copy_outbound',
    technique: 'T1041',
    when: { minFiles: 50, orSignal: '자료실 전체 복사' },
    evidence: 'T1041: 한 번에 수십~수백 건의 파일이 외부로 나가거나 자료실 전체가 복사되는 것은, 한 사람이 짧은 기간에 대량의 자료를 반출하는 유출 형태입니다.',
  },
  {
    name: 'transfer_signal_below_threshold',
    technique: 'T1048',
    when: { needsTag: true, minLevel: 4, maxPoints: 1 },
    evidence: 'T1041/T1048 표시는 있으나 크기가 작거나 실패·읽기만이거나 평소 목적지라 뚜렷한 대량 반출 신호가 부족해, 정상 수업 전송과 구별되지 않으므로 알림으로만 남깁니다.',
  },
];

export const BLOCK_AT = 0.85;  // 이 값 이상이면 block
export const ALERT_AT = 0.5;   // 이 값 이상이면 alert, 아래는 record
const NORMAL_CAP = 0.4;        // 평소 사건(수준 3 이하 또는 표시 없음)은 아무리 높아도 record
const POINT = 0.1;             // 뚜렷한 신호 1점마다 확신도 +0.1 (4점이면 0.9)
const BIG_BYTES = 50_000_000;  // 학생이 정한 시험용 기준: 대용량 전송
const MASS_FILES = 50;         // 학생이 정한 시험용 기준: 한 번에 나간 파일 수
const REPEATS = 8;             // 학생이 정한 시험용 기준: 같은 목적지 반복

const byName = (name) => PATTERNS.find((p) => p.name === name);
const round = (x) => Math.round(Math.min(1, Math.max(0, x)) * 100) / 100;

function numberOf(value) {
  const n = typeof value === 'number' ? value : Number.parseInt(String(value ?? ''), 10);
  return Number.isFinite(n) && n >= 0 ? n : 0;
}

const hasTag = (alert) => Array.isArray(alert?.rule?.mitre) && alert.rule.mitre.some((t) => /^T10(41|48)/u.test(String(t)));

// 설명을 문장으로 나눠, 실패·읽기만·아직 없음·아님 같은 부정 문장은 신호로 세지 않습니다.
function positiveSentences(description) {
  return String(description ?? '')
    .split(/(?<=[.!?。])\s*/u)
    .map((s) => s.trim())
    .filter(Boolean)
    .filter((s) => !/없습니다|않았습니다|않습니다|아닙니다|아직|실패|읽힌 뒤|읽었/u.test(s));
}

function signalsOf(alert) {
  const text = positiveSentences(alert?.rule?.description).join(' ');
  const data = alert?.data && typeof alert.data === 'object' && !Array.isArray(alert.data) ? alert.data : {};
  const bytes = numberOf(data.bytes);
  const files = numberOf(data.files);
  const count = numberOf(data.count);
  const s = {};
  // 핵심 신호(실제로 많은 자료가 나간 일)
  s.big = bytes >= BIG_BYTES;
  s.mass = files >= MASS_FILES;
  s.whole = /자료실 전체/u.test(text);
  // 보조 신호(평소와 다른 상황)
  s.repeated = count >= REPEATS || /(\d+)번\s*(?:반복|입니다)/u.test(text) && numberOf((/(\d+)번/u.exec(text) || [])[1]) >= REPEATS;
  s.newDest = /처음 보는 (?:목적지|주소)|평소와 다른 주소|다른 주소로|외부 주소로/u.test(text);
  s.multiDest = /목적지 두 곳|목적지 \d+곳/u.test(text);
  s.unusualPort = /쓰지 않던 포트/u.test(text);
  s.offHours = /수업 시간 밖|업무 시간 밖/u.test(text);
  s.archive = /압축 파일/u.test(text);
  s.command = /명령 통로/u.test(text);
  s.knownDest = /평소 목적지|수업 자료 주소|백업처럼/u.test(text); // 깎는 신호
  return s;
}

const CORE = ['big', 'mass', 'whole'];
const WEIGHTS = { big: 3, mass: 3, whole: 2, repeated: 2, newDest: 2, multiDest: 2, unusualPort: 2, offHours: 2, archive: 1, command: 1 };

function evaluate(alert) {
  const level = numberOf(alert?.rule?.level);
  // 평소 사건: 수준이 낮거나(3 이하) 유출 기술 표시가 없습니다. 패턴을 붙이지 않습니다.
  if (!hasTag(alert) || level <= 3) return { pattern: null, confidence: round(Math.min(NORMAL_CAP, 0.1 + level / 100)) };

  const s = signalsOf(alert);
  const hasCore = CORE.some((key) => s[key]);
  let points = Object.entries(WEIGHTS).reduce((sum, [key, weight]) => sum + (s[key] ? weight : 0), 0);
  if (s.knownDest) points -= 2;
  // 크기·파일 수로 "많이 나갔다"는 핵심 신호가 없으면, 목적지·시각 같은 보조 신호만으로는 1점까지만 셉니다.
  points = hasCore ? Math.max(0, points) : Math.min(1, Math.max(0, points));
  const confidence = round(Math.min(0.98, 0.5 + POINT * points));

  let name = 'transfer_signal_below_threshold';
  if (points >= 2) {
    if (s.repeated || (s.command && s.big)) name = 'repeated_large_transfer_same_destination';
    else if (s.offHours) name = 'offhours_archive_transfer';
    else if (s.mass || s.whole) name = 'bulk_file_copy_outbound';
    else name = 'large_transfer_to_new_destination';
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
    ? `${pattern.name} (${pattern.technique}): ${action === 'block' ? '대량 반출 신호가 여러 개 겹쳐 목적지를 막을 후보입니다' : '대량 반출 신호가 뚜렷하지 않아 알립니다'}`
    : 'no_pattern: 평소 사건이라 기록만 합니다';
  return { action, confidence, reason };
}
