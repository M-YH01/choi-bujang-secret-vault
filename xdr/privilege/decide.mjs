// 보너스 xdr-05: 권한 가로채기(권한 상승) 판단 모듈.
// 이 파일은 다른 파일이나 패키지를 불러오지 않고, 파일을 읽거나 쓰지 않으며, 바깥에 묻지 않고 혼자 계산합니다.
// 판단 결과만 돌려줍니다. 파일 쓰기·판정기 연결은 respond.mjs가 따로 합니다.

// xdr/privilege/patterns.json 의 패턴을 그대로 옮겨 적은 상수입니다(시험이 두 곳이 같은지 비교합니다).
export const PATTERNS = [
  {
    name: 'admin_group_added_unusually',
    technique: 'T1078',
    when: { signal: '관리자 그룹 추가가 원격 주소·여러 계정·빠졌다 다시 들어옴과 함께 나타남' },
    evidence: 'T1078: 공격자는 훔친 평범한 계정을 관리자 그룹에 넣어 권한을 얻으므로, 평소와 다른 관리자 그룹 추가는 정상 계정 도용 뒤의 권한 확보 형태입니다.',
  },
  {
    name: 'fresh_admin_runs_privileged_command',
    technique: 'T1068',
    when: { signal: '방금 관리자가 된 계정이나 관리자 그룹 추가 직후 관리자 명령 실행' },
    evidence: 'T1068: 권한이 높아진 직후 바로 관리자 명령을 실행하는 것은, 올린 권한을 곧바로 쓰는 권한 상승 악용의 결과 형태입니다.',
  },
  {
    name: 'session_elevated_or_impersonated',
    technique: 'T1068',
    when: { signal: '세션이 관리자 권한으로 바뀜 또는 다른 계정의 권한으로 명령 실행' },
    evidence: 'T1068/T1078: 세션의 권한이 갑자기 바뀌거나 다른 계정의 권한으로 명령이 실행되는 것은, 권한을 가로채 쓰는 형태입니다.',
  },
  {
    name: 'privilege_use_off_hours_or_new_source',
    technique: 'T1078',
    when: { signal: '수업 시간 밖이거나 처음 보는 주소에서 관리자 권한 사용' },
    evidence: 'T1078: 도용한 정상 계정은 평소와 다른 시각·주소에서 쓰이는 경우가 많아, 업무 시간 밖이나 처음 보는 주소의 권한 사용은 도용의 신호입니다.',
  },
  {
    name: 'privilege_signal_below_threshold',
    technique: 'T1078',
    when: { needsTag: true, minLevel: 4, maxPoints: 1 },
    evidence: 'T1078/T1068 표시는 있으나 관리자 그룹 추가·관리자 명령 같은 뚜렷한 권한 상승 신호가 하나뿐이거나 없어(취소·실패·변경 없음 포함), 정상 수업 작업과 구별되지 않으므로 알림으로만 남깁니다.',
  },
];

export const BLOCK_AT = 0.85;  // 이 값 이상이면 block
export const ALERT_AT = 0.5;   // 이 값 이상이면 alert, 아래는 record
const NORMAL_CAP = 0.4;        // 평소 사건(수준 3 이하 또는 표시 없음)은 아무리 높아도 record
const POINT = 0.1;             // 뚜렷한 신호 1점마다 확신도 +0.1 (4점이면 0.9)

const byName = (name) => PATTERNS.find((p) => p.name === name);
const round = (x) => Math.round(Math.min(1, Math.max(0, x)) * 100) / 100;

function numberOf(value) {
  const n = typeof value === 'number' ? value : Number.parseInt(String(value ?? ''), 10);
  return Number.isFinite(n) && n >= 0 ? n : 0;
}

const TAGS = ['T1068', 'T1078'];
const hasTag = (alert) => Array.isArray(alert?.rule?.mitre) && alert.rule.mitre.some((t) => TAGS.some((tag) => String(t).startsWith(tag)));

// 설명을 문장으로 나눠, 취소·실패·읽기·변경 없음·아님 같은 부정 문장은 신호로 세지 않습니다.
function positiveSentences(description) {
  return String(description ?? '')
    .split(/(?<=[.!?。])\s*/u)
    .map((s) => s.trim())
    .filter(Boolean)
    .filter((s) => !/없습니다|않았습니다|않습니다|아닙니다|취소|실패|조회|읽었|읽기만/u.test(s));
}

function signalsOf(alert) {
  const text = positiveSentences(alert?.rule?.description).join(' ');
  const count = numberOf(alert?.data?.count);
  const s = {};
  // 핵심 신호(권한을 실제로 올리거나 쓴 일)
  s.groupAdd = /관리자 그룹(?:에|\s)[^.]*(?:추가|들어)|관리자로\s*(?:다시\s*)?들어/u.test(text);
  s.command = /(?:관리자|권한)\s*명령[을이]?\s*(?:한 번\s*)?실행|명령[을이]?\s*실행/u.test(text);
  s.newlyAdmin = /방금 관리자가 된/u.test(text);
  s.sessionElevated = /관리자 권한으로 바뀌/u.test(text);
  s.impersonation = /다른 계정의 권한/u.test(text);
  s.reAdd = /다시\s*관리자로\s*들어/u.test(text);
  // 보조 신호(평소와 다른 상황)
  s.remote = /원격 주소/u.test(text);
  s.newSource = /처음 보는 주소|요청 주소는 처음/u.test(text);
  s.offHours = /수업 시간 밖|업무처럼 보이지 않는 시각/u.test(text);
  s.multiAccount = count >= 4 || /계정\s*\d+개/u.test(text) && numberOf((/계정\s*(\d+)개/u.exec(text) || [])[1]) >= 4;
  s.usualSource = /평소 주소/u.test(text); // 깎는 신호
  return s;
}

const CORE = ['groupAdd', 'command', 'newlyAdmin', 'sessionElevated', 'impersonation', 'reAdd'];
const WEIGHTS = { groupAdd: 3, command: 3, newlyAdmin: 2, sessionElevated: 2, impersonation: 2, reAdd: 2, remote: 2, newSource: 2, offHours: 2, multiAccount: 2 };

function evaluate(alert) {
  const level = numberOf(alert?.rule?.level);
  // 평소 사건: 수준이 낮거나(3 이하) 권한 기술 표시가 없습니다. 패턴을 붙이지 않습니다.
  if (!hasTag(alert) || level <= 3) return { pattern: null, confidence: round(Math.min(NORMAL_CAP, 0.1 + level / 100)) };

  const s = signalsOf(alert);
  const hasCore = CORE.some((key) => s[key]);
  let points = Object.entries(WEIGHTS).reduce((sum, [key, weight]) => sum + (s[key] ? weight : 0), 0);
  if (s.usualSource) points -= 2;
  // 권한을 올리거나 쓴 핵심 신호가 하나도 없으면, 시각·주소 같은 보조 신호만으로는 1점까지만 셉니다.
  points = hasCore ? Math.max(0, points) : Math.min(1, Math.max(0, points));
  const confidence = round(Math.min(0.98, 0.5 + POINT * points));

  let name = 'privilege_signal_below_threshold';
  if (points >= 2) {
    if (s.groupAdd && s.command) name = 'fresh_admin_runs_privileged_command';
    else if (s.groupAdd || s.reAdd || s.multiAccount) name = 'admin_group_added_unusually';
    else if (s.impersonation || s.sessionElevated) name = 'session_elevated_or_impersonated';
    else if (s.command || s.newlyAdmin) name = 'fresh_admin_runs_privileged_command';
    else name = 'privilege_use_off_hours_or_new_source';
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
    ? `${pattern.name} (${pattern.technique}): ${action === 'block' ? '권한 상승 신호가 여러 개 겹쳐 세션을 거둘 후보입니다' : '권한 상승 신호가 뚜렷하지 않아 알립니다'}`
    : 'no_pattern: 평소 사건이라 기록만 합니다';
  return { action, confidence, reason };
}
