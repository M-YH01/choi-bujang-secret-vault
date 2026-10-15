// 보너스 xdr-03: 알려진 취약점(CVE-2021-44228 형태) 악용 판단 모듈.
// 이 파일은 다른 파일이나 패키지를 불러오지 않고, 파일을 읽거나 쓰지 않으며, 바깥에 묻지 않고 혼자 계산합니다.
// 판단 결과만 돌려줍니다. 파일 쓰기·판정기 연결은 respond.mjs가 따로 합니다.
// 요청 값은 정규식으로 "읽기만" 합니다. 조회 구문 안의 주소로 접속하거나 구문을 실행하지 않고, 이유 글에도 원문을 옮기지 않습니다.

// xdr/known-cve/patterns.json 의 패턴을 그대로 옮겨 적은 상수입니다(시험이 두 곳이 같은지 비교합니다).
export const PATTERNS = [
  {
    name: 'jndi_lookup_in_header',
    technique: 'T1190',
    when: { field: 'useragent', contains: '${jndi:<ldap|ldaps|rmi|dns|iiop|http|https>://' },
    evidence: 'CVE-2021-44228 / T1190: 요청 머리글(User-Agent 등)에 ${jndi:ldap://...} 형태의 원격 조회 구문이 들어가, 기록 도구가 그 구문을 풀다가 바깥 코드를 불러오게 하는 형태입니다.',
  },
  {
    name: 'jndi_lookup_in_parameter',
    technique: 'T1190',
    when: { field: 'url', contains: '${jndi:<ldap|ldaps|rmi|dns|iiop|http|https>://' },
    evidence: 'CVE-2021-44228 / T1190: 주소의 요청 인자에 ${jndi:ldap://...} 형태의 원격 조회 구문이 들어가, 인자가 기록되는 순간 취약한 로그4j가 구문을 푸는 형태입니다.',
  },
  {
    name: 'jndi_lookup_repeated_or_multi_field',
    technique: 'T1190',
    when: { minFields: 2, orMinRepeats: 2 },
    evidence: 'CVE-2021-44228 / T1190: 같은 원격 조회 구문이 머리글과 주소에 함께 있거나 같은 주소에서 반복되는 것은, 우연한 입력이 아니라 취약한 위치를 찾으려는 자동 악용 형태입니다.',
  },
  {
    name: 'known_scanner_trace_with_lookup',
    technique: 'T1190',
    when: { descriptionHas: '점검', needsLookup: true },
    evidence: 'CVE-2021-44228 / T1190: 알려진 취약점 점검 도구가 상태 확인 주소 등에 같은 조회 구문을 넣어 보는 흔적이 구문과 함께 있으면 악용 시도로 봅니다.',
  },
  {
    name: 'cve_marker_without_lookup',
    technique: 'T1190',
    when: { needsT1190Tag: true, lookup: false },
    evidence: 'T1190 표시는 있으나 요청 값에 완전한 ${jndi:...://} 조회 구문이 없어(CVE 번호·단어·조각만 있음) 악용으로 단정할 수 없으므로 막지 않고 알림으로만 남깁니다.',
  },
];

export const BLOCK_AT = 0.85;  // 이 값 이상이면 block
export const ALERT_AT = 0.5;   // 이 값 이상이면 alert, 아래는 record
const NORMAL_CAP = 0.4;        // 정상으로 보이는 사건(수준 3 이하, T1190 표시 없음)은 아무리 높아도 record

// 완전한 조회 구문: ${jndi:프로토콜://  (프로토콜은 알려진 것만)
const LOOKUP = /\$\{\s*jndi\s*:\s*(?:ldaps?|rmi|dns|iiop|https?)\s*:\/\//iu;

const byName = (name) => PATTERNS.find((p) => p.name === name);

function numberOf(value) {
  const n = typeof value === 'number' ? value : Number.parseInt(String(value ?? ''), 10);
  return Number.isFinite(n) && n >= 0 ? n : 0;
}

const round = (x) => Math.round(Math.min(1, Math.max(0, x)) * 100) / 100;
const hasT1190 = (alert) => Array.isArray(alert?.rule?.mitre) && alert.rule.mitre.includes('T1190');
const levelOf = (alert) => numberOf(alert?.rule?.level);

// 요청 값(머리글·인자)이 들어 있는 칸 이름. 주소·계정 칸은 요청 값이 아닙니다.
function lookupFields(alert) {
  const data = alert?.data;
  if (!data || typeof data !== 'object' || Array.isArray(data)) return [];
  return Object.entries(data)
    .filter(([key, value]) => key !== 'srcip' && key !== 'srcuser' && typeof value === 'string' && LOOKUP.test(value))
    .map(([key]) => key);
}

function evaluate(alert) {
  const level = levelOf(alert);
  const tagged = hasT1190(alert);
  const repeats = numberOf(alert?.data?.count);
  const description = String(alert?.rule?.description ?? '');

  if (!tagged && level <= 3) return { pattern: null, confidence: 0.1 };

  const fields = lookupFields(alert);
  if (fields.length > 0) {
    const header = fields.includes('useragent');
    let pattern = header ? byName('jndi_lookup_in_header') : byName('jndi_lookup_in_parameter');
    let c = 0.8;
    if (level >= 10) c += 0.05;
    if (fields.length >= 2 || repeats >= 2) { c += 0.05; pattern = byName('jndi_lookup_repeated_or_multi_field'); }
    if (description.includes('점검')) { c += 0.05; pattern = byName('known_scanner_trace_with_lookup'); }
    if (!tagged) c = Math.min(c, 0.7); // T1190 표시가 없으면 막지 않고 알립니다.
    return { pattern, confidence: round(c) };
  }

  // 완전한 조회 구문이 없음: 표시가 있으면 알림 구간(막지 않습니다).
  if (tagged) {
    let c = 0.5;
    if (level >= 7) c += 0.05;
    if (repeats >= 2) c += 0.05;
    return { pattern: byName('cve_marker_without_lookup'), confidence: round(Math.min(c, BLOCK_AT - 0.2)) };
  }
  return { pattern: null, confidence: round(Math.min(NORMAL_CAP, 0.1 + level / 100)) };
}

export function decide(alert) {
  if (!alert || typeof alert !== 'object' || Array.isArray(alert)) {
    return { action: 'record', confidence: 0, reason: 'no_pattern: 경보 형식이 아니라 기록만 합니다' };
  }
  const { pattern, confidence } = evaluate(alert);
  const action = confidence >= BLOCK_AT ? 'block' : confidence >= ALERT_AT ? 'alert' : 'record';
  const reason = pattern
    ? `${pattern.name} (${pattern.technique}): ${action === 'block' ? '완전한 조회 구문이 요청 값에 있어 차단 후보입니다' : '구문이 뚜렷하지 않아 알립니다'}`
    : 'no_pattern: 일치하는 패턴이 없어 기록만 합니다';
  return { action, confidence, reason };
}
