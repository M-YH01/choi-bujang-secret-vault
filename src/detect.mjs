// 9단계 탐지 함수입니다. docs/DETECT_EVENTS.md의 사건 계약 그대로입니다.
// 사건마다 읽는 값은 at(시각), method(요청 종류), identity.sub(가명 사용자) 세 개뿐입니다.
// 네트워크·기기·지역·헤더·메모 내용·토큰·실명은 읽지도 저장하지도 출력하지도 않습니다.
// 이 함수는 회수를 "제안"만 합니다. 회수 API를 부르거나 기기 권한을 바꾸지 않습니다.
// 반 엔진이 검증한 사건만 전달해야 하며, 브라우저가 보낸 사용자 번호는 받지 않습니다.
export const BURST_RULE = 'burst_read';

const WINDOW_MS = 10 * 60 * 1000; // 10분 구간. 첫 사건과 마지막 사건의 시각 차가 10분 이하이면 같은 구간입니다.
const LIMIT = 120;                // 구간 안 GET이 120건을 "넘을" 때만 의심입니다(정확히 120건은 의심 아님).
const MAX_SUB_LENGTH = 128;

// ---- 입력 처리 --------------------------------------------------------------
// 세 값이 모두 올바른 GET 사건만 근거로 삼습니다. 값이 없거나 모양이 틀린 사건은
// 정상값으로 채우지 않고 건너뜁니다(세지 않음). 사건 전체를 복사해 두지 않습니다.
function readEvent(event) {
  if (event === null || typeof event !== 'object') return null;
  const { at, method } = event;
  const sub = event.identity?.sub;
  if (method !== 'GET') return null;
  if (typeof sub !== 'string' || sub.length === 0 || sub.length > MAX_SUB_LENGTH) return null;
  if (typeof at !== 'string') return null;
  const time = Date.parse(at);
  if (!Number.isFinite(time)) return null;
  return { sub, time };
}

// 같은 가명 사용자의 GET 시각만 모읍니다. 다른 사용자의 사건은 합치지 않습니다.
function readTimesBySubject(events) {
  const bySubject = new Map();
  for (const event of events) {
    const read = readEvent(event);
    if (!read) continue;
    const times = bySubject.get(read.sub);
    if (times) times.push(read.time); else bySubject.set(read.sub, [read.time]);
  }
  return bySubject;
}

// ---- 규칙 burst_read --------------------------------------------------------
// 시각을 오름차순으로 놓고, 창 안(첫 사건~마지막 사건이 10분 이하)의 건수가 120을 넘는
// 첫 시각을 찾습니다. 창 계산은 at 시각만 씁니다. 못 찾으면 null입니다.
function firstBurstTime(times) {
  const sorted = [...times].sort((a, b) => a - b);
  let left = 0;
  for (let right = 0; right < sorted.length; right += 1) {
    while (sorted[right] - sorted[left] > WINDOW_MS) left += 1;
    if (right - left + 1 > LIMIT) return sorted[right];
  }
  return null;
}

export function detect(events) {
  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');
  // 의심 사용자가 여럿이면 가장 먼저 한도를 넘은 사용자 한 명을 돌려줍니다(같은 시각이면 sub 순서).
  let suspect = null;
  for (const [sub, times] of readTimesBySubject(events)) {
    const burstAt = firstBurstTime(times);
    if (burstAt === null) continue;
    if (suspect === null || burstAt < suspect.burstAt || (burstAt === suspect.burstAt && sub < suspect.sub)) {
      suspect = { sub, burstAt };
    }
  }
  if (suspect === null) return { action: 'observe' };
  // 돌려주는 키는 정확히 세 개뿐입니다. 기기 번호 같은 다른 키는 덧붙이지 않습니다.
  return { action: 'propose_revocation', reasonCode: BURST_RULE, subject: suspect.sub };
}
