// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기입니다. (docs/DECIDER_REQUEST.md 계약 v1)
// 규칙은 단계마다 하나씩 더합니다.
//   6단계 device_registered : 등록된 기기에서 온 요청만 허용합니다.
//   7단계 step_up_required  : 평소와 다른 시각·네트워크에서 자료를 갑자기 많이 읽으면 다시 확인합니다.
//   8단계 resource_zone     : 서비스와 정확한 경로 모양으로 구역을 나누고, 허용 목록 밖은 모두 거부합니다.
//
// 읽는 요청 항목은 requestId, deviceRegistered, service, method, route, path, signals, recentEvents, stepUp뿐입니다.
// 쿼리(queryLength, querySha256)로 기능을 고르지 않으므로 읽지 않습니다.
// 브라우저가 보낸 userId, role, device, identity, geo, 헤더, 토큰은 읽지도 믿지도 않습니다.
// 계약에 없는 이름을 만들어 쓰지 마세요.
export const RULE_IDS = Object.freeze(['device_registered', 'resource_zone', 'step_up_required']);

// ---- 입력 검사 ------------------------------------------------------------
// 엔진이 검증해 준 값만 근거로 삼습니다. 없거나 모양이 맞지 않거나 출처가 불명확하면
// "정상값"으로 채우지 않고 그 근거를 아예 쓰지 않습니다(= 이상 신호로 세지 않음).
// deviceId·subjectId·route 같은 항목은 이번 규칙에 쓰지 않습니다.

// 심판이 보낸 가상 접속 사건(source: judge_fixture)만 읽습니다. 현재 실제 경로의 source는 "none"이라
// 실제 접속은 이 규칙에 걸리지 않고, judge_fixture 값도 실제 위치 증거로 취급하지 않습니다.
// region은 읽지 않습니다: 지역 하나만으로는 차단하거나 다시 확인을 요구하지 않습니다.
function virtualSignals(request) {
  const signals = request?.signals;
  if (!signals || typeof signals !== 'object' || Array.isArray(signals)) return null;
  if (signals.source !== 'judge_fixture') return null;
  const { network, hour } = signals;
  if (typeof network !== 'string' || !Number.isInteger(hour) || hour < 0 || hour > 23) return null;
  return { network, hour };
}

// 최근 5분 안의 risk_signal 사건 횟수 합계. 엔진이 준 배열(최대 12건)에서 모양이 맞는 항목만 셉니다.
const BURST_WINDOW_SECONDS = 300;
function recentBurstCount(request) {
  const events = request?.recentEvents;
  if (!Array.isArray(events)) return 0;
  let total = 0;
  for (const event of events.slice(0, 12)) {
    if (event && typeof event === 'object' && event.kind === 'risk_signal'
        && Number.isInteger(event.ageSeconds) && event.ageSeconds >= 0 && event.ageSeconds <= BURST_WINDOW_SECONDS
        && Number.isInteger(event.count) && event.count > 0) total += event.count;
  }
  return total;
}

// 엔진이 확인한 재확인 결과: verified가 정확히 true이고 나이가 0~900초일 때만 인정합니다.
function stepUpDone(request) {
  const stepUp = request?.stepUp;
  return Boolean(stepUp) && stepUp.verified === true
    && Number.isInteger(stepUp.authAgeSeconds) && stepUp.authAgeSeconds >= 0 && stepUp.authAgeSeconds <= 900;
}

// 세 가지가 모두 겹칠 때만 이상으로 봅니다: 평소 없는 시각(0~5시) + 처음 보는 네트워크 + 짧은 시간의 많은 읽기.
const UNUSUAL_HOURS = (hour) => hour >= 0 && hour <= 5;
const BURST_THRESHOLD = 10;
function isCompositeAnomaly(request) {
  const signals = virtualSignals(request);
  return Boolean(signals) && UNUSUAL_HOURS(signals.hour) && signals.network === 'unusual'
    && recentBurstCount(request) >= BURST_THRESHOLD;
}

// ---- 8단계: 구역 규칙 -------------------------------------------------------
// 구역(서비스)마다 허용하는 "메서드 + 경로 모양" 목록입니다. 목록에 없으면 거부합니다.
//  - notes: 자료 ID 하나를 고르는 경로만. ID 없는 전체 목록(GET /notes)과 추가(POST /notes)는 거부합니다.
//    메모 주인 비교는 판정기가 아니라 자료 API(src/notes-api.mjs)에서 합니다.
//  - announcements(반 공지): 읽기(GET)만. 쓰기(POST·PUT·PATCH·DELETE)는 누구에게나 거부합니다.
//    강사의 공지 수정은 판정기가 아니라 서버의 관리 경로에서 처리합니다(요청에 역할이 없습니다).
//  - instructor(강사 자료): 판정기에서는 모두 거부합니다.
// 서비스 이름 announcements·instructor는 계약 문서에 정의돼 있지 않아 이 저장소가 정한 값입니다.
const ZONE_RULES = Object.freeze({
  notes: [['GET', [':id']], ['PUT', [':id']], ['DELETE', [':id']]],
  announcements: [['GET', []], ['GET', [':id']]],
  instructor: [],
});
const ROUTE_SHAPE = /^(GET|POST|PUT|PATCH|DELETE) (\/[A-Za-z0-9_:/-]{1,120})$/u;

// 맨 앞의 /api 구간은 한 번만 떼어 내고, 빈 구간(//, 끝 슬래시)이 있으면 거부합니다.
function splitSegments(text) {
  const segments = text.split('/').slice(1);
  if (segments[0] === 'api') segments.shift();
  return segments.length > 0 && segments.every((part) => part !== '') ? segments : null;
}

// 자료 ID 자리는 UUID로 좁히지 않습니다(심판의 가상 요청 ID는 UUID가 아닐 수 있음).
// 다만 한 구간이어야 하고, ., .., 쿼리·해시·공백·제어 문자·인코딩된 슬래시는 거부합니다.
function plainIdSegment(part) {
  return typeof part === 'string' && part.length >= 1 && part.length <= 128
    && part !== '.' && part !== '..' && !/[?#\\\s\u0000-\u001f\u007f]|%2f|%5c/iu.test(part);
}

function zoneAllows(request) {
  const { service, method, route, path } = request ?? {};
  const shape = typeof route === 'string' ? ROUTE_SHAPE.exec(route) : null;
  if (!shape || typeof service !== 'string' || typeof path !== 'string' || method !== shape[1]) return false;
  const routeSegments = splitSegments(shape[2]);
  const pathSegments = path.startsWith('/') ? splitSegments(path) : null;
  if (!routeSegments || !pathSegments || routeSegments.length !== pathSegments.length) return false;
  if (routeSegments[0] !== service || pathSegments[0] !== service) return false;
  if (!Object.hasOwn(ZONE_RULES, service)) return false;
  const rest = routeSegments.slice(1);
  const allowed = ZONE_RULES[service].some(([allowedMethod, allowedRest]) => allowedMethod === method
    && allowedRest.length === rest.length && allowedRest.every((part, index) => part === rest[index]));
  if (!allowed) return false;
  return rest.every((part, index) => (part === ':id'
    ? plainIdSegment(pathSegments[index + 1]) : pathSegments[index + 1] === part));
}

const respond = (request, decision, reasonCode, ruleIds) => ({
  schema: 'aleph.decision.v1',
  requestId: request?.requestId,
  decision,
  reasonCode,
  ruleIds,
});

export async function decide(request) {
  // 6단계: 기기 등록 여부가 정확히 true일 때만 다음 규칙으로 갑니다. 그 밖의 모양은 모두 거부입니다.
  if (request?.deviceRegistered !== true) {
    return respond(request, 'deny', 'device_not_registered', ['device_registered']);
  }
  // 8단계: 허용 목록에 없는 구역·메서드·경로는 거부합니다(모르는 경로도 거부).
  if (!zoneAllows(request)) {
    return respond(request, 'deny', 'resource_not_allowed', ['resource_zone']);
  }
  // 7단계: 복합 이상 접속은 다시 확인합니다. 확인이 끝난 요청은 허용합니다.
  if (isCompositeAnomaly(request)) {
    return stepUpDone(request)
      ? respond(request, 'allow', 'approved', ['device_registered', 'resource_zone', 'step_up_required'])
      : respond(request, 'step_up', 'step_up_required', ['step_up_required']);
  }
  return respond(request, 'allow', 'approved', ['device_registered', 'resource_zone']);
}
