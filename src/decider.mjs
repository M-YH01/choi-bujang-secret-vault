// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기입니다. (docs/DECIDER_REQUEST.md 계약 v1)
// 규칙은 단계마다 하나씩 더합니다.
//   6단계 device_registered : 등록된 기기에서 온 요청만 허용합니다.
//   7단계 step_up_required  : 평소와 다른 시각·네트워크에서 자료를 갑자기 많이 읽으면 다시 확인합니다.
//
// 읽는 요청 항목은 requestId, deviceRegistered, signals, recentEvents, stepUp뿐입니다.
// 브라우저가 보낸 userId, role, device, identity, geo, 헤더, 토큰은 읽지도 믿지도 않습니다.
// 계약에 없는 이름을 만들어 쓰지 마세요.
export const RULE_IDS = Object.freeze(['device_registered', 'step_up_required']);

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
  // 7단계: 복합 이상 접속은 다시 확인합니다. 확인이 끝난 요청은 허용합니다.
  if (isCompositeAnomaly(request)) {
    return stepUpDone(request)
      ? respond(request, 'allow', 'approved', ['device_registered', 'step_up_required'])
      : respond(request, 'step_up', 'step_up_required', ['step_up_required']);
  }
  return respond(request, 'allow', 'approved', ['device_registered']);
}
