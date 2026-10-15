// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기입니다. (docs/DECIDER_REQUEST.md 계약 v1)
// 6단계: 등록된 기기에서 온 요청만 허용합니다. 규칙은 단계마다 하나씩 더합니다.
//
// 읽는 요청 항목은 requestId와 deviceRegistered 둘뿐입니다. 브라우저가 보낸 userId, role,
// device, identity, geo나 토큰은 읽지도 믿지도 않습니다. 계약에 없는 이름을 만들어 쓰지 마세요.
export const RULE_IDS = Object.freeze(['device_registered']);

export async function decide(request) {
  // 기기 등록 여부가 정확히 true일 때만 허용합니다. false, 값 없음, 문자열 'true' 같은 모양은 모두 거부입니다.
  const registered = request?.deviceRegistered === true;
  return {
    schema: 'aleph.decision.v1',
    requestId: request?.requestId,
    decision: registered ? 'allow' : 'deny',
    reasonCode: registered ? 'approved' : 'device_not_registered',
    ruleIds: ['device_registered'],
  };
}
