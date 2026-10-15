// 8단계: 구역별 자원 ID. 메모(note), 반 공지(notice), 강사 자료(instructor)를 서로 다른 구역으로 나눕니다.
// 자원 ID는 "구역:번호" 모양이고, 서버가 요청마다 어느 구역의 자료인지 구별하는 데 씁니다.
// 기존 자료와 주소는 바꾸지 않습니다. 이 파일은 판정기(src/decider.mjs)와 따로 동작합니다.
export const ZONES = Object.freeze(['note', 'notice', 'instructor']);

const ID_PART = /^[A-Za-z0-9_-]{1,64}$/u;

export function resourceId(zone, id) {
  if (!ZONES.includes(zone) || typeof id !== 'string' || !ID_PART.test(id)) {
    throw new Error('invalid_resource');
  }
  return `${zone}:${id}`;
}

export function parseResourceId(value) {
  if (typeof value !== 'string') return null;
  const [zone, id, extra] = value.split(':');
  if (extra !== undefined || !ZONES.includes(zone) || !ID_PART.test(id ?? '')) return null;
  return { zone, id };
}
