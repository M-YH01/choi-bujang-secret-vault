import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
// 실제로 보낸 요청의 결과만 기록합니다. 심판의 판정이 아닙니다.
function appOrigin(config) {
  let app;
  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  return app;
}

const request = (url) => fetch(url, {
  redirect: 'error', signal: AbortSignal.timeout(10000), headers: { Accept: 'application/json' },
});

// 1단계: 비로그인 요청으로 공개 /data.json에서 가상 메모를 읽을 수 있는가.
async function anonymousDataJson(config, app) {
  if (typeof config.sampleMarker !== 'string' || !config.sampleMarker) throw new Error('가상 메모의 확인 표시를 넣어 주세요.');
  const response = await request(new URL('/data.json', app));
  let visible = false;
  if (response.ok) {
    try {
      const data = await response.json();
      visible = data?.sampleMarker === config.sampleMarker && Array.isArray(data.notes)
        && data.notes.length > 0;
    } catch {
      // A non-JSON response is a failed check, not a successful deployment.
    }
  }
  return { attackId: 'anonymous_note_read', expected: '비로그인 화면에서 가상 메모를 확인',
    observed: visible ? '비로그인 요청에서 공개 가상 메모 확인 표시가 보임' : `비로그인 요청에서 확인 표시가 보이지 않음 (HTTP ${response.status})` };
}

// 3단계: 로그인 없이 /api/notes 목록을 부르면 401·403과 JSON 오류로 거부되는가.
async function anonymousNoteList(app) {
  const response = await request(new URL('/api/notes', app));
  const isJson = (response.headers.get('content-type') ?? '').includes('json');
  let hasError = false;
  try {
    const data = await response.json();
    hasError = typeof data?.error === 'string';
  } catch {
    // HTML이나 빈 응답은 거부로 인정하지 않습니다.
  }
  const rejected = (response.status === 401 || response.status === 403) && isJson && hasError;
  return { attackId: 'anonymous_note_list', expected: '로그인 없이 /api/notes 메모 목록을 읽기',
    observed: rejected ? `로그인 없는 요청이 JSON 오류로 거부됨 (HTTP ${response.status})`
      : `로그인 없는 요청이 JSON 오류로 거부되지 않음 (HTTP ${response.status})` };
}

// 4단계: 로그인 없이 한 건 경로(/api/notes/:id)를 불러도 JSON 오류로 거부되는가.
// 번호는 존재하지 않는 시험용 값이라 실제 메모를 읽지 않습니다.
async function anonymousNoteItem(app) {
  const response = await request(new URL('/api/notes/00000000-0000-4000-8000-000000000000', app));
  const isJson = (response.headers.get('content-type') ?? '').includes('json');
  let hasError = false;
  try {
    const data = await response.json();
    hasError = typeof data?.error === 'string';
  } catch {
    // HTML이나 빈 응답은 거부로 인정하지 않습니다.
  }
  const rejected = (response.status === 401 || response.status === 403) && isJson && hasError;
  return { attackId: 'anonymous_note_item', expected: '로그인 없이 /api/notes/:id 한 건을 읽기',
    observed: rejected ? `로그인 없는 요청이 JSON 오류로 거부됨 (HTTP ${response.status})`
      : `로그인 없는 요청이 JSON 오류로 거부되지 않음 (HTTP ${response.status})` };
}

// 10단계: 로그인 없이 복원 경로(POST /api/restore/notes/:id)를 불러도 JSON 오류로 거부되는가.
// 번호는 존재하지 않는 시험용 값이고 토큰은 보내지 않으므로 아무 메모도 바뀌지 않습니다.
async function anonymousRestore(app) {
  const response = await fetch(new URL('/api/restore/notes/00000000-0000-4000-8000-000000000000', app), {
    method: 'POST', redirect: 'error', signal: AbortSignal.timeout(10000), headers: { Accept: 'application/json' },
  });
  let hasError = false;
  try { hasError = typeof (await response.json())?.error === 'string'; } catch { /* 본문이 JSON이 아니면 거부로 인정하지 않습니다. */ }
  const isJson = (response.headers.get('content-type') ?? '').includes('json');
  const rejected = (response.status === 401 || response.status === 403) && isJson && hasError;
  return { attackId: 'anonymous_restore', expected: '로그인 없이 복원 경로로 메모 되살리기',
    observed: rejected ? `로그인 없는 요청이 JSON 오류로 거부됨 (HTTP ${response.status})`
      : `로그인 없는 요청이 JSON 오류로 거부되지 않음 (HTTP ${response.status})` };
}

// 11단계: 로그인 없이 기기 승인 상태를 물어도 거부되는가(승인 상태가 새어 나가지 않는가).
async function anonymousDeviceStatus(app) {
  const response = await fetch(new URL('/api/device', app), {
    redirect: 'error', signal: AbortSignal.timeout(10000), headers: { Accept: 'application/json' },
  });
  let hasError = false;
  try { hasError = typeof (await response.json())?.error === 'string'; } catch { /* 본문이 JSON이 아니면 거부로 인정하지 않습니다. */ }
  const isJson = (response.headers.get('content-type') ?? '').includes('json');
  const rejected = (response.status === 401 || response.status === 403) && isJson && hasError;
  return { attackId: 'anonymous_device_status', expected: '로그인 없이 기기 승인 상태 읽기',
    observed: rejected ? `로그인 없는 요청이 JSON 오류로 거부됨 (HTTP ${response.status})`
      : `로그인 없는 요청이 JSON 오류로 거부되지 않음 (HTTP ${response.status})` };
}

// 12단계: npm run verify:matrix가 남긴 실측 표(artifacts/verification-matrix.json)를 읽어 요약만 적습니다.
// 표가 없으면 미실행입니다. 이 점검은 요청을 새로 보내지 않고, 표에 없는 결과를 만들어 내지 않습니다.
function matrixSummary() {
  const file = join(dirname(fileURLToPath(import.meta.url)), '..', 'artifacts', 'verification-matrix.json');
  const expected = '1~11단계 정상·금지 요청을 실제로 보내 기대 결과와 대조한 실측 표';
  let data;
  try { data = JSON.parse(readFileSync(file, 'utf8')); } catch {
    return { attackId: 'verification_matrix', expected, observed: '실측 표 파일이 없어 미실행 (npm run verify:matrix를 먼저 실행하세요)' };
  }
  const s = data?.summary;
  if (data?.schema !== 'aleph.verification-matrix.v1' || !s || ![s.total, s.match, s.mismatch, s.notRun].every(Number.isInteger)) {
    return { attackId: 'verification_matrix', expected, observed: '실측 표 형식을 읽지 못해 미실행으로 처리' };
  }
  const last = data.rows?.map((r) => r.checkedAt).filter(Boolean).sort().at(-1) ?? '없음';
  return { attackId: 'verification_matrix', expected,
    observed: `전체 ${s.total}줄 중 기대와 같음 ${s.match}, 기대와 다름 ${s.mismatch}, 미실행 ${s.notRun} (마지막 확인 ${last})` };
}

function attack41() {
  return { attackId: 'attack_41', expected: '41종 총공세 방어', observed: '41종 총공세는 이 저장소에서 실행하지 않아 미실행 (통과로 세지 않음)' };
}

// 5단계: 공개 키로 원본 자료 주소를 직접 불러도 메모가 나오지 않는가.
// 공개 키는 배포가 공개한 /aleph.json에서 읽어 요청 헤더에만 쓰고, 키와 응답 본문은 기록하지 않습니다.
async function directOriginalRead(config, app) {
  const attackId = 'direct_original_read';
  const expected = '공개 키로 원본 자료 주소를 직접 불러 메모 읽기';
  let original;
  try {
    original = new URL(config.originalApiUrl);
  } catch {
    throw new Error('aleph.config.json의 originalApiUrl을 확인해 주세요.');
  }
  if (original.protocol !== 'https:' || original.search || original.username || original.password) {
    throw new Error('aleph.config.json의 originalApiUrl은 쿼리 없는 HTTPS 주소여야 합니다.');
  }
  const info = await (await request(new URL('/aleph.json', app))).json().catch(() => null);
  const key = info?.database?.publishableKey;
  if (typeof key !== 'string' || !key) {
    return { attackId, expected, observed: '배포의 /aleph.json에서 공개 키를 읽지 못해 점검하지 못함' };
  }
  const target = new URL(original);
  target.searchParams.set('select', 'id');
  target.searchParams.set('limit', '1');
  const response = await fetch(target, {
    redirect: 'error', signal: AbortSignal.timeout(10000),
    headers: { Accept: 'application/json', apikey: key },
  });
  let rows = null;
  if (response.ok) {
    try { const data = await response.json(); rows = Array.isArray(data) ? data.length : null; } catch { /* 본문 없음 */ }
  }
  const observed = !response.ok ? `공개 키 직접 요청이 거부됨 (HTTP ${response.status})`
    : rows === 0 ? `공개 키 직접 요청이 성공했지만 메모가 0건 (HTTP ${response.status})`
      : `공개 키 직접 요청으로 메모가 읽힘 (HTTP ${response.status})`;
  return { attackId, expected, observed };
}

export async function runAttackChecks(config) {
  if (![1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12].includes(config.step)) {
    throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
  }
  const app = appOrigin(config);
  if (config.step === 1) return [await anonymousDataJson(config, app)];
  // 3단계에서는 /data.json에 메모가 없는지, /api/notes가 로그인 없이 거부되는지 함께 봅니다.
  // 정상 로그인(A)과 타인(B) 요청은 토큰이 필요해서 이 점검에서는 실행하지 않습니다(미실행).
  // 4단계의 A·B 교차 요청(남의 번호로 읽기·수정·삭제)도 토큰이 필요해 이 점검에서는 미실행입니다.
  const results = [await anonymousDataJson({ ...config, sampleMarker: config.sampleMarker }, app),
    await anonymousNoteList(app)];
  if (config.step >= 4) results.push(await anonymousNoteItem(app));
  if (config.step >= 5) results.push(await directOriginalRead(config, app));
  if (config.step >= 10) results.push(await anonymousRestore(app));
  // 승인된 기기에서의 정상 열림과 승인 전 거부(로그인 토큰·기기 쿠키 필요)는 이 점검에서 실행하지 않습니다(미실행).
  if (config.step >= 11) results.push(await anonymousDeviceStatus(app));
  if (config.step >= 12) results.push(matrixSummary(), attack41());
  return results;
}
