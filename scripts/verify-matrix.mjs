// 12단계 제작 2: 1~11단계의 정상·금지 요청을 배포 주소에 실제로 보내고, 결과를 한 표로 남깁니다.
//
//   npm run verify:matrix
//
// 표의 열: 단계 · 구분(정상/금지) · 요청 · 기대 결과 · 실제 API 결과 · 판정 · 요청 ID · 확인 시각
// 판정은 셋뿐입니다: match(기대와 같음) · mismatch(기대와 다름) · not_run(보내지 못했거나 조건이 안 됨).
// - 응답 본문은 기록하지 않습니다. 상태 코드, 오류 코드, 모양만 남기므로 메모 내용은 표에 들어가지 않습니다.
// - 요청 ID는 응답 머리글(x-vercel-id, sb-request-id, x-request-id)에서 읽은 값입니다. 없으면 "없음"입니다.
// - 로그인이 필요한 줄은 학생이 이 PowerShell 창에서만 넣는 환경변수로 실행합니다(코드·Git·표에는 남지 않음):
//     $env:ALEPH_A_EMAIL / $env:ALEPH_A_PASSWORD   (계정 A)
//     $env:ALEPH_B_EMAIL / $env:ALEPH_B_PASSWORD   (계정 B, 선택)
//   값이 없으면 그 줄은 not_run입니다. 통과 처리하지 않습니다.
// - 41종 총공세는 이 도구가 실행하지 않습니다. 항상 not_run으로 적습니다.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const MATRIX_SCHEMA = 'aleph.verification-matrix.v1';
const ZERO_ID = '00000000-0000-4000-8000-000000000000';
const COOKIE = '__Host-device';
const TIMEOUT = 15000;

const REQUEST_ID_HEADERS = ['x-vercel-id', 'sb-request-id', 'x-request-id'];
const requestIdOf = (headers) => {
  for (const name of REQUEST_ID_HEADERS) {
    const value = headers?.get?.(name);
    if (typeof value === 'string' && /^[A-Za-z0-9:_.-]{1,120}$/u.test(value)) return value;
  }
  return '없음';
};

// 응답을 상태·오류 코드·모양으로만 줄입니다(본문 원문은 버립니다).
async function observe(response) {
  const type = response.headers.get('content-type') ?? '';
  let json = null;
  if (type.includes('json')) { try { json = await response.json(); } catch { json = null; } }
  else { try { await response.arrayBuffer(); } catch { /* 본문은 쓰지 않습니다. */ } }
  return {
    status: response.status,
    error: typeof json?.error === 'string' ? json.error : null,
    deviceState: typeof json?.deviceState === 'string' ? json.deviceState : (typeof json?.state === 'string' ? json.state : null),
    isArray: Array.isArray(json),
    emptyNotes: Array.isArray(json?.notes) && json.notes.length === 0,
    schema: typeof json?.schema === 'string' ? json.schema : null,
    hasName: typeof json?.name === 'string' && json.name.length > 0,
    firstId: Array.isArray(json) && typeof json[0]?.id === 'string' ? json[0].id : null,
    count: Array.isArray(json) ? json.length : null,
    setCookie: response.headers.get('set-cookie'),
    requestId: requestIdOf(response.headers),
  };
}

const fmt = (o) => [`HTTP ${o.status}`, o.error, o.deviceState ? `기기 ${o.deviceState}` : null, o.schema].filter(Boolean).join(' · ');

export function buildCases({ origin, originalApiUrl, publishableKey }) {
  const anon = (extra = {}) => ({ headers: { Accept: 'application/json' }, ...extra });
  return [
    // ---- 로그인 없이 보내는 줄(항상 실행) ----
    { id: 's1-home', step: 1, kind: '정상', label: 'GET /', expected: '200 · 화면이 열림',
      send: (c) => c.fetch('/', anon()), judge: (o) => o.status === 200 },
    { id: 's2-data-json', step: 2, kind: '금지', label: 'GET /data.json', expected: '200 · 공개 파일에 메모가 없음(빈 배열)',
      send: (c) => c.fetch('/data.json', anon()), judge: (o) => o.status === 200 && o.emptyNotes },
    { id: 's3-notes-anon', step: 3, kind: '금지', label: 'GET /api/notes (로그인 없음)', expected: '401 · UNAUTHORIZED',
      send: (c) => c.fetch('/api/notes', anon()), judge: (o) => o.status === 401 && o.error === 'UNAUTHORIZED' },
    { id: 's4-note-anon', step: 4, kind: '금지', label: `GET /api/notes/${ZERO_ID} (로그인 없음)`, expected: '401 · UNAUTHORIZED',
      send: (c) => c.fetch(`/api/notes/${ZERO_ID}`, anon()), judge: (o) => o.status === 401 && o.error === 'UNAUTHORIZED' },
    { id: 's5-original-direct', step: 5, kind: '금지', label: '공개 키로 원본 자료 주소 직접 읽기', expected: '거부(오류 상태) 또는 0건',
      send: async (c) => {
        if (!originalApiUrl || !publishableKey) return { skip: '배포가 공개한 원본 주소·공개 키를 읽지 못했습니다.' };
        return c.fetchAbsolute(originalApiUrl, { headers: { apikey: publishableKey, Accept: 'application/json' } });
      },
      judge: (o) => o.status >= 400 || (o.status === 200 && o.isArray && o.count === 0) },
    { id: 's10-restore-anon', step: 10, kind: '금지', label: `POST /api/restore/notes/${ZERO_ID} (로그인 없음)`, expected: '401 · UNAUTHORIZED',
      send: (c) => c.fetch(`/api/restore/notes/${ZERO_ID}`, anon({ method: 'POST' })), judge: (o) => o.status === 401 && o.error === 'UNAUTHORIZED' },
    { id: 's10-unmatched', step: 10, kind: '금지', label: 'GET /api/없는주소', expected: '404 · 없는 주소는 열리지 않음',
      send: (c) => c.fetch('/api/no-such-route', anon()), judge: (o) => o.status === 404 },
    { id: 's11-manifest', step: 11, kind: '정상', label: 'GET /manifest.webmanifest', expected: '200 · 앱 이름이 있는 설정 파일',
      send: (c) => c.fetch('/manifest.webmanifest', anon()), judge: (o) => o.status === 200 && o.hasName },
    { id: 's11-device-anon', step: 11, kind: '금지', label: 'GET /api/device (로그인 없음)', expected: '401 · UNAUTHORIZED',
      send: (c) => c.fetch('/api/device', anon()), judge: (o) => o.status === 401 && o.error === 'UNAUTHORIZED' },
    { id: 's12-ops-anon', step: 12, kind: '금지', label: 'GET /api/ops/summary (로그인 없음)', expected: '401 · UNAUTHORIZED',
      send: (c) => c.fetch('/api/ops/summary', anon()), judge: (o) => o.status === 401 && o.error === 'UNAUTHORIZED' },

    // ---- 계정 A (환경변수가 있을 때만) ----
    { id: 's11-notes-A-no-device', step: 11, kind: '금지', label: 'GET /api/notes (A 로그인, 기기 쿠키 없음)', expected: '403 · DEVICE_NOT_APPROVED',
      needs: 'A', send: (c) => c.fetch('/api/notes', { headers: { Accept: 'application/json' }, auth: 'A', cookie: false }),
      judge: (o) => o.status === 403 && o.error === 'DEVICE_NOT_APPROVED' },
    { id: 's12-ops-A-no-device', step: 12, kind: '금지', label: 'GET /api/ops/summary (A 로그인, 기기 쿠키 없음)', expected: '403 · DEVICE_NOT_APPROVED',
      needs: 'A', send: (c) => c.fetch('/api/ops/summary', { headers: { Accept: 'application/json' }, auth: 'A', cookie: false }),
      judge: (o) => o.status === 403 && o.error === 'DEVICE_NOT_APPROVED' },
    { id: 's11-device-A', step: 11, kind: '정상', label: 'GET /api/device (A 로그인, 이 도구의 기기 쿠키)', expected: '200 · 기기 상태(none/pending/approved/revoked)',
      needs: 'A', send: (c) => c.fetch('/api/device', { headers: { Accept: 'application/json' }, auth: 'A', cookie: true }),
      judge: (o) => o.status === 200 && ['none', 'pending', 'approved', 'revoked'].includes(o.deviceState) },
    { id: 's3-notes-A', step: 3, kind: '정상', label: 'GET /api/notes (A 로그인, 승인된 기기)', expected: '200 · 메모 목록(배열)',
      needs: 'A', approved: 'A', send: (c) => c.fetch('/api/notes', { headers: { Accept: 'application/json' }, auth: 'A', cookie: true }),
      judge: (o) => o.status === 200 && o.isArray, capture: 'A_NOTE_ID' },
    { id: 's4-note-A-missing', step: 4, kind: '금지', label: `GET /api/notes/${ZERO_ID} (A 로그인, 없는 번호)`, expected: '404 · NOT_FOUND',
      needs: 'A', approved: 'A', send: (c) => c.fetch(`/api/notes/${ZERO_ID}`, { headers: { Accept: 'application/json' }, auth: 'A', cookie: true }),
      judge: (o) => o.status === 404 && o.error === 'NOT_FOUND' },
    { id: 's10-restore-A-dry', step: 10, kind: '금지', label: `POST /api/restore/notes/${ZERO_ID} (A, 사본 없는 번호, 확인만)`, expected: '404 · NOT_FOUND',
      needs: 'A', approved: 'A',
      send: (c) => c.fetch(`/api/restore/notes/${ZERO_ID}`, { method: 'POST', headers: { Accept: 'application/json', 'Content-Type': 'application/json' }, body: '{"dryRun":true}', auth: 'A', cookie: true }),
      judge: (o) => o.status === 404 && o.error === 'NOT_FOUND' },
    { id: 's12-ops-A', step: 12, kind: '정상', label: 'GET /api/ops/summary (A 로그인, 승인된 기기)', expected: '200 · aleph.ops.summary.v1',
      needs: 'A', approved: 'A', send: (c) => c.fetch('/api/ops/summary', { headers: { Accept: 'application/json' }, auth: 'A', cookie: true }),
      judge: (o) => o.status === 200 && o.schema === 'aleph.ops.summary.v1' },

    // ---- 계정 B가 A의 메모를 읽으려는 금지 요청 ----
    { id: 's4-s8-cross-read', step: 8, kind: '금지', label: 'GET /api/notes/<A의 메모 번호> (B 로그인, 승인된 기기)', expected: '404 · NOT_FOUND (남의 메모와 없는 메모를 같게 답함)',
      needs: 'B', approved: 'B', needsCapture: 'A_NOTE_ID',
      send: (c, ctx) => c.fetch(`/api/notes/${encodeURIComponent(ctx.A_NOTE_ID)}`, { headers: { Accept: 'application/json' }, auth: 'B', cookie: true }),
      judge: (o) => o.status === 404 && o.error === 'NOT_FOUND' },

    // ---- API로 관찰할 수 없는 단계: 항상 not_run ----
    { id: 's6-decider', step: 6, kind: '정상·금지', label: '판정기 허용/거부 (반 엔진이 부르는 경로)', expected: '허용·거부 판정', fixedSkip: '운영 반 엔진이 판정기를 부르는지 확인하지 못했습니다. 로컬 가상 요청 연습(npm run decider:test)만 있습니다.' },
    { id: 's7-step-up', step: 7, kind: '정상·금지', label: '평소와 다른 접속의 다시 확인', expected: '다시 확인 요구', fixedSkip: '반 엔진 경로로만 관찰할 수 있어 실행하지 못했습니다.' },
    { id: 's9-detect', step: 9, kind: '금지', label: '조회 폭주 탐지와 접속 회수', expected: '회수 제안', fixedSkip: '반 엔진의 사건 전달과 접속 회수 연결을 확인하지 못했습니다. 로컬 가상 사건 연습만 있습니다.' },
    { id: 'attack-41', step: 12, kind: '금지', label: '41종 총공세', expected: '41종 모두 방어', fixedSkip: '이 저장소에서 실행하지 않았습니다. 통과로 세지 않습니다.' },
  ];
}

// ---- 실행기 ----------------------------------------------------------------
function readCookieFile(path) {
  try { const v = readFileSync(path, 'utf8').trim(); return /^[A-Za-z0-9_-]{43}$/u.test(v) ? v : null; } catch { return null; }
}

export async function runMatrix({ base, env = process.env, fetchImpl = fetch, now = () => new Date(), cookieDir = null }) {
  const origin = new URL(base).origin;
  const timed = (url, init) => fetchImpl(url, { redirect: 'manual', signal: AbortSignal.timeout(TIMEOUT), ...init });

  let info = null;
  try { info = await (await timed(new URL('/aleph.json', origin), { headers: { Accept: 'application/json' } })).json(); } catch { /* 아래에서 not_run으로 처리 */ }
  const db = info?.database;
  const publishableKey = typeof db?.publishableKey === 'string' ? db.publishableKey : null;

  // 계정별 로그인 토큰은 메모리에만 둡니다. 표·파일·로그에 남기지 않습니다.
  const users = {};
  for (const name of ['A', 'B']) {
    const email = env[`ALEPH_${name}_EMAIL`]; const password = env[`ALEPH_${name}_PASSWORD`];
    users[name] = { token: null, cookie: null, state: null, why: null };
    if (!email || !password) { users[name].why = `환경변수 ALEPH_${name}_EMAIL·ALEPH_${name}_PASSWORD가 없습니다.`; continue; }
    if (!db?.url || !publishableKey) { users[name].why = '배포 설정(/aleph.json)을 읽지 못했습니다.'; continue; }
    try {
      const res = await timed(`${db.url}/auth/v1/token?grant_type=password`, {
        method: 'POST', headers: { apikey: publishableKey, 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password }) });
      const data = await res.json();
      if (res.ok && typeof data?.access_token === 'string') users[name].token = data.access_token;
      else users[name].why = `로그인하지 못했습니다 (HTTP ${res.status}).`;
    } catch { users[name].why = '로그인 요청을 보내지 못했습니다.'; }
    if (users[name].token && cookieDir) users[name].cookie = readCookieFile(join(cookieDir, `device-${name}.txt`));
  }

  const cookieHeader = (u) => (u.cookie ? { Cookie: `${COOKIE}=${u.cookie}` } : {});
  const client = {
    fetch: (path, init = {}) => {
      const { auth, cookie, ...rest } = init;
      const headers = { ...(rest.headers ?? {}) };
      if (auth) { Object.assign(headers, { Authorization: `Bearer ${users[auth].token}` }); if (cookie) Object.assign(headers, cookieHeader(users[auth])); }
      return timed(new URL(path, origin), { ...rest, headers });
    },
    fetchAbsolute: (url, init) => timed(url, init),
  };

  // 승인 전 기기라면 이 도구의 기기 쿠키를 서버에 요청합니다(승인은 요청이 아니라 운영자의 SQL로만 됩니다).
  for (const name of ['A', 'B']) {
    const u = users[name];
    if (!u.token) continue;
    if (!u.cookie) {
      try {
        const res = await client.fetch('/api/device', { method: 'POST', headers: { Accept: 'application/json', 'Content-Type': 'application/json' }, body: JSON.stringify({ label: `verify-matrix-${name}` }), auth: name, cookie: false });
        const match = /__Host-device=([A-Za-z0-9_-]{43})/u.exec(res.headers.get('set-cookie') ?? '');
        if (match) { u.cookie = match[1]; if (cookieDir) { mkdirSync(cookieDir, { recursive: true }); writeFileSync(join(cookieDir, `device-${name}.txt`), match[1], { mode: 0o600 }); } }
      } catch { /* 아래 상태 확인에서 not_run으로 이어집니다. */ }
    }
    try {
      const o = await observe(await client.fetch('/api/device', { headers: { Accept: 'application/json' }, auth: name, cookie: true }));
      u.state = o.status === 200 ? o.deviceState : null;
    } catch { u.state = null; }
  }

  const ctx = {};
  const rows = [];
  for (const c of buildCases({ origin, originalApiUrl: info?.originalApiUrl, publishableKey })) {
    const row = { id: c.id, step: c.step, kind: c.kind, request: c.label, expected: c.expected, actual: null, verdict: 'not_run', requestId: '없음', checkedAt: null, note: null };
    const skip = (why) => { row.note = why; rows.push(row); };
    if (c.fixedSkip) { skip(c.fixedSkip); continue; }
    if (c.needs) {
      const u = users[c.needs];
      if (!u.token) { skip(u.why ?? '로그인하지 못했습니다.'); continue; }
      if (c.approved && u.state !== 'approved') { skip(`계정 ${c.approved}의 이 도구 기기 상태가 ${u.state ?? '확인 못 함'}입니다. 승인된 기기에서만 실행합니다.`); continue; }
    }
    if (c.needsCapture && !ctx[c.needsCapture]) { skip('A 계정에 메모가 없거나 A 줄이 실행되지 않아 쓸 번호가 없습니다.'); continue; }
    try {
      const sent = await c.send(client, ctx);
      if (sent?.skip) { skip(sent.skip); continue; }
      const o = await observe(sent);
      row.checkedAt = now().toISOString();
      row.requestId = o.requestId;
      row.actual = fmt(o);
      const ok = c.judge(o);
      row.verdict = ok ? 'match' : 'mismatch';
      if (c.capture && o.firstId) ctx[c.capture] = o.firstId;
    } catch {
      row.actual = '요청을 보내지 못했습니다(연결 실패·시간 초과).';
      row.checkedAt = now().toISOString();
      row.verdict = 'not_run';
    }
    rows.push(row);
  }

  const count = (v) => rows.filter((r) => r.verdict === v).length;
  return {
    schema: MATRIX_SCHEMA, base: origin, createdAt: now().toISOString(), rows,
    summary: { total: rows.length, match: count('match'), mismatch: count('mismatch'), notRun: count('not_run') },
    attack41: { total: 41, executed: 0, verdict: 'not_run', note: '41종 총공세는 이 도구가 실행하지 않았습니다.' },
  };
}

export function renderMarkdown(result) {
  const cell = (v) => String(v ?? '').replaceAll('|', '/').replaceAll('\n', ' ');
  const lines = [
    `# 1~12단계 정상·금지 요청 실측 표`, '',
    `배포 주소: ${result.base} · 만든 시각: ${result.createdAt}`,
    `요약: 전체 ${result.summary.total}줄 · 기대와 같음 ${result.summary.match} · 기대와 다름 ${result.summary.mismatch} · 미실행 ${result.summary.notRun}`,
    `41종 총공세: 실행 ${result.attack41.executed}/${result.attack41.total} — 미실행(통과로 세지 않음)`, '',
    '| 단계 | 구분 | 요청 | 기대 결과 | 실제 API 결과 | 판정 | 요청 ID | 확인 시각 |', '|---|---|---|---|---|---|---|---|',
  ];
  for (const r of result.rows) {
    const verdict = { match: '기대와 같음', mismatch: '기대와 다름', not_run: '미실행' }[r.verdict];
    lines.push(`| ${r.step} | ${cell(r.kind)} | ${cell(r.request)} | ${cell(r.expected)} | ${cell(r.actual ?? `(미실행) ${r.note ?? ''}`)} | ${verdict} | ${cell(r.requestId)} | ${cell(r.checkedAt ?? '-')} |`);
  }
  return `${lines.join('\n')}\n`;
}

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const config = JSON.parse(readFileSync(join(root, 'aleph.config.json'), 'utf8'));
    const base = config.publicAppUrl;
    if (typeof base !== 'string' || !base.startsWith('https://') || base.includes('example')) throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
    const result = await runMatrix({ base, cookieDir: join(root, 'artifacts') });
    mkdirSync(join(root, 'artifacts'), { recursive: true });
    writeFileSync(join(root, 'artifacts', 'verification-matrix.json'), `${JSON.stringify(result, null, 2)}\n`);
    writeFileSync(join(root, 'artifacts', 'verification-matrix.md'), renderMarkdown(result));
    process.stdout.write(renderMarkdown(result));
    process.stdout.write('\n저장: artifacts/verification-matrix.json, artifacts/verification-matrix.md (Git에는 올라가지 않습니다)\n');
    if (result.summary.mismatch > 0) process.exitCode = 1;
  } catch (error) {
    process.stderr.write(`실측 표 첫 오류: ${error.message}\n`);
    process.exitCode = 1;
  }
}
