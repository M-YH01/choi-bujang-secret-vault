// 12단계 탈환 작전실의 서버 요약: GET /api/ops/summary
//
// 이 요약은 "서버가 실제로 읽은 값"과 "아직 확인하지 못한 것"을 따로 담습니다.
// - confirmed : 서버 표(device_approvals, study_notes_backup, study_notes_audit)를 지금 읽어 센 값입니다.
// - practice  : 가상 요청으로 코드를 돌려 본 연습 결과입니다. 심판·반 엔진의 판정이 아닙니다.
// - not_run   : 실행하지 못했거나 연결을 확인하지 못한 것입니다. 통과로 세지 않습니다.
// 로그인과 기기 승인을 통과한 사람의 기록만 세며, 메모 제목·본문·이메일·토큰은 읽지도 돌려주지도 않습니다.
// 화면의 문구는 이 응답을 그대로 보여 줄 뿐이고 통과의 근거가 아닙니다. 수치는 sql/12-ops-check.sql로 서버 표와 맞춰 봅니다.
import { randomUUID } from 'node:crypto';
import { createClient } from '@supabase/supabase-js';
import { createAuthenticator, defaultVerify, fail, send } from './notes-api.mjs';
import { defaultGate } from './device-approval.mjs';

export const SUMMARY_SCHEMA = 'aleph.ops.summary.v1';
const AUDIT_READ_LIMIT = 1000;
const DEVICE_STATES = ['pending', 'approved', 'revoked'];

const upstream = () => Object.assign(new Error('ops_store_failed'), { code: 'UNAVAILABLE' });

export function createSupabaseOpsStore(client) {
  const run = async (query) => {
    const { data, error } = await query;
    if (error) throw upstream();
    return data ?? [];
  };
  // 열은 개수를 세는 데 필요한 것만 읽습니다. 제목·본문·해시 원문은 읽지 않습니다.
  return {
    async devices(userId) {
      return run(client.from('device_approvals').select('status').eq('user_id', userId));
    },
    async backups(userId) {
      return run(client.from('study_notes_backup').select('backed_up_at').eq('owner_id', userId).order('backed_up_at', { ascending: false }).limit(5000));
    },
    async audit(userId) {
      return run(client.from('study_notes_audit').select('action, result, at').eq('actor', userId).order('at', { ascending: false }).limit(AUDIT_READ_LIMIT));
    },
  };
}

function defaultOpsStore() {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SECRET_KEY;
  if (typeof url !== 'string' || !url.startsWith('https://') || typeof key !== 'string' || !key) throw new Error('not_configured');
  return createSupabaseOpsStore(createClient(url, key, { auth: { persistSession: false, autoRefreshToken: false } }));
}

// 가상 요청 연습: 코드가 계약대로 움직이는지만 봅니다. 운영 엔진과 연결되었다는 뜻이 아닙니다.
export async function runPractice() {
  const out = { decider: { status: 'unavailable' }, detect: { status: 'unavailable' } };
  try {
    const { decide, RULE_IDS } = await import('./decider.mjs');
    const { checkDecider } = await import('../scripts/decider-test.mjs');
    const results = await checkDecider({ decide, ruleIds: RULE_IDS });
    out.decider = { status: 'practice', ruleIds: [...RULE_IDS], total: results.length, passed: results.filter((r) => r.passed).length };
  } catch { /* 연습을 못 돌려도 요약 전체를 막지 않습니다. 상태는 unavailable로 남습니다. */ }
  try {
    const { BURST_RULE } = await import('./detect.mjs');
    const { detect } = await import('./detect.mjs');
    const { checkDetection } = await import('../scripts/detect-test.mjs');
    const results = await checkDetection(detect);
    out.detect = { status: 'practice', rules: [BURST_RULE], total: results.length, passed: results.filter((r) => r.passed).length };
  } catch { /* 위와 같습니다. */ }
  return out;
}

const tally = (rows, key) => {
  const counts = {};
  for (const row of rows) {
    const name = typeof row?.[key] === 'string' ? row[key].slice(0, 60) : 'unknown';
    counts[name] = (counts[name] ?? 0) + 1;
  }
  return counts;
};
const latest = (rows, key) => {
  let best = null;
  for (const row of rows) { const t = Date.parse(row?.[key]); if (Number.isFinite(t) && (best === null || t > best)) best = t; }
  return best === null ? null : new Date(best).toISOString();
};

export const NOT_RUN = Object.freeze([
  { id: 'class_engine_decider', reason: '운영 반 엔진이 이 판정기를 실제로 부르는지 확인하지 못했습니다.' },
  { id: 'class_engine_detect', reason: '운영 반 엔진의 사건 전달과 접속 회수가 연결되었는지 확인하지 못했습니다.' },
  { id: 'real_revocation', reason: '탐지는 회수를 "제안"만 합니다. 실제 접속 회수는 실행하지 않았습니다.' },
  { id: 'attack_41', reason: '41종 총공세는 이 저장소에서 실행하지 않았습니다. 통과로 세지 않습니다.' },
]);

export function createOpsApi({ verify, getStore, gate = null, practice = runPractice, now = () => new Date() }) {
  const authenticate = createAuthenticator(verify, gate);

  async function handle(request, response) {
    response.setHeader('Cache-Control', 'no-store');
    if (request.method !== 'GET') {
      response.setHeader('Allow', 'GET');
      return fail(response, 405, 'METHOD_NOT_ALLOWED', '허용되지 않는 요청 방식입니다.');
    }
    const identity = await authenticate(request, response);
    if (!identity) return undefined;

    let devices; let backups; let audit;
    try {
      const store = getStore();
      [devices, backups, audit] = await Promise.all([store.devices(identity.userId), store.backups(identity.userId), store.audit(identity.userId)]);
    } catch {
      console.error('ops_store_failed');
      return fail(response, 502, 'UNAVAILABLE', '서버 기록을 읽지 못했습니다. 잠시 뒤 다시 시도하세요.');
    }
    const drill = await practice();
    const header = request.headers?.['x-vercel-id'];
    const requestId = typeof header === 'string' && /^[A-Za-z0-9:_-]{1,120}$/u.test(header) ? header : randomUUID();
    const deviceCounts = Object.fromEntries(DEVICE_STATES.map((s) => [s, 0]));
    for (const row of devices) if (DEVICE_STATES.includes(row?.status)) deviceCounts[row.status] += 1;

    return send(response, 200, {
      schema: SUMMARY_SCHEMA,
      requestId,
      generatedAt: now().toISOString(),
      scope: 'signed_in_user_only',
      sections: {
        decider: drill.decider,
        detect: drill.detect,
        revoke: { status: 'confirmed', source: 'device_approvals', devices: deviceCounts, note: '탐지는 회수를 제안만 하며 실제 회수는 연결하지 않았습니다.' },
        restore: {
          status: 'confirmed', source: 'study_notes_backup, study_notes_audit',
          backups: { count: backups.length, latestAt: latest(backups, 'backed_up_at') },
          audit: { total: audit.length, truncated: audit.length >= AUDIT_READ_LIMIT, byAction: tally(audit, 'action'), byResult: tally(audit, 'result'), latestAt: latest(audit, 'at') },
        },
      },
      notRun: NOT_RUN,
    });
  }
  return { handle };
}

export const opsApi = createOpsApi({ verify: defaultVerify, getStore: defaultOpsStore, gate: defaultGate });
