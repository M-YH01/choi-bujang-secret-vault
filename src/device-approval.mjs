// 11단계: 기기 승인. 설치했다는 표시나 "승인" 버튼만으로는 아무 권한도 생기지 않습니다.
//
// - 기기 식별자는 서버가 만든 무작위 값이고, 브라우저에는 HttpOnly 쿠키로만 놓입니다(자바스크립트가 읽지 못함).
//   localStorage·sessionStorage·IndexedDB에는 기기 키도 로그인 토큰도 넣지 않습니다.
// - 서버 표(device_approvals)에는 식별자의 SHA-256 해시만 저장합니다. 원문은 저장하지 않습니다.
// - 승인(status = approved)은 이 코드로 만들 수 없습니다. 운영자가 Supabase에서 직접 바꿉니다.
//   서버 키(service_role)에는 status를 쓰거나 바꿀 권한을 주지 않았습니다(sql/11-device-approvals.sql).
// - 메모 API는 로그인이 맞아도 (로그인한 사람, 이 기기)가 정확히 approved일 때만 열립니다.
//   확인 중 오류가 나면 열지 않습니다(닫힌 채로 실패).
import { createHash, randomBytes } from 'node:crypto';
import { createClient } from '@supabase/supabase-js';

export const COOKIE_NAME = '__Host-device';
export const STATES = Object.freeze(['none', 'pending', 'approved', 'revoked']);
const DEVICE_ID = /^[A-Za-z0-9_-]{43}$/u;
const MAX_PENDING_PER_USER = 5;
const COOKIE_SECONDS = 60 * 60 * 24 * 180;
const TABLE = 'device_approvals';

export const hashDevice = (deviceId) => createHash('sha256').update(String(deviceId), 'utf8').digest('hex');
export const newDeviceId = () => randomBytes(32).toString('base64url');

// 요청 머리글의 쿠키에서 기기 식별자만 읽습니다. 모양이 다르면 없는 것으로 봅니다.
export function readDeviceId(request) {
  const header = request?.headers?.cookie;
  if (typeof header !== 'string') return null;
  for (const part of header.split(';')) {
    const index = part.indexOf('=');
    if (index < 0) continue;
    if (part.slice(0, index).trim() !== COOKIE_NAME) continue;
    const value = part.slice(index + 1).trim();
    return DEVICE_ID.test(value) ? value : null;
  }
  return null;
}

export const deviceCookie = (deviceId) =>
  `${COOKIE_NAME}=${deviceId}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=${COOKIE_SECONDS}`;

// 운영자가 표에서 요청을 찾을 때 쓰는 짧은 번호입니다. 권한이 없는 값이라 화면에 보여도 됩니다.
export const requestCode = (rowId) => String(rowId ?? '').replaceAll('-', '').slice(0, 8);

// 사람이 적은 기기 이름은 짧게, 제어 문자 없이만 받습니다(운영자가 어느 기기인지 알아보는 용도일 뿐입니다).
export function cleanLabel(value) {
  if (typeof value !== 'string') return null;
  const text = value.replace(/[\u0000-\u001f\u007f<>]/gu, ' ').replace(/\s+/gu, ' ').trim().slice(0, 40);
  return text || null;
}

// "열어 줄 것인가"는 정확히 approved일 때만 true입니다.
export const isApproved = (state) => state === 'approved';

const upstream = (error) => Object.assign(new Error('device_store_failed'), { code: 'UNAVAILABLE', upstreamCode: error?.code ?? null });

export function createSupabaseDeviceStore(client) {
  const run = async (query) => {
    const { data, error } = await query;
    if (error) throw upstream(error);
    return data;
  };
  return {
    async find(userId, hash) {
      const row = await run(client.from(TABLE).select('id, status').eq('user_id', userId).eq('device_hash', hash).maybeSingle());
      return row ? { id: row.id, status: row.status } : null;
    },
    async countPending(userId) {
      const rows = await run(client.from(TABLE).select('id').eq('user_id', userId).eq('status', 'pending'));
      return Array.isArray(rows) ? rows.length : 0;
    },
    // status는 보내지 않습니다. 표의 기본값(pending)만 들어갑니다.
    async createPending({ userId, hash, label }) {
      const row = await run(client.from(TABLE).insert({ user_id: userId, device_hash: hash, label }).select('id').single());
      return { id: row.id, status: 'pending' };
    },
  };
}

function defaultDeviceStore() {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SECRET_KEY;
  if (typeof url !== 'string' || !url.startsWith('https://') || typeof key !== 'string' || !key) throw new Error('not_configured');
  return createSupabaseDeviceStore(createClient(url, key, { auth: { persistSession: false, autoRefreshToken: false } }));
}

// (로그인한 사람, 이 요청의 기기)의 상태. 쿠키가 없으면 표를 읽지 않고 none입니다.
export async function deviceState(store, userId, request) {
  const deviceId = readDeviceId(request);
  if (!deviceId) return { state: 'none', deviceId: null, row: null };
  const row = await store.find(userId, hashDevice(deviceId));
  const state = row && STATES.includes(row.status) ? row.status : 'none';
  return { state, deviceId, row };
}

// 메모 API가 로그인 확인 직후에 부르는 문입니다. { allowed, state }를 돌려주고, 오류는 그대로 던집니다.
// 끄는 스위치는 없습니다. 환경변수나 인자로 검사를 건너뛸 수 없습니다.
export function createDeviceGate({ getStore = defaultDeviceStore } = {}) {
  return async function gate(request, identity) {
    const { state } = await deviceState(getStore(), identity.userId, request);
    return { allowed: isApproved(state), state };
  };
}

export const defaultGate = createDeviceGate();
export { MAX_PENDING_PER_USER, defaultDeviceStore };
