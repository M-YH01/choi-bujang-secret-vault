// 가상 메모 API의 핵심 로직입니다. api/notes/*.js가 이 모듈을 부릅니다.
//
// - 요청 토큰은 틀의 src/verify-login.mjs(도우미)로만 검사합니다.
//   브라우저가 보낸 userId·role·owner_id 같은 값은 읽지도 믿지도 않습니다.
// - 토큰이 없거나 검사에 실패하면 자료 없이 401 JSON 오류로 거부합니다.
// - 서버 전용 키(SUPABASE_SECRET_KEY)는 환경변수에서만 읽고, 응답·로그에 내보내지 않습니다.
//
// 알려진 약점(4단계에서 고칩니다): GET·PUT·DELETE /:id는 아직 소유자를 검사하지 않아서
// 로그인한 사람이면 다른 사람의 메모도 읽고 고치고 지울 수 있습니다.
import { createClient } from '@supabase/supabase-js';
import config from '../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from './verify-login.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const MAX_TITLE = 200;
const MAX_BODY = 5000;
const MAX_LIST = 200;
const TABLE = 'study_notes';

const toNote = (row) => ({ id: row.id, title: row.title, body: row.content });

// ---- Supabase 저장소 (서버 전용 키로 접근) -------------------------------
// 오류는 코드만 담은 Error로 바꿔 던집니다. 메시지에 주소나 요청 내용이 섞이지 않게 합니다.
function storeError(error) {
  const failure = new Error('store_failed');
  failure.code = error?.code === '23505' ? 'CONFLICT' : 'UNAVAILABLE';
  failure.upstreamCode = typeof error?.code === 'string' ? error.code : 'unknown';
  return failure;
}

export function createSupabaseStore(client) {
  const table = () => client.from(TABLE);
  return {
    async list(userId) {
      // 주인이 있는 메모는 본인 것만, 주인이 없는(시작 틀의) 가상 메모는 로그인한 모두에게 보여 줍니다.
      const { data, error } = await table().select('id, title, content')
        .or(`owner_id.eq.${userId},owner_id.is.null`)
        .order('created_at', { ascending: true }).order('id', { ascending: true })
        .limit(MAX_LIST);
      if (error) throw storeError(error);
      return (data ?? []).map(toNote);
    },
    async get(id) {
      const { data, error } = await table().select('id, title, content').eq('id', id).maybeSingle();
      if (error) throw storeError(error);
      return data ? toNote(data) : null;
    },
    async create({ id, ownerId, title, content }) {
      const { data, error } = await table().insert({ id, owner_id: ownerId, title, content })
        .select('id').single();
      if (error) throw storeError(error);
      return data.id;
    },
    async update(id, { title, content }) {
      const { data, error } = await table().update({ title, content }).eq('id', id)
        .select('id, title, content').maybeSingle();
      if (error) throw storeError(error);
      return data ? toNote(data) : null;
    },
    async remove(id) {
      const { data, error } = await table().delete().eq('id', id).select('id');
      if (error) throw storeError(error);
      return Array.isArray(data) && data.length > 0;
    },
  };
}

// ---- 응답 도우미 -----------------------------------------------------------
function send(response, status, payload) {
  response.setHeader('Cache-Control', 'no-store');
  return response.status(status).json(payload);
}
const fail = (response, status, error, message) => send(response, status, { error, message });

function readJsonBody(request) {
  let body = request.body;
  if (typeof body === 'string') {
    try { body = JSON.parse(body); } catch { return null; }
  }
  return body && typeof body === 'object' && !Array.isArray(body) ? body : null;
}

// 서버가 받아들이는 값은 title·body(·POST의 id)뿐입니다. 나머지 필드는 버립니다.
function readFields(request) {
  const input = readJsonBody(request);
  if (!input) return null;
  const { title, body } = input;
  if (typeof title !== 'string' || !title.trim() || title.length > MAX_TITLE) return null;
  if (typeof body !== 'string' || body.length > MAX_BODY) return null;
  return { title: title.trim(), content: body, id: input.id };
}

// ---- API ------------------------------------------------------------------
export function createNotesApi({ verify, getStore }) {
  async function authenticate(request, response) {
    const authorization = request.headers?.authorization;
    if (typeof authorization !== 'string' || !authorization) {
      response.setHeader('WWW-Authenticate', 'Bearer');
      fail(response, 401, 'UNAUTHORIZED', '로그인이 필요합니다.');
      return null;
    }
    let identity;
    try {
      identity = await verify(authorization);
    } catch {
      console.error('login_verifier_unavailable');
      fail(response, 500, 'NOT_CONFIGURED', '로그인 검사를 준비하지 못했습니다.');
      return null;
    }
    if (!identity || typeof identity.userId !== 'string' || !UUID.test(identity.userId)) {
      response.setHeader('WWW-Authenticate', 'Bearer');
      fail(response, 401, 'UNAUTHORIZED', '로그인 정보가 올바르지 않습니다.');
      return null;
    }
    return identity;
  }

  async function run(response, work) {
    try {
      return await work(getStore());
    } catch (error) {
      if (error?.code === 'CONFLICT') {
        return fail(response, 409, 'CONFLICT', '같은 id의 메모가 이미 있습니다.');
      }
      // 오류 코드만 기록합니다. 키·주소·요청 내용은 남기지 않습니다.
      console.error('notes_store_failed', error?.upstreamCode ?? 'unavailable');
      return fail(response, error?.code === 'NOT_CONFIGURED' ? 500 : 502,
        error?.code === 'NOT_CONFIGURED' ? 'NOT_CONFIGURED' : 'UNAVAILABLE',
        '메모를 처리하지 못했습니다. 잠시 뒤 다시 시도하세요.');
    }
  }

  async function collection(request, response) {
    if (request.method !== 'GET' && request.method !== 'POST') {
      response.setHeader('Allow', 'GET, POST');
      return fail(response, 405, 'METHOD_NOT_ALLOWED', '허용되지 않는 요청 방식입니다.');
    }
    const identity = await authenticate(request, response);
    if (!identity) return undefined;

    if (request.method === 'GET') {
      return run(response, async (store) => send(response, 200, await store.list(identity.userId)));
    }
    const fields = readFields(request);
    const wantedId = fields?.id;
    if (!fields || (wantedId !== undefined && (typeof wantedId !== 'string' || !UUID.test(wantedId)))) {
      return fail(response, 400, 'INVALID_REQUEST',
        'title(1~200자)과 body(5000자 이하) 문자열이 필요하고, id를 넣는다면 UUID여야 합니다.');
    }
    const id = wantedId ?? crypto.randomUUID();
    return run(response, async (store) => {
      // owner_id는 서버가 검사한 사용자 ID만 씁니다.
      await store.create({ id, ownerId: identity.userId, title: fields.title, content: fields.content });
      return send(response, 201, { id });
    });
  }

  async function item(request, response) {
    if (!['GET', 'PUT', 'DELETE'].includes(request.method)) {
      response.setHeader('Allow', 'GET, PUT, DELETE');
      return fail(response, 405, 'METHOD_NOT_ALLOWED', '허용되지 않는 요청 방식입니다.');
    }
    const identity = await authenticate(request, response);
    if (!identity) return undefined;

    const raw = request.query?.id;
    const id = Array.isArray(raw) ? raw[0] : raw;
    if (typeof id !== 'string' || !UUID.test(id)) {
      return fail(response, 404, 'NOT_FOUND', '메모를 찾을 수 없습니다.');
    }
    if (request.method === 'GET') {
      return run(response, async (store) => {
        const note = await store.get(id);
        return note ? send(response, 200, note)
          : fail(response, 404, 'NOT_FOUND', '메모를 찾을 수 없습니다.');
      });
    }
    if (request.method === 'PUT') {
      const fields = readFields(request);
      if (!fields) {
        return fail(response, 400, 'INVALID_REQUEST',
          'title(1~200자)과 body(5000자 이하) 문자열이 필요합니다.');
      }
      return run(response, async (store) => {
        const note = await store.update(id, { title: fields.title, content: fields.content });
        return note ? send(response, 200, note)
          : fail(response, 404, 'NOT_FOUND', '메모를 찾을 수 없습니다.');
      });
    }
    return run(response, async (store) => (await store.remove(id))
      ? send(response, 200, { id })
      : fail(response, 404, 'NOT_FOUND', '메모를 찾을 수 없습니다.'));
  }

  return { collection, item };
}

// ---- 실제 서버 런타임용 기본 연결 ---------------------------------------------
let cachedVerifier;
async function defaultVerify(authorization) {
  // 환경변수가 없으면 여기서 오류를 던지고, API는 이를 NOT_CONFIGURED(500)로 바꿉니다.
  cachedVerifier ??= createLoginVerifier({
    config, supabaseSecretKey: process.env.SUPABASE_SECRET_KEY,
  });
  return cachedVerifier(authorization);
}

function defaultStore() {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SECRET_KEY;
  if (typeof url !== 'string' || !url.startsWith('https://') || typeof key !== 'string' || !key) {
    const failure = new Error('not_configured');
    failure.code = 'NOT_CONFIGURED';
    throw failure;
  }
  return createSupabaseStore(createClient(url, key, {
    auth: { persistSession: false, autoRefreshToken: false },
  }));
}

export const notesApi = createNotesApi({ verify: defaultVerify, getStore: defaultStore });
