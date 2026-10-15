// GET /api/device  : 이 기기의 승인 상태를 알려 줍니다(로그인 필요).
// POST /api/device : 이 기기의 승인을 "요청"합니다(로그인 필요). 요청은 pending 줄 하나를 만들 뿐이고 권한을 주지 않습니다.
//
// 승인은 이 API로 할 수 없습니다. 운영자가 Supabase에서 표의 status를 직접 바꿔야 하고,
// 서버 키에는 status를 쓰거나 바꿀 권한이 없습니다. 본문의 status·approved·userId·deviceId는 읽지 않습니다.
import { createAuthenticator, fail, send } from './notes-api.mjs';
import {
  MAX_PENDING_PER_USER, cleanLabel, defaultDeviceStore, deviceCookie, deviceState, hashDevice, newDeviceId,
  readDeviceId, requestCode,
} from './device-approval.mjs';
import { defaultVerify } from './notes-api.mjs';

export function createDeviceApi({ verify, getStore }) {
  const authenticate = createAuthenticator(verify); // 이 경로는 기기 승인 전에도 부를 수 있어야 하므로 문을 달지 않습니다.

  const view = ({ state, row }) => ({
    state,
    ...(state === 'pending' && row ? { requestCode: requestCode(row.id) } : {}),
  });

  async function handle(request, response) {
    if (request.method !== 'GET' && request.method !== 'POST') {
      response.setHeader('Allow', 'GET, POST');
      return fail(response, 405, 'METHOD_NOT_ALLOWED', '허용되지 않는 요청 방식입니다.');
    }
    const identity = await authenticate(request, response);
    if (!identity) return undefined;

    let store;
    try {
      store = getStore();
    } catch {
      console.error('device_not_configured');
      return fail(response, 500, 'NOT_CONFIGURED', '서버 설정을 준비하지 못했습니다.');
    }
    try {
      const current = await deviceState(store, identity.userId, request);
      if (request.method === 'GET') return send(response, 200, view(current));

      // POST: 이미 줄이 있으면(승인 대기·승인·회수) 새로 만들지 않고 현재 상태를 그대로 알려 줍니다.
      if (current.state !== 'none') return send(response, 200, view(current));
      if (await store.countPending(identity.userId) >= MAX_PENDING_PER_USER) {
        return fail(response, 429, 'TOO_MANY_REQUESTS', '승인 대기 요청이 너무 많습니다. 운영자가 처리한 뒤 다시 요청하세요.');
      }
      let body = request.body;
      if (typeof body === 'string') { try { body = JSON.parse(body); } catch { body = null; } }
      const label = cleanLabel(body && typeof body === 'object' ? body.label : null);
      const deviceId = current.deviceId ?? newDeviceId();
      const row = await store.createPending({ userId: identity.userId, hash: hashDevice(deviceId), label });
      if (!readDeviceId(request)) response.setHeader('Set-Cookie', deviceCookie(deviceId));
      return send(response, 201, view({ state: 'pending', row }));
    } catch (error) {
      console.error('device_store_failed', error?.upstreamCode ?? 'unavailable');
      return fail(response, 502, 'UNAVAILABLE', '기기 확인을 하지 못했습니다. 잠시 뒤 다시 시도하세요.');
    }
  }

  return { handle };
}

export const deviceApi = createDeviceApi({ verify: defaultVerify, getStore: defaultDeviceStore });
