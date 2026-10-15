// GET·POST /api/device — 이 기기의 승인 상태 확인과 승인 요청. 로직은 src/device-api.mjs에 있습니다.
import { deviceApi } from '../../src/device-api.mjs';

export default (request, response) => deviceApi.handle(request, response);
