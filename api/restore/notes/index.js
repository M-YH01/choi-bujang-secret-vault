// 번호 없는 주소(POST /api/restore/notes)로 부르면 본문의 id에서 복구할 메모를 읽습니다.
import { restoreApi } from '../../../src/restore-api.mjs';

export default (request, response) => restoreApi.restoreOne(request, response);
