// POST /api/restore/notes/:id — 비공개 사본에서 메모 한 건만 되돌립니다. 로직은 src/restore-api.mjs에 있습니다.
import { restoreApi } from '../../../src/restore-api.mjs';

export default (request, response) => restoreApi.restoreOne(request, response);
