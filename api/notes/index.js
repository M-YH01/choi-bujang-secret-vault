// GET /api/notes (내 메모 목록), POST /api/notes (메모 추가). 로직은 src/notes-api.mjs에 있습니다.
import { notesApi } from '../../src/notes-api.mjs';

export default function handler(request, response) {
  return notesApi.collection(request, response);
}
