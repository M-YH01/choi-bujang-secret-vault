// GET·PUT·DELETE /api/notes/:id. 로직은 src/notes-api.mjs에 있습니다.
// 아직 소유자를 검사하지 않습니다(4단계에서 고칩니다).
import { notesApi } from '../../src/notes-api.mjs';

export default function handler(request, response) {
  return notesApi.item(request, response);
}
