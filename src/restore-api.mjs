// 10단계: 비공개 메모 사본에서 지정한 한 건만 되돌리는 POST /api/restore/notes/:id 입니다.
//
// - 로그인은 메모 API와 같은 확인기(createAuthenticator)를 씁니다. 요청 본문의 userId·owner_id·role은 읽지 않습니다.
// - 사본(study_notes_backup)의 ID·소유자·내용 해시를 대조하고, 검증된 사용자가 사본의 소유자일 때만 되돌립니다.
//   남의 사본과 없는 사본은 같은 404입니다.
// - 되돌리는 것은 그 한 건뿐입니다. 다른 메모와 감사 기록(study_notes_audit)은 건드리지 않습니다.
//   감사 기록은 추가만 합니다(시작 기록 → 결과 기록).
// - 본문 { "dryRun": true } 이면 아무것도 쓰지 않고 바뀔 내용만 알려 줍니다.
// - 메모 제목·내용·토큰·키는 응답과 로그에 싣지 않습니다. 로그는 짧은 코드만 남깁니다.
import { createHash } from 'node:crypto';
import { createClient } from '@supabase/supabase-js';
import { createAuthenticator, defaultVerify, fail, send, storeError, UUID } from './notes-api.mjs';

const NOTES = 'study_notes';
const BACKUP = 'study_notes_backup';
const AUDIT = 'study_notes_audit';

// 내용 해시: sha256( UTF-8(제목) + 0x00 + UTF-8(내용) ). sql/10-backup-tables.sql이 같은 방식으로 계산합니다.
export function contentSha256(title, content) {
  return createHash('sha256')
    .update(Buffer.concat([Buffer.from(String(title), 'utf8'), Buffer.from([0]), Buffer.from(String(content), 'utf8')]))
    .digest('hex');
}

const ownerOrNull = (value) => (typeof value === 'string' ? value : null);

export function createSupabaseRestoreStore(client) {
  const run = async (query) => {
    const { data, error } = await query;
    if (error) throw storeError(error);
    return data;
  };
  return {
    async getBackup(id) {
      const row = await run(client.from(BACKUP).select('id, owner_id, title, content, content_sha256').eq('id', id).maybeSingle());
      return row ? { id: row.id, ownerId: ownerOrNull(row.owner_id), title: row.title, content: row.content,
        contentSha256: row.content_sha256 } : null;
    },
    async getCurrent(id) {
      const row = await run(client.from(NOTES).select('id, owner_id, title, content').eq('id', id).maybeSingle());
      return row ? { id: row.id, ownerId: ownerOrNull(row.owner_id), title: row.title, content: row.content } : null;
    },
    // 그 한 건만 넣거나 고칩니다. 고칠 때는 id와 owner_id가 모두 맞는 행만 바뀝니다.
    async insertOne({ id, ownerId, title, content }) {
      await run(client.from(NOTES).insert({ id, owner_id: ownerId, title, content }));
    },
    async updateOne({ id, ownerId, title, content }) {
      const rows = await run(client.from(NOTES).update({ title, content }).eq('id', id).eq('owner_id', ownerId).select('id'));
      if (!Array.isArray(rows) || rows.length !== 1) throw storeError({ code: 'no_row' });
    },
    async audit({ actor, action, noteId, digest, result }) {
      await run(client.from(AUDIT).insert({ actor, action, note_id: noteId, content_sha256: digest, result }));
    },
  };
}

export function createRestoreApi({ verify, getStore }) {
  const authenticate = createAuthenticator(verify);

  async function restoreOne(request, response) {
    if (request.method !== 'POST') {
      response.setHeader('Allow', 'POST');
      return fail(response, 405, 'METHOD_NOT_ALLOWED', '허용되지 않는 요청 방식입니다.');
    }
    const identity = await authenticate(request, response);
    if (!identity) return undefined;
    const userId = identity.userId;

    const raw = request.query?.id;
    const id = Array.isArray(raw) ? raw[0] : raw;
    const notFound = () => fail(response, 404, 'NOT_FOUND', '복원할 사본을 찾을 수 없습니다.');
    if (typeof id !== 'string' || !UUID.test(id)) return notFound();

    let input = request.body;
    if (typeof input === 'string') { try { input = JSON.parse(input); } catch { input = null; } }
    const dryRun = Boolean(input && typeof input === 'object' && !Array.isArray(input) && input.dryRun === true);

    let store;
    try {
      store = getStore();
    } catch {
      console.error('restore_not_configured');
      return fail(response, 500, 'NOT_CONFIGURED', '서버 설정을 준비하지 못했습니다.');
    }
    const record = (action, digest, result) => store.audit({ actor: userId, action, noteId: id, digest, result });
    try {
      // 1) 사본 ID와 소유자 대조. 남의 사본과 없는 사본은 같은 404입니다.
      const backup = await store.getBackup(id);
      if (!backup || backup.id !== id || backup.ownerId !== userId) {
        console.warn('restore_denied', backup ? 'not_owner' : 'no_backup');
        return notFound();
      }
      // 2) 사본 내용 해시 대조. 사본이 바뀌었으면 복원하지 않습니다.
      const digest = contentSha256(backup.title, backup.content);
      if (typeof backup.contentSha256 !== 'string' || digest !== backup.contentSha256) {
        console.warn('restore_denied', 'backup_hash_mismatch');
        if (!dryRun) await record('restore_note', digest, 'rejected_backup_hash').catch(() => console.error('audit_write_failed'));
        return send(response, 422, { error: 'BACKUP_INVALID', message: '사본의 내용 해시가 맞지 않아 복원하지 않았습니다.', backupVerified: false });
      }
      // 3) 현재 상태 확인. 다른 사람의 행을 덮어쓰지 않고, 이미 같으면 아무것도 하지 않습니다.
      const current = await store.getCurrent(id);
      if (current && current.ownerId !== userId) {
        console.warn('restore_denied', 'current_owner_differs');
        return fail(response, 409, 'CONFLICT', '현재 메모의 소유자가 사본과 달라 복원하지 않았습니다.');
      }
      // 사본 검증 결과와 "바뀔 항목"(이름만, 내용 없음)을 응답에 함께 알립니다.
      const proof = { backupVerified: true, backupVersion: digest.slice(0, 12), contentSha256: digest };
      const changes = !current ? ['row_missing']
        : [current.title !== backup.title && 'title', current.content !== backup.content && 'content'].filter(Boolean);
      if (current && contentSha256(current.title, current.content) === digest) {
        return send(response, 200, { id, restored: false, reason: 'already_matches', ...proof, changes: [] });
      }
      if (dryRun) {
        return send(response, 200, { id, dryRun: true, wouldRestore: true, replacesExisting: Boolean(current), ...proof, changes });
      }
      // 4) 시작 기록 → 그 한 건만 되돌리기 → 다시 읽어 해시 확인 → 결과 기록. 시작 기록이 안 되면 아무것도 바꾸지 않습니다.
      await record('restore_note', digest, 'started');
      try {
        const row = { id, ownerId: userId, title: backup.title, content: backup.content };
        if (current) await store.updateOne(row); else await store.insertOne(row);
        const after = await store.getCurrent(id);
        if (!after || after.ownerId !== userId || contentSha256(after.title, after.content) !== digest) {
          throw storeError({ code: 'verify_failed' });
        }
      } catch (error) {
        await record('restore_note', digest, 'failed').catch(() => console.error('audit_write_failed'));
        throw error;
      }
      await record('restore_note', digest, 'restored').catch(() => console.error('audit_write_failed'));
      return send(response, 200, { id, restored: true, ...proof, changes });
    } catch (error) {
      console.error('restore_failed', error?.upstreamCode ?? 'unavailable');
      return fail(response, 502, 'UNAVAILABLE', '복원하지 못했습니다. 잠시 뒤 다시 시도하세요.');
    }
  }

  return { restoreOne };
}

function defaultRestoreStore() {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SECRET_KEY;
  if (typeof url !== 'string' || !url.startsWith('https://') || typeof key !== 'string' || !key) {
    throw new Error('not_configured');
  }
  return createSupabaseRestoreStore(createClient(url, key, { auth: { persistSession: false, autoRefreshToken: false } }));
}

export const restoreApi = createRestoreApi({ verify: defaultVerify, getStore: defaultRestoreStore });
