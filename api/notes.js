// 가상 메모를 Supabase study_notes 테이블에서 읽어 오는 서버 함수입니다.
// SUPABASE_URL과 SUPABASE_SECRET_KEY는 Vercel 환경변수에서만 읽습니다.
// 비밀 키는 응답·로그·브라우저 파일 어디에도 내보내지 않습니다.
// 알려진 약점: 이 함수는 로그인 없이 누구나 호출할 수 있는 공개 주소입니다.
import { createClient } from '@supabase/supabase-js';

const MAX_NOTES = 100;

function fail(response, status, code) {
  response.setHeader('Cache-Control', 'no-store');
  response.status(status).json({ error: code });
}

export default async function handler(request, response) {
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    response.setHeader('Allow', 'GET, HEAD');
    return fail(response, 405, 'METHOD_NOT_ALLOWED');
  }

  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SECRET_KEY;
  if (typeof url !== 'string' || !url.startsWith('https://') || typeof key !== 'string' || !key) {
    console.error('notes_not_configured');
    return fail(response, 500, 'NOTES_NOT_CONFIGURED');
  }

  try {
    const supabase = createClient(url, key, {
      auth: { persistSession: false, autoRefreshToken: false },
    });
    const { data, error } = await supabase
      .from('study_notes')
      .select('title, content')
      .order('id', { ascending: true })
      .limit(MAX_NOTES);
    if (error) {
      // 오류 코드만 기록합니다. 메시지에는 주소나 요청 내용이 섞일 수 있습니다.
      console.error('notes_query_failed', typeof error.code === 'string' ? error.code : 'unknown');
      return fail(response, 502, 'NOTES_UNAVAILABLE');
    }
    response.setHeader('Cache-Control', 'no-store');
    return response.status(200).json({
      notes: (data ?? []).map(({ title, content }) => ({ title, content })),
    });
  } catch {
    console.error('notes_request_failed');
    return fail(response, 502, 'NOTES_UNAVAILABLE');
  }
}
