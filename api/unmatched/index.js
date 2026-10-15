// /api 아래에서 어떤 파일과도 맞지 않는 요청이 vercel.json의 대체 경로로 이 함수에 옵니다.
// 요청 방식과 원래 경로만 짧게 기록하고 JSON 404를 돌려줍니다. 쿼리·헤더·본문·로그인 값은 읽지도 남기지도 않습니다.
// 구체적인 함수(notes, restore 등)와 public 파일이 항상 우선이며, 이 함수는 맞는 것이 없을 때만 쓰입니다.
export function unmatchedApi(request, response) {
  const method = String(request.method ?? '').slice(0, 8);
  const raw = request.query?.p;
  const rest = Array.isArray(raw) ? raw.join('/') : typeof raw === 'string' ? raw : '';
  const path = `/api/${rest}`.replace(/[^A-Za-z0-9_\-./:~%]/gu, '?').slice(0, 120);
  console.warn('unmatched_api', method, path);
  response.setHeader('Cache-Control', 'no-store');
  return response.status(404).json({ error: 'NOT_FOUND', message: '없는 주소입니다.' });
}

export default unmatchedApi;
