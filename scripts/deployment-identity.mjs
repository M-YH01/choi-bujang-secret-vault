const OWNER = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/u;
const REPO = /^[A-Za-z0-9._-]{1,100}$/u;
const SHA = /^[a-f0-9]{40}$/iu;
const HOST = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.vercel\.app$/iu;
const SUPABASE_HOST = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.supabase\.co$/u;
// 공개(publishable) 키만 허용합니다. secret 키나 서버 전용 키는 이 형식이 아니라서 거부됩니다.
const PUBLISHABLE_KEY = /^sb_publishable_[A-Za-z0-9_-]{16,200}$/u;
const DATABASE_TABLE = 'study_notes';

function supabaseOrigin(value) {
  let url;
  try { url = new URL(value); } catch { return null; }
  if (url.protocol !== 'https:' || url.username || url.password || url.port
      || url.pathname !== '/' || url.search || url.hash
      || !SUPABASE_HOST.test(url.hostname)) return null;
  return url.origin;
}

export function deploymentIdentity(env, config) {
  const owner = env.VERCEL_GIT_REPO_OWNER;
  const repo = env.VERCEL_GIT_REPO_SLUG;
  const commit = env.VERCEL_GIT_COMMIT_SHA;
  const host = env.VERCEL_URL;
  if (env.VERCEL_GIT_PROVIDER !== 'github' || !OWNER.test(owner || '')
      || !REPO.test(repo || '') || repo === '.' || repo === '..'
      || repo.toLowerCase().endsWith('.git') || !SHA.test(commit || '')
      || !HOST.test(host || '') || config?.step !== 1
      || typeof config.judgeIssuer !== 'string'
      || !/^https:\/\/[a-z0-9-]+\.up\.railway\.app\/defense\/judge$/iu.test(config.judgeIssuer)
      || typeof config.sampleMarker !== 'string'
      || !/^[A-Z0-9_]{1,80}$/u.test(config.sampleMarker)) {
    throw new Error('배포 식별 정보를 확인할 수 없습니다. Vercel 시스템 환경변수와 1단계 시작 틀을 확인하세요.');
  }
  const databaseUrl = supabaseOrigin(env.SUPABASE_URL);
  const publishableKey = env.SUPABASE_PUBLISHABLE_KEY;
  if (!databaseUrl || typeof publishableKey !== 'string' || !PUBLISHABLE_KEY.test(publishableKey)) {
    throw new Error('Supabase 주소와 공개 키를 확인하세요. Vercel 환경변수 SUPABASE_URL은 https://….supabase.co 형태여야 하고, SUPABASE_PUBLISHABLE_KEY에는 sb_publishable_ 로 시작하는 공개 키만 넣습니다. 서버 전용 키는 넣지 마세요.');
  }
  return {
    schema: 'aleph.defense.deployment.v1',
    step: 1,
    repoUrl: `https://github.com/${owner.toLowerCase()}/${repo.toLowerCase()}`,
    commit: commit.toLowerCase(),
    publicAppUrl: `https://${host.toLowerCase()}`,
    judgeIssuer: config.judgeIssuer,
    sampleMarker: config.sampleMarker,
    database: {
      schema: 'aleph.defense.database.v1',
      url: databaseUrl,
      publishableKey,
      table: DATABASE_TABLE,
    },
  };
}
