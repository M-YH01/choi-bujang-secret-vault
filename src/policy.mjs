// 10단계: 검증된 정책 사본(스냅샷)과 현재 "시험 정책"의 차이를 보고, 사본 버전으로 되돌립니다.
// 시험 정책 = src/decider.mjs, src/detect.mjs, aleph.config.json의 allowedRoutes 값 하나뿐입니다.
// 실제 운영 정책·다른 서비스의 규칙·감사 기록(policy/audit.log)은 읽기만 하거나 건드리지 않습니다.
// 메모 본문, 이메일, 토큰, 비밀값은 다루지 않습니다. 가상 요청의 값은 모두 고정된 연습용 문자열입니다.
import { createHash } from 'node:crypto';
import { appendFile, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { pathToFileURL } from 'node:url';

export const SNAPSHOT_SCHEMA = 'aleph.policy-snapshot.v1';
export const SNAPSHOT_PATH = 'policy/verified-policy.json';
export const AUDIT_PATH = 'policy/audit.log';
export const POLICY_FILES = Object.freeze(['src/decider.mjs', 'src/detect.mjs']);
const CONFIG_PATH = 'aleph.config.json';

const sha256 = (text) => createHash('sha256').update(text, 'utf8').digest('hex');

// 키 순서와 상관없이 같은 내용이면 같은 글자가 되도록 정렬해서 직렬화합니다.
export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

// ---- 고정된 가상 요청·가상 사건 -------------------------------------------------
const AT = '2026-10-01T05:00:00.000Z';
const baseRequest = (over = {}) => ({
  schema: 'aleph.decision.v1', requestId: 'policy-probe', classId: 'class_fixture',
  projectId: 'project_fixture', subjectId: 'learner_fixture', deviceId: 'a'.repeat(16),
  service: 'notes', method: 'GET', path: '/notes/demo', route: 'GET /notes/:id',
  queryLength: 0, querySha256: sha256(''), at: AT, policyRevision: 1, deviceRegistered: true,
  stepUp: { verified: false, authAgeSeconds: null },
  recentEvents: [], signals: { source: 'judge_fixture', region: 'local', network: 'usual', hour: 14 },
  ...over,
});
const risky = { source: 'judge_fixture', region: 'foreign', network: 'unusual', hour: 3 };
const burst = [{ kind: 'risk_signal', ageSeconds: 60, count: 20 }];
const reads = (count) => Array.from({ length: count }, (_, index) => ({
  at: new Date(Date.UTC(2026, 9, 1) + index * 2000).toISOString(), method: 'GET', identity: { sub: 'learner_fixture' },
}));

const DECIDER_PROBES = {
  '노트 GET 허용': baseRequest(),
  '노트 PUT 허용': baseRequest({ method: 'PUT', route: 'PUT /notes/:id' }),
  '노트 DELETE 허용': baseRequest({ method: 'DELETE', route: 'DELETE /notes/:id' }),
  '노트 POST 거부': baseRequest({ method: 'POST', route: 'POST /notes/:id' }),
  '공지 GET 허용': baseRequest({ service: 'announcements', path: '/announcements/demo', route: 'GET /announcements/:id' }),
  '공지 PUT 거부': baseRequest({ service: 'announcements', method: 'PUT', path: '/announcements/demo', route: 'PUT /announcements/:id' }),
  '강사 영역 거부': baseRequest({ service: 'instructor', path: '/instructor/demo', route: 'GET /instructor/:id' }),
  '미등록 기기 거부': baseRequest({ deviceRegistered: false }),
  '복합 이상 재확인': baseRequest({ signals: risky, recentEvents: burst }),
  '복합 이상 확인 완료': baseRequest({ signals: risky, recentEvents: burst, stepUp: { verified: true, authAgeSeconds: 60 } }),
};
const DETECT_PROBES = {
  '조회 120건 관찰': reads(120),
  '조회 121건 회수 제안': reads(121),
};

// 한 폴더(루트)의 시험 정책을 읽어 서술합니다. 코드는 그 폴더의 파일을 그대로 불러 실행합니다.
export async function describePolicy(root) {
  const stamp = `${Date.now()}-${Math.random().toString(36).slice(2)}`;
  const load = (file) => import(`${pathToFileURL(join(root, file)).href}?v=${stamp}`);
  const deciderModule = await load('src/decider.mjs');
  const detectModule = await load('src/detect.mjs');
  const files = {};
  for (const file of POLICY_FILES) files[file] = sha256(await readFile(join(root, file), 'utf8'));
  const config = JSON.parse(await readFile(join(root, CONFIG_PATH), 'utf8'));
  const probes = {};
  for (const [name, request] of Object.entries(DECIDER_PROBES)) {
    const response = await deciderModule.decide(structuredClone(request));
    probes[`decide: ${name}`] = { decision: response.decision, reasonCode: response.reasonCode, ruleIds: response.ruleIds };
  }
  for (const [name, events] of Object.entries(DETECT_PROBES)) {
    probes[`detect: ${name}`] = await detectModule.detect(structuredClone(events));
  }
  return {
    ruleIds: [...deciderModule.RULE_IDS],
    allowedRoutes: [...(config.allowedRoutes ?? [])],
    files,
    probes,
  };
}

const digestOf = (policy) => sha256(canonicalJson(policy));

// ---- 스냅샷 만들기 ------------------------------------------------------------------
export async function createSnapshot(root, { replace = false } = {}) {
  const target = join(root, SNAPSHOT_PATH);
  if (!replace) {
    const exists = await readFile(target, 'utf8').then(() => true, () => false);
    if (exists) throw new Error('이미 검증된 사본이 있습니다. 덮어쓰려면 --replace를 붙이세요(옛 사본은 Git 기록에 남습니다).');
  }
  const policy = await describePolicy(root);
  const files = {};
  for (const file of POLICY_FILES) {
    files[file] = { sha256: policy.files[file], content: await readFile(join(root, file), 'utf8') };
  }
  const digest = digestOf(policy);
  const snapshot = { schema: SNAPSHOT_SCHEMA, version: digest.slice(0, 12), digest, policy, files };
  await mkdir(dirname(target), { recursive: true });
  await writeFile(target, `${JSON.stringify(snapshot, null, 2)}\n`);
  return snapshot;
}

// ---- 사본 검증: 실패하면 예외를 던져 diff·restore가 멈추게 합니다 ------------------
export async function loadVerifiedSnapshot(root) {
  let snapshot;
  try {
    snapshot = JSON.parse(await readFile(join(root, SNAPSHOT_PATH), 'utf8'));
  } catch {
    throw new Error(`검증된 정책 사본(${SNAPSHOT_PATH})이 없거나 읽을 수 없습니다. 중단합니다.`);
  }
  const bad = (why) => new Error(`검증된 정책 사본이 올바르지 않습니다(${why}). 중단합니다.`);
  if (snapshot?.schema !== SNAPSHOT_SCHEMA) throw bad('형식');
  if (typeof snapshot.digest !== 'string' || typeof snapshot.version !== 'string' || !snapshot.policy || !snapshot.files) throw bad('필드');
  for (const file of POLICY_FILES) {
    const entry = snapshot.files[file];
    if (typeof entry?.content !== 'string' || sha256(entry.content) !== entry.sha256
      || snapshot.policy.files?.[file] !== entry.sha256) throw bad(`${file} 해시`);
  }
  if (Object.keys(snapshot.files).length !== POLICY_FILES.length) throw bad('파일 목록');
  if (digestOf(snapshot.policy) !== snapshot.digest || snapshot.digest.slice(0, 12) !== snapshot.version) throw bad('요약값');
  // 사본에 들어 있는 코드를 임시 폴더에서 실제로 실행해, 기록된 시험 결과를 다시 만들 수 있는지 확인합니다.
  const temp = await mkdtemp(join(tmpdir(), 'policy-verify-'));
  try {
    await mkdir(join(temp, 'src'), { recursive: true });
    for (const file of POLICY_FILES) await writeFile(join(temp, file), snapshot.files[file].content);
    await writeFile(join(temp, CONFIG_PATH), JSON.stringify({ allowedRoutes: snapshot.policy.allowedRoutes }));
    const replay = await describePolicy(temp);
    if (digestOf(replay) !== snapshot.digest) throw bad('사본 코드의 시험 결과가 기록과 다름');
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
  return snapshot;
}

// ---- 차이 계산(다른 점만) -----------------------------------------------------------
export function diffPolicies(good, current) {
  const changes = [];
  for (const file of POLICY_FILES) {
    if (good.files[file] !== current.files[file]) changes.push({ kind: 'file', name: file, good: good.files[file].slice(0, 12), current: current.files[file].slice(0, 12) });
  }
  for (const route of good.allowedRoutes.filter((r) => !current.allowedRoutes.includes(r))) changes.push({ kind: 'route_missing', name: route });
  for (const route of current.allowedRoutes.filter((r) => !good.allowedRoutes.includes(r))) changes.push({ kind: 'route_extra', name: route });
  for (const id of good.ruleIds.filter((r) => !current.ruleIds.includes(r))) changes.push({ kind: 'rule_missing', name: id });
  for (const id of current.ruleIds.filter((r) => !good.ruleIds.includes(r))) changes.push({ kind: 'rule_extra', name: id });
  for (const name of Object.keys({ ...good.probes, ...current.probes })) {
    if (canonicalJson(good.probes[name]) !== canonicalJson(current.probes[name])) {
      changes.push({ kind: 'probe', name, good: good.probes[name] ?? null, current: current.probes[name] ?? null });
    }
  }
  return changes;
}

export async function diffAgainstSnapshot(root) {
  const snapshot = await loadVerifiedSnapshot(root);
  const current = await describePolicy(root);
  return { snapshot, current, changes: diffPolicies(snapshot.policy, current) };
}

const KIND_LABEL = {
  file: '코드 파일이 다름', route_missing: '사본에는 있는데 지금은 없는 허용 경로', route_extra: '지금만 있는 허용 경로',
  rule_missing: '사본에는 있는데 지금은 없는 규칙', rule_extra: '지금만 있는 규칙', probe: '가상 요청 결과가 다름',
};
export function formatChanges(changes) {
  if (changes.length === 0) return ['차이 없음: 지금 시험 정책이 검증된 사본과 같습니다.'];
  return changes.map((change) => {
    const detail = change.kind === 'probe'
      ? ` — 사본 ${JSON.stringify(change.good)} / 지금 ${JSON.stringify(change.current)}`
      : change.kind === 'file' ? ` — 사본 ${change.good}… / 지금 ${change.current}…` : '';
    return `- ${KIND_LABEL[change.kind]}: ${change.name}${detail}`;
  });
}

// ---- 되돌리기 -----------------------------------------------------------------------
async function audit(root, entry) {
  const target = join(root, AUDIT_PATH);
  await mkdir(dirname(target), { recursive: true });
  await appendFile(target, `${JSON.stringify({ at: new Date().toISOString(), ...entry })}\n`); // 덧붙이기만 합니다.
}

// apply가 false이면 계획만 보여 주고 아무것도 쓰지 않습니다.
export async function restorePolicy(root, { apply = false, confirm = null } = {}) {
  const { snapshot, current, changes } = await diffAgainstSnapshot(root); // 사본이 없거나 틀리면 여기서 중단
  const plan = changes.filter((c) => c.kind === 'file' || c.kind === 'route_missing' || c.kind === 'route_extra');
  const result = { version: snapshot.version, changes, applied: false, plan: plan.map((c) => `${c.kind}:${c.name}`) };
  if (!apply) return result;
  if (confirm !== snapshot.version) {
    throw new Error(`실행 확인이 없습니다. 위 변경을 확인한 뒤 --apply --confirm ${snapshot.version} 로 다시 실행하세요.`);
  }
  if (changes.length === 0) return result;
  const before = current.files;
  for (const file of POLICY_FILES) {
    if (current.files[file] !== snapshot.files[file].sha256) await writeFile(join(root, file), snapshot.files[file].content);
  }
  if (canonicalJson(current.allowedRoutes) !== canonicalJson(snapshot.policy.allowedRoutes)) {
    const config = JSON.parse(await readFile(join(root, CONFIG_PATH), 'utf8'));
    config.allowedRoutes = [...snapshot.policy.allowedRoutes]; // 다른 키는 그대로 둡니다.
    await writeFile(join(root, CONFIG_PATH), `${JSON.stringify(config, null, 2)}\n`);
  }
  const after = await describePolicy(root);
  const ok = digestOf(after) === snapshot.digest;
  await audit(root, {
    action: 'policy_restore', version: snapshot.version, result: ok ? 'restored' : 'verify_failed',
    changed: plan.map((c) => `${c.kind}:${c.name}`), filesBefore: before, filesAfter: after.files,
  });
  if (!ok) throw new Error('되돌린 뒤 다시 확인했더니 사본과 다릅니다. 기록(policy/audit.log)을 확인하세요.');
  return { ...result, applied: true };
}
