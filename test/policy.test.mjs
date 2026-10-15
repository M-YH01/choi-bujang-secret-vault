import assert from 'node:assert/strict';
import { test } from 'node:test';
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  AUDIT_PATH, SNAPSHOT_PATH, createSnapshot, diffAgainstSnapshot, formatChanges, loadVerifiedSnapshot, restorePolicy,
} from '../src/policy.mjs';

const REPO = new URL('..', import.meta.url).pathname;

// 실제 저장소를 건드리지 않도록 정책 파일만 임시 폴더에 복사해서 시험합니다.
async function workspace({ withSnapshot = true } = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'policy-test-'));
  await mkdir(join(dir, 'src'));
  for (const file of ['src/decider.mjs', 'src/detect.mjs', 'aleph.config.json']) await cp(join(REPO, file), join(dir, file));
  if (withSnapshot) await createSnapshot(dir);
  return dir;
}
const read = (dir, file) => readFile(join(dir, file), 'utf8');
const done = (dir) => rm(dir, { recursive: true, force: true });

test('a fresh snapshot verifies and shows no difference', async () => {
  const dir = await workspace();
  try {
    const { changes } = await diffAgainstSnapshot(dir);
    assert.deepEqual(changes, []);
    assert.deepEqual(formatChanges(changes), ['차이 없음: 지금 시험 정책이 검증된 사본과 같습니다.']);
    await assert.rejects(createSnapshot(dir), /--replace/);
  } finally { await done(dir); }
});

test('the committed snapshot matches the current repository policy', async () => {
  const { changes, snapshot } = await diffAgainstSnapshot(REPO);
  assert.deepEqual(changes, [], '정책을 바꿨다면 diff를 확인하고 사본을 의도적으로 갱신해야 합니다');
  assert.match(snapshot.version, /^[0-9a-f]{12}$/u);
});

test('diff lists only what differs: edited code, extra route, changed answers', async () => {
  const dir = await workspace();
  try {
    const decider = await read(dir, 'src/decider.mjs');
    await writeFile(join(dir, 'src/decider.mjs'), decider.replace("'deny', 'device_not_registered'", "'allow', 'approved'"));
    const config = JSON.parse(await read(dir, 'aleph.config.json'));
    config.allowedRoutes.push('POST /api/notes/:id');
    await writeFile(join(dir, 'aleph.config.json'), JSON.stringify(config, null, 2));
    const { changes } = await diffAgainstSnapshot(dir);
    const kinds = changes.map((c) => `${c.kind}:${c.name}`);
    assert.ok(kinds.includes('file:src/decider.mjs'));
    assert.ok(kinds.includes('route_extra:POST /api/notes/:id'));
    assert.ok(kinds.includes('probe:decide: 미등록 기기 거부'));
    assert.equal(kinds.some((k) => k.includes('src/detect.mjs')), false);
    assert.equal(kinds.some((k) => k.includes('노트 GET 허용')), false);
  } finally { await done(dir); }
});

test('a missing, edited or hollow snapshot aborts before any comparison', async () => {
  const none = await workspace({ withSnapshot: false });
  try { await assert.rejects(diffAgainstSnapshot(none), /없거나 읽을 수 없습니다/u); } finally { await done(none); }

  const edited = await workspace();
  try {
    const snap = JSON.parse(await read(edited, SNAPSHOT_PATH));
    snap.files['src/decider.mjs'].content += '\n// 몰래 바꿈\n';
    await writeFile(join(edited, SNAPSHOT_PATH), JSON.stringify(snap));
    await assert.rejects(loadVerifiedSnapshot(edited), /해시/u);
  } finally { await done(edited); }

  // 코드와 해시를 함께 바꿔도(해시를 다시 계산해도) 기록된 시험 결과·요약값과 맞지 않으면 거부합니다.
  const forged = await workspace();
  try {
    const { createHash } = await import('node:crypto');
    const snap = JSON.parse(await read(forged, SNAPSHOT_PATH));
    const content = snap.files['src/decider.mjs'].content.replace("'deny', 'device_not_registered'", "'allow', 'approved'");
    const hash = createHash('sha256').update(content).digest('hex');
    snap.files['src/decider.mjs'] = { sha256: hash, content };
    snap.policy.files['src/decider.mjs'] = hash;
    await writeFile(join(forged, SNAPSHOT_PATH), JSON.stringify(snap));
    await assert.rejects(loadVerifiedSnapshot(forged), /올바르지 않습니다/u);
  } finally { await done(forged); }

  const wrongSchema = await workspace();
  try {
    const snap = JSON.parse(await read(wrongSchema, SNAPSHOT_PATH));
    snap.schema = 'other';
    await writeFile(join(wrongSchema, SNAPSHOT_PATH), JSON.stringify(snap));
    await assert.rejects(restorePolicy(wrongSchema, { apply: true, confirm: snap.version }), /형식/u);
  } finally { await done(wrongSchema); }
});

test('restore without --apply only plans: nothing is written', async () => {
  const dir = await workspace();
  try {
    const before = await read(dir, 'src/detect.mjs');
    await writeFile(join(dir, 'src/detect.mjs'), before.replace('LIMIT = 120', 'LIMIT = 999'));
    const tampered = await read(dir, 'src/detect.mjs');
    const result = await restorePolicy(dir);
    assert.equal(result.applied, false);
    assert.ok(result.plan.includes('file:src/detect.mjs'));
    assert.equal(await read(dir, 'src/detect.mjs'), tampered);
    await assert.rejects(readFile(join(dir, AUDIT_PATH)), /ENOENT/u);
  } finally { await done(dir); }
});

test('--apply without the right confirm is refused and changes nothing', async () => {
  const dir = await workspace();
  try {
    await writeFile(join(dir, 'src/detect.mjs'), (await read(dir, 'src/detect.mjs')).replace('LIMIT = 120', 'LIMIT = 999'));
    const tampered = await read(dir, 'src/detect.mjs');
    for (const confirm of [null, '', 'wrong', '000000000000']) {
      await assert.rejects(restorePolicy(dir, { apply: true, confirm }), /실행 확인/u);
    }
    assert.equal(await read(dir, 'src/detect.mjs'), tampered);
  } finally { await done(dir); }
});

test('confirmed restore returns exact bytes, keeps other config keys and appends to the audit log', async () => {
  const dir = await workspace();
  try {
    const goodDecider = await read(dir, 'src/decider.mjs');
    const goodDetect = await read(dir, 'src/detect.mjs');
    const goodConfig = JSON.parse(await read(dir, 'aleph.config.json'));
    const snap = JSON.parse(await read(dir, SNAPSHOT_PATH));

    await mkdir(join(dir, 'policy'), { recursive: true });
    await writeFile(join(dir, AUDIT_PATH), '{"at":"old","action":"earlier_entry"}\n'); // 이전 감사 기록
    await writeFile(join(dir, 'src/decider.mjs'), goodDecider.replace("'deny', 'resource_not_allowed'", "'allow', 'approved'"));
    const config = { ...goodConfig, allowedRoutes: [...goodConfig.allowedRoutes, 'POST /api/notes/:id'], step: 77, note: '다른 서비스 값' };
    await writeFile(join(dir, 'aleph.config.json'), JSON.stringify(config, null, 2));

    const result = await restorePolicy(dir, { apply: true, confirm: snap.version });
    assert.equal(result.applied, true);
    assert.equal(await read(dir, 'src/decider.mjs'), goodDecider);
    assert.equal(await read(dir, 'src/detect.mjs'), goodDetect);
    const after = JSON.parse(await read(dir, 'aleph.config.json'));
    assert.deepEqual(after.allowedRoutes, goodConfig.allowedRoutes);
    assert.equal(after.step, 77);
    assert.equal(after.note, '다른 서비스 값');
    assert.deepEqual((await diffAgainstSnapshot(dir)).changes, []);

    const lines = (await read(dir, AUDIT_PATH)).trim().split('\n');
    assert.equal(lines[0], '{"at":"old","action":"earlier_entry"}');
    assert.equal(lines.length, 2);
    const entry = JSON.parse(lines[1]);
    assert.equal(entry.result, 'restored');
    assert.ok(entry.changed.includes('file:src/decider.mjs'));
    assert.equal(/content|secret|token/iu.test(lines[1]), false);

    // 이미 같으면 아무것도 쓰지 않고 기록도 늘리지 않습니다.
    const again = await restorePolicy(dir, { apply: true, confirm: snap.version });
    assert.equal(again.applied, false);
    assert.equal((await read(dir, AUDIT_PATH)).trim().split('\n').length, 2);
  } finally { await done(dir); }
});

test('after restore the restored decider still denies what must be denied', async () => {
  const dir = await workspace();
  try {
    const snap = JSON.parse(await read(dir, SNAPSHOT_PATH));
    await writeFile(join(dir, 'src/decider.mjs'), 'export const RULE_IDS = [];\nexport async function decide(r){return {};}\n');
    await restorePolicy(dir, { apply: true, confirm: snap.version });
    const { describePolicy } = await import('../src/policy.mjs');
    const policy = await describePolicy(dir);
    assert.equal(policy.probes['decide: 미등록 기기 거부'].decision, 'deny');
    assert.equal(policy.probes['decide: 강사 영역 거부'].decision, 'deny');
    assert.equal(policy.probes['decide: 노트 GET 허용'].decision, 'allow');
    assert.equal(policy.probes['detect: 조회 121건 회수 제안'].action, 'propose_revocation');
  } finally { await done(dir); }
});

test('policy tooling touches only policy files and never imports secrets or memo text', async () => {
  const source = await readFile(join(REPO, 'src/policy.mjs'), 'utf8');
  assert.equal(/process\.env|SUPABASE|study_notes|reset --hard/u.test(source), false);
});
