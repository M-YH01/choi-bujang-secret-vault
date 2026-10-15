// 10단계 정책 도구. 시험 정책만 다룹니다(실제 운영 정책은 건드리지 않습니다).
//   npm run policy:snapshot              현재 정책을 검증된 사본으로 저장(이미 있으면 거부, 덮어쓰기는 -- --replace)
//   npm run policy:diff                  사본과 지금의 "다른 점만" 출력(사본이 없거나 틀리면 중단)
//   npm run policy:restore               되돌릴 내용을 보여 주기만 함(아무것도 바꾸지 않음)
//   npm run policy:restore -- --apply --confirm <버전>   확인한 뒤 실제로 되돌림
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createSnapshot, diffAgainstSnapshot, formatChanges, restorePolicy } from '../src/policy.mjs';

const args = process.argv.slice(2);
const command = args[0];
const flag = (name) => args.includes(name);
const value = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] ?? null : null; };
const root = value('--root') ? resolve(value('--root')) : resolve(fileURLToPath(new URL('..', import.meta.url)));
const out = (line) => process.stdout.write(`${line}\n`);

try {
  if (command === 'snapshot') {
    const snapshot = await createSnapshot(root, { replace: flag('--replace') });
    out(`검증된 사본을 저장했습니다. 버전 ${snapshot.version}`);
  } else if (command === 'diff') {
    const { snapshot, changes } = await diffAgainstSnapshot(root);
    out(`사본 버전 ${snapshot.version} (검증 통과)`);
    formatChanges(changes).forEach(out);
    if (changes.length > 0) process.exitCode = 2; // 차이가 있음을 알리는 표시일 뿐 오류가 아닙니다.
  } else if (command === 'restore') {
    const result = await restorePolicy(root, { apply: flag('--apply'), confirm: value('--confirm') });
    out(`사본 버전 ${result.version} (검증 통과)`);
    formatChanges(result.changes).forEach(out);
    out(result.applied ? '되돌렸고, 다시 확인한 결과 사본과 같습니다. policy/audit.log에 기록을 덧붙였습니다.'
      : result.changes.length === 0 ? '되돌릴 내용이 없습니다.'
        : `아직 아무것도 바꾸지 않았습니다. 위 내용을 확인했다면: npm run policy:restore -- --apply --confirm ${result.version}`);
  } else {
    throw new Error('사용법: snapshot | diff | restore [--apply --confirm <버전>]');
  }
} catch (error) {
  process.stderr.write(`정책 도구 첫 오류: ${error.message}\n`);
  process.exitCode = 1;
}
