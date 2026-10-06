import { copyFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { deploymentIdentity } from './deployment-identity.mjs';

const root = resolve(import.meta.dirname, '..');
const source = resolve(root, 'data.json');
const output = resolve(root, 'public', 'data.json');
const config = JSON.parse(await readFile(resolve(root, 'aleph.config.json'), 'utf8'));
if (![1, 2, 3].includes(config.step)) {
  throw new Error('이 단계의 빌드 흐름을 scripts/build-public.mjs에 맞춰 주세요. (현재 step 1~3 지원)');
}
const data = JSON.parse(await readFile(source, 'utf8'));
if (!Array.isArray(data.notes)) {
  throw new Error('data.json 형식을 확인하세요. notes는 빈 배열이어야 합니다.');
}
if (data.notes.length > 0) {
  throw new Error('메모는 공개 data.json에 둘 수 없습니다. 메모는 Supabase에 두고 /api/notes로 읽으세요.');
}
await mkdir(resolve(root, 'public'), { recursive: true });
await copyFile(source, output);
console.log('메모 없는 공개 data.json을 public/data.json에 복사했습니다.');
if (!process.argv.includes('--local')) {
  const identity = deploymentIdentity(process.env, config);
  await writeFile(resolve(root, 'public', 'aleph.json'),
    `${JSON.stringify(identity, null, 2)}\n`, 'utf8');
  console.log('배포 저장소·커밋·주소를 public/aleph.json에 기록했습니다.');
}
