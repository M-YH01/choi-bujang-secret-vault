// 설치형 웹앱 아이콘(PNG)을 만듭니다. 직접 그린 단순한 도형이라 외부 그림이나 로고를 쓰지 않습니다.
// 사용: node scripts/make-icons.mjs  (public/icons/에 icon-192.png, icon-512.png, icon-maskable-512.png)
import { mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { deflateSync } from 'node:zlib';

const crcTable = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});
const crc32 = (buffer) => {
  let c = 0xffffffff;
  for (const byte of buffer) c = crcTable[(c ^ byte) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
};
const chunk = (type, data) => {
  const head = Buffer.alloc(8);
  head.writeUInt32BE(data.length, 0);
  head.write(type, 4, 'ascii');
  const tail = Buffer.alloc(4);
  tail.writeUInt32BE(crc32(Buffer.concat([head.subarray(4), data])), 0);
  return Buffer.concat([head, data, tail]);
};

const BG = [0x10, 0x1a, 0x28];
const RING = [0x8a, 0xd8, 0xdf];
const KEY = [0xec, 0xf4, 0xff];

// 어두운 바탕 + 하늘색 원 테두리 + 가운데 열쇠 구멍 모양. safe가 true면 가장자리 여백을 더 둡니다(maskable용).
function pixels(size, safe) {
  const rows = [];
  const c = size / 2;
  const radius = size * (safe ? 0.3 : 0.38);
  const ringWidth = size * 0.05;
  for (let y = 0; y < size; y += 1) {
    const row = Buffer.alloc(1 + size * 3);
    for (let x = 0; x < size; x += 1) {
      const dx = x + 0.5 - c;
      const dy = y + 0.5 - c;
      const distance = Math.hypot(dx, dy);
      let color = BG;
      if (Math.abs(distance - radius) <= ringWidth / 2) color = RING;
      const hole = Math.hypot(dx, dy + size * 0.04) <= size * 0.07;
      const stem = Math.abs(dx) <= size * 0.03 && dy >= size * 0.0 && dy <= size * 0.15;
      if (hole || stem) color = KEY;
      row.set(color, 1 + x * 3);
    }
    rows.push(row);
  }
  return Buffer.concat(rows);
}

function png(size, safe) {
  const header = Buffer.alloc(13);
  header.writeUInt32BE(size, 0);
  header.writeUInt32BE(size, 4);
  header.set([8, 2, 0, 0, 0], 8);
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', header),
    chunk('IDAT', deflateSync(pixels(size, safe), { level: 9 })),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

const out = resolve(import.meta.dirname, '..', 'public', 'icons');
await mkdir(out, { recursive: true });
await writeFile(resolve(out, 'icon-192.png'), png(192, false));
await writeFile(resolve(out, 'icon-512.png'), png(512, false));
await writeFile(resolve(out, 'icon-maskable-512.png'), png(512, true));
console.log('아이콘 3개를 public/icons/에 만들었습니다.');
