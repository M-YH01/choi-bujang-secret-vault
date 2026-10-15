// 보너스 xdr-03 제작 1: Wazuh 모양 경보에서 시각·출발 주소·계정·규칙 수준·설명만 뽑는 읽기 모듈(확인용).
// decide.mjs가 불러오지 않습니다. 원본 경보 파일은 고치지 않고, 비밀값처럼 보이는 값은 가려서 내보냅니다.
//
//   node xdr/known-cve/read-alerts.mjs
import { readFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const FIXTURE = join(here, '..', 'fixtures', 'known-cve.json');

// 비밀값처럼 보이는 것: 이름=값 형태의 비밀번호·토큰·키, Bearer 토큰, sb_secret_, JWT 모양, 긴 16진수·base64 덩어리.
const SECRET_PATTERNS = [
  /\b(?:password|passwd|pwd|pass|secret|token|api[_-]?key|apikey|authorization)\s*[:=]\s*\S+/giu,
  /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/gu,
  /\bsb_secret_[A-Za-z0-9_-]+/gu,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]*)?/gu,
  /\b[A-Fa-f0-9]{32,}\b/gu,
  /\b[A-Za-z0-9+/_-]{40,}={0,2}/gu,
];

export function redact(value) {
  if (typeof value !== 'string') return '';
  let text = value.replace(/[\u0000-\u001f\u007f]/gu, ' ');
  for (const pattern of SECRET_PATTERNS) text = text.replace(pattern, '[가림]');
  return text.trim();
}

export function pickRow(alert) {
  return {
    at: redact(alert?.timestamp),
    srcip: redact(alert?.data?.srcip),
    srcuser: redact(alert?.data?.srcuser),
    level: Number.isFinite(alert?.rule?.level) ? alert.rule.level : null,
    description: redact(alert?.rule?.description),
  };
}

export async function readAlerts(path = FIXTURE) {
  const fixture = JSON.parse(await readFile(path, 'utf8'));
  if (fixture?.schema !== 'aleph.xdr.fixture.v1' || !Array.isArray(fixture.alerts)) {
    throw new Error('경보 묶음 형식이 아닙니다.');
  }
  return { total: fixture.alerts.length, rows: fixture.alerts.map(pickRow) };
}

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  try {
    const { total, rows } = await readAlerts();
    for (const row of rows) {
      process.stdout.write(`${row.at} | ${row.srcip} | ${row.srcuser} | 수준 ${row.level} | ${row.description}\n`);
    }
    process.stdout.write(`경보 ${total}건 / 뽑은 줄 ${rows.length}줄${total === rows.length ? ' (같음)' : ' (다름: 확인 필요)'}\n`);
    if (total !== rows.length) process.exitCode = 1;
  } catch (error) {
    process.stderr.write(`경보 읽기 첫 오류: ${error.message}\n`);
    process.exitCode = 1;
  }
}
