# BYTE BACK 방어전 시작 틀 R5

이 저장소는 1단계에서 학생 본인이 GitHub 저장소와 Vercel 배포를 만드는 출발점입니다. 시작 틀에 들어 있던 메모 네 건은 가상 자료이며, 2단계부터는 저장소가 아니라 Supabase에 둡니다. 실제 학생 자료, 토큰, 비밀키를 넣지 마세요.

## 학생이 하는 일: 세 걸음

1. GitHub 계정을 만듭니다.
2. 방어전 1단계 카드의 **Deploy** 버튼을 누릅니다. Vercel에 GitHub로 로그인하고, 새 저장소가 **본인 계정의 Public 저장소**인지 확인한 뒤 Deploy를 누릅니다.
3. 배포가 끝나면 화면에 나온 `https://…vercel.app` 주소를 방어전 1단계 카드에 붙여넣고 제출합니다. 저장소 주소나 설정 파일은 적지 않습니다.

배포가 끝나면 `/`에서 점령된 가상 자료실을 볼 수 있습니다. 시작 틀에서는 `/data.json`에 같은 가상 메모가 공개되어 있었고, 이 공개 상태를 확인하는 것이 1단계의 출발점이었습니다. 이 저장소는 2단계 작업으로 메모를 `/data.json`에서 빼고 서버 함수로 읽게 바꿨고, 3단계에서 로그인한 사람만 읽고 고치게 바꿨습니다(바로 아래 참고). 1단계 접수와 심판 판정은 포털에서 확인합니다.

## 3단계: 로그인과 메모 추가·수정·삭제 (현재 작동하는 기능)

- 화면(`/`)에서 이메일·비밀번호로 로그인·로그아웃합니다. 로그인은 Supabase Auth 공식 SDK(`@supabase/supabase-js`)로 하고, 실패하면 이유(맞지 않는 계정, 이메일 미확인, 시도 과다 등)를 화면에 보여 줍니다. 로그인 전에는 메모가 한 건도 보이지 않습니다.
- 로그인한 사람은 메모를 추가·수정·삭제할 수 있습니다. 화면은 로그인 토큰을 `Authorization: Bearer …` 헤더로 보냅니다.
- 서버 함수 `api/notes/index.js`(`GET`·`POST /api/notes`)와 `api/notes/[id].js`(`GET`·`PUT`·`DELETE /api/notes/:id`)는 공통 코드 `src/notes-api.mjs`를 씁니다. 토큰이 없거나 틀리면 HTML이 아니라 JSON 오류(`401 {"error":"UNAUTHORIZED",…}`)로 거부합니다.
- 토큰 확인은 시작 틀의 `src/verify-login.mjs`(수정하지 않음)로 합니다. 새 메모의 `owner_id`는 브라우저가 보낸 값이 아니라 **서버가 확인한 사용자 id**로 채웁니다. 요청 본문의 `owner_id`·`userId`·`role` 같은 값은 무시합니다.
- 로그인 발급자 정보는 `aleph.config.json`의 `identityProvider`(발급자 주소, audience, 공개 키 목록 주소)에 있고 비밀값은 없습니다. 허용 경로는 `allowedRoutes`(`/api/notes`, `/api/notes/:id`)입니다. 빌드가 만드는 `/aleph.json`에도 두 값이 들어가며, 발급자가 `SUPABASE_URL`과 같은 프로젝트를 가리키지 않으면 빌드가 실패합니다.
- 환경변수(Vercel Project Settings > Environment Variables): `SUPABASE_URL`(경로 없는 `https://….supabase.co`), `SUPABASE_PUBLISHABLE_KEY`(공개 키), `SUPABASE_SECRET_KEY`(서버 전용, 브라우저에 절대 노출하지 않음). 넣거나 바꾼 뒤에는 다시 배포합니다.
- 시험 계정: Supabase 대시보드 Authentication > Users > Add user로 직접 만듭니다(비밀번호는 화면에서만 입력하고 어디에도 적지 않습니다).
- 다시 실행: `npm run test:notes`, `npm run test:r5`, `npm run build -- --local`
- 3단계 저장점: `aleph.config.json`의 `step`을 3으로 올리고 `scripts/deployment-identity.mjs`·`scripts/build-public.mjs`·`src/attack-check.mjs`가 step 3을 받게 했습니다. `src/attack-check.mjs`는 비로그인 `/data.json`(메모 없음 확인)과 비로그인 `GET /api/notes`(401·403과 JSON 오류로 거부되는지)를 실제로 요청해 결과만 기록합니다. 정상 로그인(A)과 다른 사람(B)으로 보내는 점검은 토큰이 필요해 **미실행**입니다.

### 3단계의 알려진 약점

- **메모의 주인을 확인하지 않습니다(4단계에서 막음).** 로그인한 B가 A의 메모 id를 알면 `GET`·`PUT`·`DELETE /api/notes/:id`로 읽고 고치고 지울 수 있습니다. 시험(`test/notes-api.test.mjs`)에도 이 약점이 그대로 기록돼 있습니다.
- 목록(`GET /api/notes`)은 `owner_id`가 내 id이거나 비어 있는 메모를 돌려줍니다. 2단계에서 옮긴 가상 메모는 `owner_id`가 비어 있어 로그인한 누구에게나 보입니다.
- `/api/notes` 주소는 여전히 공개되어 있습니다. 로그인 없이는 거부할 뿐, 막는 것은 토큰 확인 하나입니다.
- 서버 전용 키는 RLS를 우회합니다. 제한은 서버 코드가 입력(제목 1~200자, 내용 5000자 이하)과 읽는 열을 검사하는 것뿐입니다.
- 호출 횟수 제한이 없고, 회원가입 제한·비밀번호 정책은 Supabase 기본값 그대로입니다.
- 브라우저에서의 로그인·추가·수정·삭제 흐름과 실제 토큰 확인은 배포 뒤 직접 확인해야 합니다. 이 저장소의 시험은 가짜 확인기로 한 단위 시험입니다.

## 2단계: 자료를 코드 밖으로 옮김 (3단계의 바탕)

- 가상 메모 네 건은 Supabase의 `public.study_notes` 테이블에 있습니다. 이 테이블은 RLS를 켜고 `anon`·`authenticated`에는 읽기 권한을 주지 않았습니다. 테이블 생성 SQL에는 메모 문장이 들어 있어 이 저장소에 커밋하지 않습니다.
- 2단계에서는 화면이 로그인 없이 `GET /api/notes`를 호출했고 서버 함수 `api/notes.js`가 `title`, `content`만 돌려줬습니다. 3단계에서 함수는 `api/notes/` 폴더로 옮겨 로그인을 요구합니다(위 참고).
- 서버 함수는 환경변수 `SUPABASE_URL`과 `SUPABASE_SECRET_KEY`를 읽습니다. Vercel의 Project Settings > Environment Variables에 직접 넣고, 넣은 뒤 다시 배포하세요. 비밀 키는 코드·Git·README·브라우저 파일·응답·로그에 넣지 않습니다. 환경변수가 없으면 함수는 500 `NOTES_NOT_CONFIGURED`만 돌려줍니다.
- `data.json`과 `public/data.json`의 `notes`는 비어 있고, 빌드(`scripts/build-public.mjs`)는 `notes`에 항목이 있으면 실패합니다. 그래서 `/data.json`에는 메모가 나오지 않습니다.
- 2단계 저장점에서는 `step`을 1로 두었습니다. 3단계에서 3으로 올렸습니다.
- 빌드가 만드는 `/aleph.json`에는 `database` 칸(Supabase 주소, 공개 키, 테이블 이름 `study_notes`)이 들어갑니다. 심판이 공개 키로 직접 요청해 보기 위한 값입니다. 값은 Vercel 환경변수 `SUPABASE_URL`(`https://….supabase.co`)과 `SUPABASE_PUBLISHABLE_KEY`(`sb_publishable_`로 시작하는 공개 키)에서 읽고, 하나라도 없거나 형식이 다르면 빌드가 실패합니다. 서버 전용 `SUPABASE_SECRET_KEY`는 이 파일에 절대 넣지 않으며, secret 키 모양의 값은 빌드가 거부합니다.
- 다시 실행: `npm run test:notes`, `npm run test:r5`, `npm run build -- --local`
- 저장점 「2단계」: `aleph.config.json`의 `repoUrl`과 `publicAppUrl`을 실제 저장소와 배포 주소로 채웠습니다(`judgeIssuer`는 그대로). 제출 묶음은 `npm run bundle`로 만들며, 커밋하지 않는 `bundle-notes.json`에 이번 단계에서 한 일을 적어 둬야 합니다. `bundle`은 실제 배포 주소로 요청을 보내므로 인터넷에 연결된 컴퓨터에서 실행합니다.

### 2단계 시점의 약점 (기록)

3단계에서 일부가 바뀌었습니다. 현재 약점은 위 '3단계의 알려진 약점'을 보세요.

- **(3단계에서 로그인 요구로 바뀜) 함수는 공개 주소였습니다.** `/api/notes`는 로그인 없이 누구나 호출해 메모를 받을 수 있습니다. 비밀 키는 서버에만 있어 새어 나가지 않지만, 함수 자체는 접근을 막지 않습니다. 로그인과 허용 경로는 3단계 이후에 추가합니다.
- 서버 전용 키는 RLS를 우회합니다. 지금의 한도는 함수가 읽는 열을 `title`, `content`로 제한하고 최대 100건만 돌려주는 것뿐입니다.
- 호출 횟수 제한이 없습니다. 반복 호출로 Supabase와 Vercel 사용량을 소모시킬 수 있습니다.
- 메모가 사용자별로 나뉘어 있지 않습니다. `owner_id`가 비어 있어, 호출한 사람이 누구든 같은 전체 목록(최대 100건)을 받습니다.

## 가상 메모 노출 확인 절차

가상 메모 문장은 이 저장소의 어떤 파일에도 적지 않습니다. 아래 절차는 문장 목록을 저장소 밖 임시 파일로 만들어 검색합니다.

**준비.** Supabase SQL Editor에서 `select content from public.study_notes order by id;`를 실행하고, 결과의 `content` 네 줄을 한 줄에 하나씩 `~/memo-sentences.txt`에 저장합니다. 파일은 저장소 밖에 두고 커밋하지 않으며, 확인이 끝나면 지웁니다. 빈 줄이 있으면 모든 줄이 일치한 것으로 나오니 빈 줄을 두지 않습니다.

**확인.** 세 가지를 각각 따로 실행하고 따로 기록합니다.

1. GitHub 최신 파일: `git fetch origin main` 뒤 `git grep -nF -f ~/memo-sentences.txt origin/main`. 통과 기준은 출력이 없는 것입니다.
2. 현재 배포 파일: `APP`에 배포 주소(`https://….vercel.app`)를 넣고 `for p in / /data.json /aleph.json; do printf '%s ' "$p"; curl -fsS "$APP$p" | grep -cF -f ~/memo-sentences.txt; done`을 실행합니다. 세 경로 모두 0이어야 통과입니다. `/aleph.json`의 `commit`이 1번에서 확인한 커밋과 다르면 새 배포가 아직 반영되지 않은 것이므로 통과로 치지 않습니다. `/api/notes`는 로그인한 사람에게 메모를 돌려주는 것이 정상이라 이 검색에서 제외하고, 위 '알려진 약점'에 따로 기록합니다.
3. 옛 기록(참고): `git grep -nF -f ~/memo-sentences.txt e3a3cd4`. 일치가 나오는 것이 현재 상태입니다.

**과거 노출은 해소되지 않았습니다.** 1번과 2번이 통과해도 "지금의 최신 파일과 현재 배포에는 없다"는 뜻일 뿐입니다. 옛 공개 커밋 `e3a3cd4`에 메모 문장이 남아 있고 저장소가 공개라 누구나 볼 수 있습니다. 이전 Vercel 배포도 삭제하기 전까지 그 시점의 파일을 계속 제공할 수 있습니다. 그래서 과거 노출이 해소됐다고 쓰지 않습니다. 커밋 이력 정리와 옛 배포 삭제는 이 단계에서 하지 않았습니다.

### 검사 결과 기록

| 날짜 | 대상 | 기준 | 결과 |
|---|---|---|---|
| 2026-10-06 | GitHub 최신 파일 | `origin/main` `9105549` | 일치 0건 (통과) |
| 2026-10-06 | 옛 공개 커밋 | `e3a3cd4` | `data.json`, `public/data.json`에 메모 네 문장이 있음 (과거 노출 그대로) |
| 2026-10-06 15:27 | 현재 배포 `/data.json` | 배포 커밋 `b6771bb` (`/aleph.json` 기준) | `notes`가 빈 배열이고 메모 문장 없음 (통과) |
| 2026-10-06 15:27 | 현재 배포 `/aleph.json` | 같은 배포 | 메모 문장 없음. 저장소는 `m-yh01/choi-bujang-secret-vault`, 커밋은 `b6771bb` |
| 2026-10-06 | 현재 배포 `/` | 같은 배포 | 정적 HTML에 메모 문장 없음 |
| 2026-10-06 15:27 | 화면에 카드 네 장 (`/api/notes`) | 배포 `b6771bb` | 502 응답으로 메모가 오지 않음 (미통과). Vercel Logs의 오류 코드는 `PGRST125`였고 `SUPABASE_URL` 값의 경로를 지운 뒤 해소 |
| 2026-10-06 15:33 | 화면에 카드 네 장 (`/api/notes`) | 배포 `6401e5d` | 메모 네 건(제목 네 개)이 응답됨 (통과). 화면 렌더링은 브라우저에서 직접 확인해야 함 |

배포 쪽 결과는 셸에서 배포 주소에 접속할 수 없어 `curl` 대신 웹 조회 도구(요약 응답)로 확인했습니다. 이 도구는 같은 주소를 15분 안에 다시 조회하면 저장된 옛 응답을 줄 수 있어, 주소 뒤에 `?check=값`을 붙여 새로 확인했습니다. 처음 적었던 "새 커밋이 아직 배포되지 않음"은 저장된 옛 응답을 본 잘못된 판단이어서 위 표로 바로잡았습니다. 위 절차의 `curl` 명령은 직접 실행해 다시 확인해야 합니다.

검색 결과가 깨끗해도 API의 약점은 따로 남습니다. 2단계 시점에는 `/api/notes`가 로그인 없이 메모를 돌려줬고, 3단계부터는 로그인을 요구하지만 소유자 확인이 없습니다. 위 '알려진 약점'을 보세요. (이 표의 `/api/notes` 확인 결과는 2단계 시점의 기록입니다.)

## 시작 틀의 자동 처리

`vercel.json`은 정적 결과물 `public`을 배포합니다. 빌드 명령 `npm run build`는 Vercel이 제공하는 GitHub 저장소 소유자·이름, 커밋 SHA, 배포 URL을 검증하고 `public/aleph.json`을 생성합니다. 이 값이 없으면 빌드가 실패하므로, 성공한 것처럼 빈 주소를 내보내지 않습니다. `aleph.json`의 내용만으로 저장소 소유권이나 방어 성공을 인정하지 않습니다. 심판이 공개 저장소의 실제 커밋과 배포된 자료를 따로 대조해야 합니다.

`aleph.config.json`의 `repoUrl`과 `publicAppUrl`은 시작 틀에서는 이전 제출 묶음 방식의 자리표시자였고, 1단계에서는 학생이 편집하지 않습니다. 이 저장소는 2단계 저장점에서 실제 주소로 채웠고, 3단계에서 `identityProvider`와 `allowedRoutes`를 더했습니다. 2단계 이후 코딩 도구가 필요한 설정과 보호 기능을 단계별로 작성합니다. `npm run bundle`과 `bundle-notes.json`도 1단계의 세 걸음에는 포함되지 않습니다.

로컬에서 가상 화면만 확인할 때는 `npm run build -- --local`을 사용합니다. 로컬 실행은 Vercel 배포나 심판 접수를 증명하지 않습니다. 저장소의 `src/attack-check.mjs`는 실제 배포가 된 뒤 `/data.json`을 비로그인으로 요청해 공개 가상 메모의 확인 표시를 읽습니다. 2단계 변경 뒤에는 `/data.json`에 메모가 없으므로 이 점검이 "확인 표시가 보이지 않음"으로 기록되는 것이 정상입니다. 3단계부터는 비로그인 `/api/notes` 점검이 함께 실행됩니다. 이 결과는 학생의 자기 점검이며 심판의 판정이 아닙니다.

## 다음 단계의 코딩 도구에 전달할 규칙

[AGENTS.md](AGENTS.md)를 먼저 읽히고 한 번에 한 제작 단위만 요청하세요. 2단계에서 `public/data.json`을 복사하는 1단계 빌드 흐름은 메모 없는 파일만 복사하도록 바꿨습니다. 3단계 이후의 로그인, 허용 경로, 5단계의 원본 API 주소, 6단계 이후 정책 규칙은 해당 단계 원고와 계약에 맞춰 추가합니다. 비밀번호·토큰·서버 전용 키·실제 학생 기록을 코드, Git, 제출 묶음에 넣지 않습니다.

`src/decider.mjs`와 `src/detect.mjs`의 로컬 시험은 반 엔진이나 운영 심판의 결과가 아닙니다. 1단계 이후 제출 묶음 계약 `aleph.defense.submission.v2`는 `scripts/bundle.mjs`에 남아 있으며, 코딩 도구가 해당 단계의 최신 배포 주소와 Git 원격을 맞춘 뒤 사용합니다.

