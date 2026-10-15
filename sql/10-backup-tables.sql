-- 10단계: 비공개 메모 사본과 감사 기록 표. Supabase SQL Editor에서 직접 검토하고 실행합니다.
-- 이 파일에는 메모 문장·이메일·키가 없습니다(자료는 실행할 때 DB 안에서만 복사됩니다).
-- 두 표 모두 RLS를 켜고 PUBLIC·anon·authenticated 권한을 주지 않습니다. 서버 전용 키로만 접근합니다.

-- 1) 사본 표: study_notes와 같은 열 + 내용 해시.
create table if not exists public.study_notes_backup (
  id uuid primary key,
  owner_id uuid,
  title text not null,
  content text not null,
  content_sha256 text not null,
  backed_up_at timestamptz not null default now()
);

-- 2) 감사 기록 표: 추가만 합니다.
create table if not exists public.study_notes_audit (
  seq bigint generated always as identity primary key,
  at timestamptz not null default now(),
  actor uuid,
  action text not null,
  note_id uuid,
  content_sha256 text,
  result text not null
);

alter table public.study_notes_backup enable row level security;
alter table public.study_notes_audit enable row level security;
revoke all on table public.study_notes_backup from public, anon, authenticated;
revoke all on table public.study_notes_audit from public, anon, authenticated;
-- 서버 전용 키(service_role)가 감사 기록을 고치거나 지우지 못하게 합니다.
revoke update, delete, truncate on table public.study_notes_audit from service_role;
-- 서버 전용 키가 꼭 필요한 권한만 갖게 합니다: 사본은 읽기만, 감사 기록은 읽기와 추가만.
grant select on table public.study_notes_backup to service_role;
grant select, insert on table public.study_notes_audit to service_role;

-- 3) 사본 만들기: 침해 전에 한 번 실행합니다. 이미 있는 사본(id)은 건드리지 않습니다.
--    내용 해시는 sha256( UTF-8(제목) + 0x00 + UTF-8(내용) )이고, 서버 코드(contentSha256)와 같은 방식입니다.
insert into public.study_notes_backup (id, owner_id, title, content, content_sha256)
select n.id, n.owner_id, n.title, n.content,
       encode(sha256(convert_to(n.title, 'UTF8') || '\x00'::bytea || convert_to(n.content, 'UTF8')), 'hex')
from public.study_notes n
where n.owner_id is not null
on conflict (id) do nothing;

-- 4) 확인: 사본 건수와 소유자별 건수(이메일 대신 짧은 ID 앞부분만 보입니다).
select left(owner_id::text, 8) as owner_prefix, count(*) as backed_up
from public.study_notes_backup group by 1 order by 1;

-- 5) 권한 확인: 세 역할 모두 두 표에 권한이 없어야 하고, service_role은 감사 표에서 SELECT·INSERT만 있어야 합니다.
select t, r, p, has_table_privilege(r, format('public.%s', t), p) as allowed
from unnest(array['study_notes_backup', 'study_notes_audit']) t,
     unnest(array['anon', 'authenticated', 'service_role']) r,
     unnest(array['SELECT', 'INSERT', 'UPDATE', 'DELETE']) p
order by t, r, p;
