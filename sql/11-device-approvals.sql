-- 11단계: 기기 승인 표. Supabase SQL Editor에서 직접 검토하고 실행합니다.
-- 이 파일에는 메모 문장·이메일·키가 없습니다. 기기 식별자 원문은 저장하지 않고 해시만 저장합니다.
-- 서버 전용 키(service_role)는 요청(pending 줄)을 만들고 읽을 수만 있고, status를 정하거나 바꿀 수 없습니다.
-- 승인·회수는 이 SQL Editor(운영자)에서 아래 4)의 문장으로만 합니다.

create table if not exists public.device_approvals (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null,
  device_hash text not null check (device_hash ~ '^[0-9a-f]{64}$'),
  label text check (label is null or char_length(label) <= 40),
  status text not null default 'pending' check (status in ('pending', 'approved', 'revoked')),
  requested_at timestamptz not null default now(),
  decided_at timestamptz,
  unique (user_id, device_hash)
);

alter table public.device_approvals enable row level security;
revoke all on table public.device_approvals from public, anon, authenticated;
revoke all on table public.device_approvals from service_role;
-- 서버가 할 수 있는 것: 읽기, 그리고 user_id·device_hash·label만 넣기(status는 기본값 pending으로만 들어감).
grant select on table public.device_approvals to service_role;
grant insert (user_id, device_hash, label) on table public.device_approvals to service_role;

-- 확인: 서버 키 권한이 위와 같은지 봅니다. status 열 INSERT·UPDATE는 false여야 합니다.
select 'table_select' as item, has_table_privilege('service_role', 'public.device_approvals', 'SELECT') as allowed
union all select 'table_update', has_table_privilege('service_role', 'public.device_approvals', 'UPDATE')
union all select 'table_delete', has_table_privilege('service_role', 'public.device_approvals', 'DELETE')
union all select 'status_insert', has_column_privilege('service_role', 'public.device_approvals', 'status', 'INSERT')
union all select 'status_update', has_column_privilege('service_role', 'public.device_approvals', 'status', 'UPDATE')
union all select 'label_insert', has_column_privilege('service_role', 'public.device_approvals', 'label', 'INSERT');

-- 4) 운영자의 승인 방법(필요할 때 하나씩 실행). 화면에 나온 "요청 번호" 앞 8글자로 줄을 찾습니다.
--    먼저 대기 중인 요청을 봅니다:
--      select left(replace(id::text, '-', ''), 8) as request_code, user_id, label, requested_at
--      from public.device_approvals where status = 'pending' order by requested_at;
--    확인한 요청 하나를 승인합니다(요청 번호를 바꿔 넣으세요):
--      update public.device_approvals set status = 'approved', decided_at = now()
--      where status = 'pending' and left(replace(id::text, '-', ''), 8) = '요청번호8글자';
--    승인한 기기를 회수합니다:
--      update public.device_approvals set status = 'revoked', decided_at = now()
--      where left(replace(id::text, '-', ''), 8) = '요청번호8글자';
