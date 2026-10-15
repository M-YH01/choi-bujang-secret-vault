-- 12단계: 탈환 작전실의 수치와 서버 기록을 맞춰 보는 읽기 전용 질의입니다. 아무것도 바꾸지 않습니다.
-- 메모 제목·내용·이메일은 읽지 않고, 사용자는 ID 앞 8글자로만 보입니다.
-- 화면(작전실)은 로그인한 사용자 한 사람의 기록만 세므로, 같은 앞 8글자 줄의 숫자와 비교하세요.

-- 1) 기기 승인 상태별 건수 (화면의 「회수 상태」)
select left(user_id::text, 8) as user_prefix, status, count(*) as devices
from public.device_approvals group by 1, 2 order by 1, 2;

-- 2) 비공개 사본 건수와 가장 늦은 사본 시각 (화면의 「복구 버전」)
select left(owner_id::text, 8) as owner_prefix, count(*) as backups, max(backed_up_at) as latest_backup_at
from public.study_notes_backup group by 1 order by 1;

-- 3) 감사 기록 건수 (화면의 「복구 버전」 감사 줄). 화면은 가장 최근 1000줄까지만 셉니다.
select left(actor::text, 8) as actor_prefix, action, result, count(*) as rows, max(at) as latest_at
from public.study_notes_audit group by 1, 2, 3 order by 1, 2, 3;
