-- 10단계 보완: 메모가 "새로 만들어질 때" 그 처음 모습을 사본 표에 자동으로 남깁니다.
-- 수동으로 한 번 만든 사본에 없는 새 메모도 변조·삭제 전에 사본이 있게 하려는 것입니다.
-- 이미 사본이 있는 메모(id)는 건드리지 않으므로, 이후에 변조된 내용이 사본을 덮어쓰지 않습니다.
-- 사본 저장이 실패해도 메모 저장은 막지 않습니다. 대신 실패했다는 사실을 감사 표에 남겨 "조용한 백업 실패"를 막습니다.
-- 이 파일에는 메모 문장·이메일·키가 없습니다. 10-backup-tables.sql을 먼저 실행한 뒤 Supabase SQL Editor에서 실행하세요.

create or replace function public.study_notes_auto_backup()
returns trigger
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
  begin
    if new.owner_id is not null then
      insert into public.study_notes_backup (id, owner_id, title, content, content_sha256)
      values (new.id, new.owner_id, new.title, new.content,
              encode(sha256(convert_to(new.title, 'UTF8') || '\x00'::bytea || convert_to(new.content, 'UTF8')), 'hex'))
      on conflict (id) do nothing;
    end if;
  exception when others then
    begin
      insert into public.study_notes_audit (actor, action, note_id, result)
      values (new.owner_id, 'auto_backup', new.id, 'failed');
    exception when others then
      null;
    end;
  end;
  return new;
end;
$$;

revoke all on function public.study_notes_auto_backup() from public, anon, authenticated;

drop trigger if exists study_notes_auto_backup_after_insert on public.study_notes;
create trigger study_notes_auto_backup_after_insert
  after insert on public.study_notes
  for each row execute function public.study_notes_auto_backup();

-- 확인: 트리거가 하나 보여야 합니다.
select tgname, tgenabled from pg_trigger
where tgrelid = 'public.study_notes'::regclass and not tgisinternal;
