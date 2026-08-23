-- Nexus security hardening (idempotent).
-- Run AFTER schema.sql and permissions.sql in the Supabase SQL Editor.
-- Replaces open `using (true)` policies with authenticated, scoped RLS.
--
-- Extra admin (SQL Editor):
--   update public.app_settings
--     set value = 'teammate@unu.edu,ayhnassef@unu.edu'
--     where key = 'bootstrap_admin_emails';
--   select public.elevate_bootstrap_admins();

create table if not exists public.app_settings (
  key text primary key,
  value text not null
);

alter table public.app_settings enable row level security;
alter table public.app_settings force row level security;

insert into public.app_settings (key, value)
values ('bootstrap_admin_emails', 'ayhnassef@unu.edu')
on conflict (key) do nothing;

create table if not exists public.chat_rate_buckets (
  user_id uuid primary key,
  window_start timestamptz not null,
  hit_count integer not null default 0
);

alter table public.chat_rate_buckets enable row level security;
alter table public.chat_rate_buckets force row level security;

create or replace function public.bootstrap_admin_emails()
returns text[]
language sql
stable
security definer
set search_path = public
as $$
  select coalesce(
    (
      select array_agg(trim(both from lower(e)))
      from unnest(string_to_array(s.value, ',')) as e
      where trim(both from e) <> ''
    ),
    array['ayhnassef@unu.edu']::text[]
  )
  from public.app_settings s
  where s.key = 'bootstrap_admin_emails';
$$;

create or replace function public.jwt_email()
returns text
language sql
stable
as $$
  select lower(nullif(trim(coalesce(auth.jwt() ->> 'email', '')), ''));
$$;

create or replace function public.current_profile_id()
returns uuid
language sql
stable
security definer
set search_path = public
as $$
  select p.id
  from public.profiles p
  where p.id = auth.uid()
     or lower(p.email) = public.jwt_email()
  order by case when p.id = auth.uid() then 0 else 1 end
  limit 1;
$$;

create or replace function public.is_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select
    auth.uid() is not null
    and (
      public.jwt_email() = any (public.bootstrap_admin_emails())
      or exists (
        select 1
        from public.profiles p
        where (p.id = auth.uid() or lower(p.email) = public.jwt_email())
          and p.is_admin = true
          and p.disabled_at is null
      )
    );
$$;

create or replace function public.is_active_user()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select
    auth.role() = 'authenticated'
    and auth.uid() is not null
    and public.jwt_email() is not null
    and public.jwt_email() like '%@unu.edu'
    and not exists (
      select 1 from public.banned_emails b
      where b.email = public.jwt_email()
    )
    and not exists (
      select 1 from public.profiles p
      where (p.id = auth.uid() or lower(p.email) = public.jwt_email())
        and p.disabled_at is not null
    );
$$;

create or replace function public.email_is_blocked(p_email text)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1 from public.banned_emails
    where email = lower(trim(p_email))
  ) or exists (
    select 1 from public.profiles
    where email = lower(trim(p_email))
      and disabled_at is not null
  );
$$;

create or replace function public.canonicalize_library_path(p text)
returns text
language plpgsql
immutable
as $$
declare
  seg text;
  out_parts text[] := '{}';
begin
  if p is null then
    return '';
  end if;
  foreach seg in array string_to_array(replace(p, '\', '/'), '/') loop
    seg := trim(seg);
    if seg = '' then
      continue;
    elsif seg = '.' or seg = '..' then
      return null;
    else
      -- Postgres `text` cannot contain NUL (0x00), so no extra NUL check here.
      out_parts := array_append(out_parts, seg);
    end if;
  end loop;
  return array_to_string(out_parts, '/');
end;
$$;

create or replace function public.library_folder_of(p_ref text)
returns text
language plpgsql
immutable
as $$
declare
  n text;
begin
  n := public.canonicalize_library_path(coalesce(p_ref, ''));
  if n is null then
    return null;
  end if;
  if n = '' or position('/' in n) = 0 then
    return '';
  end if;
  return regexp_replace(n, '/[^/]+$', '');
end;
$$;

create or replace function public.can_read_library_path(p_doc_path text)
returns boolean
language plpgsql
stable
security definer
set search_path = public
as $$
declare
  pid uuid := public.current_profile_id();
  admin boolean;
  role text;
  folder text;
  matched text;
begin
  if not public.is_active_user() then
    return false;
  end if;
  if pid is null then
    return false;
  end if;

  select p.is_admin, p.library_role
    into admin, role
  from public.profiles p
  where p.id = pid;

  if not found then
    return false;
  end if;
  if admin then
    return true;
  end if;
  if role is distinct from 'view' and role is distinct from 'edit' then
    return false;
  end if;

  folder := public.library_folder_of(p_doc_path);
  if folder is null then
    return false;
  end if;

  select l.folder_path
    into matched
  from public.library_folder_locks l
  where l.folder_path = ''
     or folder = l.folder_path
     or folder like l.folder_path || '/%'
  order by length(l.folder_path) desc
  limit 1;

  if matched is null then
    return true;
  end if;

  return exists (
    select 1
    from public.library_folder_viewers v
    where v.folder_path = matched
      and v.profile_id = pid
  );
end;
$$;

create or replace function public.can_edit_library()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select public.is_active_user()
    and (
      public.is_admin()
      or exists (
        select 1 from public.profiles p
        where p.id = public.current_profile_id()
          and p.library_role = 'edit'
          and p.disabled_at is null
      )
    );
$$;

create or replace function public.elevate_bootstrap_admins()
returns void
language sql
security definer
set search_path = public
as $$
  update public.profiles
  set is_admin = true, library_role = 'edit'
  where lower(email) = any (public.bootstrap_admin_emails());
$$;

select public.elevate_bootstrap_admins();

alter table public.profiles
  alter column library_role set default 'none';

update public.profiles
set library_role = 'none'
where library_role is null;

alter table public.profiles
  drop constraint if exists profiles_library_role_check;
alter table public.profiles
  add constraint profiles_library_role_check
  check (library_role in ('none', 'view', 'edit'));

create or replace function public.protect_profile_privileges()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if tg_op = 'INSERT' then
    if auth.uid() is not null then
      NEW.id := auth.uid();
      NEW.email := coalesce(public.jwt_email(), lower(NEW.email));
      NEW.is_admin := false;
      NEW.library_role := 'none';
      NEW.disabled_at := null;
      NEW.disabled_reason := null;
    end if;
    if lower(NEW.email) = any (public.bootstrap_admin_emails()) then
      NEW.is_admin := true;
      NEW.library_role := 'edit';
    end if;
    return NEW;
  end if;

  if auth.uid() is null then
    return NEW;
  end if;

  NEW.id := OLD.id;
  NEW.email := OLD.email;
  NEW.is_admin := OLD.is_admin;
  NEW.library_role := OLD.library_role;
  NEW.disabled_at := OLD.disabled_at;
  NEW.disabled_reason := OLD.disabled_reason;
  return NEW;
end;
$$;

drop trigger if exists protect_profile_privileges on public.profiles;
create trigger protect_profile_privileges
  before insert or update on public.profiles
  for each row execute function public.protect_profile_privileges();

create or replace function public.enforce_library_document_limits()
returns trigger
language plpgsql
as $$
declare
  canonical text;
begin
  canonical := public.canonicalize_library_path(coalesce(NEW.external_ref, NEW.filename));
  if canonical is null then
    raise exception 'Invalid library path';
  end if;
  NEW.external_ref := nullif(canonical, '');
  if NEW.text_content is not null and char_length(NEW.text_content) > 1500000 then
    NEW.text_content := left(NEW.text_content, 1500000);
  end if;
  if NEW.byte_size is not null and NEW.byte_size > 41943040 then
    raise exception 'File exceeds 40 MB';
  end if;
  return NEW;
end;
$$;

drop trigger if exists enforce_library_document_limits on public.library_documents;
create trigger enforce_library_document_limits
  before insert or update on public.library_documents
  for each row execute function public.enforce_library_document_limits();

create or replace function public.enforce_auth_email_policy()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if NEW.email is null or split_part(lower(NEW.email), '@', 2) is distinct from 'unu.edu' then
    raise exception 'Access is limited to @unu.edu accounts'
      using errcode = '42501';
  end if;
  if exists (
    select 1 from public.banned_emails b where b.email = lower(NEW.email)
  ) then
    raise exception 'This email is banned from Nexus'
      using errcode = '42501';
  end if;
  return NEW;
end;
$$;

drop trigger if exists enforce_auth_email_policy_bi on auth.users;
create trigger enforce_auth_email_policy_bi
  before insert on auth.users
  for each row execute function public.enforce_auth_email_policy();

drop trigger if exists enforce_auth_email_policy_bu on auth.users;
create trigger enforce_auth_email_policy_bu
  before update of email on auth.users
  for each row execute function public.enforce_auth_email_policy();

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  admin boolean;
begin
  admin := lower(NEW.email) = any (public.bootstrap_admin_emails());
  insert into public.profiles (id, email, display_name, library_role, is_admin)
  values (
    NEW.id,
    lower(NEW.email),
    nullif(trim(coalesce(NEW.raw_user_meta_data->>'full_name', NEW.raw_user_meta_data->>'name')), ''),
    case when admin then 'edit' else 'none' end,
    admin
  )
  on conflict (id) do nothing;
  return NEW;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

drop policy if exists "profiles all for service" on public.profiles;
drop policy if exists "conversations all for service" on public.conversations;
drop policy if exists "messages all for service" on public.messages;
drop policy if exists "library all for service" on public.library_documents;
drop policy if exists "directory all for service" on public.directory_contacts;
drop policy if exists "events all for service" on public.events;
drop policy if exists "publications all for service" on public.publications;
drop policy if exists "banned_emails all" on public.banned_emails;
drop policy if exists "library_folder_viewers all" on public.library_folder_viewers;
drop policy if exists "library_folder_locks all" on public.library_folder_locks;

drop policy if exists "profiles select" on public.profiles;
drop policy if exists "profiles insert own" on public.profiles;
drop policy if exists "profiles update own" on public.profiles;
drop policy if exists "conversations select own" on public.conversations;
drop policy if exists "conversations insert own" on public.conversations;
drop policy if exists "conversations update own" on public.conversations;
drop policy if exists "conversations delete own" on public.conversations;
drop policy if exists "messages select own" on public.messages;
drop policy if exists "messages insert own" on public.messages;
drop policy if exists "messages update own" on public.messages;
drop policy if exists "messages delete own" on public.messages;
drop policy if exists "library select allowed" on public.library_documents;
drop policy if exists "library insert editors" on public.library_documents;
drop policy if exists "library update editors" on public.library_documents;
drop policy if exists "library delete editors" on public.library_documents;
drop policy if exists "directory staff" on public.directory_contacts;
drop policy if exists "events staff" on public.events;
drop policy if exists "publications staff" on public.publications;
drop policy if exists "banned_emails select admin" on public.banned_emails;
drop policy if exists "folder_locks select" on public.library_folder_locks;
drop policy if exists "folder_viewers select" on public.library_folder_viewers;

alter table public.profiles force row level security;
alter table public.conversations force row level security;
alter table public.messages force row level security;
alter table public.library_documents force row level security;
alter table public.directory_contacts force row level security;
alter table public.events force row level security;
alter table public.publications force row level security;
alter table public.banned_emails force row level security;
alter table public.library_folder_viewers force row level security;
alter table public.library_folder_locks force row level security;

create policy "profiles select" on public.profiles
  for select to authenticated
  using (
    id = auth.uid()
    or lower(email) = public.jwt_email()
    or public.is_admin()
  );

create policy "profiles insert own" on public.profiles
  for insert to authenticated
  with check (
    id = auth.uid()
    and lower(email) = public.jwt_email()
  );

create policy "profiles update own" on public.profiles
  for update to authenticated
  using (id = auth.uid() or lower(email) = public.jwt_email())
  with check (id = auth.uid() or lower(email) = public.jwt_email());

create policy "conversations select own" on public.conversations
  for select to authenticated
  using (public.is_active_user() and user_id = public.current_profile_id());

create policy "conversations insert own" on public.conversations
  for insert to authenticated
  with check (public.is_active_user() and user_id = public.current_profile_id());

create policy "conversations update own" on public.conversations
  for update to authenticated
  using (public.is_active_user() and user_id = public.current_profile_id())
  with check (public.is_active_user() and user_id = public.current_profile_id());

create policy "conversations delete own" on public.conversations
  for delete to authenticated
  using (public.is_active_user() and user_id = public.current_profile_id());

create policy "messages select own" on public.messages
  for select to authenticated
  using (
    public.is_active_user()
    and exists (
      select 1 from public.conversations c
      where c.id = conversation_id
        and c.user_id = public.current_profile_id()
    )
  );

create policy "messages insert own" on public.messages
  for insert to authenticated
  with check (
    public.is_active_user()
    and exists (
      select 1 from public.conversations c
      where c.id = conversation_id
        and c.user_id = public.current_profile_id()
    )
  );

create policy "messages update own" on public.messages
  for update to authenticated
  using (
    public.is_active_user()
    and exists (
      select 1 from public.conversations c
      where c.id = conversation_id
        and c.user_id = public.current_profile_id()
    )
  )
  with check (
    public.is_active_user()
    and exists (
      select 1 from public.conversations c
      where c.id = conversation_id
        and c.user_id = public.current_profile_id()
    )
  );

create policy "messages delete own" on public.messages
  for delete to authenticated
  using (
    public.is_active_user()
    and exists (
      select 1 from public.conversations c
      where c.id = conversation_id
        and c.user_id = public.current_profile_id()
    )
  );

create policy "library select allowed" on public.library_documents
  for select to authenticated
  using (public.can_read_library_path(coalesce(external_ref, filename)));

create policy "library insert editors" on public.library_documents
  for insert to authenticated
  with check (
    public.can_edit_library()
    and public.can_read_library_path(coalesce(external_ref, filename))
  );

create policy "library update editors" on public.library_documents
  for update to authenticated
  using (
    public.can_edit_library()
    and public.can_read_library_path(coalesce(external_ref, filename))
  )
  with check (
    public.can_edit_library()
    and public.can_read_library_path(coalesce(external_ref, filename))
  );

create policy "library delete editors" on public.library_documents
  for delete to authenticated
  using (
    public.can_edit_library()
    and public.can_read_library_path(coalesce(external_ref, filename))
  );

create policy "directory staff" on public.directory_contacts
  for all to authenticated
  using (public.is_active_user())
  with check (public.is_active_user());

create policy "events staff" on public.events
  for all to authenticated
  using (public.is_active_user())
  with check (public.is_active_user());

create policy "publications staff" on public.publications
  for all to authenticated
  using (public.is_active_user())
  with check (public.is_active_user());

create policy "banned_emails select admin" on public.banned_emails
  for select to authenticated
  using (public.is_admin());

create policy "folder_locks select" on public.library_folder_locks
  for select to authenticated
  using (public.is_active_user());

create policy "folder_viewers select" on public.library_folder_viewers
  for select to authenticated
  using (
    public.is_admin()
    or (public.is_active_user() and profile_id = public.current_profile_id())
  );

revoke all on all tables in schema public from anon, public;
revoke all on all sequences in schema public from anon, public;
revoke all on all functions in schema public from anon, public;

grant usage on schema public to anon, authenticated;

grant select, insert, update on public.profiles to authenticated;
grant select, insert, update, delete on public.conversations to authenticated;
grant select, insert, update, delete on public.messages to authenticated;
grant select, insert, update, delete on public.library_documents to authenticated;
grant select, insert, update, delete on public.directory_contacts to authenticated;
grant select, insert, update, delete on public.events to authenticated;
grant select, insert, update, delete on public.publications to authenticated;
grant select on public.banned_emails to authenticated;
grant select on public.library_folder_locks to authenticated;
grant select on public.library_folder_viewers to authenticated;

grant execute on function public.email_is_blocked(text) to anon, authenticated;
grant execute on function public.is_admin() to authenticated;
grant execute on function public.is_active_user() to authenticated;
grant execute on function public.current_profile_id() to authenticated;
grant execute on function public.jwt_email() to authenticated;
grant execute on function public.can_read_library_path(text) to authenticated;
grant execute on function public.can_edit_library() to authenticated;
grant execute on function public.canonicalize_library_path(text) to authenticated;
grant execute on function public.library_folder_of(text) to authenticated;
