-- Run in Supabase SQL Editor BEFORE deploying the member signup pages.
-- Administrator website login: info@lvbnn.com (must exist in Supabase Auth).
-- Add a second verified administrator email to the array if needed.
begin;
create table if not exists public.directory_members (
  user_id uuid primary key references auth.users(id) on delete cascade,
  email text not null,
  full_name text not null default '',
  organization text not null default '',
  status text not null default 'pending' check (status in ('pending','approved','revoked')),
  role text not null default 'member' check (role in ('member','admin')),
  created_at timestamptz not null default now()
);
alter table public.directory_members enable row level security;
create or replace function public.directory_is_admin() returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.directory_members
    where user_id = (select auth.uid()) and role = 'admin' and status = 'approved');
$$;
create or replace function public.directory_can_read() returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.directory_members
    where user_id = (select auth.uid()) and status = 'approved');
$$;
revoke all on function public.directory_is_admin(), public.directory_can_read() from public;
grant execute on function public.directory_is_admin(), public.directory_can_read() to authenticated;
create or replace function public.directory_create_request() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  insert into public.directory_members(user_id,email,full_name,organization)
  values (new.id,coalesce(new.email,''),left(coalesce(new.raw_user_meta_data->>'full_name',''),200),
    left(coalesce(new.raw_user_meta_data->>'organization',''),200))
  on conflict (user_id) do nothing;
  return new;
end;
$$;
revoke all on function public.directory_create_request() from public;
drop trigger if exists directory_signup_request on auth.users;
create trigger directory_signup_request after insert on auth.users
for each row execute function public.directory_create_request();
insert into public.directory_members(user_id,email)
select id,coalesce(email,'') from auth.users on conflict (user_id) do nothing;
do $$
declare admin_emails text[] := array['info@lvbnn.com'];
begin
  if exists (select 1 from unnest(admin_emails) e where e like 'REPLACE_%') then
    raise exception 'Replace the administrator email before running. No changes committed.';
  end if;
  if exists (select 1 from unnest(admin_emails) e
    where not exists (select 1 from auth.users u where lower(u.email) = lower(e))) then
    raise exception 'Every administrator email must match an existing Supabase Auth user.';
  end if;
  update public.directory_members set role='admin',status='approved'
  where lower(email) in (select lower(e) from unnest(admin_emails) e);
end;
$$;
-- Replace permissive policies rather than adding restrictive ones alongside them.
do $$
declare p record;
begin
  for p in select tablename,policyname from pg_policies
    where schemaname='public' and tablename in ('Contractors','directory_members') loop
    execute format('drop policy %I on public.%I',p.policyname,p.tablename);
  end loop;
end;
$$;
revoke all on public.directory_members from anon, authenticated;
grant select on public.directory_members to authenticated;
grant update(status) on public.directory_members to authenticated;
create policy member_read on public.directory_members for select to authenticated
using (user_id = (select auth.uid()) or public.directory_is_admin());
create policy admin_status on public.directory_members for update to authenticated
using (public.directory_is_admin() and role='member')
with check (public.directory_is_admin() and role='member');
alter table public."Contractors" enable row level security;
revoke all on public."Contractors" from anon, authenticated;
grant select,insert,update,delete on public."Contractors" to authenticated;
create policy approved_read on public."Contractors" for select to authenticated
using (public.directory_can_read());
create policy admin_insert on public."Contractors" for insert to authenticated
with check (public.directory_is_admin());
create policy admin_update on public."Contractors" for update to authenticated
using (public.directory_is_admin()) with check (public.directory_is_admin());
create policy admin_delete on public."Contractors" for delete to authenticated
using (public.directory_is_admin());
commit;
