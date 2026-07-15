-- Phase 1 · append-only audit log + rate-limiting substrate for code lookups.

create table public.events (
  id bigint generated always as identity primary key,
  entity_type text not null,
  entity_id uuid not null,
  event text not null,
  actor text not null default 'system',
  payload jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

comment on table public.events is
  'Append-only audit log. Every state transition on vouchers/bookings/exchanges/payouts writes a row — non-negotiable for a money-adjacent system. UPDATE/DELETE are blocked by trigger for every role, service role included.';

create index events_entity_idx on public.events (entity_type, entity_id, created_at);

create trigger events_append_only
  before update or delete on public.events
  for each row execute function public.forbid_mutation();

create table public.activation_attempts (
  id bigint generated always as identity primary key,
  ip inet not null,
  succeeded boolean not null default false,
  created_at timestamptz not null default now()
);

comment on table public.activation_attempts is
  'Sliding-window rate limiting for voucher-code lookups — the app''s main abuse surface (codes are semi-guessable). The activation edge function inserts one row per attempt and enforces per-IP and global thresholds by counting recent rows BEFORE touching vouchers. Never stores attempted codes. Old rows pruned by a scheduled function.';

create index activation_attempts_ip_idx on public.activation_attempts (ip, created_at desc);
create index activation_attempts_created_idx on public.activation_attempts (created_at);

alter table public.events enable row level security;
alter table public.activation_attempts enable row level security;
revoke all on public.events from anon, authenticated;
revoke all on public.activation_attempts from anon, authenticated;
